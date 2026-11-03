import io
import json
import pandas as pd
import logging
import os
import sys
from urllib.parse import urlsplit
from db import get_conn, require_running_scan
from ownership import (
    load_trusted_domains,
    normalize_hostname,
    ownership_for_discovery,
)
from recon_artifact import (
    ReconArtifactError,
    read_validated_recon_artifact,
    scan_recon_artifact_path,
)


class DownstreamEvidenceError(RuntimeError):
    pass


def normalize_artifact_text(value):
    if pd.isna(value):
        return ""
    return str(value).strip()


HTTP_OBSERVATION_STATUSES = {
    "RESPONDED",
    "NO_RESPONSE",
    "FAILED",
    "UNKNOWN",
}


def normalize_http_observation_status(value):
    status = normalize_artifact_text(value).upper()
    if status in HTTP_OBSERVATION_STATUSES:
        return status
    return "UNKNOWN"


DOWNSTREAM_EVIDENCE_TABLES = (
    "domain_san",
    "domain_dns",
    "domain_cert",
    "domain_ports",
    "domain_tech",
    "domain_technology_observations",
    "domain_asn",
    "domain_provider",
    "domain_findings",
    "domain_risk",
)


def require_no_downstream_evidence(cur, requested_scan_id):
    for table in DOWNSTREAM_EVIDENCE_TABLES:
        cur.execute(
            f"SELECT 1 FROM {table} WHERE scan_id = %s LIMIT 1",
            (requested_scan_id,),
        )
        if cur.fetchone() is not None:
            raise DownstreamEvidenceError(
                f"Scan {requested_scan_id} has downstream evidence in {table}; "
                "ingestion retry is not allowed"
            )

    cur.execute(
        """
        SELECT 1
        FROM domain_states ds
        WHERE ds.scan_id = %s
        AND NOT EXISTS (
            SELECT 1
            FROM scan_results sr
            WHERE sr.scan_id = ds.scan_id
            AND sr.domain_id = ds.domain_id
        )
        LIMIT 1
        """,
        (requested_scan_id,),
    )
    if cur.fetchone() is not None:
        raise DownstreamEvidenceError(
            f"Scan {requested_scan_id} has downstream state without membership; "
            "ingestion retry is not allowed"
        )

    cur.execute(
        """
        SELECT 1
        FROM domain_sources
        WHERE scan_id = %s
        AND source = 'san'
        LIMIT 1
        """,
        (requested_scan_id,),
    )
    if cur.fetchone() is not None:
        raise DownstreamEvidenceError(
            f"Scan {requested_scan_id} has downstream SAN provenance; "
            "ingestion retry is not allowed"
        )

scan_id = int(sys.argv[1])
artifact_path = scan_recon_artifact_path("data", scan_id)

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/app.log"),
        logging.StreamHandler()
    ]
)

manifest, artifact_data = read_validated_recon_artifact(artifact_path, scan_id)
df = pd.read_csv(io.BytesIO(artifact_data))

if len(df.index) != manifest["row_count"]:
    raise ReconArtifactError(
        "Recon artifact row count does not match its manifest"
    )

conn = get_conn()
cur = None
try:
    cur = conn.cursor()
    require_running_scan(cur, scan_id)
    require_no_downstream_evidence(cur, scan_id)
    trusted_domains = load_trusted_domains(cur)
    known_domains = trusted_domains.known_domains

    # Before downstream stages run, these scan-local rows are the ingest-owned
    # projection. Rebuild them so retries converge to the validated artifact.
    cur.execute("DELETE FROM domain_sources WHERE scan_id = %s", (scan_id,))
    cur.execute("DELETE FROM domain_states WHERE scan_id = %s", (scan_id,))
    cur.execute("DELETE FROM scan_results WHERE scan_id = %s", (scan_id,))

    for _, row in df.iterrows():

        domain = normalize_artifact_text(row.get("Domain", "")).lower()
        seed = normalize_artifact_text(row.get("Seed", ""))
        sources_raw = normalize_artifact_text(row.get("Source", "")).lower()
        sources = [s.strip() for s in sources_raw.split(",") if s.strip()]

        # pick primary source (first one)
        primary_source = sources[0] if sources else "unknown"

        if not domain:
            continue

        # Trusted roots are the union of seed_domains and known_domains.
        # The seed value remains discovery provenance; it does not grant trust.
        normalized_domain = normalize_hostname(domain)
        known = normalized_domain in known_domains if normalized_domain else False
        ownership_status = ownership_for_discovery(
            domain,
            sources,
            seed,
            trusted_domains=trusted_domains,
        )

        # ----------------------------
        # Parse fields
        # ----------------------------
        ip = normalize_artifact_text(row.get("IP", ""))
        if ip.lower() in ["", "nan", "none", "n/a"]:
            ip = ""

        has_ip = ip != ""

        try:
            http_status = int(row.get("HTTP_Status", 0))
        except:
            http_status = 0

        http_live = http_status >= 200 and http_status < 600

        reverse_dns = normalize_artifact_text(row.get("Reverse_DNS", ""))
        http_reason = normalize_artifact_text(row.get("HTTP_Reason", ""))
        redirect_evidence = {
            "requested_url": None,
            "http_status": http_status if http_status else None,
            "first_hop_location": None,
            "first_hop_destination": None,
            "observed_hops": [],
            "verified_terminal_url": None,
            "completion_status": "UNKNOWN",
            "stop_reason": "artifact_redirect_evidence_unavailable",
        }
        raw_redirect_evidence = normalize_artifact_text(
            row.get("HTTP_Redirect_Evidence", "")
        )
        if raw_redirect_evidence:
            try:
                candidate_evidence = json.loads(raw_redirect_evidence)
                if isinstance(candidate_evidence, dict):
                    redirect_evidence = candidate_evidence
            except (TypeError, ValueError):
                redirect_evidence["stop_reason"] = "invalid_artifact_redirect_evidence"

        # A legacy Final_URL cell is not proof of a terminal response.
        # New final_url values require structured evidence of a terminal response.
        final_url = None
        final_status = None
        if redirect_evidence.get("completion_status") == "COMPLETE":
            verified_url = redirect_evidence.get("verified_terminal_url")
            try:
                terminal_status = int(redirect_evidence.get("http_status"))
                parsed_url = urlsplit(str(verified_url or ""))
                _ = parsed_url.port
                if (
                    verified_url
                    and parsed_url.scheme.lower() in {"http", "https"}
                    and parsed_url.hostname
                    and not 300 <= terminal_status < 400
                ):
                    final_url = str(verified_url)
                    final_status = terminal_status
            except (TypeError, ValueError):
                pass

        title = normalize_artifact_text(row.get("Title", ""))[:500]
        http_observation_status = normalize_http_observation_status(
            row.get("HTTP_Observation_Status", "")
        )

        # ----------------------------
        # Insert domain
        # ----------------------------
        cur.execute("""
        INSERT INTO domains(
            domain,
            first_seen_scan,
            last_seen_scan,
            is_known,
            source,
            ownership_status
        )
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (domain)
        DO UPDATE SET
            first_seen_scan = CASE
                WHEN domains.first_seen_scan IS NULL THEN EXCLUDED.first_seen_scan
                WHEN EXCLUDED.first_seen_scan IS NULL THEN domains.first_seen_scan
                ELSE LEAST(domains.first_seen_scan, EXCLUDED.first_seen_scan)
            END,
            last_seen_scan = CASE
                WHEN domains.last_seen_scan IS NULL THEN EXCLUDED.last_seen_scan
                WHEN EXCLUDED.last_seen_scan IS NULL THEN domains.last_seen_scan
                ELSE GREATEST(domains.last_seen_scan, EXCLUDED.last_seen_scan)
            END,
            is_known = EXCLUDED.is_known,
            ownership_status = CASE
                WHEN domains.ownership_status = 'EXTERNAL' THEN 'EXTERNAL'
                WHEN EXCLUDED.ownership_status = 'CONFIRMED' THEN 'CONFIRMED'
                WHEN domains.ownership_status = 'CONFIRMED' THEN 'CONFIRMED'
                ELSE domains.ownership_status
            END,
            source = CASE
                WHEN domains.source = 'seed' THEN EXCLUDED.source
                ELSE domains.source
            END
        RETURNING id
        """, (
            domain, scan_id, scan_id, known, primary_source, ownership_status,
        ))

        res = cur.fetchone()

        if res:
            domain_id = res[0]
        else:
            # fallback (VERY IMPORTANT)
            cur.execute("SELECT id FROM domains WHERE domain=%s", (domain,))
            domain_id = cur.fetchone()[0]

        # ----------------------------
        # Insert scan result
        # ----------------------------
        cur.execute(
            """
            INSERT INTO scan_results(scan_id, domain_id, seed)
            VALUES (%s,%s,%s)
            ON CONFLICT DO NOTHING
            """,
            (scan_id, domain_id, seed)
        )

        # ----------------------------
        # Insert domain state
        # ----------------------------
        cur.execute(
            """
            INSERT INTO domain_states(
                scan_id,
                domain_id,
                ip,
                has_ip,
                http_status,
                http_live,
                reverse_dns,
                http_reason,
                final_url,
                final_status,
                title,
                http_observation_status,
                http_redirect_evidence
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
            ON CONFLICT (domain_id, scan_id)
            DO UPDATE SET
                ip = EXCLUDED.ip,
                has_ip = EXCLUDED.has_ip,
                http_status = EXCLUDED.http_status,
                http_live = EXCLUDED.http_live,
                reverse_dns = EXCLUDED.reverse_dns,
                http_reason = EXCLUDED.http_reason,
                final_url = EXCLUDED.final_url,
                final_status = EXCLUDED.final_status,
                title = EXCLUDED.title,
                http_observation_status = EXCLUDED.http_observation_status,
                http_redirect_evidence = EXCLUDED.http_redirect_evidence
            """,
            (
                scan_id,
                domain_id,
                ip,
                has_ip,
                http_status,
                http_live,
                reverse_dns,
                http_reason,
                final_url,
                final_status,
                title,
                http_observation_status,
                json.dumps(redirect_evidence)
            )
        )

        # ----------------------------
        # Insert sources (multi-source)
        # ----------------------------
        sources_raw = normalize_artifact_text(row.get("Source", ""))
        sources = [s.strip().lower() for s in sources_raw.split(",") if s.strip()]

        for src in sources:
            src = src.strip()
            if not src:
                continue

            cur.execute(
                """
                INSERT INTO domain_sources(domain_id, scan_id, source, seed)
                VALUES (%s,%s,%s,%s)
                ON CONFLICT DO NOTHING
                """,
                (domain_id, scan_id, src, seed)
            )

    conn.commit()
except Exception:
    if conn is not None:
        conn.rollback()
    raise
finally:
    if cur is not None and hasattr(cur, "close"):
        cur.close()
    if conn is not None:
        conn.close()

print("Ingestion done")
