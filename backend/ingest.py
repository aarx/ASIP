import io
import pandas as pd
import logging
import os
import sys
from db import get_conn
from recon_artifact import ReconArtifactError, read_validated_recon_artifact

scan_id = int(sys.argv[1])
artifact_path = "data/final_output.csv"

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
cur = conn.cursor()

for _, row in df.iterrows():

    domain = str(row.get("Domain", "")).strip().lower()
    seed = str(row.get("Seed", "")).strip()
    sources_raw = str(row.get("Source", "")).strip().lower()
    sources = [s.strip() for s in sources_raw.split(",") if s.strip()]
    
    # pick primary source (first one)
    primary_source = sources[0] if sources else "unknown"

    if not domain:
        continue

    # ----------------------------
    # Known domain check
    # ----------------------------
    cur.execute(
        "SELECT 1 FROM known_domains WHERE domain=%s",
        (domain,)
    )
    known = cur.fetchone() is not None

    # ----------------------------
    # Parse fields
    # ----------------------------
    ip = str(row.get("IP", "")).strip()
    if ip.lower() in ["", "nan", "none", "n/a"]:
        ip = ""

    has_ip = ip != ""

    try:
        http_status = int(row.get("HTTP_Status", 0))
    except:
        http_status = 0

    http_live = http_status >= 200 and http_status < 600

    reverse_dns = str(row.get("Reverse_DNS", "")).strip()
    http_reason = str(row.get("HTTP_Reason", "")).strip()
    final_url = str(row.get("Final_URL", "")).strip()

    try:
        final_status = int(row.get("Final_Status", 0))
    except:
        final_status = 0

    title = str(row.get("Title", "")).strip()[:500]

    # ----------------------------
    # Insert domain
    # ----------------------------
    cur.execute("""
    INSERT INTO domains(
        domain,
        first_seen_scan,
        last_seen_scan,
        is_known,
        source
    )
    VALUES (
        %s,
        %s,
        %s,
        EXISTS (
            SELECT 1 FROM known_domains WHERE domain = %s
        ),
        %s
    )
    ON CONFLICT (domain)
    DO UPDATE SET
        last_seen_scan = EXCLUDED.last_seen_scan,
        is_known = (
            SELECT EXISTS (
                SELECT 1 FROM known_domains WHERE domain = EXCLUDED.domain
            )
        ),
        source = CASE
            WHEN domains.source = 'seed' THEN EXCLUDED.source
            ELSE domains.source
        END
    RETURNING id
    """, (domain, scan_id, scan_id, domain, primary_source))
    
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
            title
        )
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (domain_id, scan_id)
        DO UPDATE SET
            ip = EXCLUDED.ip,
            http_status = EXCLUDED.http_status,
            http_live = EXCLUDED.http_live,
            reverse_dns = EXCLUDED.reverse_dns,
            http_reason = EXCLUDED.http_reason,
            final_url = EXCLUDED.final_url,
            final_status = EXCLUDED.final_status,
            title = EXCLUDED.title
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
            title
        )
    )

    # ----------------------------
    # Insert sources (multi-source)
    # ----------------------------
    sources_raw = str(row.get("Source", ""))
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
conn.close()

print("Ingestion done")
