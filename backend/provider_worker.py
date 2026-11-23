import socket
import logging
import os
import sys
import ipaddress
import json
import time
from db import get_conn, require_running_scan
from authorization_policy import (
    active_scan_authorization_sql,
    default_operation_enabled,
    passive_dns_discovery_sql,
)

scan_id = int(sys.argv[1])

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/app.log"),
        logging.StreamHandler()
    ]
)

PROVIDER_KEYWORDS = {
    "cloudflare": "Cloudflare",
    "amazon": "AWS",
    "aws": "AWS",
    "azure": "Azure",
    "google": "GCP",
    "fastly": "Fastly",
    "akamai": "Akamai",
    "edgekey": "Akamai"
}


def normalize_public_ip(value):
    try:
        address = ipaddress.ip_address(str(value).strip())
    except (TypeError, ValueError):
        return None, "invalid_ip"
    if not address.is_global:
        return None, "non_public_ip"
    return str(address), None


def detect_provider(ip):

    try:
        rdns = socket.gethostbyaddr(ip)[0].lower()

        for k,v in PROVIDER_KEYWORDS.items():
            if k in rdns:
                return v

        return "Unknown"

    except:
        return "Unknown"

def map_provider(org):
    if not org:
        return "Unknown"

    o = org.lower()

    # remove ASN prefix
    if " " in o:
        o = o.split(" ", 1)[1]

    if "amazon" in o or "aws" in o:
        return "AWS"
    if "cloudflare" in o:
        return "Cloudflare"
    if "akamai" in o:
        return "Akamai"
    if "google" in o:
        return "GCP"
    if "microsoft" in o:
        return "Azure"

    return "Other"


def get_provider_candidates(cur, target_scan_id):
    cur.execute(f"""
    SELECT DISTINCT ON (d.id) d.id, d.domain, a.ip, a.org
    FROM domains d
    JOIN domain_asn a
      ON d.id = a.domain_id
      AND a.scan_id = %s
    JOIN scan_results sr
      ON sr.domain_id = a.domain_id
      AND sr.scan_id = a.scan_id
    JOIN domain_states ds
      ON ds.domain_id = sr.domain_id
      AND ds.scan_id = sr.scan_id
      AND ds.has_ip IS TRUE
      AND ds.ip = a.ip
    LEFT JOIN domain_provider dp
      ON d.id = dp.domain_id
      AND dp.scan_id = %s
    WHERE dp.domain_id IS NULL
      AND {active_scan_authorization_sql('d', 'ASN_METADATA')}
      AND {passive_dns_discovery_sql('d', 'sr')}
    ORDER BY d.id, a.scan_id DESC
    """, (target_scan_id, target_scan_id))
    return cur.fetchall()


def _inserted_row(cur):
    count = getattr(cur, "rowcount", 0)
    return int(isinstance(count, int) and count > 0)


def main():
    started = time.monotonic()
    conn = get_conn()
    summary = {}
    try:
        cur = conn.cursor()
        require_running_scan(cur, scan_id)
        candidates = get_provider_candidates(cur, scan_id)
        conn.commit()
        disabled_by_policy = not default_operation_enabled("ASN_METADATA")
        if disabled_by_policy:
            summary = {
                "selected": 0,
                "candidate_targets": len(candidates),
                "eligible_targets": 0,
                "asn_input_rows": len(candidates),
                "processed_targets": 0,
                "completed": 0,
                "succeeded": 0,
                "skipped": len(candidates),
                "mapped_targets": 0,
                "invalid_ip_skips": 0,
                "non_public_ip_skips": 0,
                "disabled_by_policy": True,
                "elapsed_seconds": round(time.monotonic() - started, 4),
            }
            return

        eligible = []
        invalid_ip_skips = 0
        non_public_ip_skips = 0
        for domain_id, domain, ip, org in candidates:
            normalized_ip, skip_reason = normalize_public_ip(ip)
            if skip_reason == "invalid_ip":
                invalid_ip_skips += 1
                continue
            if skip_reason == "non_public_ip":
                non_public_ip_skips += 1
                continue
            eligible.append((domain_id, domain, normalized_ip, org))

        mapped = 0
        for domain_id, domain, ip, org in eligible:
            provider = map_provider(org or "") or "Other"
            print(f"{domain} → {org} → {provider}")
            cur.execute(f"""
            INSERT INTO domain_provider(domain_id, scan_id, provider)
            SELECT %s, %s, %s
            WHERE EXISTS (
                SELECT 1 FROM scan_results sr
                JOIN domain_states ds
                  ON ds.domain_id = sr.domain_id AND ds.scan_id = sr.scan_id
                JOIN domains d ON d.id = sr.domain_id
                WHERE sr.scan_id = %s AND sr.domain_id = %s
                  AND ds.has_ip IS TRUE AND ds.ip = %s
                  AND {active_scan_authorization_sql('d', 'ASN_METADATA')}
                  AND {passive_dns_discovery_sql('d', 'sr')}
            )
            ON CONFLICT (domain_id, scan_id) DO NOTHING
            """, (domain_id, scan_id, provider, scan_id, domain_id, ip))
            mapped += _inserted_row(cur)

        conn.commit()
        print("Provider enrichment complete")
        summary = {
            "selected": len(eligible),
            "candidate_targets": len(candidates),
            "eligible_targets": len(eligible),
            "asn_input_rows": len(candidates),
            "processed_targets": len(eligible),
            "completed": mapped,
            "succeeded": mapped,
            "skipped": invalid_ip_skips + non_public_ip_skips,
            "mapped_targets": mapped,
            "invalid_ip_skips": invalid_ip_skips,
            "non_public_ip_skips": non_public_ip_skips,
            "disabled_by_policy": disabled_by_policy,
            "elapsed_seconds": round(time.monotonic() - started, 4),
        }
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
        if summary:
            if summary["disabled_by_policy"]:
                print("ASN_METADATA disabled by operation policy; no provider inputs authorized")
            print("ASIP_WORKER_SUMMARY " + json.dumps(summary, separators=(",", ":")), flush=True)

if __name__ == "__main__":
    main()
