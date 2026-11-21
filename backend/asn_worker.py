import requests
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


def get_domains(cur, scan_id):

    cur.execute(f"""
    SELECT DISTINCT ON (d.id) d.id, d.domain, s.ip
    FROM domains d
    JOIN domain_states s
      ON d.id = s.domain_id
      AND s.scan_id = %s
    JOIN scan_results sr
      ON sr.domain_id = s.domain_id
      AND sr.scan_id = s.scan_id
    
    LEFT JOIN domain_asn da
      ON d.id = da.domain_id
      AND da.scan_id = %s
    
    WHERE s.has_ip = TRUE
    AND da.domain_id IS NULL
    AND {active_scan_authorization_sql('d', 'ASN_METADATA')}
    AND {passive_dns_discovery_sql('d', 'sr')}
    ORDER BY d.id, s.scan_id DESC
    """, (scan_id, scan_id))

    rows = cur.fetchall()
    return rows


def enrich_asn(ip):

    try:
        address = ipaddress.ip_address(str(ip).strip())
        if not address.is_global:
            return None
        ip = str(address)
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if not 200 <= r.status_code < 300:
            print(f"ASN lookup failed for {ip} → HTTP {r.status_code}")
            return None

        data = r.json()
        if not isinstance(data, dict):
            raise ValueError("unexpected response shape")

        org = data.get("org", "")
        if not isinstance(org, str):
            raise ValueError("unexpected organization value")
        asn = org.split()[0] if org else ""
        return asn, org

    except Exception as e:
        print(f"ASN lookup failed for {ip} → {type(e).__name__}")
        return None


def normalize_public_ip(value):
    """Return a canonical globally routable IP or a stable skip reason."""
    try:
        address = ipaddress.ip_address(str(value).strip())
    except (TypeError, ValueError):
        return None, "invalid_ip"
    if not address.is_global:
        return None, "non_public_ip"
    return str(address), None


def asn_target_authorized(cur, target_scan_id, domain_id, ip):
    """Recheck the exact current-scan IP before external metadata use."""
    cur.execute(f"""
    SELECT EXISTS (
        SELECT 1
        FROM domains d
        JOIN scan_results sr
          ON sr.domain_id = d.id AND sr.scan_id = %s
        JOIN domain_states s
          ON s.domain_id = d.id AND s.scan_id = sr.scan_id
        WHERE d.id = %s
          AND s.has_ip IS TRUE
          AND s.ip = %s
          AND {active_scan_authorization_sql('d', 'ASN_METADATA')}
          AND {passive_dns_discovery_sql('d', 'sr')}
    )
    """, (target_scan_id, domain_id, ip))
    row = cur.fetchone()
    return bool(row and row[0])


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
        domains = get_domains(cur, scan_id)
        # Release the scan-row lock and selection transaction before HTTP.
        conn.commit()

        disabled_by_policy = not default_operation_enabled("ASN_METADATA")
        if disabled_by_policy:
            summary = {
                "selected": 0,
                "total_candidates": len(domains),
                "candidate_targets": len(domains),
                "eligible_targets": 0,
                "processed_targets": 0,
                "completed": 0,
                "succeeded": 0,
                "skipped": len(domains),
                "failed": 0,
                "mapped_targets": 0,
                "unique_ips_queried": 0,
                "duplicate_ip_lookup_reuses": 0,
                "invalid_ip_skips": 0,
                "non_public_ip_skips": 0,
                "authorization_skips": len(domains),
                "lookup_failures": 0,
                "failed_targets": 0,
                "disabled_by_policy": True,
                "elapsed_seconds": round(time.monotonic() - started, 4),
            }
            return
        eligible = []
        invalid_ip_skips = 0
        non_public_ip_skips = 0
        for domain_id, domain, ip in domains:
            normalized_ip, skip_reason = normalize_public_ip(ip)
            if skip_reason == "invalid_ip":
                invalid_ip_skips += 1
                continue
            if skip_reason == "non_public_ip":
                non_public_ip_skips += 1
                continue
            eligible.append((domain_id, domain, normalized_ip))

        results = []
        lookup_cache = {}
        authorization_skips = 0
        processed_targets = 0
        lookup_failures = 0
        duplicate_ip_lookup_reuses = 0
        persisted_targets = 0
        for domain_id, domain, ip in eligible:
            # Recheck the exact current-scan address and operation grant
            # immediately before sending it to the metadata service.
            require_running_scan(cur, scan_id)
            authorized = asn_target_authorized(cur, scan_id, domain_id, ip)
            conn.commit()
            if not authorized:
                authorization_skips += 1
                print(f"Skipping ASN metadata lookup outside authorized scope: {domain}")
                continue

            processed_targets += 1
            if ip in lookup_cache:
                duplicate_ip_lookup_reuses += 1
                asn_result = lookup_cache[ip]
            else:
                print("ASN lookup →", domain)
                asn_result = enrich_asn(ip)
                lookup_cache[ip] = asn_result
                if asn_result is None:
                    lookup_failures += 1
            if asn_result is not None:
                results.append((domain_id, domain, ip, asn_result))

        # Keep result writes atomic as one stage transaction. Revalidate every
        # target after network work, immediately before persisting its result.
        require_running_scan(cur, scan_id)
        for domain_id, domain, ip, (asn, org) in results:
            if not asn_target_authorized(cur, scan_id, domain_id, ip):
                authorization_skips += 1
                print(f"Skipping ASN metadata persistence after authorization changed: {domain}")
                continue
            cur.execute("""
            INSERT INTO domain_asn(domain_id, scan_id, ip, asn, org)
            SELECT %s, %s, %s, %s, %s
            WHERE EXISTS (
                SELECT 1 FROM scan_results sr
                WHERE sr.scan_id = %s AND sr.domain_id = %s
            )
            ON CONFLICT (domain_id, scan_id) DO NOTHING
            """, (domain_id, scan_id, ip, asn, org, scan_id, domain_id))
            persisted_targets += _inserted_row(cur)

        conn.commit()
        print("ASN enrichment done")
        summary = {
            "selected": len(eligible),
            "total_candidates": len(domains),
            "candidate_targets": len(domains),
            "eligible_targets": len(eligible),
            "processed_targets": processed_targets,
            "completed": persisted_targets,
            "succeeded": persisted_targets,
            "skipped": invalid_ip_skips + non_public_ip_skips + authorization_skips,
            "failed": max(0, processed_targets - len(results)),
            "mapped_targets": persisted_targets,
            "unique_ips_queried": len(lookup_cache),
            "duplicate_ip_lookup_reuses": duplicate_ip_lookup_reuses,
            "invalid_ip_skips": invalid_ip_skips,
            "non_public_ip_skips": non_public_ip_skips,
            "authorization_skips": authorization_skips,
            "lookup_failures": lookup_failures,
            "failed_targets": max(0, processed_targets - len(results)),
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
                print("ASN_METADATA disabled by operation policy; no external lookups performed")
            print("ASIP_WORKER_SUMMARY " + json.dumps(summary, separators=(",", ":")), flush=True)

if __name__ == "__main__":
    main()
