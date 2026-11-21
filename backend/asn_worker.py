import requests
import logging
import os
import sys
import ipaddress
from db import get_conn, require_running_scan
from authorization_policy import (
    active_scan_authorization_sql,
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


def main():

    conn = get_conn()
    try:
        cur = conn.cursor()
        require_running_scan(cur, scan_id)
        domains = get_domains(cur, scan_id)
        # Release the scan-row lock and selection transaction before HTTP.
        conn.commit()

        results = []
        for domain_id, domain, ip in domains:
            # Recheck the exact current-scan address and operation grant
            # immediately before sending it to the metadata service.
            require_running_scan(cur, scan_id)
            authorized = asn_target_authorized(cur, scan_id, domain_id, ip)
            conn.commit()
            if not authorized:
                print(f"Skipping ASN metadata lookup outside authorized scope: {domain}")
                continue

            try:
                address = ipaddress.ip_address(str(ip).strip())
            except ValueError:
                print(f"Skipping ASN metadata lookup for invalid address: {domain}")
                continue
            if not address.is_global:
                print(f"Skipping ASN metadata lookup for non-public address: {domain}")
                continue
            ip = str(address)

            print("ASN lookup →", domain)
            print("Trying insert →", domain_id, ip)

            asn_result = enrich_asn(ip)
            if asn_result is not None:
                results.append((domain_id, domain, ip, asn_result))

        # Keep result writes atomic as one stage transaction. Revalidate every
        # target after network work, immediately before persisting its result.
        require_running_scan(cur, scan_id)
        for domain_id, domain, ip, (asn, org) in results:
            if not asn_target_authorized(cur, scan_id, domain_id, ip):
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

        conn.commit()
        print("ASN enrichment done")
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

if __name__ == "__main__":
    main()
