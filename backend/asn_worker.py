import requests
import logging
import os
import sys
from db import get_conn, require_running_scan

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

    cur.execute("""
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
    ORDER BY d.id, s.scan_id DESC
    """, (scan_id, scan_id))

    rows = cur.fetchall()
    return rows


def enrich_asn(ip):

    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        data = r.json()

        org = data.get("org", "")
        asn = org.split()[0] if org else ""
        return asn, org

    except:
        return "", ""


def main():

    conn = get_conn()
    cur = conn.cursor()
    require_running_scan(cur, scan_id)

    domains = get_domains(cur, scan_id)

    for domain_id, domain, ip in domains:

        print("ASN lookup →", domain)
        print("Trying insert →", domain_id, ip)

        asn, org = enrich_asn(ip)

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
    conn.close()

    print("ASN enrichment done")

if __name__ == "__main__":
    main()
