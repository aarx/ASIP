import psycopg2
import requests
import logging
import os
import sys

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

def get_conn():
    return psycopg2.connect(
        host="db",
        dbname="asm_db",
        user="asm",
        password="asm123"
    )


def get_domains(scan_id):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    SELECT DISTINCT ON (d.id) d.id, d.domain, s.ip
    FROM domains d
    JOIN domain_states s
      ON d.id = s.domain_id
      AND s.scan_id = %s
    
    LEFT JOIN domain_asn da
      ON d.id = da.domain_id
      AND da.scan_id = %s
    
    WHERE s.has_ip = TRUE
    AND da.domain_id IS NULL
    ORDER BY d.id, s.scan_id DESC
    """, (scan_id, scan_id))

    rows = cur.fetchall()
    conn.close()
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

    domains = get_domains(scan_id)

    conn = get_conn()
    cur = conn.cursor()

    for domain_id, domain, ip in domains:

        print("ASN lookup →", domain)
        print("Trying insert →", domain_id, ip)

        asn, org = enrich_asn(ip)

        cur.execute("""
        INSERT INTO domain_asn(domain_id, scan_id, ip, asn, org)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (domain_id, scan_id) DO NOTHING
        """, (domain_id, scan_id, ip, asn, org))

    conn.commit()
    conn.close()

    print("ASN enrichment done")

if __name__ == "__main__":
    main()
