import psycopg2
import requests
import logging
import os

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

def get_latest_scan():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT MAX(id) FROM scans")
    scan_id = cur.fetchone()[0]

    conn.close()
    return scan_id


def get_domains(scan_id):
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    SELECT DISTINCT ON (d.id) d.id, d.domain, s.ip
    FROM domains d
    JOIN domain_states s
    ON d.id = s.domain_id
    WHERE s.has_ip = TRUE
    AND d.asn_done = FALSE
    ORDER BY d.id, s.scan_id DESC
    LIMIT 1000
    """)

    rows = cur.fetchall()
    conn.close()
    return rows


def enrich_asn(ip):

    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        data = r.json()

        return data.get("org",""), data.get("org","")

    except:
        return "", ""


def main():

    scan_id = get_latest_scan()
    domains = get_domains(scan_id)

    conn = get_conn()
    cur = conn.cursor()

    for domain_id, ip, domain in domains:

        print("ASN lookup →", domain)
        print("Trying insert →", domain_id, ip)

        asn, org = enrich_asn(ip)

        cur.execute("""
        INSERT INTO domain_asn(domain_id, scan_id, ip, asn, org)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (domain_id, ip) DO NOTHING
        """, (domain_id, scan_id, ip, asn, org))

        cur.execute("""
            UPDATE domains
            SET asn_done = TRUE
            WHERE id = %s
        """, (domain_id,))

    conn.commit()
    conn.close()

    print("ASN enrichment done")


if __name__ == "__main__":
    main()
