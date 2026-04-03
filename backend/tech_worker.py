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

TECH_HEADERS = {
    "nginx": "nginx",
    "apache": "apache",
    "iis": "microsoft-iis",
    "php": "php",
    "asp": "asp",
    "cloudflare": "cloudflare"
}

def get_conn():
    return psycopg2.connect(
        host="db",
        dbname="asm_db",
        user="asm",
        password="asm123"
    )

def detect_tech(domain):

    try:
        r = requests.get(
            f"http://{domain}",
            timeout=4,
            allow_redirects=True,
            verify=False
        )

        server = r.headers.get("Server","").lower()
        powered = r.headers.get("X-Powered-By","").lower()

        for k in TECH_HEADERS:
            if k in server or k in powered:
                return TECH_HEADERS[k]

        return "unknown"

    except:
        return "unknown"


def main():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT MAX(id) FROM scans")
    scan_id = cur.fetchone()[0]

    cur.execute("""
    SELECT DISTINCT ON (d.id) d.id, d.domain
    FROM domains d
    JOIN domain_states s
    ON d.id = s.domain_id
    WHERE s.scan_id = %s
    AND d.tech_done = FALSE
    AND s.http_status > 0
    ORDER BY d.id, s.scan_id DESC
    LIMIT 1000
    """, (scan_id,))
    rows = cur.fetchall()

    for domain_id, domain in rows:

        techs = detect_tech(domain)

        print("Tech detect →", domain, techs)
        
        if isinstance(techs, str):
            techs = [techs]
            
        if not techs:
            techs = ["Unknown"]
        
        for tech in techs:
        

            cur.execute("""
            INSERT INTO domain_tech(domain_id, scan_id, tech)
            VALUES (%s, %s, %s)
            ON CONFLICT (domain_id, tech) DO NOTHING
            """, (domain_id, scan_id, tech))
        
        cur.execute("""
            UPDATE domains
            SET tech_done = TRUE
            WHERE id = %s
        """, (domain_id,))

    conn.commit()
    conn.close()

    print("Tech enrichment complete")


if __name__ == "__main__":
    main()
