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

    cur.execute("""
    SELECT DISTINCT ON (d.id) d.id, d.domain
    FROM domains d
    JOIN domain_states s
      ON d.id = s.domain_id
    LEFT JOIN domain_tech dt
      ON d.id = dt.domain_id
      AND dt.scan_id = %s
    
    WHERE s.scan_id = %s
    AND dt.domain_id IS NULL
    AND s.http_status > 0
    ORDER BY d.id, s.scan_id DESC
    """, (scan_id, scan_id))
    
    rows = cur.fetchall()
    
    print("Rows to process:", len(rows))

    for domain_id, domain in rows:

        techs = detect_tech(domain)

        print("Tech detect →", domain, techs)
        
        if isinstance(techs, str):
            techs = [techs]
            
        if not techs:
            techs = ["Unknown"]
        
        for tech in techs:
        
            print("DEBUG → inserting into domain_tech")
            cur.execute("""
            INSERT INTO domain_tech(domain_id, scan_id, tech)
            VALUES (%s, %s, %s)
            ON CONFLICT (domain_id, scan_id) DO NOTHING
            """, (domain_id, scan_id, tech))

    conn.commit()
    conn.close()

    print("Tech enrichment complete")


if __name__ == "__main__":
    main()
