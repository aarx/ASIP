import socket
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
def main():

    conn = get_conn()
    cur = conn.cursor()
    require_running_scan(cur, scan_id)

    cur.execute("""
    SELECT DISTINCT ON (d.id) d.id, d.domain, a.org
    FROM domains d
    JOIN domain_asn a
      ON d.id = a.domain_id
      AND a.scan_id = %s
    
    LEFT JOIN domain_provider dp
      ON d.id = dp.domain_id
      AND dp.scan_id = %s
    
    WHERE dp.domain_id IS NULL
    ORDER BY d.id, a.scan_id DESC
    """, (scan_id, scan_id))

    rows = cur.fetchall()

    for domain_id, domain, org in rows:

        provider = map_provider(org or "") or "Other"
    
        print(f"{domain} → {org} → {provider}")

        cur.execute("""
        INSERT INTO domain_provider(domain_id, scan_id, provider)
        VALUES (%s, %s, %s)
        ON CONFLICT (domain_id, scan_id) DO NOTHING
        """, (domain_id, scan_id, provider)) 

    conn.commit()
    conn.close()

    print("Provider enrichment complete")

if __name__ == "__main__":
    main()
