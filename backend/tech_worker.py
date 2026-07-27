import requests
import logging
import os
import sys
from db import get_conn

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

def detect_tech(domain):

    try:
        r = requests.get(
            f"http://{domain}",
            timeout=4,
            allow_redirects=True,
            verify=False
        )

        techs = set()

        server = r.headers.get("Server","").lower()
        powered = r.headers.get("X-Powered-By","").lower()
        headers = str(r.headers).lower()
        body = r.text.lower()
        cookies = str(r.cookies).lower()

        # ----------------------------
        # Header-based detection
        # ----------------------------
        for k in TECH_HEADERS:
            if k in server or k in powered:
                techs.add(TECH_HEADERS[k])

        # Cloud providers / CDN (🔥 add these)
        if "cf-ray" in headers:
            techs.add("cloudflare")

        if "akamai" in headers:
            techs.add("akamai")

        if "azure" in headers or "x-azure" in headers:
            techs.add("azure")

        if "x-amz" in headers or "amazon" in headers:
            techs.add("aws")

        if "fastly" in headers:
            techs.add("fastly")

        # ----------------------------
        # HTML fingerprinting
        # ----------------------------
        if "wp-content" in body or "wordpress" in cookies:
            techs.add("wordpress")

        if "react" in body or "_next" in body:
            techs.add("react/nextjs")

        if "vue" in body:
            techs.add("vue")

        if "angular" in body:
            techs.add("angular")

        if "jquery" in body:
            techs.add("jquery")

        if "bootstrap" in body:
            techs.add("bootstrap")

        if "shopify" in body:
            techs.add("shopify")

        if "cdn.jsdelivr" in body:
            techs.add("cdn")

        # ----------------------------
        # fallback
        # ----------------------------
        if not techs:
            techs.add("unknown")

        return list(techs)

    except:
        return ["unknown"]

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
    AND d.scannable = TRUE   -- ✅ ADD THIS LINE
    
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
            SELECT 1 FROM domain_tech
            WHERE domain_id=%s AND scan_id=%s AND tech=%s
            """, (domain_id, scan_id, tech))
            
            if not cur.fetchone():
                cur.execute("""
                INSERT INTO domain_tech(domain_id, scan_id, tech)
                VALUES (%s, %s, %s)
                """, (domain_id, scan_id, tech))

    conn.commit()
    conn.close()

    print("Tech enrichment complete")


if __name__ == "__main__":
    main()
