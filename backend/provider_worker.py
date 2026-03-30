import psycopg2
import socket

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

def get_conn():
    return psycopg2.connect(
        host="db",
        dbname="asm_db",
        user="asm",
        password="asm123"
    )

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
        provider = "Unknown"

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

    cur.execute("SELECT MAX(id) FROM scans")
    scan_id = cur.fetchone()[0]

    cur.execute("""
    SELECT DISTINCT ON (d.id) d.id, d.domain, a.org
    FROM domains d
    JOIN domain_asn a
    ON d.id = a.domain_id
    WHERE d.provider_done = FALSE
    ORDER BY d.id
    LIMIT 1000
    """)

    rows = cur.fetchall()

    for domain_id, domain, org in rows:

        provider = map_provider(org or "")
    
        print(f"{domain} → {org} → {provider}")

        cur.execute("""
        INSERT INTO domain_provider(domain_id, scan_id, provider)
        VALUES (%s, %s, %s)
        ON CONFLICT (domain_id) DO NOTHING
        """, (domain_id, scan_id, provider))

        cur.execute("""
        UPDATE domains
        SET provider_done = TRUE
        WHERE id = %s
        """, (domain_id,))        
               

    conn.commit()
    conn.close()

    print("Provider enrichment complete")

if __name__ == "__main__":
    main()
