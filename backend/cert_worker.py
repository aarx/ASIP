import psycopg2
import socket
import ssl
from datetime import datetime
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

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


def get_domains():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT d.id, d.domain, ds.ip
        FROM domain_states ds
        JOIN domains d 
          ON d.id = ds.domain_id
          AND ds.scan_id = %s
        
        LEFT JOIN domain_cert dc
          ON d.id = dc.domain_id
          AND dc.scan_id = %s
        
        WHERE ds.has_ip = TRUE
        AND dc.domain_id IS NULL
    """, (scan_id, scan_id))

    rows = cur.fetchall()
    conn.close()

    return rows


def fetch_cert_expiry(domain):

    socket.setdefaulttimeout(3)
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:

                cert = ssock.getpeercert()

                expiry = cert["notAfter"]
                expiry_dt = datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z")

                days = (expiry_dt - datetime.utcnow()).days

                if days < 0:
                    status = "expired"
                elif days < 15:
                    status = "critical"
                elif days < 45:
                    status = "warning"
                else:
                    status = "healthy"

                return expiry_dt.date(), days, status

    except:
        return None, None, "no_cert"


def main():

    domains = get_domains()

    print("Scan ID:", scan_id)
    print("Rows to process:", len(domains))

    conn = get_conn()
    cur = conn.cursor()

    
    MAX_WORKERS = 40
    
    def scan_cert(domain_tuple):
    
        domain_id, domain, ip = domain_tuple
    
        expiry, days, status = fetch_cert_expiry(domain)
    
        return (domain_id, expiry, days, status)
    
    
    total = len(domains)
    done = 0
    
    print(f"Cert scan for {total} domains")
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
    
        futures = [exe.submit(scan_cert, d) for d in domains]
    
        for f in as_completed(futures):
    
            domain_id, expiry, days, status = f.result()
    
            done += 1
    
            if done % 20 == 0:
                print(f"[CERT PROGRESS] {done}/{total}")
    
            cur.execute("""
                INSERT INTO domain_cert(
                    domain_id,
                    scan_id,
                    expiry_date,
                    days_to_expiry,
                    cert_status
                )
                VALUES (%s,%s,%s,%s,%s)
                ON CONFLICT (domain_id, scan_id) DO NOTHING
            """, (domain_id, scan_id, expiry, days, status))
    
    
    conn.commit()
    conn.close()

    print("Certificate enrichment complete")


if __name__ == "__main__":
    main()
