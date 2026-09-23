import socket
import OpenSSL
import ssl
from datetime import datetime
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
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



def get_domains():

    conn = get_conn()
    cur = conn.cursor()
    require_running_scan(cur, scan_id)

    cur.execute("""
        SELECT d.id, d.domain, ds.ip, ds.final_url
        FROM domain_states ds
        JOIN domains d 
          ON d.id = ds.domain_id
          AND ds.scan_id = %s
        
        LEFT JOIN domain_cert dc
          ON d.id = dc.domain_id
          AND dc.scan_id = %s
        
        WHERE ds.has_ip = TRUE
        AND ds.http_status > 0
        AND dc.domain_id IS NULL
        AND d.scannable = TRUE   -- ✅ ADD THIS
    """, (scan_id, scan_id))

    rows = cur.fetchall()
    conn.close()

    return rows    

def fetch_cert_expiry(domain):

    socket.setdefaulttimeout(3)

    hosts = [domain]

    # optional safe fallback
    if domain.count('.') == 1:
        hosts.append(f"www.{domain}")

    for host in hosts:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:

                    cert_bin = ssock.getpeercert(binary_form=True)
                    
                    x509 = ssl.DER_cert_to_PEM_cert(cert_bin)
                    
                    x509_obj = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, x509)
                    
                    expiry = x509_obj.get_notAfter().decode("utf-8")
                    expiry_dt = datetime.strptime(expiry, "%Y%m%d%H%M%SZ")

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

        except Exception as e:
            print(f"[CERT ERROR] {host} → {e}")
            continue

    return None, None, "no_cert"


def main():

    domains = get_domains()

    print("Scan ID:", scan_id)
    print("Rows to process:", len(domains))

    conn = get_conn()
    cur = conn.cursor()
    require_running_scan(cur, scan_id)

    
    MAX_WORKERS = 40
    
    def scan_cert(domain_tuple):
    
        domain_id, domain, ip, final_url = domain_tuple
    
        host = domain
    
        if final_url:
            try:
                parsed = urlparse(final_url)
                if parsed.hostname:
                    host = parsed.hostname
            except:
                pass
    
        expiry, days, status = fetch_cert_expiry(host)
    
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
