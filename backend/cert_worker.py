import psycopg2
import socket
import ssl
from datetime import datetime


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

    cur.execute("SELECT MAX(id) FROM scans")
    scan_id = cur.fetchone()[0]

    cur.execute("""
        SELECT d.id, d.domain, ds.ip
        FROM domain_states ds
        JOIN domains d ON d.id = ds.domain_id
        WHERE ds.scan_id=%s
        AND ds.has_ip = TRUE
    """, (scan_id,))

    rows = cur.fetchall()
    conn.close()

    return scan_id, rows


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

    scan_id, domains = get_domains()

    print("Cert scan for", len(domains), "domains")

    conn = get_conn()
    cur = conn.cursor()

    from concurrent.futures import ThreadPoolExecutor, as_completed
    
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
            """, (domain_id, scan_id, expiry, days, status))
    
    
    conn.commit()
    conn.close()

    print("Certificate enrichment complete")


if __name__ == "__main__":
    main()
