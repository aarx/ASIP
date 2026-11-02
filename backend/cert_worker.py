import OpenSSL
import ssl
from datetime import datetime
import logging
import os
import sys
from authorization_policy import (
    active_scan_authorization_sql,
    recheck_active_authorization,
)
from db import get_conn, require_running_scan
from http_probe import open_validated_tls_socket


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



def get_domains(cur, scan_id):

    cur.execute(f"""
        SELECT d.id, d.domain, ds.ip
        FROM domain_states ds
        JOIN domains d 
          ON d.id = ds.domain_id
          AND ds.scan_id = %s
        JOIN scan_results sr
          ON sr.domain_id = ds.domain_id
          AND sr.scan_id = ds.scan_id
        
        LEFT JOIN domain_cert dc
          ON d.id = dc.domain_id
          AND dc.scan_id = %s
        
        WHERE ds.has_ip = TRUE
        AND ds.http_status > 0
        AND dc.domain_id IS NULL
        AND {active_scan_authorization_sql('d', 'HTTP_TLS_OBSERVATION')}
    """, (scan_id, scan_id))

    rows = cur.fetchall()

    return rows    

def fetch_cert_expiry(domain, *, before_request=None, expected_ip=None):
    if before_request is None or not before_request():
        return None
    try:
        with open_validated_tls_socket(domain, expected_ip=expected_ip) as ssock:
            cert_bin = ssock.getpeercert(binary_form=True)
        x509 = ssl.DER_cert_to_PEM_cert(cert_bin)
        x509_obj = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, x509
        )
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
    except Exception as exc:
        print(f"[CERT ERROR] {domain} → {type(exc).__name__}")
        return None


def main():

    conn = get_conn()
    cur = conn.cursor()
    require_running_scan(cur, scan_id)

    domains = get_domains(cur, scan_id)
    print("Scan ID:", scan_id)
    print("Rows to process:", len(domains))

    total = len(domains)
    print(f"Cert scan for {total} domains")
    for done, row in enumerate(domains, start=1):
        domain_id, domain = row[:2]
        ip = row[2] if len(row) > 2 else None
        def authorized():
            allowed, reason = recheck_active_authorization(
                cur,
                scan_id=scan_id,
                domain_id=domain_id,
                testing_level="HTTP_TLS_OBSERVATION",
            )
            conn.commit()
            if not allowed:
                print(f"Skipping certificate observation for {domain}: {reason}")
            return allowed

        cert_result = fetch_cert_expiry(
            domain,
            expected_ip=ip,
            before_request=authorized,
        )
        if done % 20 == 0:
            print(f"[CERT PROGRESS] {done}/{total}")
        if cert_result is None:
            continue
        expiry, days, status = cert_result
        cur.execute("""
                INSERT INTO domain_cert(
                    domain_id,
                    scan_id,
                    expiry_date,
                    days_to_expiry,
                    cert_status
                )
                SELECT %s,%s,%s,%s,%s
                WHERE EXISTS (
                    SELECT 1 FROM scan_results sr
                    WHERE sr.scan_id = %s AND sr.domain_id = %s
                )
                ON CONFLICT (domain_id, scan_id) DO NOTHING
            """, (domain_id, scan_id, expiry, days, status, scan_id, domain_id))
    
    
    conn.commit()
    conn.close()

    print("Certificate enrichment complete")


if __name__ == "__main__":
    main()
