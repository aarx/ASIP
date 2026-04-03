import psycopg2
import ssl
import socket
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


def fetch_san_domains(domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=1.5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        san = cert.get("subjectAltName", [])
        return [entry[1] for entry in san if entry[0] == "DNS"]

    except Exception:
        return []


def main():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    SELECT DISTINCT ON (d.id) d.id, d.domain
    FROM domains d
    JOIN domain_states ds
    ON d.id = ds.domain_id
    WHERE ds.has_ip = TRUE
    AND d.san_processed = FALSE
    ORDER BY d.id, ds.scan_id DESC
    LIMIT 2000
    """)
    
    rows = cur.fetchall()

    print("Processing domains:", len(rows))

    new_count = 0

    for i, (domain_id, domain) in enumerate(rows, start=1):
    
        if i % 50 == 0:
            print(f"[{i}/{len(rows)}] Processing: {domain}")
    
        san_domains = fetch_san_domains(domain)
    
        for san in san_domains:
            san = san.lower().strip()
    
            if "*" in san:
                continue
    
            cur.execute("SELECT 1 FROM domains WHERE domain=%s", (san,))
            exists = cur.fetchone()
    
            if not exists:
                cur.execute("""
                    INSERT INTO domains(domain, source, enrichment_status)
                    VALUES (%s, 'san', 'pending')
                """, (san,))
                new_count += 1
    
        # ⭐ ADD THIS BLOCK HERE
        cur.execute("""
            UPDATE domains 
            SET san_processed = TRUE 
            WHERE id = %s
        """, (domain_id,))
        
        if i % 100 == 0:
            conn.commit()
            print("Checkpoint commit at:", i)
    
        if new_count % 50 == 0 and new_count != 0:
            print("New domains added:", new_count)            
            

    conn.commit()
    conn.close()

    print("SAN expansion complete. New domains:", new_count)


if __name__ == "__main__":
    main()
