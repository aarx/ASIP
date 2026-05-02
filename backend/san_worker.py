import psycopg2
import ssl
import socket
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

    except Exception as e:
        print(f"[SAN ERROR] {domain} -> {e}")
        return []

def is_scannable(domain, seeds):
    for seed in seeds:
        if domain == seed or domain.endswith("." + seed):
            return True
    return False

def main():
     
    conn = get_conn()
    cur = conn.cursor()

    print("SAN scan for scan_id:", scan_id)

    cur.execute("SELECT domain FROM seed_domains")
    seeds = [r[0].strip().lower() for r in cur.fetchall()]  
    print("Loaded seeds:", seeds)

    cur.execute("SELECT domain FROM known_domains")
    known_set = set(r[0].strip().lower() for r in cur.fetchall())
    
    print("Loaded known domains:", len(known_set))

    cur.execute("""
    SELECT DISTINCT ON (d.id) d.id, d.domain
    FROM domains d
    JOIN domain_states ds
      ON d.id = ds.domain_id
      AND ds.scan_id = %s
    
    LEFT JOIN domain_san dsan
      ON d.id = dsan.domain_id
      AND dsan.scan_id = %s
      
    WHERE dsan.domain_id IS NULL
    
    AND dsan.domain_id IS NULL
    ORDER BY d.id, ds.scan_id DESC
    """, (scan_id, scan_id))
    
    rows = cur.fetchall()

    print("Scan ID:", scan_id)
    print("Rows to process:", len(rows))

    new_count = 0

    for i, (domain_id, domain) in enumerate(rows, start=1):
    
        # classify original domain too
        
        is_known = domain in known_set
        scannable = is_scannable(domain, seeds) or is_known
        
        cur.execute("""
        UPDATE domains
        SET scannable = %s
        WHERE id = %s
        AND (validation_source IS NULL OR validation_source != 'manual')
        """, (scannable, domain_id))
    
        if i % 50 == 0:
            print(f"[{i}/{len(rows)}] Processing: {domain}")
    
        san_domains = list(set(fetch_san_domains(domain)))

        cur.execute("""
        INSERT INTO domain_san(domain_id, scan_id)
        VALUES (%s, %s)
        ON CONFLICT (domain_id, scan_id) DO NOTHING
        """, (domain_id, scan_id))
            
        for san in san_domains:
            san = san.lower().strip()
                     
            san = san.replace("*.", "")
                
            if san == domain:
                continue

            if "." not in san:
                continue                
     
            # insert or get domain_id
            san = san.lower().strip()
            
            is_known = san in known_set
            scannable = is_scannable(san, seeds) or is_known
            
            cur.execute("""
            INSERT INTO domains(
                domain,
                first_seen_scan,
                last_seen_scan,
                first_seen_at,
                last_seen_at,
                is_known,
                scannable
            )
            VALUES (
                %s,
                %s,
                %s,
                NOW(),
                NOW(),
                EXISTS (SELECT 1 FROM known_domains WHERE domain = %s),
                %s
            )
            ON CONFLICT (domain)
            DO UPDATE SET 
                last_seen_scan = EXCLUDED.last_seen_scan,
                last_seen_at = NOW(),
                is_known = (
                    SELECT EXISTS (
                        SELECT 1 FROM known_domains WHERE domain = EXCLUDED.domain
                    )
                ),
                scannable = CASE
                    WHEN domains.validation_source = 'manual' THEN domains.scannable
                    ELSE EXCLUDED.scannable
                END
                
            RETURNING id, (xmax = 0) AS inserted
            """, (san, scan_id, scan_id, san, scannable))
            
            new_domain_id, inserted = cur.fetchone()
                        
            # count only if newly inserted
            if inserted:
                new_count += 1        

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
