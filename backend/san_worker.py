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


def fetch_san_domains(domain, before_request=None):
    if before_request is None or not before_request():
        return None
    try:
        with open_validated_tls_socket(
            domain, before_request=before_request
        ) as ssock:
            cert = ssock.getpeercert()

        san = cert.get("subjectAltName", [])
        return [entry[1] for entry in san if entry[0] == "DNS"]

    except Exception as e:
        print(f"[SAN ERROR] {domain} -> {e}")
        return None

def add_current_scan_membership(cur, parent_domain_id, child_domain_id):
    cur.execute("""
    SELECT seed
    FROM scan_results
    WHERE scan_id = %s
    AND domain_id = %s
    """, (scan_id, parent_domain_id))

    parent_scan_result = cur.fetchone()
    if not parent_scan_result:
        raise RuntimeError(
            f"Parent domain {parent_domain_id} is missing scan_results for scan {scan_id}"
        )

    cur.execute("""
    INSERT INTO scan_results(scan_id, domain_id, seed)
    VALUES (%s, %s, %s)
    ON CONFLICT (scan_id, domain_id) DO NOTHING
    """, (scan_id, child_domain_id, parent_scan_result[0]))

def main():
     
    conn = get_conn()
    cur = conn.cursor()
    require_running_scan(cur, scan_id)

    print("SAN scan for scan_id:", scan_id)

    cur.execute("SELECT domain FROM known_domains")
    known_set = set(r[0].strip().lower() for r in cur.fetchall())
    
    print("Loaded known domains:", len(known_set))

    cur.execute(f"""
    SELECT DISTINCT ON (d.id) d.id, d.domain
    FROM domains d
    JOIN scan_results sr
      ON d.id = sr.domain_id
      AND sr.scan_id = %s
    JOIN domain_states ds
      ON d.id = ds.domain_id
      AND ds.scan_id = %s
    
    LEFT JOIN domain_san dsan
      ON d.id = dsan.domain_id
      AND dsan.scan_id = %s
      
    WHERE dsan.domain_id IS NULL
      AND {active_scan_authorization_sql('d', 'HTTP_TLS_OBSERVATION')}
    ORDER BY d.id, ds.scan_id DESC
    """, (scan_id, scan_id, scan_id))
    
    rows = cur.fetchall()

    print("Scan ID:", scan_id)
    print("Rows to process:", len(rows))

    new_count = 0

    for i, (domain_id, domain) in enumerate(rows, start=1):

        # The candidate list survives checkpoint commits, so prove current-scan
        # membership again before any global update, network observation, or
        # scan-scoped write.
        cur.execute("""
        SELECT 1
        FROM scan_results
        WHERE scan_id = %s
        AND domain_id = %s
        """, (scan_id, domain_id))
        if cur.fetchone() is None:
            print(f"Skipping non-member SAN parent: {domain}")
            continue

        def authorized():
            allowed, reason = recheck_active_authorization(
                cur,
                scan_id=scan_id,
                domain_id=domain_id,
                testing_level="HTTP_TLS_OBSERVATION",
            )
            conn.commit()
            if not allowed:
                print(f"Skipping SAN TLS observation for {domain}: {reason}")
            return allowed

        if not authorized():
            continue
    
        if i % 50 == 0:
            print(f"[{i}/{len(rows)}] Processing: {domain}")
    
        san_observation = fetch_san_domains(domain, before_request=authorized)
        if san_observation is None:
            continue

        # Do not recreate a scan membership that disappeared while the TLS
        # observation was in flight.
        cur.execute("""
            SELECT 1
              FROM scan_results
             WHERE scan_id = %s
               AND domain_id = %s
        """, (scan_id, domain_id))
        if cur.fetchone() is None:
            print(f"Skipping SAN writes for non-member parent: {domain}")
            continue

        san_domains = list(set(san_observation))

        cur.execute("""
        INSERT INTO domain_san(domain_id, scan_id)
        SELECT %s, %s
        WHERE EXISTS (
            SELECT 1
            FROM scan_results sr
            WHERE sr.scan_id = %s
            AND sr.domain_id = %s
        )
        ON CONFLICT (domain_id, scan_id) DO NOTHING
        """, (domain_id, scan_id, scan_id, domain_id))
            
        for san in san_domains:
            san = san.lower().strip()
                     
            san = san.replace("*.", "")
                
            if san == domain:
                continue

            if "." not in san:
                continue                
     
            # insert or get domain_id
            san = san.lower().strip()
            
            cur.execute("""
            INSERT INTO domains(
                domain,
                first_seen_scan,
                last_seen_scan,
                first_seen_at,
                last_seen_at,
                is_known,
                source,
                ownership_status
            )
            VALUES (
                %s,
                %s,
                %s,
                NOW(),
                NOW(),
                EXISTS (SELECT 1 FROM known_domains WHERE domain = %s),
                %s,
                CASE
                    WHEN EXISTS (
                        SELECT 1 FROM known_domains WHERE domain = %s
                    ) THEN 'CONFIRMED'
                    WHEN EXISTS (
                        SELECT 1 FROM seed_domains root
                        WHERE %s = LOWER(TRIM(TRAILING '.' FROM root.domain))
                           OR %s LIKE '%%.' || LOWER(TRIM(TRAILING '.' FROM root.domain))
                    ) THEN 'CONFIRMED'
                    ELSE 'CANDIDATE'
                END
            )
            ON CONFLICT (domain)
            DO UPDATE SET 
                first_seen_scan = CASE
                    WHEN domains.first_seen_scan IS NULL THEN EXCLUDED.first_seen_scan
                    WHEN EXCLUDED.first_seen_scan IS NULL THEN domains.first_seen_scan
                    ELSE LEAST(domains.first_seen_scan, EXCLUDED.first_seen_scan)
                END,
                last_seen_scan = CASE
                    WHEN domains.last_seen_scan IS NULL THEN EXCLUDED.last_seen_scan
                    WHEN EXCLUDED.last_seen_scan IS NULL THEN domains.last_seen_scan
                    ELSE GREATEST(domains.last_seen_scan, EXCLUDED.last_seen_scan)
                END,
                last_seen_at = NOW(),
                is_known = (
                    SELECT EXISTS (
                        SELECT 1 FROM known_domains WHERE domain = EXCLUDED.domain
                    )
                ),
                ownership_status = CASE
                    WHEN EXISTS (
                        SELECT 1 FROM known_domains WHERE domain = EXCLUDED.domain
                    ) THEN 'CONFIRMED'
                    WHEN domains.ownership_status = 'EXTERNAL' THEN 'EXTERNAL'
                    WHEN domains.ownership_status = 'CONFIRMED' THEN 'CONFIRMED'
                    WHEN EXCLUDED.ownership_status = 'CONFIRMED' THEN 'CONFIRMED'
                    ELSE domains.ownership_status
                END,
                source = CASE
                    WHEN domains.source = 'seed' THEN 'san'
                    ELSE domains.source
                END
            RETURNING id, (xmax = 0) AS inserted
            """, (san, scan_id, scan_id, san, "san", san, san, san))
            
            new_domain_id, inserted = cur.fetchone()

            add_current_scan_membership(cur, domain_id, new_domain_id)
            
            # add SAN as a source (for attribution)
            cur.execute("""
            INSERT INTO domain_sources(domain_id, scan_id, source, seed)
            SELECT %s, %s, %s, %s
            WHERE EXISTS (
                SELECT 1
                FROM scan_results sr
                WHERE sr.scan_id = %s
                AND sr.domain_id = %s
            )
            ON CONFLICT DO NOTHING
            """, (
                new_domain_id, scan_id, "san", domain,
                scan_id, new_domain_id,
            ))
                        
                        
            # count only if newly inserted
            if inserted:
                new_count += 1        

        if i % 100 == 0:
            conn.commit()
            require_running_scan(cur, scan_id)
            print("Checkpoint commit at:", i)
    
        if new_count % 50 == 0 and new_count != 0:
            print("New domains added:", new_count)            
            

    conn.commit()
    conn.close()

    print("SAN expansion complete. New domains:", new_count)


if __name__ == "__main__":
    main()
