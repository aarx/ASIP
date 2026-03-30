import pandas as pd
import psycopg2

conn = psycopg2.connect(
    host="db",
    dbname="asm_db",
    user="asm",
    password="asm123"
)

cur = conn.cursor()

df = pd.read_csv("data/final_output.csv")

# create new scan
cur.execute(
    "INSERT INTO scans(seed) VALUES (%s) RETURNING id",
    ("multi-seed-scan",)
)

scan_id = cur.fetchone()[0]

print("Created scan:", scan_id)

for _, row in df.iterrows():

    domain = row["Domain"]
    seed = row["Seed"]
    
    domain = domain.strip().lower()
    
    cur.execute(
        "SELECT 1 FROM known_domains WHERE domain=%s",
        (domain,)
    )
    known = cur.fetchone() is not None

    ip = row.get("IP", "")
    http_status = row.get("HTTP_Status", "")

    try:
        http_status = int(http_status)
    except:
        http_status = 0
        
    print("Debug HTTP:", domain, http_status)    
    http_live = http_status != 0

    raw_ip = row.get("IP")
    if raw_ip is None:
        ip = ""
    else:
        ip = str(raw_ip).strip()
    
    if ip.lower() in ["", "nan", "none", "n/a"]:
        ip = ""
    
    has_ip = ip != ""


    cur.execute(
        """
        INSERT INTO domains(domain, first_seen_scan, last_seen_scan, is_known)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (domain)
        DO UPDATE SET
            last_seen_scan = EXCLUDED.last_seen_scan,
            is_known = domains.is_known OR EXCLUDED.is_known
        RETURNING id
        """,
        (domain, scan_id, scan_id, known)
    )
    
    domain_id = cur.fetchone()[0]

    cur.execute(
        """
        INSERT INTO scan_results(scan_id, domain_id, seed)
        VALUES (%s,%s,%s)
        ON CONFLICT DO NOTHING
        """,
        (scan_id, domain_id, seed)
    )
    
    cur.execute(
    """
    INSERT INTO domain_states(
        scan_id,
        domain_id,
        ip,
        has_ip,
        http_status,
        http_live
    )
    VALUES (%s,%s,%s,%s,%s,%s)
    """,
    (
        scan_id,
        domain_id,
        ip,
        has_ip,
        http_status,
        http_live
    )
)

conn.commit()
conn.close()

print("Ingestion done")
