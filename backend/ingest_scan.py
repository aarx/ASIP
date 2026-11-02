import pandas as pd
import psycopg2
from ownership import ownership_for_discovery

conn = psycopg2.connect(
    host="db",
    dbname="asm_db",
    user="asm",
    password="asm123"
)

cur = conn.cursor()

df = pd.read_csv("latest_scan.csv")

# create scan record
cur.execute(
    "INSERT INTO scans(seed) VALUES (%s) RETURNING id",
    ("abc.com",)
)

scan_id = cur.fetchone()[0]

for _, row in df.iterrows():

    domain = row["Domain"]
    seed = row["Seed"]

    cur.execute(
        "SELECT id FROM domains WHERE domain=%s",
        (domain,)
    )

    res = cur.fetchone()

    if res is None:

        cur.execute(
            "SELECT EXISTS (SELECT 1 FROM known_domains WHERE domain=%s)",
            (domain.lower().strip(),)
        )
        is_known = cur.fetchone()[0]
        ownership_status = ownership_for_discovery(
            domain, (), seed, is_known=is_known
        )

        cur.execute(
            "INSERT INTO domains(domain, first_seen_scan, last_seen_scan, ownership_status) "
            "VALUES (%s,%s,%s,%s) RETURNING id",
            (domain, scan_id, scan_id, ownership_status)
        )

        domain_id = cur.fetchone()[0]

    else:

        domain_id = res[0]

        cur.execute(
            "UPDATE domains SET last_seen_scan=%s WHERE id=%s",
            (scan_id, domain_id)
        )

    cur.execute(
        "INSERT INTO scan_results(scan_id, domain_id, seed) VALUES (%s,%s,%s)",
        (scan_id, domain_id, seed)
    )

conn.commit()
conn.close()
