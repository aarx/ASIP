import pandas as pd
from db import get_conn
from ownership import (
    load_trusted_domains,
    normalize_hostname,
    ownership_for_discovery,
)

conn = get_conn()

cur = conn.cursor()

trusted_domains = load_trusted_domains(cur)
cur.execute("SELECT domain FROM known_domains")
known_domains = {
    normalized
    for (known_domain,) in cur.fetchall()
    if (normalized := normalize_hostname(known_domain))
}

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

        normalized_domain = normalize_hostname(domain)
        is_known = normalized_domain in known_domains if normalized_domain else False
        ownership_status = ownership_for_discovery(
            domain, (), seed, is_known=is_known,
            trusted_domains=trusted_domains,
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
