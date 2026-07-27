import csv
from db import get_conn

cur = conn.cursor()

with open("/app/data/known_domains.csv") as f:
    reader = csv.DictReader(f)

    for row in reader:
        domain = row["Domains"].strip().lower()

        cur.execute(
            """
            INSERT INTO known_domains(domain, source)
            VALUES (%s, %s)
            ON CONFLICT (domain) DO NOTHING
            """,
            (domain, "initial_import")
        )

conn.commit()
conn.close()

print("Known domains loaded")
