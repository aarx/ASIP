import csv
from db import get_conn

conn = get_conn()
cur = conn.cursor()

try:
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
except Exception:
    conn.rollback()
    raise
finally:
    conn.close()

print("Known domains loaded")
