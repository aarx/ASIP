import psycopg2
import csv

conn = psycopg2.connect(
    host="db",
    dbname="asm_db",
    user="asm",
    password="asm123"
)

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
