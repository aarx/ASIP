import csv
from db import get_conn

KNOWN_DOMAINS_FILE = "/app/data/known_domains.csv"

conn = get_conn()
cur = conn.cursor()

try:
    with open(KNOWN_DOMAINS_FILE, newline="") as f:
        reader = csv.DictReader(f)

        if not reader.fieldnames or "domain" not in reader.fieldnames:
            raise ValueError(
                f"{KNOWN_DOMAINS_FILE} must contain a 'domain' column"
            )

        loaded = 0

        for row in reader:
            domain = (row.get("domain") or "").strip().lower()

            if not domain:
                continue

            cur.execute(
                """
                INSERT INTO known_domains(domain, source)
                VALUES (%s, %s)
                ON CONFLICT (domain) DO NOTHING
                """,
                (domain, "initial_import")
            )

            cur.execute(
                """
                UPDATE domains
                SET is_known = TRUE,
                    ownership_status = 'CONFIRMED'
                WHERE domain = %s
                """,
                (domain,)
            )

            loaded += 1

    conn.commit()

except Exception:
    conn.rollback()
    raise

finally:
    conn.close()

print(f"Known domains loaded: {loaded}")
