import csv
import sys

from db import get_conn
from ownership import OWNERSHIP_CONFIRMED, normalize_ownership_status


def apply_ownership(cur, domain, status):
    domain = (domain or "").strip().lower()
    status = normalize_ownership_status(status)

    cur.execute(
        "SELECT EXISTS (SELECT 1 FROM known_domains WHERE domain = %s)",
        (domain,),
    )
    if cur.fetchone()[0] and status != OWNERSHIP_CONFIRMED:
        raise ValueError(
            f"Known inventory domain {domain} must remain CONFIRMED"
        )

    cur.execute(
        """
        UPDATE domains
        SET ownership_status = %s
        WHERE domain = %s
        RETURNING domain
        """,
        (status, domain),
    )
    return cur.fetchone() is not None


def main(file_path):
    conn = get_conn()
    try:
        cur = conn.cursor()
        with open(file_path, newline="") as csvfile:
            for row in csv.DictReader(csvfile):
                domain = row.get("domain")
                status = row.get("ownership_status")
                if domain and status:
                    apply_ownership(cur, domain, status)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python ownership_ingest.py ownership.csv")
    main(sys.argv[1])
