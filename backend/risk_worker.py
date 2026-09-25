import logging
import os
import sys

from db import get_conn, require_running_scan
from risk_engine import calculate_scan_risks, serialize_reasons


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


def main():
    conn = get_conn()
    cur = conn.cursor()
    require_running_scan(cur, scan_id)

    print("Computing canonical risk for scan:", scan_id)
    cur.execute("""
        DELETE FROM domain_risk dr
        USING domains d
        WHERE dr.domain_id = d.id
          AND dr.scan_id = %s
          AND d.ownership_status <> 'CONFIRMED'
          AND EXISTS (
              SELECT 1
              FROM scan_results sr
              WHERE sr.scan_id = dr.scan_id
                AND sr.domain_id = dr.domain_id
          )
    """, (scan_id,))
    risks = calculate_scan_risks(cur, scan_id)

    count = 0
    for domain_risk in risks:
        cur.execute("""
            INSERT INTO domain_risk(domain_id, scan_id, risk_score, reasons)
            SELECT %s, %s, %s, %s
            WHERE EXISTS (
                SELECT 1
                FROM scan_results sr
                WHERE sr.scan_id = %s
                  AND sr.domain_id = %s
            )
            ON CONFLICT(domain_id, scan_id)
            DO UPDATE SET
                risk_score = EXCLUDED.risk_score,
                reasons = EXCLUDED.reasons
        """, (
            domain_risk.domain_id,
            scan_id,
            domain_risk.result.score,
            serialize_reasons(domain_risk.result.reasons),
            scan_id,
            domain_risk.domain_id,
        ))
        count += cur.rowcount

        if count and count % 200 == 0:
            print("Processed:", count)

    conn.commit()
    conn.close()

    print("Canonical risk computation complete:", count)


if __name__ == "__main__":
    main()
