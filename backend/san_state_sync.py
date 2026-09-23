import sys
from db import get_conn, require_running_scan

scan_id = int(sys.argv[1])


def main():

    conn = get_conn()
    cur = conn.cursor()
    require_running_scan(cur, scan_id)

    print("Running SAN state sync for scan:", scan_id)

    # 🔥 Insert missing domain_states for this scan
    cur.execute("""
    INSERT INTO domain_states(
        domain_id,
        scan_id,
        ip,
        has_ip,
        http_status,
        http_live
    )
    SELECT
        sr.domain_id,
        sr.scan_id,
        '',
        FALSE,
        0,
        FALSE
    FROM scan_results sr

    JOIN domains d
      ON d.id = sr.domain_id

    LEFT JOIN domain_states ds
      ON sr.domain_id = ds.domain_id
      AND sr.scan_id = ds.scan_id

    WHERE sr.scan_id = %s
    AND ds.domain_id IS NULL
    """, (scan_id,))

    inserted = cur.rowcount

    conn.commit()
    conn.close()

    print(f"SAN state sync complete. Inserted: {inserted}")

if __name__ == "__main__":
    main()
