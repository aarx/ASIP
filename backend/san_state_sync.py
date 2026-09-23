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
        d.id,
        %s,
        '',
        FALSE,
        0,
        FALSE
    FROM domains d

    LEFT JOIN domain_states ds
      ON d.id = ds.domain_id
      AND ds.scan_id = %s

    WHERE ds.domain_id IS NULL
    AND d.last_seen_scan = %s
    """, (scan_id, scan_id, scan_id))

    inserted = cur.rowcount

    conn.commit()
    conn.close()

    print(f"SAN state sync complete. Inserted: {inserted}")

if __name__ == "__main__":
    main()
