import sys

from db import get_conn, require_running_scan
from http_probe import http_probe


scan_id = int(sys.argv[1])


def main():
    conn = get_conn()
    cur = conn.cursor()
    require_running_scan(cur, scan_id)

    cur.execute("""
        SELECT d.id, d.domain
        FROM domains d
        JOIN scan_results sr
          ON d.id = sr.domain_id
          AND sr.scan_id = %s
        JOIN domain_states ds
          ON d.id = ds.domain_id
          AND ds.scan_id = %s
        WHERE ds.has_ip = TRUE
        AND COALESCE(ds.http_status, 0) = 0
        AND d.scannable = TRUE
        AND EXISTS (
            SELECT 1
            FROM domain_sources src
            WHERE src.domain_id = d.id
            AND src.scan_id = %s
            AND src.source = 'san'
        )
    """, (scan_id, scan_id, scan_id))

    rows = cur.fetchall()
    observed = 0

    for domain_id, domain in rows:
        result = http_probe(domain)
        if not result:
            continue

        http_status = result["http_status"]
        cur.execute("""
            UPDATE domain_states
            SET http_status = %s,
                http_live = %s,
                http_reason = %s,
                final_url = %s,
                final_status = %s,
                title = %s
            WHERE domain_id = %s
            AND scan_id = %s
            AND COALESCE(http_status, 0) = 0
            AND EXISTS (
                SELECT 1
                FROM scan_results sr
                WHERE sr.scan_id = domain_states.scan_id
                AND sr.domain_id = domain_states.domain_id
            )
        """, (
            http_status,
            200 <= http_status < 600,
            result["http_reason"],
            result["final_url"],
            result["final_status"],
            result["title"][:500],
            domain_id,
            scan_id
        ))
        observed += cur.rowcount

    conn.commit()
    conn.close()

    print(f"SAN HTTP observation complete. Updated: {observed}")


if __name__ == "__main__":
    main()
