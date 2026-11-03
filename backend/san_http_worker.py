import json
import sys

from authorization_policy import (
    active_scan_authorization_sql,
    recheck_active_authorization,
)
from db import get_conn, require_running_scan
from http_probe import http_probe


scan_id = int(sys.argv[1])


def main():
    conn = get_conn()
    cur = conn.cursor()
    require_running_scan(cur, scan_id)

    cur.execute(f"""
        SELECT d.id, d.domain, ds.ip
        FROM domains d
        JOIN scan_results sr
          ON d.id = sr.domain_id
          AND sr.scan_id = %s
        JOIN domain_states ds
          ON d.id = ds.domain_id
          AND ds.scan_id = %s
        WHERE ds.has_ip = TRUE
        AND COALESCE(ds.http_status, 0) = 0
        AND EXISTS (
            SELECT 1
            FROM domain_sources src
            WHERE src.domain_id = d.id
            AND src.scan_id = %s
            AND src.source = 'san'
        )
        AND {active_scan_authorization_sql('d', 'HTTP_TLS_OBSERVATION')}
    """, (scan_id, scan_id, scan_id))

    rows = cur.fetchall()
    observed = 0

    for row in rows:
        domain_id, domain = row[:2]
        ip = row[2] if len(row) > 2 else None
        def authorized():
            allowed, reason = recheck_active_authorization(
                cur,
                scan_id=scan_id,
                domain_id=domain_id,
                testing_level="HTTP_TLS_OBSERVATION",
            )
            conn.commit()
            if not allowed:
                print(f"Skipping SAN HTTP observation for {domain}: {reason}")
            return allowed

        if not authorized():
            continue

        result = http_probe(
            domain,
            expected_ip=ip,
            before_request=authorized,
        )
        if not result:
            continue

        outcome = result.get("http_observation_status", "UNKNOWN")
        if outcome != "RESPONDED":
            cur.execute("""
            UPDATE domain_states
            SET http_observation_status = %s,
                http_redirect_evidence = %s::jsonb
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
                outcome,
                json.dumps(result.get("redirect_evidence")),
                domain_id,
                scan_id
            ))
            observed += cur.rowcount
            continue

        http_status = result["http_status"]
        cur.execute("""
            UPDATE domain_states
            SET http_status = %s,
                http_live = %s,
                http_reason = %s,
                final_url = %s,
                final_status = %s,
                http_redirect_evidence = %s::jsonb,
                title = %s,
                http_observation_status = %s
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
            json.dumps(result.get("redirect_evidence"))
            if result.get("redirect_evidence") is not None else None,
            result["title"][:500],
            outcome,
            domain_id,
            scan_id
        ))
        observed += cur.rowcount

    conn.commit()
    conn.close()

    print(f"SAN HTTP observation complete. Updated: {observed}")


if __name__ == "__main__":
    main()
