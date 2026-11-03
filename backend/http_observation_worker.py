"""Authorized HTTP/TLS observation for the current scan."""

import json
import sys

from authorization_policy import (
    active_scan_authorization_sql,
    recheck_active_authorization,
)
from db import get_conn, require_running_scan
from http_probe import http_probe


scan_id = int(sys.argv[1])
TESTING_LEVEL = "HTTP_TLS_OBSERVATION"


def _authorize(cur, conn, domain_id, domain_name=None):
    allowed, reason = recheck_active_authorization(
        cur,
        scan_id=scan_id,
        domain_id=domain_id,
        domain_name=domain_name,
        testing_level=TESTING_LEVEL,
    )
    # End the policy query transaction before opening a network connection so
    # revocation/expiry remains visible to the next check.
    conn.commit()
    if not allowed:
        print(f"Skipping HTTP/TLS observation for {domain_id}: {reason}")
    return allowed


def main():
    conn = get_conn()
    cur = conn.cursor()
    require_running_scan(cur, scan_id)

    cur.execute(f"""
        SELECT d.id, d.domain, ds.ip
        FROM domains d
        JOIN scan_results sr
          ON sr.domain_id = d.id
         AND sr.scan_id = %s
        JOIN domain_states ds
          ON ds.domain_id = d.id
         AND ds.scan_id = sr.scan_id
        WHERE ds.has_ip IS TRUE
          AND COALESCE(ds.http_status, 0) = 0
          AND {active_scan_authorization_sql('d', TESTING_LEVEL)}
        ORDER BY d.id
    """, (scan_id,))
    rows = cur.fetchall()
    observed = 0

    for domain_id, domain, ip in rows:
        if not _authorize(cur, conn, domain_id):
            continue

        result = http_probe(
            domain,
            expected_ip=ip,
            before_request=lambda target_domain=None, domain_id=domain_id: _authorize(
                cur, conn, domain_id, target_domain
            ),
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
                       SELECT 1 FROM scan_results sr
                        WHERE sr.scan_id = domain_states.scan_id
                          AND sr.domain_id = domain_states.domain_id
                   )
            """, (
                outcome,
                json.dumps(result.get("redirect_evidence")),
                domain_id,
                scan_id,
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
                   SELECT 1 FROM scan_results sr
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
            scan_id,
        ))
        observed += cur.rowcount

    conn.commit()
    conn.close()
    print(f"HTTP/TLS observation complete. Updated: {observed}")


if __name__ == "__main__":
    main()
