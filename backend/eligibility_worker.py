"""Evaluate automatic technical eligibility for one running scan.

This stage is deliberately separate from active authorization.  It only
updates currently unscannable, non-manual rows that have confirmed ownership
evidence and are covered by an active approved scope.  Worker-specific
prerequisites and the live authorization recheck remain authoritative before
any network operation.
"""

import sys

from authorization_policy import active_scope_coverage_sql
from db import get_conn, require_running_scan


scan_id = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else None


def automatic_eligibility_sql():
    """Return the idempotent current-scan eligibility update."""
    canonical = "LOWER(TRIM(TRAILING '.' FROM d.domain))"
    scope_coverage = active_scope_coverage_sql("d")
    return f"""
        UPDATE domains d
        SET scannable = TRUE
        FROM scan_results sr
        WHERE sr.scan_id = %s
          AND sr.domain_id = d.id
          AND d.scannable IS NOT TRUE
          AND d.validation_source IS NULL
          AND d.ownership_status = 'CONFIRMED'
          AND {canonical} = d.domain
          AND {canonical} ~ '^[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?)+$'
          AND (
              EXISTS (
                  SELECT 1
                  FROM known_domains kd
                  WHERE LOWER(TRIM(TRAILING '.' FROM kd.domain)) = {canonical}
              )
              OR EXISTS (
                  SELECT 1
                  FROM seed_domains root
                  WHERE {canonical} = LOWER(TRIM(TRAILING '.' FROM root.domain))
                     OR {canonical} LIKE '%%.' || LOWER(TRIM(TRAILING '.' FROM root.domain))
              )
          )
          AND {scope_coverage}
    """


def apply_automatic_eligibility(cur, scan_id):
    """Mark only newly eligible current-scan rows and return update count."""
    cur.execute(automatic_eligibility_sql(), (scan_id,))
    return cur.rowcount


def main():
    if scan_id is None:
        raise SystemExit("Usage: python eligibility_worker.py <scan_id>")
    conn = get_conn()
    try:
        cur = conn.cursor()
        require_running_scan(cur, scan_id)
        updated = apply_automatic_eligibility(cur, scan_id)
        conn.commit()
        print(f"Automatic eligibility complete. Updated: {updated}")
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()
