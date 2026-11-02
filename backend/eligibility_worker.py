"""Evaluate automatic technical eligibility for one running scan.

This stage is deliberately separate from active authorization. It updates
only current-scan rows inside the trusted operator inventory, while preserving
manual decisions. Worker-specific testing-level permission and live policy
rechecks remain authoritative before any network operation.
"""

import sys

from db import get_conn, require_running_scan
from ownership import trusted_boundary_sql


scan_id = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else None


def automatic_eligibility_sql():
    """Return the idempotent current-scan eligibility update."""
    trusted = trusted_boundary_sql("d.domain")
    return f"""
        UPDATE domains d
        SET ownership_status = 'CONFIRMED',
            scannable = TRUE
        FROM scan_results sr
        WHERE sr.scan_id = %s
          AND sr.domain_id = d.id
          AND d.validation_source IS NULL
          AND d.ownership_status <> 'EXTERNAL'
          AND {trusted}
          AND (
              d.scannable IS NOT TRUE
              OR d.ownership_status <> 'CONFIRMED'
          )
    """


def automatic_ineligibility_sql():
    """Clear stale automatic eligibility for current-scan out-of-scope rows."""
    trusted = trusted_boundary_sql("d.domain")
    return f"""
        UPDATE domains d
        SET scannable = FALSE
        FROM scan_results sr
        WHERE sr.scan_id = %s
          AND sr.domain_id = d.id
          AND d.scannable IS TRUE
          AND NOT {trusted}
    """


def apply_automatic_eligibility(cur, scan_id):
    """Reconcile automatic eligibility for current-scan members only."""
    cur.execute(automatic_ineligibility_sql(), (scan_id,))
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
