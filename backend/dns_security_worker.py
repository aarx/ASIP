"""Optional DNS Security scan stage. Disabled unless explicitly authorized."""

import json
import logging
import sys
import time
import argparse

from asset_reporting import reporting_asset_class_sql
from authorization_policy import (
    active_scan_authorization_sql,
    default_operation_enabled,
    normalize_dns_security_target_ids,
)
from db import get_conn
from dns_security import (
    BoundedDnsResolver,
    DnsQueryBudget,
    DNS_SECURITY_OPERATION,
    MAX_RUN_SCOPED_DNS_QUERIES,
    assess_dns_domain,
    dns_security_query_authorizer,
    persist_dns_security_check,
)


def _emit(summary):
    logging.info("dns_security_stage %s", json.dumps(summary, sort_keys=True, separators=(",", ":")))


def run_dns_security_stage(scan_id, *, run_scoped=False, resolver_factory=None):
    started = time.monotonic()
    summary = {
        "scan_id": int(scan_id), "selected": 0, "completed": 0,
        "checks_persisted": 0, "authorization_skips": 0,
        "policy_stops": 0, "disabled": False, "worker_errors": 0,
        "run_scoped": False, "run_scope_target_count": 0,
        "query_attempts": 0, "query_budget_exhausted": False,
        "elapsed_seconds": 0.0,
    }
    exit_code = 0
    globally_enabled = default_operation_enabled(DNS_SECURITY_OPERATION)
    if not globally_enabled and not run_scoped:
        summary["disabled"] = True
        summary["elapsed_seconds"] = round(time.monotonic() - started, 4)
        _emit(summary)
        return 0

    try:
        conn = get_conn()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT status, dns_security_target_ids FROM scans WHERE id = %s",
                (scan_id,),
            )
            scan = cur.fetchone()
            if scan is None or scan[0] != "RUNNING":
                raise RuntimeError("scan is not RUNNING")
            target_ids = normalize_dns_security_target_ids(scan[1])
            if not globally_enabled and target_ids is None:
                summary["disabled"] = True
                summary["policy_stops"] += 1
                conn.rollback()
                return 0
            if run_scoped and target_ids is None:
                summary["disabled"] = True
                summary["policy_stops"] += 1
                conn.rollback()
                return 0
            if target_ids is not None:
                summary["run_scoped"] = True
                summary["run_scope_target_count"] = len(target_ids)
            classification = reporting_asset_class_sql("d.domain", "d.ownership_status")
            authorization = active_scan_authorization_sql(
                "d", DNS_SECURITY_OPERATION, scan_alias="s"
            )
            cur.execute(f"""
                SELECT DISTINCT d.id, d.domain
                  FROM scan_results sr
                  JOIN scans s ON s.id = sr.scan_id
                  JOIN domains d ON d.id = sr.domain_id
                 WHERE sr.scan_id = %s
                   AND s.status = 'RUNNING'
                   AND d.scannable IS TRUE
                   AND ({classification}) IN ('KNOWN', 'SHADOW')
                   AND (%s::INTEGER[] IS NULL OR d.id = ANY(%s::INTEGER[]))
                   AND {authorization}
                 ORDER BY d.id
            """, (scan_id, list(target_ids) if target_ids is not None else None,
                  list(target_ids) if target_ids is not None else None))
            targets = cur.fetchall()
            summary["selected"] = len(targets)
            conn.rollback()
        finally:
            conn.close()

        query_budget = (
            DnsQueryBudget(MAX_RUN_SCOPED_DNS_QUERIES)
            if target_ids is not None else None
        )
        for domain_id, domain in targets:
            if (not default_operation_enabled(DNS_SECURITY_OPERATION)
                    and target_ids is None):
                summary["disabled"] = True
                summary["policy_stops"] += 1
                break
            worker_conn = None
            try:
                worker_conn = get_conn()
                worker_conn.autocommit = True
                cur = worker_conn.cursor()
                authorize = dns_security_query_authorizer(cur, scan_id)
                resolver = BoundedDnsResolver(
                    resolver_factory=resolver_factory,
                    operation_enabled=lambda: (
                        default_operation_enabled(DNS_SECURITY_OPERATION)
                        or target_ids is not None
                    ),
                    query_budget=query_budget,
                )
                report = assess_dns_domain(
                    domain, resolver, authorize,
                )
                summary["query_attempts"] += resolver.query_attempts
                if query_budget is not None and query_budget.exhausted:
                    summary["query_budget_exhausted"] = True
                if any(item["evidence"].get("error_category") == "OPERATION_DISABLED"
                       for item in report["observations"]):
                    summary["disabled"] = True
                    summary["policy_stops"] += 1
                    break
                query_errors = [
                    item for item in report["observations"]
                    if item["evidence"].get("error_category") == "AUTHORIZATION_ERROR"
                ]
                if query_errors:
                    raise RuntimeError("DNS query authorization could not be verified")
                if any(item["evidence"].get("error_category") == "AUTHORIZATION_DENIED"
                       for item in report["observations"]):
                    summary["authorization_skips"] += 1
                persisted = 0
                for check in report["checks"]:
                    if (not default_operation_enabled(DNS_SECURITY_OPERATION)
                            and target_ids is None):
                        summary["disabled"] = True
                        summary["policy_stops"] += 1
                        break
                    if not persist_dns_security_check(
                        cur, scan_id=scan_id, domain_id=domain_id, check=check,
                    ):
                        # A revoked/ineligible parent is a safe skip. SQL or
                        # policy evaluation errors are raised by the helper.
                        summary["authorization_skips"] += 1
                        break
                    persisted += 1
                summary["checks_persisted"] += persisted
                summary["completed"] += 1
                if summary["disabled"]:
                    break
            finally:
                if worker_conn is not None:
                    worker_conn.close()
    except Exception:
        logging.exception("DNS Security stage failed closed for scan_id=%s", scan_id)
        summary["worker_errors"] += 1
        exit_code = 1
    finally:
        summary["elapsed_seconds"] = round(time.monotonic() - started, 4)
        _emit(summary)
    return exit_code


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run an authorized DNS Security scan stage")
    parser.add_argument("scan_id", type=int)
    parser.add_argument("--run-scoped", action="store_true")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    try:
        scan_id = args.scan_id
        if scan_id <= 0:
            raise ValueError
    except ValueError:
        logging.error("scan_id must be a positive integer")
        return 2
    return run_dns_security_stage(scan_id, run_scoped=args.run_scoped)


if __name__ == "__main__":
    raise SystemExit(main())
