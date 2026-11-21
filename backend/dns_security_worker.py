"""Optional DNS Security scan stage. Disabled unless explicitly authorized."""

import json
import logging
import sys
import time
import argparse
import threading
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

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
from stage_progress import emit_stage_progress

DEFAULT_DNS_SECURITY_WORKERS = 4
MAX_DNS_SECURITY_WORKERS = 4


class DnsSecurityTargetFailure(RuntimeError):
    def __init__(self, cause, query_attempts):
        super().__init__(str(cause))
        self.query_attempts = int(query_attempts)


def configured_dns_security_workers(value=None):
    """Return the conservative, fixed DNS hostname concurrency."""
    if value is None:
        value = DEFAULT_DNS_SECURITY_WORKERS
    try:
        requested = int(value)
    except (TypeError, ValueError):
        requested = DEFAULT_DNS_SECURITY_WORKERS
    return min(MAX_DNS_SECURITY_WORKERS, max(1, requested))


class _WorkerConnections:
    """Reuse one autocommit connection per worker thread, never concurrently."""

    def __init__(self):
        self._local = threading.local()
        self._lock = threading.Lock()
        self._connections = []

    def get(self):
        conn = getattr(self._local, "connection", None)
        if conn is None:
            conn = get_conn()
            conn.autocommit = True
            self._local.connection = conn
            with self._lock:
                self._connections.append(conn)
        elif getattr(conn, "closed", False):
            raise RuntimeError("DNS Security worker database connection was lost")
        return conn

    def close_all(self):
        with self._lock:
            connections, self._connections = self._connections, []
        for conn in connections:
            try:
                if not getattr(conn, "closed", False) and not conn.autocommit:
                    conn.rollback()
                    conn.autocommit = True
                conn.close()
            except Exception:
                logging.exception("Failed to close a DNS Security worker connection")


def _assess_target(scan_id, domain_id, domain, *, connections, query_budget,
                   resolver_factory, operation_enabled):
    if not operation_enabled():
        return {"completed": False, "disabled": True,
                "query_attempts": 0, "checks_persisted": 0}

    conn = connections.get()
    cur = conn.cursor()
    resolver = None
    try:
        authorize = dns_security_query_authorizer(cur, scan_id)
        resolver = BoundedDnsResolver(
            resolver_factory=resolver_factory,
            operation_enabled=operation_enabled,
            query_budget=query_budget,
        )
        report = assess_dns_domain(domain, resolver, authorize)
        if any(item["evidence"].get("error_category") == "AUTHORIZATION_ERROR"
               for item in report["observations"]):
            raise RuntimeError("DNS query authorization could not be verified")

        authorization_skips = sum(
            item["evidence"].get("error_category") == "AUTHORIZATION_DENIED"
            for item in report["observations"]
        )
        disabled = any(
            item["evidence"].get("error_category") == "OPERATION_DISABLED"
            for item in report["observations"]
        )
        if disabled:
            return {
                "completed": False,
                "disabled": True,
                "query_attempts": resolver.query_attempts,
                "checks_persisted": 0,
                "authorization_skips": authorization_skips,
                "query_budget_exhausted": bool(query_budget and query_budget.exhausted),
            }
        persisted = 0
        conn.autocommit = False
        try:
            for check in report["checks"]:
                if not operation_enabled():
                    disabled = True
                    break
                if not persist_dns_security_check(
                    cur, scan_id=scan_id, domain_id=domain_id, check=check,
                ):
                    # Current scan membership/authorization was revoked.
                    authorization_skips += 1
                    break
                persisted += 1
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            if not getattr(conn, "closed", False):
                conn.autocommit = True

        return {
            "completed": True,
            "disabled": disabled,
            "query_attempts": resolver.query_attempts,
            "checks_persisted": persisted,
            "authorization_skips": authorization_skips,
            "query_budget_exhausted": bool(query_budget and query_budget.exhausted),
        }
    except Exception as exc:
        if not getattr(conn, "closed", False) and not conn.autocommit:
            try:
                conn.rollback()
                conn.autocommit = True
            except Exception:
                logging.exception("DNS Security transaction cleanup failed")
        if resolver is not None:
            raise DnsSecurityTargetFailure(exc, resolver.query_attempts) from exc
        raise
    finally:
        try:
            cur.close()
        except Exception:
            pass


def _emit(summary):
    print(
        "dns_security_stage "
        + json.dumps(summary, sort_keys=True, separators=(",", ":")),
        flush=True,
    )


def _emit_progress(scan_id, summary, started, *, force=False, status="RUNNING"):
    now = time.monotonic()
    last = summary.get("_last_progress", 0.0)
    if not force and now - last < 30:
        return
    summary["_last_progress"] = now
    selected = summary.get("selected", 0)
    processed = summary.get("_processed", 0)
    emit_stage_progress(
        scan_id, "DNS Security", status=status,
        selected=selected, total=selected, processed=processed,
        completed=summary.get("completed", 0),
        succeeded=summary.get("completed", 0),
        failed=summary.get("worker_errors", 0),
        skipped=summary.get("authorization_skips", 0),
        elapsed_seconds=now - started,
    )


def run_dns_security_stage(scan_id, *, run_scoped=False, resolver_factory=None,
                           workers=None):
    started = time.monotonic()
    summary = {
        "scan_id": int(scan_id), "selected": 0, "completed": 0,
        "checks_persisted": 0, "authorization_skips": 0,
        "policy_stops": 0, "disabled": False, "worker_errors": 0,
        "run_scoped": False, "run_scope_target_count": 0,
        "query_attempts": 0, "query_budget_exhausted": False,
        "worker_count": configured_dns_security_workers(workers),
        "elapsed_seconds": 0.0,
        "_processed": 0,
        "_last_progress": 0.0,
    }
    exit_code = 0
    globally_enabled = default_operation_enabled(DNS_SECURITY_OPERATION)
    if not globally_enabled:
        summary["disabled"] = True
        summary["elapsed_seconds"] = round(time.monotonic() - started, 4)
        _emit_progress(scan_id, summary, started, force=True, status="RUNNING")
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

        _emit_progress(scan_id, summary, started, force=True)

        query_budget = (
            DnsQueryBudget(MAX_RUN_SCOPED_DNS_QUERIES)
            if target_ids is not None else None
        )
        # Run-scoped execution is limited to a few explicitly selected assets
        # and has one shared query budget. Preserve its original deterministic
        # authorization/query order; full scans use the bounded hostname pool.
        worker_count = (
            1 if query_budget is not None
            else min(summary["worker_count"], max(1, len(targets)))
        )
        summary["worker_count"] = worker_count
        connections = _WorkerConnections()
        stop_dispatch = threading.Event()

        def operation_enabled():
            if stop_dispatch.is_set():
                return False
            enabled = default_operation_enabled(DNS_SECURITY_OPERATION)
            if not enabled:
                stop_dispatch.set()
            return enabled

        iterator = iter(targets)
        pending = {}
        executor = ThreadPoolExecutor(
            max_workers=worker_count, thread_name_prefix="dns-security"
        )
        exhausted = False
        failure = None
        try:
            while pending or (not exhausted and not stop_dispatch.is_set() and failure is None):
                while (not exhausted and not stop_dispatch.is_set() and failure is None
                       and len(pending) < worker_count):
                    try:
                        domain_id, domain = next(iterator)
                    except StopIteration:
                        exhausted = True
                        break
                    future = executor.submit(
                        _assess_target, scan_id, domain_id, domain,
                        connections=connections, query_budget=query_budget,
                        resolver_factory=resolver_factory,
                        operation_enabled=operation_enabled,
                    )
                    pending[future] = (domain_id, domain)

                if not pending:
                    break
                done, _ = wait(tuple(pending), timeout=0.1,
                               return_when=FIRST_COMPLETED)
                for future in done:
                    pending.pop(future)
                    if future.cancelled():
                        continue
                    summary["_processed"] += 1
                    try:
                        result = future.result()
                    except Exception as exc:
                        summary["worker_errors"] += 1
                        summary["query_attempts"] += getattr(
                            exc, "query_attempts", 0
                        )
                        if failure is None:
                            failure = exc
                        continue
                    summary["query_attempts"] += result.get("query_attempts", 0)
                    summary["checks_persisted"] += result.get("checks_persisted", 0)
                    summary["authorization_skips"] += result.get("authorization_skips", 0)
                    summary["query_budget_exhausted"] |= result.get(
                        "query_budget_exhausted", False
                    )
                    if result["completed"]:
                        summary["completed"] += 1
                    if result["disabled"]:
                        if not summary["disabled"]:
                            summary["policy_stops"] += 1
                        summary["disabled"] = True
                        stop_dispatch.set()
                _emit_progress(scan_id, summary, started)

                if failure is not None or stop_dispatch.is_set():
                    for future in pending:
                        future.cancel()

            if query_budget is not None:
                summary["query_budget_exhausted"] = query_budget.exhausted
            if failure is not None:
                raise failure
        finally:
            executor.shutdown(wait=True, cancel_futures=True)
            connections.close_all()
    except Exception:
        logging.exception("DNS Security stage failed closed for scan_id=%s", scan_id)
        if summary["worker_errors"] == 0:
            summary["worker_errors"] = 1
        exit_code = 1
    finally:
        summary["elapsed_seconds"] = round(time.monotonic() - started, 4)
        _emit_progress(
            scan_id, summary, started, force=True,
            status="RUNNING" if exit_code == 0 else "FAILED",
        )
        summary.pop("_processed", None)
        summary.pop("_last_progress", None)
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
