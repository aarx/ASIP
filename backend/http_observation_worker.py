"""Authorized, bounded HTTP/TLS observation for the current scan."""

import json
import logging
import os
import signal
import sys
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

from authorization_policy import (
    active_scan_authorization_sql,
    recheck_active_authorization,
)
from db import get_conn, require_running_scan
from http_probe import HTTP_FAILED, HTTP_NO_RESPONSE, HTTP_UNKNOWN, http_probe
from stage_progress import emit_stage_progress


scan_id = int(sys.argv[1])
TESTING_LEVEL = "HTTP_TLS_OBSERVATION"
DEFAULT_HTTP_WORKERS = 2
MAX_HTTP_WORKERS = 2
logger = logging.getLogger("http_observation")
logging.basicConfig(level=logging.INFO, format="%(message)s")


class ObservationStageError(RuntimeError):
    """One or more HTTP observation targets failed unexpectedly."""


class ObservationInterrupted(RuntimeError):
    """The observation stage was interrupted before all targets completed."""


class CancellationGate:
    """Order cancellation registration against scan-scoped result commits.

    The reentrant lock is held only while recording cancellation or while a
    worker performs the lifecycle-guarded write and commit. It is never held
    during authorization, DNS, TLS, or HTTP work. Reentrancy lets a Python
    signal handler safely register cancellation if it interrupts the main
    thread while that thread is already inside ``set``.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._cancelled = False

    def is_set(self):
        with self._lock:
            return self._cancelled

    def set(self):
        with self._lock:
            self._cancelled = True

    def run_if_active(self, operation):
        """Run one DB write+commit before cancellation, or reject it after."""
        with self._lock:
            if self._cancelled:
                return None
            return operation()


def configured_http_workers(value=None):
    """Return the bounded worker count; invalid configuration uses default."""
    if value is None:
        value = os.environ.get("ASIP_HTTP_WORKERS", str(DEFAULT_HTTP_WORKERS))
    try:
        requested = int(value)
    except (TypeError, ValueError):
        requested = DEFAULT_HTTP_WORKERS
    return min(MAX_HTTP_WORKERS, max(1, requested))


def _authorize(cur, conn, target_scan_id, domain_id, domain_name=None,
               cancel_event=None, state=None):
    if cancel_event is not None and cancel_event.is_set():
        return False
    allowed, reason = recheck_active_authorization(
        cur,
        scan_id=target_scan_id,
        domain_id=domain_id,
        domain_name=domain_name,
        testing_level=TESTING_LEVEL,
    )
    # Finish each policy transaction before DNS or socket work so changes to
    # scope, expiry, revocation, or scan lifecycle remain visible on recheck.
    conn.commit()
    if not allowed:
        if reason == "authorization check failed" and state is not None:
            state["authorization_error"] = True
        elif state is not None:
            state["authorization_denied"] = True
        return False
    return True


def _probe_error_flag(result):
    evidence = result.get("redirect_evidence") or {}
    reason = str(evidence.get("stop_reason") or "").lower()
    return bool(
        result.get("read_error")
        or result.get("http_observation_status") in {HTTP_NO_RESPONSE, HTTP_FAILED}
        or "timeout" in reason
        or "ambiguous" in reason
        or "pre_request_failure" in reason
        or "phase_unknown" in reason
    )


def _incomplete_flag(result):
    if result.get("http_observation_status") == HTTP_NO_RESPONSE:
        # A normal failure to receive an HTTP response has its own stage
        # category and is not counted as an executor/worker failure.
        return False
    evidence = result.get("redirect_evidence") or {}
    reason = str(evidence.get("stop_reason") or "").lower()
    return bool(
        result.get("read_error")
        or result.get("http_observation_status") in {HTTP_FAILED, HTTP_UNKNOWN}
        or "timeout" in reason
        or "ambiguous" in reason
        or "pre_request_failure" in reason
        or "phase_unknown" in reason
    )


def _target_metric(target_scan_id, domain_id, started, outcome,
                   redirect_count=0, timeout_or_error=False,
                   probe_elapsed=None):
    logger.info("http_target %s", json.dumps({
        "scan_id": target_scan_id,
        "domain_id": domain_id,
        "elapsed_seconds": round(time.monotonic() - started, 4),
        "probe_elapsed_seconds": (
            round(probe_elapsed, 4) if probe_elapsed is not None else None
        ),
        "outcome": outcome,
        "redirect_count": int(redirect_count or 0),
        "timeout_or_error": bool(timeout_or_error),
    }, separators=(",", ":")))


def _persist_result(cur, conn, target_scan_id, domain_id, result):
    outcome = result.get("http_observation_status", HTTP_UNKNOWN)
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
            target_scan_id,
        ))
    else:
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
            target_scan_id,
        ))
    conn.commit()
    return cur.rowcount


def _observe_target(row, target_scan_id, cancel_event, active_state):
    domain_id, domain, ip = row
    started = time.monotonic()
    state = {"authorization_error": False, "authorization_denied": False}
    conn = None
    try:
        if cancel_event.is_set():
            _target_metric(target_scan_id, domain_id, started, "CANCELLED")
            return {"kind": "cancelled", "domain_id": domain_id}

        conn = get_conn()
        cur = conn.cursor()
        require_running_scan(cur, target_scan_id)
        conn.commit()

        def authorized(target_domain=None):
            return _authorize(
                cur,
                conn,
                target_scan_id,
                domain_id,
                target_domain,
                cancel_event,
                state,
            )

        if not authorized():
            if state["authorization_error"]:
                raise RuntimeError("HTTP authorization database check failed")
            _target_metric(target_scan_id, domain_id, started,
                           "AUTHORIZATION_SKIPPED")
            return {"kind": "authorization_skipped", "domain_id": domain_id}

        probe_started = time.monotonic()
        result = http_probe(
            domain,
            expected_ip=ip,
            before_request=authorized,
        )
        probe_elapsed = time.monotonic() - probe_started
        if state["authorization_error"]:
            raise RuntimeError("HTTP authorization database check failed")
        # Hold the scan row lock through the scan-scoped write. If lifecycle
        # has ended, this target fails instead of mutating a terminal scan.
        # The gate orders this complete transaction against cancellation
        # registration, closing the check-then-commit race.

        def persist_if_active():
            require_running_scan(cur, target_scan_id)
            return _persist_result(cur, conn, target_scan_id, domain_id, result)

        persisted = cancel_event.run_if_active(persist_if_active)
        if persisted is None:
            conn.rollback()
            _target_metric(target_scan_id, domain_id, started, "CANCELLED")
            return {"kind": "cancelled", "domain_id": domain_id}
        evidence = result.get("redirect_evidence") or {}
        outcome = result.get("http_observation_status", HTTP_UNKNOWN)
        error_flag = _probe_error_flag(result)
        _target_metric(
            target_scan_id,
            domain_id,
            started,
            outcome,
            result.get("redirect_count", 0),
            error_flag,
            probe_elapsed,
        )
        return {
            "kind": "observation",
            "domain_id": domain_id,
            "outcome": outcome,
            "persisted": persisted,
            "incomplete": _incomplete_flag(result),
            "stop_reason": evidence.get("stop_reason"),
            "authorization_denied": state["authorization_denied"],
        }
    except Exception:
        _target_metric(target_scan_id, domain_id, started, "WORKER_ERROR",
                       timeout_or_error=True)
        raise
    finally:
        try:
            if conn is not None:
                conn.close()
        finally:
            with active_state["lock"]:
                active_state["active"] -= 1


def _unique_targets(rows):
    seen = set()
    unique = []
    for row in rows:
        domain_id = row[0]
        if domain_id in seen:
            continue
        seen.add(domain_id)
        unique.append(tuple(row))
    return unique


def run_observations(rows, target_scan_id, *, workers=None, cancel_event=None):
    """Process the selected rows with a fixed-size, bounded worker pool."""
    worker_count = configured_http_workers(workers)
    targets = _unique_targets(rows)
    if cancel_event is None:
        cancel_event = CancellationGate()
    elif not isinstance(cancel_event, CancellationGate):
        raise TypeError("cancel_event must be a CancellationGate")
    started = time.monotonic()
    active_state = {"active": 0, "maximum": 0, "lock": threading.Lock()}
    counts = {
        "completed_observations": 0,
        "persisted_results": 0,
        "authorization_skips": 0,
        "http_no_response": 0,
        "failed_incomplete": 0,
        "worker_errors": 0,
        "cancelled_targets": 0,
        "unresolved_redirects": 0,
    }
    errors = []
    iterator = iter(targets)
    futures = {}
    executor = ThreadPoolExecutor(max_workers=worker_count,
                                  thread_name_prefix="http-observation")
    exhausted = False
    interrupted = False
    stop_dispatch = False
    internal_failure = False
    submitted = 0
    processed_targets = 0
    last_progress = 0.0

    def report_progress(force=False):
        nonlocal last_progress
        now = time.monotonic()
        if not force and now - last_progress < 30:
            return
        emit_stage_progress(
            target_scan_id, "HTTP/TLS Observation", selected=len(targets),
            total=len(targets), processed=processed_targets,
            completed=counts["completed_observations"] + counts["http_no_response"],
            succeeded=counts["persisted_results"], failed=counts["worker_errors"],
            skipped=counts["authorization_skips"] + counts["cancelled_targets"],
            elapsed_seconds=now - started,
        )
        last_progress = now

    def run_target(row):
        with active_state["lock"]:
            active_state["active"] += 1
            active_state["maximum"] = max(
                active_state["maximum"], active_state["active"]
            )
        return _observe_target(row, target_scan_id, cancel_event, active_state)

    try:
        report_progress(force=True)
        while futures or (not exhausted and not stop_dispatch):
            while (not exhausted and not stop_dispatch
                   and not cancel_event.is_set()
                   and len(futures) < worker_count):
                try:
                    row = next(iterator)
                except StopIteration:
                    exhausted = True
                    break
                future = executor.submit(run_target, row)
                futures[future] = row[0]
                submitted += 1

            if cancel_event.is_set() and not internal_failure:
                interrupted = True
                stop_dispatch = True
                for future in futures:
                    future.cancel()

            if not futures:
                break
            done, _pending = wait(
                tuple(futures),
                timeout=0.1,
                return_when=FIRST_COMPLETED,
            )
            for future in done:
                domain_id = futures.pop(future)
                if not future.cancelled():
                    processed_targets += 1
                if future.cancelled():
                    counts["cancelled_targets"] += 1
                    report_progress()
                    continue
                try:
                    result = future.result()
                except Exception as exc:
                    counts["worker_errors"] += 1
                    errors.append((domain_id, exc))
                    stop_dispatch = True
                    internal_failure = True
                    cancel_event.set()
                    report_progress()
                    continue
                if result["kind"] == "authorization_skipped":
                    counts["authorization_skips"] += 1
                elif result["kind"] == "cancelled":
                    counts["cancelled_targets"] += 1
                else:
                    if result["authorization_denied"]:
                        counts["authorization_skips"] += 1
                    counts["persisted_results"] += int(result["persisted"] > 0)
                    outcome = result["outcome"]
                    if outcome == "RESPONDED":
                        counts["completed_observations"] += 1
                    elif outcome == HTTP_NO_RESPONSE:
                        counts["http_no_response"] += 1
                    if result["incomplete"]:
                        counts["failed_incomplete"] += 1
                    if result.get("stop_reason"):
                        counts["unresolved_redirects"] += 1
                report_progress()

        if cancel_event.is_set() and not internal_failure:
            interrupted = interrupted or not errors
        if errors:
            stop_dispatch = True
    except KeyboardInterrupt:
        interrupted = True
        cancel_event.set()
        for future in futures:
            future.cancel()
    finally:
        # On operator interruption the existing orchestrator terminates the
        # stage process group after its bounded grace period. Do not block the
        # signal path on network work; callbacks also refuse subsequent hops.
        executor.shutdown(wait=not interrupted, cancel_futures=True)

    if interrupted:
        counts["cancelled_targets"] += max(0, len(targets) - submitted)

    report_progress(force=True)

    summary = {
        "scan_id": target_scan_id,
        "selected": len(targets),
        **counts,
        "elapsed_seconds": round(time.monotonic() - started, 4),
        "maximum_observed_concurrency": active_state["maximum"],
        "configured_workers": worker_count,
        "interrupted": interrupted,
    }
    logger.info("http_stage_summary %s", json.dumps(summary, separators=(",", ":")))

    if interrupted:
        raise ObservationInterrupted("HTTP observation stage interrupted")
    if errors:
        domain_id, error = errors[0]
        raise ObservationStageError(
            f"HTTP observation worker failed for domain_id={domain_id}: "
            f"{type(error).__name__}"
        ) from error
    if counts["worker_errors"]:
        raise ObservationStageError("HTTP observation workers failed")
    return summary


def _select_targets(target_scan_id):
    conn = get_conn()
    try:
        cur = conn.cursor()
        require_running_scan(cur, target_scan_id)
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
        """, (target_scan_id,))
        rows = cur.fetchall()
        conn.commit()
        return rows
    finally:
        conn.close()


def main():
    cancel_event = CancellationGate()
    previous_handlers = {}

    def request_cancel(_signum, _frame):
        cancel_event.set()

    if threading.current_thread() is threading.main_thread():
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, request_cancel)
    started = time.monotonic()
    try:
        rows = _select_targets(scan_id)
        summary = run_observations(rows, scan_id, cancel_event=cancel_event)
        print(
            "HTTP/TLS observation complete. "
            f"Updated: {summary['persisted_results']}"
        )
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        logger.debug("HTTP/TLS worker elapsed %.4fs", time.monotonic() - started)


if __name__ == "__main__":
    main()
