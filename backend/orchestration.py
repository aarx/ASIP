import subprocess
import argparse
import json
import hashlib
import pathlib
from datetime import datetime
import time
import logging
import os
import selectors
import signal
import socket
import sys
import threading
import uuid
import config
from db import get_conn
from authorization_policy import (
    DEFAULT_SCAN_OPERATIONS_ENV,
    configured_scan_operations,
    default_operation_enabled,
    normalize_dns_security_target_ids,
)
from brand_redirect_intelligence import optional_pipeline_stage
from worker_outcome import RETRYABLE_INCOMPLETE_EXIT_CODE
from scan_diagnostics import (
    MAX_RECOVERY_ATTEMPTS,
    MAX_STAGE_ATTEMPTS as MAX_DIAGNOSTIC_ATTEMPTS,
    _as_document,
    extract_worker_summary,
    finish_stage_attempt,
    start_stage_attempt,
    update_stage_progress,
)
from stage_progress import progress_payload

ASIP_ORCHESTRATION_LOCK_ID = 0x41534950
MAX_STAGE_ATTEMPTS = 2
CHILD_TERMINATE_GRACE_SECONDS = 5
OVERLAP_SKIP_EXIT_CODE = 0
DEFAULT_RUNNER_HEARTBEAT_INTERVAL_SECONDS = 15
RUNNER_HEARTBEAT_RECOVERY_SECONDS = 60
RUNNER_HEARTBEAT_RETRY_INITIAL_SECONDS = 1
RUNNER_HEARTBEAT_RETRY_MAX_SECONDS = 10
DEFAULT_RUNNER_ORPHAN_GRACE_SECONDS = 120
PROCESS_GROUP_POLL_INTERVAL_SECONDS = 0.05
MAX_STAGE_OUTPUT_CAPTURE_BYTES = 64 * 1024
MAX_STAGE_OUTPUT_LINE_BYTES = 8 * 1024
STAGE_PROGRESS_INTERVAL_SECONDS = 30
STAGE_PROGRESS_LOCK_TIMEOUT = "1s"
STAGE_PROGRESS_STATEMENT_TIMEOUT = "2s"
STAGE_PROGRESS_MARKER = "ASIP_STAGE_PROGRESS "

_ACTIVE_STAGE_PROCESS = None
_ACTIVE_STAGE_DIAGNOSTICS = None
MAX_TOTAL_ATTEMPTS_PER_STAGE = 4
PIPELINE_IDENTITY_VERSION = 1


class StageExecutionError(RuntimeError):
    """A required stage failed."""


class RunnerLeaseError(RuntimeError):
    """The orchestration runner no longer owns its scan lease."""


def _is_transient_heartbeat_error(exc):
    """Recognize connection establishment/loss errors, never SQL failures."""
    if isinstance(exc, (socket.gaierror, TimeoutError, ConnectionError)):
        return True
    message = str(exc).lower()
    connection_markers = (
        "could not translate host name",
        "temporary failure in name resolution",
        "name or service not known",
        "connection refused",
        "connection timed out",
        "connection reset by peer",
        "network is unreachable",
        "no route to host",
        "could not receive data from server",
        "could not connect to server",
        "server closed the connection unexpectedly",
        "ssl syscall error: eof detected",
        "connection already closed",
        "connection is closed",
    )
    return (type(exc).__name__ == "OperationalError"
            and any(marker in message for marker in connection_markers))


def _positive_env_int(name, default):
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return value if value > 0 else default


def runner_heartbeat_interval_seconds():
    return _positive_env_int(
        "ASIP_RUNNER_HEARTBEAT_INTERVAL_SECONDS",
        DEFAULT_RUNNER_HEARTBEAT_INTERVAL_SECONDS,
    )


def runner_orphan_grace_seconds():
    return _positive_env_int(
        "ASIP_RUNNER_ORPHAN_GRACE_SECONDS",
        DEFAULT_RUNNER_ORPHAN_GRACE_SECONDS,
    )

# -------------------------
# LOGGING SETUP
# -------------------------

os.makedirs("logs", exist_ok=True)

def setup_logging(log_file):

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ],
        force=True
    )


def acquire_orchestration_lock():
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT pg_try_advisory_lock(%s)",
            (ASIP_ORCHESTRATION_LOCK_ID,)
        )
        locked = bool(cur.fetchone()[0])
        conn.commit()
    except Exception:
        conn.rollback()
        conn.close()
        raise

    if not locked:
        conn.close()
        return None

    return conn


def release_orchestration_lock(conn):
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT pg_advisory_unlock(%s)",
            (ASIP_ORCHESTRATION_LOCK_ID,)
        )
        cur.fetchone()
        conn.commit()
    finally:
        conn.close()


def recover_orphaned_scans(conn):
    """Fail closed on every RUNNING row until execution is externally contained.

    The advisory lock only proves that no launcher currently owns its
    PostgreSQL session. It cannot prove that a stage process or descendant
    started by a dead launcher has stopped. Lease age is therefore diagnostic
    only; neither fresh nor expired leases authorize automatic recovery.
    """
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, runner_token, heartbeat_at
        FROM scans
        WHERE status = 'RUNNING'
        ORDER BY id
        """
    )
    rows = cur.fetchall()
    # Advisory locks are session-scoped; release the read transaction before
    # the runner starts any long-lived stage or network operation.
    conn.commit()

    if not rows:
        return []

    legacy = [row[0] for row in rows if not row[1] or row[2] is None]
    if legacy:
        raise RuntimeError(
            "Unowned RUNNING scan requires explicit reconciliation: "
            + ",".join(str(scan_id) for scan_id in legacy)
        )

    managed = [row[0] for row in rows]
    raise RuntimeError(
        "RUNNING scan requires operator containment and reconciliation; "
        "lease metadata cannot prove its worker process tree has terminated: "
        + ",".join(str(scan_id) for scan_id in managed)
    )


class RunnerHeartbeat:
    """Refresh a scan lease from a separate short-lived DB connection."""

    def __init__(self, scan_id, runner_token, interval_seconds=None):
        self.scan_id = scan_id
        self.runner_token = runner_token
        self.interval_seconds = interval_seconds or runner_heartbeat_interval_seconds()
        self._stop = threading.Event()
        self._failure = None
        self._thread = threading.Thread(
            target=self._run,
            name=f"asip-scan-heartbeat-{scan_id}",
            daemon=True,
        )

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=max(self.interval_seconds, 1) + 5)

    def ensure_healthy(self):
        if self._failure is not None:
            raise RunnerLeaseError(str(self._failure))

    def _run(self):
        while not self._stop.wait(self.interval_seconds):
            failure_started = time.monotonic()
            retry_delay = RUNNER_HEARTBEAT_RETRY_INITIAL_SECONDS
            had_transient_failure = False
            while not self._stop.is_set():
                conn = None
                try:
                    # Each retry deliberately acquires a fresh connection.
                    conn = get_conn()
                    cur = conn.cursor()
                    cur.execute(
                        """
                        UPDATE scans
                        SET heartbeat_at = NOW()
                        WHERE id = %s
                          AND status = 'RUNNING'
                          AND runner_token = %s
                        """,
                        (self.scan_id, self.runner_token),
                    )
                    if cur.rowcount != 1:
                        raise RunnerLeaseError(
                            f"scan {self.scan_id} runner lease is no longer owned"
                        )
                    conn.commit()
                    if had_transient_failure:
                        logging.info(
                            "scan %s heartbeat recovered after transient database failure",
                            self.scan_id,
                        )
                    break
                except RunnerLeaseError as exc:
                    self._failure = exc
                    self._stop.set()
                except Exception as exc:
                    elapsed = time.monotonic() - failure_started
                    if not _is_transient_heartbeat_error(exc):
                        self._failure = RunnerLeaseError(
                            f"scan {self.scan_id} heartbeat failed: {exc}"
                        )
                        self._stop.set()
                    elif elapsed >= RUNNER_HEARTBEAT_RECOVERY_SECONDS:
                        self._failure = RunnerLeaseError(
                            f"scan {self.scan_id} heartbeat failed after "
                            f"{int(elapsed)}s transient database outage: {exc}"
                        )
                        logging.error("%s", self._failure)
                        self._stop.set()
                    else:
                        had_transient_failure = True
                        logging.warning(
                            "scan %s heartbeat connection failed; retrying in %ss "
                            "(recovery window %ss): %s",
                            self.scan_id, retry_delay,
                            RUNNER_HEARTBEAT_RECOVERY_SECONDS, exc,
                        )
                        if self._stop.wait(min(
                            retry_delay,
                            max(0, RUNNER_HEARTBEAT_RECOVERY_SECONDS - elapsed),
                        )):
                            break
                        retry_delay = min(
                            retry_delay * 2, RUNNER_HEARTBEAT_RETRY_MAX_SECONDS
                        )
                finally:
                    if conn is not None:
                        try:
                            conn.close()
                        except Exception:
                            logging.exception("Failed to close heartbeat connection")
                if self._failure is not None:
                    break

# -------------------------
# CREATE SCAN
# -------------------------
def create_scan(scan_identity=None, dns_security_target_ids=None):
    dns_security_target_ids = normalize_dns_security_target_ids(
        dns_security_target_ids
    )
    runner_token = str(uuid.uuid4())
    conn = get_conn()
    try:
        cur = conn.cursor()
        pipeline_identity_value = (
            scan_identity.get("pipeline_identity")
            if isinstance(scan_identity, dict) else None
        )
        if pipeline_identity_value is not None:
            pipeline_identity_value["seed_domains_sha256"] = _seed_domains_fingerprint(cur)
        if dns_security_target_ids is None:
            # Keep ordinary scans compatible with schemas before migration
            # 012. Only an explicit run-scoped invocation needs this column.
            cur.execute("""
            INSERT INTO scans(
                started_at, completed_at, status,
                runner_token, heartbeat_at, failure_reason, stage_diagnostics
            )
            VALUES (
                NOW(), NULL, 'RUNNING', %s, NOW(), NULL,
                jsonb_build_object(
                    'version', 1,
                    'pipeline_identity', NULL,
                    'current_stage', NULL,
                    'attempts', '[]'::jsonb,
                    'recovery_history', '[]'::jsonb,
                    'scan_outcome', NULL,
                    'last_updated_at', NOW()
                )
            )
            RETURNING id
            """, (runner_token,))
        else:
            cur.execute("""
            INSERT INTO scans(
                started_at, completed_at, status,
                runner_token, heartbeat_at, failure_reason, stage_diagnostics,
                dns_security_target_ids
            )
            VALUES (
                NOW(), NULL, 'RUNNING', %s, NOW(), NULL,
                jsonb_build_object(
                    'version', 1,
                    'pipeline_identity', NULL,
                    'current_stage', NULL,
                    'attempts', '[]'::jsonb,
                    'recovery_history', '[]'::jsonb,
                    'scan_outcome', NULL,
                    'last_updated_at', NOW()
                ), %s
            )
            RETURNING id
            """, (runner_token, list(dns_security_target_ids)))
        scan_id = cur.fetchone()[0]
        if scan_identity is not None:
            # Retain the exact owned row before commit. If commit is interrupted
            # after reaching PostgreSQL, the caller can safely address this ID
            # without guessing from global RUNNING state.
            scan_identity["scan_id"] = scan_id
            scan_identity["runner_token"] = runner_token
        if pipeline_identity_value is not None:
            cur.execute(
                "UPDATE scans SET stage_diagnostics = "
                "jsonb_set(stage_diagnostics, '{pipeline_identity}', %s::jsonb) "
                "WHERE id = %s AND status = 'RUNNING' AND runner_token = %s",
                (json.dumps(pipeline_identity_value, sort_keys=True), scan_id, runner_token),
            )
            if cur.rowcount != 1:
                raise RuntimeError("could not persist scan pipeline identity")
        conn.commit()
        return scan_id
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def mark_scan_terminal(scan_id, status, failure_reason=None, runner_token=None):
    if status not in {"SUCCEEDED", "FAILED"}:
        raise ValueError(f"Invalid terminal scan status: {status}")

    conn = get_conn()
    try:
        cur = conn.cursor()
        query = """
        UPDATE scans
        SET status = %s,
            completed_at = NOW(),
            heartbeat_at = NOW(),
            failure_reason = %s
        WHERE id = %s
        AND status = 'RUNNING'
        """
        params = [status, failure_reason]
        if runner_token is not None:
            category = (
                "INTERRUPTED" if failure_reason == "INTERRUPTED"
                else "SCAN_FAILED" if status == "FAILED" else None
            )
            query = query.replace(
                "failure_reason = %s",
                "failure_reason = %s,\n            stage_diagnostics = "
                "COALESCE(stage_diagnostics, jsonb_build_object("
                "'version', 1, 'current_stage', NULL, 'attempts', '[]'::jsonb, "
                "'scan_outcome', NULL)) || jsonb_build_object("
                "'version', 1, 'current_stage', NULL, "
                "'scan_outcome', jsonb_build_object("
                "'status', %s, 'completed_at', NOW(), 'error_category', %s), "
                "'last_updated_at', NOW())"
            )
            params.extend([status, category])
        params.append(scan_id)
        if runner_token is not None:
            query += " AND runner_token = %s"
            params.append(runner_token)
        query += " RETURNING id"
        cur.execute(query, tuple(params))

        if cur.fetchone() is None:
            raise RuntimeError(
                f"Scan {scan_id} did not transition from RUNNING to {status}"
            )

        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

# -------------------------
# RUN STEP
# -------------------------
def stop_active_child(process):
    """Terminate the whole stage group, then escalate and reap the leader."""
    process_group_id = process.pid
    try:
        os.killpg(process_group_id, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except OSError:
        logging.exception("Child cleanup could not signal the process group")
        try:
            process.terminate()
        except ProcessLookupError:
            pass
        except Exception:
            logging.exception("Child cleanup fallback terminate failed")

    deadline = time.monotonic() + CHILD_TERMINATE_GRACE_SECONDS
    while time.monotonic() < deadline:
        try:
            os.killpg(process_group_id, 0)
        except ProcessLookupError:
            break
        except OSError:
            # If existence cannot be established, continue to the bounded
            # SIGKILL attempt rather than assuming descendants are gone.
            break
        try:
            process.poll()
        except Exception:
            logging.exception("Child cleanup could not poll the stage leader")
        time.sleep(PROCESS_GROUP_POLL_INTERVAL_SECONDS)

    else:
        logging.warning("Stage process group persisted after SIGTERM; escalating")


    try:
        os.killpg(process_group_id, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        logging.exception("Child cleanup could not kill the process group")
        try:
            if process.poll() is None:
                process.kill()
        except ProcessLookupError:
            pass
        except Exception:
            logging.exception("Child cleanup fallback kill failed")

    try:
        process.wait(timeout=CHILD_TERMINATE_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        logging.error("Child cleanup timed out while reaping after SIGKILL")
        try:
            process.wait(timeout=CHILD_TERMINATE_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            logging.error("Child leader remains unreaped after bounded SIGKILL wait")
        except Exception:
            logging.exception("Child cleanup final reap failed")
    except Exception:
        logging.exception("Child cleanup final reap failed")

    deadline = time.monotonic() + CHILD_TERMINATE_GRACE_SECONDS
    while True:
        try:
            os.killpg(process_group_id, 0)
        except ProcessLookupError:
            return
        except OSError:
            # Permission/inspection failures do not prove the group is gone.
            pass
        if time.monotonic() >= deadline:
            raise RuntimeError(
                "could not prove the failed stage process group has terminated"
            )
        time.sleep(PROCESS_GROUP_POLL_INTERVAL_SECONDS)


def _child_is_running(process):
    poll = getattr(process, "poll", None)
    return not callable(poll) or poll() is None


def _diagnostics_start(scan_id, runner_token, name, stage_order, attempt,
                       execution_mode="FULL", runner_id=None, required=False):
    if scan_id is None or runner_token is None or stage_order is None:
        return
    conn = None
    try:
        conn = get_conn()
        updated = start_stage_attempt(
            conn, scan_id, runner_token, name, stage_order, attempt,
            execution_mode, runner_id,
        )
        if not updated:
            raise RunnerLeaseError(
                f"scan {scan_id} is no longer RUNNING under this runner token"
            )
    except RunnerLeaseError:
        raise
    except Exception:
        if required:
            raise
        logging.exception(
            "Scan diagnostics START persistence failed for scan=%s stage=%s; "
            "continuing with the existing stage execution policy",
            scan_id, name,
        )
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                logging.exception("Failed to close diagnostics connection")


def _diagnostics_finish(scan_id, runner_token, name, stage_order, attempt,
                        status, duration, error_category=None, summary=None,
                        required=False, exit_code=None):
    summary = summary or {}
    selected = summary.get("selected", summary.get("selected_parent_targets"))
    processed = next((summary[key] for key in (
        "completed", "completed_parent_targets", "completed_observations",
        "persisted_results",
    ) if isinstance(summary.get(key), int)), None)
    completion_progress = progress_payload(
        scan_id or 0, name, status=status, selected=selected, total=selected,
        processed=processed, completed=summary.get("completed", processed),
        succeeded=summary.get("completed", processed),
        failed=summary.get("worker_errors", summary.get("failed_targets", 0)),
        skipped=summary.get("authorization_skips", 0),
        elapsed_seconds=duration,
    )
    logging.info(
        "%s%s", STAGE_PROGRESS_MARKER,
        json.dumps(completion_progress, separators=(",", ":")),
    )
    if scan_id is None or runner_token is None or stage_order is None:
        return
    conn = None
    try:
        conn = get_conn()
        updated = finish_stage_attempt(
            conn, scan_id, runner_token, name, stage_order, attempt,
            status, duration, error_category, summary,
            exit_code,
        )
        if not updated:
            message = (
                "Scan diagnostics outcome was not persisted for scan=%s stage=%s "
                "attempt=%s; stage execution outcome is unchanged"
            )
            if required:
                raise RunnerLeaseError(message % (scan_id, name, attempt))
            logging.warning(message, scan_id, name, attempt)
    except Exception:
        if required:
            raise
        logging.exception(
            "Scan diagnostics outcome persistence failed for scan=%s stage=%s; "
            "stage execution outcome is unchanged",
            scan_id, name,
        )
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                logging.exception("Failed to close diagnostics connection")


def _diagnostics_progress(scan_id, runner_token, name, stage_order, attempt,
                          progress):
    if scan_id is None or runner_token is None or stage_order is None:
        return
    conn = None
    try:
        conn = get_conn()
        # Progress is best-effort. Bound both row-lock waits and total query
        # time so a diagnostics lock cannot stop the stdout pipe reader.
        cur = conn.cursor()
        cur.execute(
            f"SET LOCAL lock_timeout = '{STAGE_PROGRESS_LOCK_TIMEOUT}'"
        )
        cur.execute(
            f"SET LOCAL statement_timeout = '{STAGE_PROGRESS_STATEMENT_TIMEOUT}'"
        )
        update_stage_progress(
            conn, scan_id, runner_token, name, stage_order, attempt, progress
        )
    except Exception as exc:
        logging.warning(
            "Scan progress update failed for scan=%s stage=%s (%s)",
            scan_id, name, type(exc).__name__,
        )
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                logging.warning("Failed to close scan progress connection")


def _append_bounded_output(output, chunk):
    output.extend(chunk)
    overflow = len(output) - MAX_STAGE_OUTPUT_CAPTURE_BYTES
    if overflow > 0:
        del output[:overflow]


def _log_stage_chunk(name, line):
    logging.info(f"[{name}] {line.decode('utf-8', errors='replace')}")


def _stream_stage_output(process, name, progress_callback=None,
                         progress_interval=STAGE_PROGRESS_INTERVAL_SECONDS):
    """Forward merged child output until exit, retaining only a bounded tail."""
    stdout = process.stdout
    try:
        file_descriptor = stdout.fileno()
    except (AttributeError, OSError, ValueError):
        # Compatibility for test doubles and non-file-backed process adapters.
        output, _ = process.communicate()
        output = output or ""
        for line in output.splitlines():
            logging.info("[%s] %s", name, line.strip())
        return output.encode("utf-8", errors="replace")[-MAX_STAGE_OUTPUT_CAPTURE_BYTES:]

    captured = bytearray()
    pending = bytearray()
    started = time.monotonic()
    next_progress = started + progress_interval

    def record_progress(progress):
        nonlocal next_progress
        if progress_callback is not None:
            try:
                progress_callback(progress)
            except Exception:
                # Progress is a display aid and must never interrupt a worker.
                logging.exception("Noncritical stage progress callback failed")
        next_progress = time.monotonic() + progress_interval

    selector = selectors.DefaultSelector()
    selector.register(stdout, selectors.EVENT_READ)
    try:
        while True:
            events = selector.select(max(0, next_progress - time.monotonic()))
            if not events:
                record_progress({
                    "status": "RUNNING",
                    "elapsed_seconds": max(0, time.monotonic() - started),
                })
                continue
            chunk = os.read(file_descriptor, 4096)
            if not chunk:
                _flush_stage_output(
                    name, pending, final=True, progress_callback=record_progress
                )
                break
            _append_bounded_output(captured, chunk)
            pending.extend(chunk)
            _flush_stage_output(
                name, pending, progress_callback=record_progress
            )
            if time.monotonic() >= next_progress:
                record_progress({
                    "status": "RUNNING",
                    "elapsed_seconds": max(0, time.monotonic() - started),
                })

        process.wait()
        return bytes(captured)
    finally:
        selector.close()


def _flush_stage_output(name, pending, final=False, progress_callback=None):
    """Log complete lines and bounded fragments without retaining huge lines."""
    while pending:
        newline = pending.find(b"\n")
        if newline >= 0 and newline < MAX_STAGE_OUTPUT_LINE_BYTES:
            line = bytes(pending[:newline]).rstrip(b"\r")
            del pending[:newline + 1]
            if progress_callback is not None:
                _parse_stage_progress(line, progress_callback)
            _log_stage_chunk(name, line)
        elif len(pending) >= MAX_STAGE_OUTPUT_LINE_BYTES:
            line = bytes(pending[:MAX_STAGE_OUTPUT_LINE_BYTES])
            del pending[:MAX_STAGE_OUTPUT_LINE_BYTES]
            if progress_callback is not None:
                _parse_stage_progress(line, progress_callback)
            _log_stage_chunk(name, line)
        elif final:
            line = bytes(pending).rstrip(b"\r")
            if progress_callback is not None:
                _parse_stage_progress(line, progress_callback)
            _log_stage_chunk(name, line)
            pending.clear()
        else:
            return


def _parse_stage_progress(line, progress_callback):
    text = line.decode("utf-8", errors="replace").strip()
    position = text.find(STAGE_PROGRESS_MARKER)
    if position < 0:
        return
    try:
        progress = json.loads(text[position + len(STAGE_PROGRESS_MARKER):])
    except (TypeError, ValueError):
        return
    if isinstance(progress, dict):
        progress_callback(progress)


def run_step(name, cmd, attempt, max_attempts, scan_id=None,
             runner_token=None, stage_order=None, execution_mode="FULL",
             runner_id=None, diagnostics_required=False):

    if scan_id is None and runner_token is None and stage_order is None:
        context = _ACTIVE_STAGE_DIAGNOSTICS
        if context is not None:
            scan_id, runner_token, stage_order = context[:3]
            if len(context) > 3:
                execution_mode, runner_id = context[3:5]
                diagnostics_required = execution_mode != "FULL"

    logging.info("=" * 60)
    logging.info(f"STARTING: {name} attempt {attempt}/{max_attempts}")
    logging.info(f"Command: {cmd}")

    _diagnostics_start(
        scan_id, runner_token, name, stage_order, attempt,
        execution_mode, runner_id, diagnostics_required,
    )
    start = time.time()
    monotonic_start = time.monotonic()
    global _ACTIVE_STAGE_PROCESS
    process = None

    try:
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True
        )
        _ACTIVE_STAGE_PROCESS = process

        def progress_update(snapshot):
            if "scan_id" in snapshot and snapshot.get("scan_id") != scan_id:
                return
            if "stage" in snapshot and snapshot.get("stage") != name:
                return
            progress = dict(snapshot)
            progress.pop("scan_id", None)
            progress.pop("stage", None)
            progress.setdefault(
                "elapsed_seconds", time.monotonic() - monotonic_start
            )
            _diagnostics_progress(
                scan_id, runner_token, name, stage_order, attempt, progress
            )

        captured_output = _stream_stage_output(
            process, name, progress_callback=progress_update
        )

        output = captured_output.decode("utf-8", errors="replace")

        returncode = process.returncode

        duration = round(time.time() - start, 2)
        if returncode == 0:
            diag_status, error_category = "SUCCEEDED", None
        elif returncode == RETRYABLE_INCOMPLETE_EXIT_CODE:
            diag_status, error_category = "FAILED", "RETRYABLE_INCOMPLETE"
        else:
            diag_status, error_category = "FAILED", "NONZERO_EXIT"
        _diagnostics_finish(
            scan_id, runner_token, name, stage_order, attempt,
            diag_status, time.monotonic() - monotonic_start,
            error_category, extract_worker_summary(output), diagnostics_required,
            returncode,
        )

        if returncode == 0:
            logging.info(
                f"COMPLETED: {name} attempt {attempt}/{max_attempts} "
                f"({duration}s)"
            )
        elif returncode == RETRYABLE_INCOMPLETE_EXIT_CODE:
            logging.warning(
                f"RETRYABLE INCOMPLETE: {name} attempt {attempt}/{max_attempts} "
                f"exit={returncode} ({duration}s)"
            )
        else:
            logging.error(
                f"FAILED: {name} attempt {attempt}/{max_attempts} "
                f"exit={returncode} ({duration}s)"
            )

        return returncode

    except KeyboardInterrupt:
        if process is not None and _child_is_running(process):
            stop_active_child(process)
        _diagnostics_finish(
            scan_id, runner_token, name, stage_order, attempt,
            "CANCELLED", time.monotonic() - monotonic_start, "INTERRUPTED",
            required=diagnostics_required,
        )
        logging.error(f"INTERRUPTED: {name} attempt {attempt}/{max_attempts}")
        raise
    except Exception:
        if process is not None and _child_is_running(process):
            stop_active_child(process)
        _diagnostics_finish(
            scan_id, runner_token, name, stage_order, attempt,
            "FAILED", time.monotonic() - monotonic_start,
            "STAGE_LAUNCH_ERROR" if process is None else "STAGE_RUNNER_ERROR",
            required=diagnostics_required,
        )
        logging.exception(f"ERROR in step: {name} attempt {attempt}/{max_attempts}")
        raise
    finally:
        if _ACTIVE_STAGE_PROCESS is process:
            _ACTIVE_STAGE_PROCESS = None
        try:
            stdout = getattr(process, "stdout", None) if process is not None else None
            if stdout is not None and hasattr(stdout, "close"):
                stdout.close()
        except Exception:
            logging.exception("Failed to close child stdout stream")


def run_required_stage(name, cmd, *, scan_id=None, runner_token=None,
                       stage_order=None, start_attempt=1,
                       max_attempts=MAX_STAGE_ATTEMPTS,
                       execution_mode="FULL", runner_id=None):
    for attempt in range(start_attempt, max_attempts + 1):
        returncode = run_step(
            name, cmd, attempt, max_attempts, scan_id, runner_token,
            stage_order, execution_mode, runner_id,
            execution_mode != "FULL",
        )

        if returncode == 0:
            return

        if (
            returncode == RETRYABLE_INCOMPLETE_EXIT_CODE
            and attempt < max_attempts
        ):
            logging.warning(
                f"RETRYING: {name} after attempt {attempt}/{max_attempts}"
            )
            continue

        raise StageExecutionError(f"{name} failed with exit code {returncode}")


def mark_interrupted_scan_failed(scan_id, runner_token=None):
    """Best-effort guarded failure transition while preserving interruption."""
    logging.error(f"PIPELINE INTERRUPTED for scan_id={scan_id}")
    try:
        if runner_token is None:
            mark_scan_terminal(scan_id, "FAILED")
        else:
            mark_scan_terminal(
                scan_id,
                "FAILED",
                failure_reason="INTERRUPTED",
                runner_token=runner_token,
            )
    except Exception:
        logging.exception("Failed to persist FAILED scan status after interrupt")


def build_pipeline(scan_id, dns_security_target_ids=None):
    """Return the one ordered stage list used by full scans and recovery."""
    pipeline = [
        ("Recon", f"python -u recon.py --scan-id {scan_id} --expand seeds.txt"),
        ("Ingest", f"python -u ingest.py {scan_id}"),
        ("Automatic Eligibility", f"python -u eligibility_worker.py {scan_id}"),
        ("SAN Expansion", f"python -u san_worker.py {scan_id}"),
        ("SAN State Sync", f"python -u san_state_sync.py {scan_id}"),
        ("Automatic Eligibility", f"python -u eligibility_worker.py {scan_id}"),
        ("DNS Resolution", f"python -u dns_worker.py {scan_id}"),
        ("HTTP/TLS Observation", f"python -u http_observation_worker.py {scan_id}"),
        ("Cert Worker", f"python -u cert_worker.py {scan_id}"),
        ("Port Scan", f"python -u port_scan_worker.py {scan_id}"),
        ("Tech Detection", f"python -u tech_worker.py {scan_id}"),
        ("ASN Lookup", f"python -u asn_worker.py {scan_id}"),
        ("Provider Mapping", f"python -u provider_worker.py {scan_id}"),
        ("Takeover Detection", f"python -u takeover_worker.py {scan_id}"),
        ("Discovery Validator", f"python -u discovery_validator.py {scan_id}"),
        ("Risk Scoring", f"python -u risk_worker.py {scan_id}"),
    ]
    brand_stage = optional_pipeline_stage(scan_id)
    if brand_stage:
        insertion = next(i for i, item in enumerate(pipeline)
                         if item[0] == "HTTP/TLS Observation") + 1
        pipeline.insert(insertion, brand_stage)

    if default_operation_enabled("DNS_SECURITY"):
        run_scoped = bool(dns_security_target_ids)
        dns_stage = (
            "DNS Security",
            f"python -u dns_security_worker.py {scan_id}"
            f"{' --run-scoped' if run_scoped else ''}",
        )
        insertion = next(i for i, item in enumerate(pipeline)
                         if item[0] == "HTTP/TLS Observation")
        pipeline.insert(insertion, dns_stage)
    return pipeline


def _pipeline_source_fingerprint():
    """Conservatively bind checkpoints to backend Python source in this image."""
    backend_dir = pathlib.Path(__file__).resolve().parent
    digest = hashlib.sha256()
    for path in sorted(backend_dir.glob("*.py"), key=lambda item: item.name):
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    for path in (
        backend_dir / "requirements.txt",
        backend_dir / "seeds.txt",
        backend_dir / "known_domains.csv",
    ):
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes() if path.is_file() else b"<missing>")
        digest.update(b"\0")
    return digest.hexdigest()


def _seed_domains_fingerprint(cur):
    cur.execute("SELECT domain FROM seed_domains ORDER BY domain")
    serialized = json.dumps(
        [str(row[0]).strip().lower().rstrip(".") for row in cur.fetchall()],
        ensure_ascii=True, separators=(",", ":"),
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def pipeline_identity(pipeline, scan_id, dns_security_target_ids=None):
    """Compact deterministic identity; never stores credentials or secrets."""
    secret_config_hashes = {
        name: hashlib.sha256(str(getattr(config, name, "")).encode("utf-8")).hexdigest()
        for name in ("CERTSPOTTER_API_KEY",)
    }
    policy_settings = {
        name: os.environ.get(name)
        for name in (
            DEFAULT_SCAN_OPERATIONS_ENV,
            "ASIP_SAN_WORKERS",
            "ASIP_HTTP_WORKERS",
            "ASIP_NMAP_WORKERS",
            "ASIP_MAX_REDIRECT_HOPS",
        )
    }
    runtime_config = {
        "database": {
            "host": config.DB_HOST,
            "name": config.DB_NAME,
            "user": config.DB_USER,
        },
        "secret_config_sha256": secret_config_hashes,
    }
    stages = [
        {"order": order, "name": name,
         "command": command.replace(str(scan_id), "{scan_id}")}
        for order, (name, command) in enumerate(pipeline)
    ]
    return {
        "version": PIPELINE_IDENTITY_VERSION,
        "stages": stages,
        "source_sha256": _pipeline_source_fingerprint(),
        "policy_settings": policy_settings,
        "runtime_config": runtime_config,
        "dns_security_target_ids": (
            list(dns_security_target_ids)
            if dns_security_target_ids is not None else None
        ),
    }


def validate_resume_checkpoint(document, pipeline):
    """Return the first stage not proven successful, rejecting ambiguity."""
    if not isinstance(document, dict):
        raise RuntimeError("scan diagnostics are unavailable; refusing recovery")
    attempts = document.get("attempts")
    if not isinstance(attempts, list) or len(attempts) > MAX_DIAGNOSTIC_ATTEMPTS:
        raise RuntimeError("scan stage history is invalid or full; refusing recovery")
    index = 0
    used = {}
    observed_orders = []
    for record in attempts:
        if not isinstance(record, dict):
            raise RuntimeError("scan stage history is ambiguous; refusing recovery")
        order = record.get("order")
        if not isinstance(order, int) or order < 0 or order >= len(pipeline):
            raise RuntimeError("scan stage history does not match pipeline")
        name = record.get("stage")
        if name != pipeline[order][0]:
            raise RuntimeError("scan stage history does not match pipeline")
        used.setdefault(order, []).append(record)
        observed_orders.append(order)
    if observed_orders != sorted(observed_orders):
        raise RuntimeError("scan stage history is out of order")

    for order in range(len(pipeline)):
        records = used.get(order, [])
        if not records:
            index = order
            if any(later > order for later in used):
                raise RuntimeError("successful stages are not a contiguous prefix")
            break
        numbers = [item.get("attempt") for item in records]
        if (any(not isinstance(number, int) or number < 1 for number in numbers)
                or numbers != list(range(1, len(numbers) + 1))):
            raise RuntimeError("stage attempt history is inconsistent")
        statuses = [item.get("status") for item in records]
        if any(status not in {"SUCCEEDED", "FAILED", "CANCELLED", "TIMED_OUT"}
               for status in statuses):
            raise RuntimeError("stage outcome is incomplete; refusing recovery")
        if "SUCCEEDED" in statuses[:-1]:
            raise RuntimeError("a completed stage was rerun; refusing recovery")
        if statuses[-1] != "SUCCEEDED":
            index = order
            if any(later > order for later in used):
                raise RuntimeError("downstream stage evidence exists after a failure")
            break
        index = order + 1
    if len(attempts) >= MAX_DIAGNOSTIC_ATTEMPTS:
        raise RuntimeError("scan stage history is full; refusing recovery")
    if index < len(pipeline) and len(used.get(index, [])) >= MAX_TOTAL_ATTEMPTS_PER_STAGE:
        raise RuntimeError("stage attempt limit reached; refusing recovery")
    return index, {order: len(records) for order, records in used.items()}


def validate_recovery_replay_safety(cur, scan_id, document, pipeline,
                                    next_order, mode,
                                    recovery_history_was_persisted):
    """Allow BRI only when ordered evidence proves this scan never reached it."""
    if mode == "RESUME":
        replay_orders = range(next_order, len(pipeline))
    elif mode == "SINGLE_FAILED_STAGE":
        replay_orders = range(next_order, min(next_order + 1, len(pipeline)))
    else:
        raise ValueError("invalid recovery mode")

    brand_order = next((order for order, (name, _command) in enumerate(pipeline)
                        if name == "Brand Redirect Intelligence"), None)
    if brand_order is None or brand_order not in replay_orders:
        return

    def refuse():
        raise RuntimeError(
            "cannot prove Brand Redirect Intelligence is a first execution; "
            "replay could duplicate persisted observations; refusing recovery"
        )

    attempts = document.get("attempts")
    if not isinstance(attempts, list):
        refuse()
    if any(
        isinstance(item, dict) and item.get("order") == brand_order
        for item in attempts
    ):
        refuse()

    # Observation rows are positive evidence of a prior operation. Their
    # absence is not enough: first execution also requires an explicit failed
    # stage before BRI and no earlier recovery, proving sequential orchestration
    # could not have reached BRI in a prior attempt.
    cur.execute(
        "SELECT EXISTS (SELECT 1 FROM brand_redirect_observations WHERE scan_id = %s)",
        (scan_id,),
    )
    observation_row = cur.fetchone()
    if not observation_row or bool(observation_row[0]):
        refuse()

    recovery_history = document.get("recovery_history")
    if (not recovery_history_was_persisted
            or not isinstance(recovery_history, list) or recovery_history):
        refuse()

    failed_stage_attempts = [
        item for item in attempts
        if isinstance(item, dict)
        and item.get("order") == next_order
        and item.get("stage") == pipeline[next_order][0]
        and item.get("status") in {"FAILED", "TIMED_OUT", "CANCELLED"}
    ] if next_order < brand_order else []
    if not failed_stage_attempts:
        refuse()


def _identity_without_source(identity):
    if not isinstance(identity, dict):
        return None
    return {key: value for key, value in identity.items() if key != "source_sha256"}


def authorize_reviewed_source_transition(scan_id, expected_old_source,
                                         expected_new_source):
    """Record the explicit, scan-36-only reliability source transition."""
    if scan_id != 36:
        raise RuntimeError("reviewed source transition is restricted to scan 36")
    for value in (expected_old_source, expected_new_source):
        if (not isinstance(value, str) or len(value) != 64
                or any(char not in "0123456789abcdef" for char in value)):
            raise RuntimeError("expected source fingerprints must be lowercase SHA-256")
    if expected_old_source == expected_new_source:
        raise RuntimeError("source transition fingerprints must be different")

    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """SELECT status, runner_token, stage_diagnostics,
                      dns_security_target_ids
                 FROM scans WHERE id = %s FOR UPDATE""",
            (scan_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise RuntimeError(f"scan {scan_id} does not exist")
        status, runner_token, raw_document, target_ids = row
        if status != "FAILED" or not runner_token:
            raise RuntimeError("scan 36 must be FAILED with prior runner ownership")
        document = _as_document(raw_document)
        if document.get("recovery_history"):
            raise RuntimeError("scan already has recovery attempts; refusing transition")
        if document.get("compatibility_transitions"):
            raise RuntimeError("scan already has a source transition; refusing replacement")

        target_ids = normalize_dns_security_target_ids(target_ids)
        pipeline = build_pipeline(scan_id, target_ids)
        current_identity = pipeline_identity(pipeline, scan_id, target_ids)
        current_identity["seed_domains_sha256"] = _seed_domains_fingerprint(cur)
        old_identity = document.get("pipeline_identity")
        if not isinstance(old_identity, dict):
            raise RuntimeError("stored pipeline identity is missing; refusing transition")
        if old_identity.get("source_sha256") != expected_old_source:
            raise RuntimeError("stored source fingerprint does not match reviewed old source")
        if current_identity.get("source_sha256") != expected_new_source:
            raise RuntimeError("running source fingerprint does not match reviewed new source")
        if _identity_without_source(old_identity) != _identity_without_source(current_identity):
            raise RuntimeError(
                "pipeline, scope, seed, policy, or runtime configuration changed; "
                "refusing source transition"
            )

        next_order, _attempt_counts = validate_resume_checkpoint(document, pipeline)
        if (next_order != 15 or len(pipeline) <= 15
                or pipeline[15][0] != "Takeover Detection"):
            raise RuntimeError(
                "scan 36 checkpoints do not prove stages 0-14 succeeded "
                "and Takeover Detection is next"
            )
        if not any(
            item.get("order") == 15
            and item.get("stage") == "Takeover Detection"
            and item.get("status") in {"FAILED", "CANCELLED", "TIMED_OUT"}
            for item in document.get("attempts", []) if isinstance(item, dict)
        ):
            raise RuntimeError("Takeover Detection failure evidence is missing")

        transition_id = str(uuid.uuid4())
        transition = {
            "transition_id": transition_id,
            "scan_id": 36,
            "type": "reviewed_reliability_only_source_change",
            "authorized_at": datetime.now().astimezone().isoformat(),
            "old_identity": old_identity,
            "new_identity": current_identity,
            "checkpoint_next_order": next_order,
        }
        document["compatibility_transitions"] = [transition]
        cur.execute(
            """UPDATE scans SET stage_diagnostics = %s::jsonb
                WHERE id = %s AND status = 'FAILED' AND runner_token = %s""",
            (json.dumps(document, separators=(",", ":")), scan_id, runner_token),
        )
        if cur.rowcount != 1:
            raise RuntimeError("scan ownership changed; refusing source transition")
        conn.commit()
        logging.warning(
            "Recorded reviewed source compatibility transition scan_id=%s "
            "transition_id=%s old_source=%s new_source=%s",
            scan_id, transition_id, expected_old_source, expected_new_source,
        )
        return transition_id
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _matching_reviewed_transition(scan_id, document, old_identity, new_identity):
    if scan_id != 36:
        return None
    transitions = document.get("compatibility_transitions")
    if not isinstance(transitions, list) or len(transitions) != 1:
        return None
    transition = transitions[0]
    if not isinstance(transition, dict):
        return None
    transition_old = transition.get("old_identity")
    transition_new = transition.get("new_identity")
    if not isinstance(transition_old, dict) or not isinstance(transition_new, dict):
        return None
    if (transition.get("scan_id") != 36
            or transition.get("type") != "reviewed_reliability_only_source_change"
            or not transition.get("transition_id")
            or transition_old.get("source_sha256") == transition_new.get("source_sha256")
            or transition.get("checkpoint_next_order") != 15
            or transition_old != old_identity
            or transition_new != new_identity
            or _identity_without_source(old_identity)
            != _identity_without_source(new_identity)):
        return None
    return transition


def begin_recovery(scan_id, mode):
    """Atomically claim a FAILED scan after validating its exact pipeline."""
    if mode not in {"RESUME", "SINGLE_FAILED_STAGE"}:
        raise ValueError("invalid recovery mode")
    conn = get_conn()
    new_token = str(uuid.uuid4())
    runner_id = str(uuid.uuid4())
    try:
        cur = conn.cursor()
        cur.execute(
            """SELECT status, runner_token, completed_at, failure_reason,
                       stage_diagnostics, dns_security_target_ids
                 FROM scans WHERE id = %s FOR UPDATE""",
            (scan_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise RuntimeError(f"scan {scan_id} does not exist")
        status, old_token, completed_at, failure_reason, document, target_ids = row
        if status != "FAILED":
            raise RuntimeError(f"scan {scan_id} is {status}; only FAILED scans can recover")
        if not old_token:
            raise RuntimeError("scan has no prior runner ownership record")
        if document is None:
            raise RuntimeError("scan diagnostics are unavailable; refusing recovery")
        raw_document = document
        if isinstance(raw_document, str):
            try:
                raw_document = json.loads(raw_document)
            except (TypeError, ValueError):
                raw_document = None
        recovery_history_was_persisted = (
            isinstance(raw_document, dict)
            and isinstance(raw_document.get("recovery_history"), list)
        )
        document = _as_document(document)
        target_ids = normalize_dns_security_target_ids(target_ids)
        pipeline = build_pipeline(scan_id, target_ids)
        expected_identity = pipeline_identity(pipeline, scan_id, target_ids)
        expected_identity["seed_domains_sha256"] = _seed_domains_fingerprint(cur)
        stored_identity = document.get("pipeline_identity")
        transition = None
        if stored_identity != expected_identity:
            transition = _matching_reviewed_transition(
                scan_id, document, stored_identity, expected_identity
            )
        if stored_identity != expected_identity and transition is None:
            raise RuntimeError(
                "scan pipeline or seed configuration is missing or incompatible; "
                "refusing recovery"
            )
        next_order, previous_attempt_counts = validate_resume_checkpoint(
            document, pipeline
        )
        if transition and (
            next_order != transition.get("checkpoint_next_order")
            or next_order != 15
            or len(pipeline) <= next_order
            or pipeline[next_order][0] != "Takeover Detection"
        ):
            raise RuntimeError(
                "reviewed source transition no longer matches the scan checkpoint"
            )
        validate_recovery_replay_safety(
            cur, scan_id, document, pipeline, next_order, mode,
            recovery_history_was_persisted,
        )
        required_records = (
            1 if mode == "SINGLE_FAILED_STAGE"
            else len(pipeline) - next_order
        )
        if len(document["attempts"]) + required_records > MAX_DIAGNOSTIC_ATTEMPTS:
            raise RuntimeError(
                "insufficient diagnostic capacity for recovery; refusing to start"
            )
        history = document.setdefault("recovery_history", [])
        if any(
            not isinstance(item, dict) or item.get("status") == "RUNNING"
            for item in history
        ):
            raise RuntimeError("scan recovery history is ambiguous; refusing recovery")
        if len(history) >= MAX_RECOVERY_ATTEMPTS:
            raise RuntimeError("scan recovery history is full; refusing recovery")
        if next_order >= len(pipeline) and mode == "SINGLE_FAILED_STAGE":
            raise RuntimeError("all stages already succeeded; no failed stage remains")
        recovery = {
            "mode": mode,
            "runner_id": runner_id,
            "started_at": datetime.now().astimezone().isoformat(),
            "completed_at": None,
            "status": "RUNNING",
            "stage": pipeline[next_order][0]
            if next_order < len(pipeline) else "Finalize scan",
            "failure_reason": str(failure_reason or "")[:500],
            "compatibility_transition_id": (
                transition["transition_id"] if transition else None
            ),
            "source_sha256_from": (
                transition["old_identity"].get("source_sha256")
                if transition else None
            ),
            "source_sha256_to": (
                transition["new_identity"].get("source_sha256")
                if transition else None
            ),
            "previous_completed_at": (
                completed_at.isoformat() if hasattr(completed_at, "isoformat")
                else str(completed_at) if completed_at is not None else None
            ),
        }
        history.append(recovery)
        document["current_stage"] = None
        cur.execute(
            """UPDATE scans
                  SET status = 'RUNNING', runner_token = %s,
                      heartbeat_at = NOW(), completed_at = NULL,
                      stage_diagnostics = %s::jsonb
                WHERE id = %s AND status = 'FAILED' AND runner_token = %s
                RETURNING id""",
            (new_token, json.dumps(document, separators=(",", ":")),
             scan_id, old_token),
        )
        if cur.fetchone() is None:
            raise RuntimeError("scan ownership changed; refusing recovery")
        conn.commit()
        return (new_token, runner_id, pipeline, next_order, previous_attempt_counts,
                str(failure_reason or ""))
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def finish_recovery(scan_id, runner_token, runner_id, status, failure_reason=None,
                   recovery_status=None):
    """Persist recovery result while retaining its original failure record."""
    if status not in {"FAILED", "SUCCEEDED"}:
        raise ValueError("invalid terminal scan status")
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """SELECT stage_diagnostics FROM scans
                 WHERE id = %s AND status = 'RUNNING' AND runner_token = %s
                 FOR UPDATE""",
            (scan_id, runner_token),
        )
        row = cur.fetchone()
        if row is None:
            raise RunnerLeaseError("recovery runner no longer owns the scan")
        document = _as_document(row[0])
        history = document.get("recovery_history", [])
        active = next((item for item in reversed(history)
                       if item.get("runner_id") == runner_id
                       and item.get("status") == "RUNNING"), None)
        if active is None:
            raise RuntimeError("recovery history is inconsistent")
        active["status"] = recovery_status or status
        active["completed_at"] = datetime.now().astimezone().isoformat()
        if failure_reason:
            active["failure_reason"] = str(failure_reason)[:500]
        document["current_stage"] = None
        document["scan_outcome"] = {
            "status": status,
            "completed_at": datetime.now().astimezone().isoformat(),
            "error_category": "SCAN_FAILED" if status == "FAILED" else None,
        }
        cur.execute(
            """UPDATE scans
                  SET status = %s, completed_at = NOW(), heartbeat_at = NOW(),
                      failure_reason = %s, stage_diagnostics = %s::jsonb
                WHERE id = %s AND status = 'RUNNING' AND runner_token = %s
                RETURNING id""",
            (status, str(failure_reason)[:500] if failure_reason else None,
             json.dumps(document, separators=(",", ":")), scan_id, runner_token),
        )
        if cur.fetchone() is None:
            raise RunnerLeaseError("recovery terminal transition lost scan ownership")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _execute_stages(scan_id, runner_token, pipeline, heartbeat, *, start_order=0,
                    previous_attempt_counts=None, execution_mode="FULL",
                    runner_id=None, single_stage=False):
    previous_attempt_counts = previous_attempt_counts or {}
    global _ACTIVE_STAGE_DIAGNOSTICS
    end_order = min(len(pipeline), start_order + 1) if single_stage else len(pipeline)
    for stage_order in range(start_order, end_order):
        name, cmd = pipeline[stage_order]
        if heartbeat is not None:
            heartbeat.ensure_healthy()
        _ACTIVE_STAGE_DIAGNOSTICS = (
            scan_id, runner_token, stage_order, execution_mode, runner_id
        )
        try:
            used = previous_attempt_counts.get(stage_order, 0)
            run_required_stage(
                name, cmd, scan_id=scan_id, runner_token=runner_token,
                stage_order=stage_order, start_attempt=used + 1,
                max_attempts=(MAX_TOTAL_ATTEMPTS_PER_STAGE
                              if execution_mode != "FULL" else MAX_STAGE_ATTEMPTS),
                execution_mode=execution_mode, runner_id=runner_id,
            )
        finally:
            _ACTIVE_STAGE_DIAGNOSTICS = None
        if heartbeat is not None:
            heartbeat.ensure_healthy()


def run_recovery(scan_id, mode):
    """Run a guarded resume or one failed stage under the normal lease."""
    started = time.time()
    try:
        token, runner_id, pipeline, start_order, attempt_counts, original_reason = (
            begin_recovery(scan_id, mode)
        )
    except Exception as exc:
        logging.error(
            "Recovery refused mode=%s scan_id=%s reason=%s",
            mode, scan_id, str(exc)[:500],
        )
        return False
    heartbeat = RunnerHeartbeat(scan_id, token)
    try:
        log_file = (
            f"logs/{datetime.now().strftime('%Y%m%d_%H%M%S')}_scan_{scan_id}_"
            f"{mode.lower()}_{runner_id[:8]}.log"
        )
        setup_logging(log_file)
        logging.info(
            "Starting scan recovery mode=%s scan_id=%s runner_id=%s stage=%s",
            mode, scan_id, runner_id,
            pipeline[start_order][0] if start_order < len(pipeline) else "Finalize scan",
        )
        heartbeat.start()
        _execute_stages(
            scan_id, token, pipeline, heartbeat, start_order=start_order,
            previous_attempt_counts=attempt_counts, execution_mode=mode,
            runner_id=runner_id, single_stage=(mode == "SINGLE_FAILED_STAGE"),
        )
        heartbeat.ensure_healthy()
        if mode == "SINGLE_FAILED_STAGE":
            finish_recovery(
                scan_id, token, runner_id, "FAILED", original_reason,
                recovery_status="SUCCEEDED",
            )
            logging.info(
                "Single failed stage completed; scan remains FAILED scan_id=%s",
                scan_id,
            )
            return True
        finish_recovery(scan_id, token, runner_id, "SUCCEEDED")
        logging.info("Resumed scan completed successfully scan_id=%s", scan_id)
        return True
    except KeyboardInterrupt:
        reason = "INTERRUPTED"
        try:
            finish_recovery(scan_id, token, runner_id, "FAILED", reason)
        except Exception:
            logging.exception("Could not persist interrupted recovery state")
        raise
    except Exception as exc:
        logging.exception("RECOVERY FAILED mode=%s scan_id=%s", mode, scan_id)
        try:
            finish_recovery(scan_id, token, runner_id, "FAILED", str(exc)[:500])
        except Exception:
            logging.exception("Could not persist failed recovery state")
        return False
    finally:
        if heartbeat._thread.ident is not None:
            heartbeat.stop()
        logging.info(
            "Recovery ended mode=%s scan_id=%s elapsed_seconds=%.2f",
            mode, scan_id, time.time() - started,
        )


# -------------------------
# MAIN PIPELINE
# -------------------------
def run_pipeline(dns_security_target_ids=None):
    dns_security_target_ids = normalize_dns_security_target_ids(
        dns_security_target_ids
    )
    if (dns_security_target_ids is not None
            and not default_operation_enabled("DNS_SECURITY")):
        raise ValueError(
            "DNS Security target selection requires the centralized operation grant"
        )

    pipeline_start = time.time()

    identity_pipeline = build_pipeline(0, dns_security_target_ids)
    scan_identity = {
        "scan_id": None,
        "pipeline_identity": pipeline_identity(
            identity_pipeline, 0, dns_security_target_ids
        ),
    }

    heartbeat = None
    runner_token = None

    def terminal_transition(status, failure_reason=None):
        kwargs = {}
        if runner_token is not None:
            kwargs["runner_token"] = runner_token
            if failure_reason is not None:
                kwargs["failure_reason"] = failure_reason
        mark_scan_terminal(scan_id, status, **kwargs)

    try:
        if dns_security_target_ids is None:
            scan_id = create_scan(scan_identity)
        else:
            scan_id = create_scan(scan_identity, dns_security_target_ids)
    except KeyboardInterrupt:
        if scan_identity["scan_id"] is not None:
            mark_interrupted_scan_failed(scan_identity["scan_id"])
        raise

    try:
        pipeline = build_pipeline(scan_id, dns_security_target_ids)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = f"logs/{timestamp}_scan_{scan_id}.log"

        setup_logging(log_file)
        runner_token = scan_identity.get("runner_token")
        if runner_token:
            heartbeat = RunnerHeartbeat(scan_id, runner_token)
            heartbeat.start()
        logging.info(f"Scan Created: {scan_id}")
        logging.info("=" * 70)
        logging.info("ASM Scan Started")
        logging.info(f"Scan ID  : {scan_id}")
        logging.info(f"Log File : {log_file}")
        logging.info("=" * 70)

        _execute_stages(
            scan_id, runner_token, pipeline, heartbeat,
            execution_mode="FULL",
        )

    except KeyboardInterrupt:
        terminal_transition("FAILED", "INTERRUPTED")
        raise

    except Exception as exc:
        logging.exception("PIPELINE EXCEPTION for scan_id=%s", scan_id)
        logging.error(f"PIPELINE FAILED for scan_id={scan_id}")
        logging.error("=" * 70)
        logging.error("ASM Scan Failed")
        duration = round(time.time() - pipeline_start, 2)
        logging.error(f"Total Duration : {duration} seconds")
        logging.error(f"Failure Detected At : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logging.error(f"Scan ID : {scan_id}")
        logging.error("=" * 70)

        try:
            terminal_transition("FAILED", str(exc)[:500])
        except Exception:
            logging.exception("Failed to persist FAILED scan status")

        sys.exit(1)

    finally:
        if heartbeat is not None:
            heartbeat.stop()

    try:
        terminal_transition("SUCCEEDED")
    except KeyboardInterrupt:
        # If SUCCEEDED committed before the interrupt surfaced, the existing
        # RUNNING guard makes this FAILED attempt a no-op rather than an
        # opposite terminal transition.
        mark_interrupted_scan_failed(scan_id, runner_token)
        raise
    except Exception:
        logging.exception(
            "All required stages completed, but SUCCEEDED status could not be persisted"
        )
        sys.exit(1)

    duration = round(time.time() - pipeline_start, 2)
    logging.info(f"Total Duration : {duration} seconds")
    logging.info(f"Completed At : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logging.info("=" * 70)
    logging.info("ASM Scan Completed Successfully")
    logging.info(f"Scan ID : {scan_id}")
    logging.info("=" * 70)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Run or recover the ShadowRecon scan pipeline",
        epilog=("Recovery examples: --resume SCAN_ID or "
                "--run-failed-stage SCAN_ID"),
    )
    recovery = parser.add_mutually_exclusive_group()
    recovery.add_argument("--resume", type=int, metavar="SCAN_ID")
    recovery.add_argument("--run-failed-stage", type=int, metavar="SCAN_ID")
    recovery.add_argument(
        "--authorize-reviewed-source-transition",
        type=int,
        metavar="SCAN_ID",
        help="record the explicitly reviewed reliability source transition for scan 36",
    )
    parser.add_argument("--expected-old-source-sha256")
    parser.add_argument("--expected-new-source-sha256")
    parser.add_argument(
        "--dns-security-target-ids",
        help=("one-run DNS Security allowlist of 1 to 3 existing domain IDs; "
              "the normal scan pipeline still runs all its usual stages"),
    )
    parser.add_argument(
        "--enable-dns-security",
        action="store_true",
        help=("enable DNS_SECURITY in the centralized operation policy for "
              "this scan/recovery process and its worker subprocesses only"),
    )
    args = parser.parse_args([] if argv is None else argv)
    try:
        dns_security_target_ids = normalize_dns_security_target_ids(
            args.dns_security_target_ids
        )
    except ValueError as exc:
        parser.error(str(exc))
    recovery_mode = (
        "RESUME" if args.resume is not None else
        "SINGLE_FAILED_STAGE" if args.run_failed_stage is not None else None
    )
    transition_mode = args.authorize_reviewed_source_transition is not None
    if transition_mode and not (
        args.expected_old_source_sha256 and args.expected_new_source_sha256
    ):
        parser.error(
            "reviewed source transition requires both expected old and new SHA-256 values"
        )
    if not transition_mode and (
        args.expected_old_source_sha256 or args.expected_new_source_sha256
    ):
        parser.error("source fingerprint arguments require transition authorization mode")
    if transition_mode and (
        args.dns_security_target_ids or args.enable_dns_security
    ):
        parser.error("source transition authorization does not accept scan options")
    if recovery_mode and dns_security_target_ids is not None:
        parser.error("DNS Security target selection is stored on the failed scan")
    if args.enable_dns_security and dns_security_target_ids is None and not recovery_mode:
        parser.error(
            "--enable-dns-security requires --dns-security-target-ids "
            "with 1 to 3 unique domain IDs"
        )
    if (dns_security_target_ids is not None
            and not args.enable_dns_security
            and not default_operation_enabled("DNS_SECURITY")):
        parser.error(
            "--dns-security-target-ids only restricts DNS Security; "
            "also pass --enable-dns-security for this scan process"
        )

    previous_handlers = {}
    for signum in (signal.SIGTERM, signal.SIGINT):
        previous_handlers[signum] = signal.getsignal(signum)
        signal.signal(signum, _handle_shutdown_signal)
    lock_conn = None
    try:
        lock_conn = acquire_orchestration_lock()
        if lock_conn is None:
            logging.error(
                "SKIPPED_OVERLAP: another ShadowRecon orchestration pipeline "
                "is already running; no scan was created"
            )
            sys.exit(OVERLAP_SKIP_EXIT_CODE)
        if transition_mode:
            transition_id = authorize_reviewed_source_transition(
                args.authorize_reviewed_source_transition,
                args.expected_old_source_sha256,
                args.expected_new_source_sha256,
            )
            print(
                "Recorded reviewed compatibility transition "
                f"{transition_id} for scan {args.authorize_reviewed_source_transition}"
            )
            return
        recover_orphaned_scans(lock_conn)
        previous_operations = os.environ.get(DEFAULT_SCAN_OPERATIONS_ENV)
        if args.enable_dns_security:
            current_operations = configured_scan_operations(previous_operations)
            if (previous_operations is not None
                    and previous_operations.strip()
                    and not current_operations):
                parser.error(
                    f"{DEFAULT_SCAN_OPERATIONS_ENV} is invalid; refusing "
                    "to alter the operation policy for this scan"
                )
            os.environ[DEFAULT_SCAN_OPERATIONS_ENV] = ",".join(
                sorted(current_operations | {"DNS_SECURITY"})
            )
        try:
            if recovery_mode:
                succeeded = run_recovery(
                    args.resume if recovery_mode == "RESUME"
                    else args.run_failed_stage,
                    recovery_mode,
                )
                if not succeeded:
                    sys.exit(1)
            elif dns_security_target_ids is None:
                run_pipeline()
            else:
                run_pipeline(dns_security_target_ids)
        finally:
            if args.enable_dns_security:
                if previous_operations is None:
                    os.environ.pop(DEFAULT_SCAN_OPERATIONS_ENV, None)
                else:
                    os.environ[DEFAULT_SCAN_OPERATIONS_ENV] = previous_operations
    finally:
        if lock_conn is not None:
            try:
                release_orchestration_lock(lock_conn)
            except Exception:
                logging.exception("Failed to explicitly release orchestration lock")
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)


def _handle_shutdown_signal(signum, _frame):
    """Route handled termination through the normal scan-failure path."""
    raise KeyboardInterrupt(f"received signal {signum}")


# -------------------------
if __name__ == "__main__":
    main(sys.argv[1:])
