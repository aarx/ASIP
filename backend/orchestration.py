import subprocess
import argparse
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
    extract_worker_summary,
    finish_stage_attempt,
    start_stage_attempt,
)

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

_ACTIVE_STAGE_PROCESS = None
_ACTIVE_STAGE_DIAGNOSTICS = None


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
                    'current_stage', NULL,
                    'attempts', '[]'::jsonb,
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
                    'current_stage', NULL,
                    'attempts', '[]'::jsonb,
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


def _diagnostics_start(scan_id, runner_token, name, stage_order, attempt):
    if scan_id is None or runner_token is None or stage_order is None:
        return
    conn = None
    try:
        conn = get_conn()
        updated = start_stage_attempt(
            conn, scan_id, runner_token, name, stage_order, attempt
        )
        if not updated:
            raise RunnerLeaseError(
                f"scan {scan_id} is no longer RUNNING under this runner token"
            )
    except RunnerLeaseError:
        raise
    except Exception:
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
                        status, duration, error_category=None, summary=None):
    if scan_id is None or runner_token is None or stage_order is None:
        return
    conn = None
    try:
        conn = get_conn()
        updated = finish_stage_attempt(
            conn, scan_id, runner_token, name, stage_order, attempt,
            status, duration, error_category, summary,
        )
        if not updated:
            logging.warning(
                "Scan diagnostics outcome was not persisted for scan=%s stage=%s "
                "attempt=%s; stage execution outcome is unchanged",
                scan_id, name, attempt,
            )
    except Exception:
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


def _append_bounded_output(output, chunk):
    output.extend(chunk)
    overflow = len(output) - MAX_STAGE_OUTPUT_CAPTURE_BYTES
    if overflow > 0:
        del output[:overflow]


def _log_stage_chunk(name, line):
    logging.info(f"[{name}] {line.decode('utf-8', errors='replace')}")


def _stream_stage_output(process, name):
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
    selector = selectors.DefaultSelector()
    selector.register(stdout, selectors.EVENT_READ)
    try:
        while True:
            if not selector.select():
                continue
            chunk = os.read(file_descriptor, 4096)
            if not chunk:
                _flush_stage_output(name, pending, final=True)
                break
            _append_bounded_output(captured, chunk)
            pending.extend(chunk)
            _flush_stage_output(name, pending)

        process.wait()
        return bytes(captured)
    finally:
        selector.close()


def _flush_stage_output(name, pending, final=False):
    """Log complete lines and bounded fragments without retaining huge lines."""
    while pending:
        newline = pending.find(b"\n")
        if newline >= 0 and newline < MAX_STAGE_OUTPUT_LINE_BYTES:
            line = bytes(pending[:newline]).rstrip(b"\r")
            del pending[:newline + 1]
            _log_stage_chunk(name, line)
        elif len(pending) >= MAX_STAGE_OUTPUT_LINE_BYTES:
            line = bytes(pending[:MAX_STAGE_OUTPUT_LINE_BYTES])
            del pending[:MAX_STAGE_OUTPUT_LINE_BYTES]
            _log_stage_chunk(name, line)
        elif final:
            _log_stage_chunk(name, bytes(pending).rstrip(b"\r"))
            pending.clear()
        else:
            return


def run_step(name, cmd, attempt, max_attempts, scan_id=None,
             runner_token=None, stage_order=None):

    if scan_id is None and runner_token is None and stage_order is None:
        context = _ACTIVE_STAGE_DIAGNOSTICS
        if context is not None:
            scan_id, runner_token, stage_order = context

    logging.info("=" * 60)
    logging.info(f"STARTING: {name} attempt {attempt}/{max_attempts}")
    logging.info(f"Command: {cmd}")

    _diagnostics_start(scan_id, runner_token, name, stage_order, attempt)
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

        captured_output = _stream_stage_output(process, name)

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
            error_category, extract_worker_summary(output),
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
        if process is not None:
            stop_active_child(process)
        _diagnostics_finish(
            scan_id, runner_token, name, stage_order, attempt,
            "CANCELLED", time.monotonic() - monotonic_start, "INTERRUPTED",
        )
        logging.error(f"INTERRUPTED: {name} attempt {attempt}/{max_attempts}")
        raise
    except Exception:
        if process is not None:
            stop_active_child(process)
        _diagnostics_finish(
            scan_id, runner_token, name, stage_order, attempt,
            "FAILED", time.monotonic() - monotonic_start,
            "STAGE_LAUNCH_ERROR" if process is None else "STAGE_RUNNER_ERROR",
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


def run_required_stage(name, cmd):
    for attempt in range(1, MAX_STAGE_ATTEMPTS + 1):
        returncode = run_step(name, cmd, attempt, MAX_STAGE_ATTEMPTS)

        if returncode == 0:
            return

        if (
            returncode == RETRYABLE_INCOMPLETE_EXIT_CODE
            and attempt < MAX_STAGE_ATTEMPTS
        ):
            logging.warning(
                f"RETRYING: {name} after attempt {attempt}/{MAX_STAGE_ATTEMPTS}"
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

    scan_identity = {"scan_id": None}
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
        pipeline = [
            # ENTRY
            ("Recon", f"python -u recon.py --scan-id {scan_id} --expand seeds.txt"),
            ("Ingest", f"python -u ingest.py {scan_id}"),

            # EXPANSION
            # The first eligibility pass authorizes existing confirmed
            # inventory before SAN TLS expansion.  SAN children are synced,
            # then evaluated again before any later active stage.
            ("Automatic Eligibility", f"python -u eligibility_worker.py {scan_id}"),
            ("SAN Expansion", f"python -u san_worker.py {scan_id}"),
            ("SAN State Sync", f"python -u san_state_sync.py {scan_id}"),
            ("Automatic Eligibility", f"python -u eligibility_worker.py {scan_id}"),

            # DNS
            ("DNS Resolution", f"python -u dns_worker.py {scan_id}"),
            ("HTTP/TLS Observation", f"python -u http_observation_worker.py {scan_id}"),

            # ENRICHMENT
            ("Cert Worker", f"python -u cert_worker.py {scan_id}"),
            ("Port Scan", f"python -u port_scan_worker.py {scan_id}"),
            ("Tech Detection", f"python -u tech_worker.py {scan_id}"),
            ("ASN Lookup", f"python -u asn_worker.py {scan_id}"),
            ("Provider Mapping", f"python -u provider_worker.py {scan_id}"),

            # TAKEOVER
            ("Takeover Detection", f"python -u takeover_worker.py {scan_id}"),

            # Validate Discovered Domains
            ("Discovery Validator", f"python -u discovery_validator.py {scan_id}"),

            # FINAL
            ("Risk Scoring", f"python -u risk_worker.py {scan_id}")
        ]

        # Brand redirect monitoring is an independent, provenance-limited
        # operation. Its deployment allowlist does not grant other scan work.
        brand_stage = optional_pipeline_stage(scan_id)
        if brand_stage:
            insertion = next(i for i, item in enumerate(pipeline)
                             if item[0] == "HTTP/TLS Observation") + 1
            pipeline.insert(insertion, brand_stage)

        # DNS Security is absent unless the centralized process operation
        # policy enables it. A scan-row target list can only narrow selection.
        if default_operation_enabled("DNS_SECURITY"):
            run_scope_argument = " --run-scoped" if dns_security_target_ids else ""
            dns_stage = (
                "DNS Security",
                f"python -u dns_security_worker.py {scan_id}{run_scope_argument}",
            )
            insertion = next(i for i, item in enumerate(pipeline)
                             if item[0] == "HTTP/TLS Observation")
            pipeline.insert(insertion, dns_stage)

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

        global _ACTIVE_STAGE_DIAGNOSTICS
        for stage_order, (name, cmd) in enumerate(pipeline):
            if heartbeat is not None:
                heartbeat.ensure_healthy()
            _ACTIVE_STAGE_DIAGNOSTICS = (scan_id, runner_token, stage_order)
            try:
                run_required_stage(name, cmd)
            finally:
                _ACTIVE_STAGE_DIAGNOSTICS = None
            if heartbeat is not None:
                heartbeat.ensure_healthy()

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
    parser = argparse.ArgumentParser(description="Run the regular ShadowRecon scan pipeline")
    parser.add_argument(
        "--dns-security-target-ids",
        help=("one-run DNS Security allowlist of 1 to 3 existing domain IDs; "
              "the normal scan pipeline still runs all its usual stages"),
    )
    parser.add_argument(
        "--enable-dns-security",
        action="store_true",
        help=("enable DNS_SECURITY in the centralized operation policy for "
              "this regular scan process and its worker subprocesses only"),
    )
    args = parser.parse_args([] if argv is None else argv)
    try:
        dns_security_target_ids = normalize_dns_security_target_ids(
            args.dns_security_target_ids
        )
    except ValueError as exc:
        parser.error(str(exc))
    if args.enable_dns_security and dns_security_target_ids is None:
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
            if dns_security_target_ids is None:
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
