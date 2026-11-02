import subprocess
from datetime import datetime
import time
import logging
import os
import signal
import sys
import threading
import uuid
from db import get_conn
from worker_outcome import RETRYABLE_INCOMPLETE_EXIT_CODE

ASIP_ORCHESTRATION_LOCK_ID = 0x41534950
MAX_STAGE_ATTEMPTS = 2
CHILD_TERMINATE_GRACE_SECONDS = 5
STAGE_TIMEOUT_EXIT_CODE = 124
OVERLAP_SKIP_EXIT_CODE = 0
DEFAULT_STAGE_TIMEOUT_SECONDS = 1800
DEFAULT_RUNNER_HEARTBEAT_INTERVAL_SECONDS = 15
DEFAULT_RUNNER_ORPHAN_GRACE_SECONDS = 120


class StageExecutionError(RuntimeError):
    """A required stage failed or exceeded its bounded execution time."""


class RunnerLeaseError(RuntimeError):
    """The orchestration runner no longer owns its scan lease."""


def _positive_env_int(name, default):
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return value if value > 0 else default


def stage_timeout_seconds(_stage_name):
    """Return the configurable per-attempt stage deadline."""
    return _positive_env_int(
        "ASIP_STAGE_TIMEOUT_SECONDS", DEFAULT_STAGE_TIMEOUT_SECONDS
    )


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
    """Fail closed on unowned RUNNING rows and recover only expired leases.

    The caller holds the canonical advisory lock. A managed runner with a
    fresh lease is treated as an active/inconsistent state and blocks a new
    run. Legacy RUNNING rows without lease metadata are never guessed to be
    stale and require explicit operator reconciliation.
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

    grace_seconds = runner_orphan_grace_seconds()
    cur.execute(
        """
        SELECT id
        FROM scans
        WHERE status = 'RUNNING'
          AND heartbeat_at >= NOW() - (%s * INTERVAL '1 second')
        ORDER BY id
        """,
        (grace_seconds,),
    )
    fresh = [row[0] for row in cur.fetchall()]
    if fresh:
        raise RuntimeError(
            "A managed RUNNING scan has a fresh lease: "
            + ",".join(str(scan_id) for scan_id in fresh)
        )

    cur.execute(
        """
        UPDATE scans
        SET status = 'FAILED',
            completed_at = NOW(),
            failure_reason = 'ORPHANED_RUNNER_RECOVERED'
        WHERE status = 'RUNNING'
          AND runner_token IS NOT NULL
          AND heartbeat_at IS NOT NULL
          AND heartbeat_at < NOW() - (%s * INTERVAL '1 second')
        RETURNING id
        """,
        (grace_seconds,),
    )
    recovered = [row[0] for row in cur.fetchall()]
    conn.commit()
    for scan_id in recovered:
        logging.warning(
            "Recovered orphaned RUNNING scan %s as FAILED", scan_id
        )
    return recovered


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
            conn = None
            try:
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
            except Exception as exc:
                self._failure = RunnerLeaseError(
                    f"scan {self.scan_id} heartbeat failed: {exc}"
                )
                self._stop.set()
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        logging.exception("Failed to close heartbeat connection")

# -------------------------
# CREATE SCAN
# -------------------------
def create_scan(scan_identity=None):
    runner_token = str(uuid.uuid4())
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO scans(
            started_at, completed_at, status,
            runner_token, heartbeat_at, failure_reason
        )
        VALUES (NOW(), NULL, 'RUNNING', %s, NOW(), NULL)
        RETURNING id
        """, (runner_token,))
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
        params = [status, failure_reason, scan_id]
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
    """Terminate and reap the subprocess group after parent interruption."""
    try:
        returncode = process.poll()
    except Exception:
        logging.exception("Child cleanup could not poll the active process")
        returncode = None

    if returncode is not None:
        try:
            process.wait(timeout=0)
        except Exception:
            logging.exception("Child cleanup could not reap the exited process")
        return

    try:
        os.killpg(process.pid, signal.SIGTERM)
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

    try:
        process.wait(timeout=CHILD_TERMINATE_GRACE_SECONDS)
        return
    except subprocess.TimeoutExpired:
        logging.warning("Child did not exit after SIGTERM; escalating to SIGKILL")
    except Exception:
        logging.exception("Child cleanup wait after SIGTERM failed")

    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        logging.exception("Child cleanup could not kill the process group")
        try:
            process.kill()
        except ProcessLookupError:
            pass
        except Exception:
            logging.exception("Child cleanup fallback kill failed")

    try:
        process.wait(timeout=CHILD_TERMINATE_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        logging.error("Child cleanup timed out while reaping after SIGKILL")
    except Exception:
        logging.exception("Child cleanup final reap failed")


def run_step(name, cmd, attempt, max_attempts, timeout_seconds=None):

    logging.info("=" * 60)
    logging.info(f"STARTING: {name} attempt {attempt}/{max_attempts}")
    logging.info(f"Command: {cmd}")

    start = time.time()
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

        timeout_seconds = timeout_seconds or stage_timeout_seconds(name)
        try:
            output, _ = process.communicate(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            logging.error(
                "TIMEOUT: %s attempt %s/%s after %ss",
                name, attempt, max_attempts, timeout_seconds,
            )
            stop_active_child(process)
            output, _ = process.communicate()
            for line in (output or "").splitlines():
                logging.info(f"[{name}] {line.strip()}")
            return STAGE_TIMEOUT_EXIT_CODE

        for line in (output or "").splitlines():
            logging.info(f"[{name}] {line.strip()}")

        returncode = process.returncode

        duration = round(time.time() - start, 2)

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
        logging.error(f"INTERRUPTED: {name} attempt {attempt}/{max_attempts}")
        raise
    except Exception:
        if process is not None:
            stop_active_child(process)
        logging.exception(f"ERROR in step: {name} attempt {attempt}/{max_attempts}")
        raise
    finally:
        try:
            stdout = getattr(process, "stdout", None) if process is not None else None
            if stdout is not None and hasattr(stdout, "close"):
                stdout.close()
        except Exception:
            logging.exception("Failed to close child stdout stream")


def run_required_stage(name, cmd):
    for attempt in range(1, MAX_STAGE_ATTEMPTS + 1):
        returncode = run_step(
            name,
            cmd,
            attempt,
            MAX_STAGE_ATTEMPTS,
        )

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

        if returncode == STAGE_TIMEOUT_EXIT_CODE:
            raise StageExecutionError(
                f"{name} timed out after {stage_timeout_seconds(name)} seconds"
            )
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
def run_pipeline():

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
        scan_id = create_scan(scan_identity)
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
            ("SAN Expansion", f"python -u san_worker.py {scan_id}"),
            ("SAN State Sync", f"python -u san_state_sync.py {scan_id}"),
            ("Automatic Eligibility", f"python -u eligibility_worker.py {scan_id}"),

            # DNS
            ("DNS Resolution", f"python -u dns_worker.py {scan_id}"),
            ("SAN HTTP Observation", f"python -u san_http_worker.py {scan_id}"),

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

        for name, cmd in pipeline:
            if heartbeat is not None:
                heartbeat.ensure_healthy()
            run_required_stage(name, cmd)
            if heartbeat is not None:
                heartbeat.ensure_healthy()

    except KeyboardInterrupt:
        terminal_transition("FAILED", "INTERRUPTED")
        raise

    except Exception as exc:
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


def main():
    lock_conn = acquire_orchestration_lock()

    if lock_conn is None:
        logging.error(
            "SKIPPED_OVERLAP: another ShadowRecon orchestration pipeline "
            "is already running; no scan was created"
        )
        sys.exit(OVERLAP_SKIP_EXIT_CODE)

    try:
        recover_orphaned_scans(lock_conn)
        run_pipeline()
    finally:
        try:
            release_orchestration_lock(lock_conn)
        except Exception:
            logging.exception("Failed to explicitly release orchestration lock")


# -------------------------
if __name__ == "__main__":
    main()
