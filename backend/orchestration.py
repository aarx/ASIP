import subprocess
from datetime import datetime
import time
import logging
import os
import signal
import sys
from db import get_conn
from worker_outcome import RETRYABLE_INCOMPLETE_EXIT_CODE

ASIP_ORCHESTRATION_LOCK_ID = 0x41534950
MAX_STAGE_ATTEMPTS = 2
CHILD_TERMINATE_GRACE_SECONDS = 5

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

# -------------------------
# CREATE SCAN
# -------------------------
def create_scan(scan_identity=None):
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO scans(started_at, completed_at, status)
        VALUES (NOW(), NULL, 'RUNNING')
        RETURNING id
        """)
        scan_id = cur.fetchone()[0]
        if scan_identity is not None:
            # Retain the exact owned row before commit. If commit is interrupted
            # after reaching PostgreSQL, the caller can safely address this ID
            # without guessing from global RUNNING state.
            scan_identity["scan_id"] = scan_id
        conn.commit()
        return scan_id
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def mark_scan_terminal(scan_id, status):
    if status not in {"SUCCEEDED", "FAILED"}:
        raise ValueError(f"Invalid terminal scan status: {status}")

    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
        UPDATE scans
        SET status = %s,
            completed_at = NOW()
        WHERE id = %s
        AND status = 'RUNNING'
        RETURNING id
        """, (status, scan_id))

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


def run_step(name, cmd, attempt, max_attempts):

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

        # STREAM OUTPUT LIVE
        for line in process.stdout:
            logging.info(f"[{name}] {line.strip()}")

        returncode = process.wait()

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

        raise RuntimeError(f"{name} failed with exit code {returncode}")


def mark_interrupted_scan_failed(scan_id):
    """Best-effort guarded failure transition while preserving interruption."""
    logging.error(f"PIPELINE INTERRUPTED for scan_id={scan_id}")
    try:
        mark_scan_terminal(scan_id, "FAILED")
    except Exception:
        logging.exception("Failed to persist FAILED scan status after interrupt")


# -------------------------
# MAIN PIPELINE
# -------------------------
def run_pipeline():

    pipeline_start = time.time()

    scan_identity = {"scan_id": None}
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
        logging.info(f"Scan Created: {scan_id}")
        logging.info("=" * 70)
        logging.info("ASM Scan Started")
        logging.info(f"Scan ID  : {scan_id}")
        logging.info(f"Log File : {log_file}")
        logging.info("=" * 70)

        for name, cmd in pipeline:
            run_required_stage(name, cmd)

    except KeyboardInterrupt:
        mark_interrupted_scan_failed(scan_id)
        raise

    except Exception:
        logging.error(f"PIPELINE FAILED for scan_id={scan_id}")
        logging.error("=" * 70)
        logging.error("ASM Scan Failed")
        duration = round(time.time() - pipeline_start, 2)
        logging.error(f"Total Duration : {duration} seconds")
        logging.error(f"Failure Detected At : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logging.error(f"Scan ID : {scan_id}")
        logging.error("=" * 70)

        try:
            mark_scan_terminal(scan_id, "FAILED")
        except Exception:
            logging.exception("Failed to persist FAILED scan status")

        sys.exit(1)

    try:
        mark_scan_terminal(scan_id, "SUCCEEDED")
    except KeyboardInterrupt:
        # If SUCCEEDED committed before the interrupt surfaced, the existing
        # RUNNING guard makes this FAILED attempt a no-op rather than an
        # opposite terminal transition.
        mark_interrupted_scan_failed(scan_id)
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
            "Another ASIP orchestration pipeline is already running; exiting"
        )
        sys.exit(1)

    try:
        run_pipeline()
    finally:
        try:
            release_orchestration_lock(lock_conn)
        except Exception:
            logging.exception("Failed to explicitly release orchestration lock")


# -------------------------
if __name__ == "__main__":
    main()
