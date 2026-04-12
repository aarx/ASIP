import subprocess
import psycopg2
from datetime import datetime
import time
import logging
import os
import sys

# -------------------------
# LOGGING SETUP
# -------------------------
os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/orchestrator.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

# -------------------------
# DB CONNECTION
# -------------------------
def get_conn():
    return psycopg2.connect(
        host="db",
        dbname="asm_db",
        user="asm",
        password="asm123"
    )

# -------------------------
# CREATE SCAN
# -------------------------
def create_scan():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    INSERT INTO scans(started_at)
    VALUES (NOW())
    RETURNING id
    """)

    scan_id = cur.fetchone()[0]
    conn.commit()
    conn.close()

    logging.info(f"Scan Created: {scan_id}")
    return scan_id

# -------------------------
# RUN STEP
# -------------------------
def run_step(name, cmd):

    logging.info("=" * 60)
    logging.info(f"STARTING: {name}")
    logging.info(f"Command: {cmd}")

    start = time.time()

    try:
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        # STREAM OUTPUT LIVE
        for line in process.stdout:
            logging.info(f"[{name}] {line.strip()}")

        process.wait()

        duration = round(time.time() - start, 2)

        if process.returncode != 0:
            logging.error(f"FAILED: {name} ({duration}s)")
            raise Exception(f"{name} failed")

        logging.info(f"COMPLETED: {name} ({duration}s)")

    except Exception as e:
        logging.exception(f"ERROR in step: {name}")
        raise e


# -------------------------
# MAIN PIPELINE
# -------------------------
def main():

    logging.info("CRON TRIGGERED ORCHESTRATION")

    scan_id = create_scan()

    pipeline = [
        # ENTRY
        ("Recon", "python -u recon.py --expand seeds.txt"),
        ("Ingest", f"python -u ingest.py {scan_id}"),

        # EXPANSION
        ("SAN Expansion", f"python -u san_worker.py {scan_id}"),
        ("SAN State Sync", f"python -u san_state_sync.py {scan_id}"),

        # DNS
        ("DNS Resolution", f"python -u dns_worker.py {scan_id}"),

        # ENRICHMENT
        ("Cert Worker", f"python -u cert_worker.py {scan_id}"),
        ("Port Scan", f"python -u port_scan_worker.py {scan_id}"),
        ("Tech Detection", f"python -u tech_worker.py {scan_id}"),
        ("ASN Lookup", f"python -u asn_worker.py {scan_id}"),
        ("Provider Mapping", f"python -u provider_worker.py {scan_id}"),

        # TAKEOVER
        ("Takeover Detection", f"python -u takeover_worker.py {scan_id}"),

        # FINAL
        ("Risk Scoring", f"python -u risk_worker.py {scan_id}")
    ]

    try:
        for name, cmd in pipeline:
            run_step(name, cmd)

        # mark complete
        conn = get_conn()
        cur = conn.cursor()

        cur.execute("""
        UPDATE scans
        SET completed_at = NOW()
        WHERE id = %s
        """, (scan_id,))

        conn.commit()
        conn.close()

        logging.info(f"SCAN COMPLETE: {scan_id}")

    except Exception as e:
        logging.error(f"PIPELINE FAILED for scan_id={scan_id}")

        # optional: mark failed
        try:
            conn = get_conn()
            cur = conn.cursor()

            cur.execute("""
            UPDATE scans
            SET completed_at = NOW()
            WHERE id = %s
            """, (scan_id,))

            conn.commit()
            conn.close()
        except:
            logging.error("Failed to update scan status in DB")

        sys.exit(1)


# -------------------------
if __name__ == "__main__":
    main()
