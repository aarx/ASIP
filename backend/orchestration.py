import subprocess
from datetime import datetime
import time
import logging
import os
import sys
from db import get_conn

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

    pipeline_start = time.time()

    scan_id = create_scan()
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    log_file = f"logs/{timestamp}_scan_{scan_id}.log"
    
    setup_logging(log_file)
    logging.info(f"Scan Created: {scan_id}")
    
    logging.info("=" * 70)
    logging.info("ASM Scan Started")
    logging.info(f"Scan ID  : {scan_id}")
    logging.info(f"Log File : {log_file}")
    logging.info("=" * 70)  

    pipeline = [
        # ENTRY
        ("Recon", "python -u recon.py --expand seeds.txt"),
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
        
        duration = round(time.time() - pipeline_start, 2)
        logging.info(f"Total Duration : {duration} seconds")
        logging.info(f"Completed At : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        logging.info("=" * 70)
        logging.info("ASM Scan Completed Successfully")
        logging.info(f"Scan ID : {scan_id}")
        logging.info("=" * 70)

    except Exception as e:
        logging.error(f"PIPELINE FAILED for scan_id={scan_id}")
        logging.error("=" * 70)
        logging.error("ASM Scan Failed")
        duration = round(time.time() - pipeline_start, 2)
        logging.error(f"Total Duration : {duration} seconds")
        logging.error(f"Completed At : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logging.error(f"Scan ID : {scan_id}")
        logging.error("=" * 70)

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
