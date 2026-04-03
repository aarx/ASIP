import subprocess
import time
from datetime import datetime

LOG_FILE = "pipeline.log"


def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def run_step(name, command):
    log(f"START: {name}")
    start = time.time()

    try:
        result = subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError:
        log(f"FAILED: {name}")
        exit(1)

    duration = round(time.time() - start, 2)
    log(f"END: {name} (took {duration}s)\n")


# 🔁 For batch workers
def run_batch_step(name, command, max_runs=10, sleep_sec=2):
    log(f"START BATCH: {name}")

    for i in range(max_runs):
        log(f"{name} - batch run {i+1}")

        result = subprocess.run(command, shell=True)

        # 👇 You can improve this condition later
        if result.returncode != 0:
            log(f"{name} - stopping (no more data or error)")
            break

        time.sleep(sleep_sec)

    log(f"END BATCH: {name}\n")


if __name__ == "__main__":

    log("===== PIPELINE START =====\n")

    run_step("Recon", "python recon.py")

    run_step("Ingest", "python ingest.py")

    run_step("Cert Worker", "python cert_worker.py")

    run_step("SAN Worker", "python san_worker.py")

    run_batch_step("Port Scan Worker", "python port_scan_worker.py")

    run_batch_step("Tech Worker", "python tech_worker.py")

    run_step("Provider Worker", "python provider_worker.py")

    run_step("ASN Worker", "python asn_worker.py")

    run_step("Risk Worker", "python risk_worker.py")

    log("===== PIPELINE COMPLETE =====")
