import logging
import ipaddress
import os
import re
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from db import get_conn, require_running_scan
from authorization_policy import (
    active_scan_authorization_sql,
    recheck_active_authorization,
)


scan_id = int(sys.argv[1])

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/app.log"),
        logging.StreamHandler(),
    ],
)


DEFAULT_PORT_SCAN_WORKERS = 2
MAX_PORT_SCAN_WORKERS = 4
PORT_SCAN_TIMEOUT_SECONDS = 60
PORT_SCAN_POLL_SECONDS = 0.25
PORT_SCAN_TERMINATE_GRACE_SECONDS = 2


class PortScanError(RuntimeError):
    """Nmap did not complete successfully; partial output is not persisted."""

    def __init__(self, message, partial_ports=()):
        super().__init__(message)
        self.partial_ports = tuple(partial_ports)


class PortScanTimeout(PortScanError):
    pass


class PortScanCancelled(PortScanError):
    pass


class PortScanStageError(RuntimeError):
    pass


def configured_worker_count(value=None):
    """Read a conservative worker limit, clamped to the supported range."""
    raw = os.environ.get("ASIP_NMAP_WORKERS") if value is None else value
    try:
        parsed = int(raw) if raw not in (None, "") else DEFAULT_PORT_SCAN_WORKERS
    except (TypeError, ValueError):
        parsed = DEFAULT_PORT_SCAN_WORKERS
    return min(MAX_PORT_SCAN_WORKERS, max(1, parsed))


def get_resolving_domains(cur, scan_id):
    cur.execute(f"""
    SELECT DISTINCT ON (d.id) d.id, d.domain, s.ip
    FROM domains d
    JOIN domain_states s
      ON d.id = s.domain_id
      AND s.scan_id = %s
    JOIN scan_results sr
      ON sr.domain_id = s.domain_id
      AND sr.scan_id = s.scan_id

    LEFT JOIN domain_ports dp
      ON d.id = dp.domain_id
      AND dp.scan_id = %s

    WHERE s.has_ip = TRUE
    AND s.ip IS NOT NULL
    AND BTRIM(s.ip) <> ''
    AND dp.domain_id IS NULL
    AND {active_scan_authorization_sql("d", "PORT_SCAN")}
    AND NOT EXISTS (
        SELECT 1
        FROM domain_states shared_state
        JOIN scan_results shared_membership
          ON shared_membership.domain_id = shared_state.domain_id
         AND shared_membership.scan_id = shared_state.scan_id
        WHERE shared_state.scan_id = s.scan_id
          AND shared_state.ip = s.ip
          AND shared_state.domain_id <> d.id
    )
    ORDER BY d.id, s.scan_id DESC
    """, (scan_id, scan_id))
    return cur.fetchall()


def _parse_ports(stdout):
    if isinstance(stdout, bytes):
        stdout = stdout.decode("utf-8", errors="replace")
    ports = []
    for line in (stdout or "").splitlines():
        line = line.strip()
        if "/tcp" not in line or "open" not in line:
            continue
        parts = re.split(r"\s+", line)
        try:
            port = int(parts[0].split("/")[0])
        except (IndexError, ValueError) as exc:
            raise PortScanError(f"could not parse Nmap output line: {line}") from exc
        ports.append((port, parts[-1]))
    return ports


def _terminate_process(process):
    """Stop this Nmap process and collect any partial output."""
    if process.poll() is None:
        try:
            process.terminate()
        except ProcessLookupError:
            pass
        try:
            stdout, _stderr = process.communicate(
                timeout=PORT_SCAN_TERMINATE_GRACE_SECONDS
            )
            return stdout
        except subprocess.TimeoutExpired:
            process.kill()
    stdout, _stderr = process.communicate()
    return stdout


def validate_destination_ip(value):
    """Accept only one public numeric address selected from this scan's state."""
    try:
        address = ipaddress.ip_address(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise PortScanError("Nmap destination is not a valid numeric IP") from exc
    if (not address.is_global or address.is_private or address.is_loopback
            or address.is_link_local or address.is_multicast
            or address.is_reserved or address.is_unspecified):
        raise PortScanError("Nmap destination IP is outside the permitted address policy")
    return str(address)


def scan_ports(destination_ip, cancel_event=None):
    """Run the existing bounded Nmap profile once, without retries."""
    destination_ip = validate_destination_ip(destination_ip)
    asm_ports = (
        "21,22,23,25,53,80,110,143,389,443,445,"
        "1521,3000,3306,3389,5000,5432,5900,"
        "5985,5986,6379,7001,7002,8000,8080,8443,"
        "8888,27017,11211"
    )
    cmd = ["nmap", "-n", "-Pn", "-T3", "--open", "-p", asm_ports, destination_ip]

    if cancel_event is not None and cancel_event.is_set():
        raise PortScanCancelled("cancelled before Nmap process start")

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except Exception as exc:
        raise PortScanError(f"could not start Nmap for {destination_ip}: {exc}") from exc

    deadline = time.monotonic() + PORT_SCAN_TIMEOUT_SECONDS
    while True:
        if cancel_event is not None and cancel_event.is_set():
            stdout = _terminate_process(process)
            partial_ports = _parse_ports(stdout)
            raise PortScanCancelled(
                f"cancelled Nmap for {destination_ip}; discarded {len(partial_ports)} partial ports",
                partial_ports,
            )

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            stdout = _terminate_process(process)
            partial_ports = _parse_ports(stdout)
            raise PortScanTimeout(
                f"Nmap timed out after {PORT_SCAN_TIMEOUT_SECONDS}s for {destination_ip}; "
                f"discarded {len(partial_ports)} partial ports",
                partial_ports,
            )

        try:
            stdout, stderr = process.communicate(
                timeout=min(PORT_SCAN_POLL_SECONDS, remaining)
            )
            break
        except subprocess.TimeoutExpired:
            continue

    ports = _parse_ports(stdout)
    if process.returncode != 0:
        raise PortScanError(
            f"Nmap exited {process.returncode} for {destination_ip}: {stderr or ''}; "
            f"discarded {len(ports)} partial ports",
            ports,
        )
    return ports


def scan_target(scan_id, domain_id, domain, destination_ip, cancel_event):
    """Authorize, scan, and persist one target using its own DB connection."""
    conn = None
    try:
        if cancel_event.is_set():
            return {"status": "cancelled", "domain": domain}

        conn = get_conn()
        cur = conn.cursor()
        require_running_scan(cur, scan_id)
        # The destination must be the single address captured in this scan's
        # domain state. Reject known shared addresses rather than letting Nmap
        # resolve the hostname to a potentially different/multiple IP set.
        destination_ip = validate_destination_ip(destination_ip)
        cur.execute("""
        SELECT s.ip,
               NOT EXISTS (
                   SELECT 1
                   FROM domain_states shared_state
                   JOIN scan_results shared_membership
                     ON shared_membership.domain_id = shared_state.domain_id
                    AND shared_membership.scan_id = shared_state.scan_id
                   WHERE shared_state.scan_id = s.scan_id
                     AND shared_state.ip = s.ip
                     AND shared_state.domain_id <> s.domain_id
               )
        FROM domain_states s
        JOIN scan_results sr
          ON sr.scan_id = s.scan_id
         AND sr.domain_id = s.domain_id
        WHERE s.scan_id = %s AND s.domain_id = %s AND s.has_ip IS TRUE
        """, (scan_id, domain_id))
        destination_state = cur.fetchone()
        if (destination_state is None
                or str(destination_state[0]).strip() != destination_ip
                or not destination_state[1]):
            conn.rollback()
            return {
                "status": "skipped",
                "domain": domain,
                "reason": "destination IP is absent, changed, or shared in the current scan",
            }

        # Recheck the domain operation grant after validating the exact
        # destination and immediately before handing that numeric IP to Nmap.
        authorized, reason = recheck_active_authorization(
            cur,
            scan_id=scan_id,
            domain_id=domain_id,
            testing_level="PORT_SCAN",
            required_scan_status="RUNNING",
        )
        if not authorized:
            if reason == "authorization check failed":
                return {
                    "status": "failed",
                    "domain": domain,
                    "reason": "runtime authorization could not be verified",
                }
            logging.info("Skipping port scan for %s: %s", domain, reason)
            return {"status": "skipped", "domain": domain, "reason": reason}
        conn.commit()

        # Authorization is checked independently in the worker immediately
        # before this single Nmap invocation. No batch decision is reused.
        if cancel_event.is_set():
            return {"status": "cancelled", "domain": domain}
        logging.info("Scanning %s", domain)
        ports = scan_ports(destination_ip, cancel_event=cancel_event)

        if cancel_event.is_set():
            return {"status": "cancelled", "domain": domain}

        cur = conn.cursor()
        require_running_scan(cur, scan_id)
        still_authorized, reason = recheck_active_authorization(
            cur,
            scan_id=scan_id,
            domain_id=domain_id,
            testing_level="PORT_SCAN",
            required_scan_status="RUNNING",
        )
        if not still_authorized:
            conn.rollback()
            return {
                "status": "failed",
                "domain": domain,
                "reason": f"authorization changed before result persistence: {reason}",
            }

        for port, service in ports:
            cur.execute("""
            INSERT INTO domain_ports(domain_id, scan_id, port, service)
            SELECT %s, %s, %s, %s
            WHERE EXISTS (
                SELECT 1 FROM scan_results sr
                WHERE sr.scan_id = %s AND sr.domain_id = %s
            )
            ON CONFLICT (domain_id, port, scan_id) DO NOTHING
            """, (domain_id, scan_id, port, service, scan_id, domain_id))
        conn.commit()

        if ports:
            logging.info("OPEN → %s → %s", domain, ports)
        return {"status": "complete", "domain": domain, "ports": len(ports)}
    except PortScanCancelled as exc:
        if conn is not None:
            conn.rollback()
        return {"status": "cancelled", "domain": domain, "reason": str(exc)}
    except Exception as exc:
        if conn is not None:
            try:
                conn.rollback()
            except Exception:
                pass
        logging.error("Port scan failed for %s: %s", domain, exc)
        return {"status": "failed", "domain": domain, "reason": str(exc)}
    finally:
        if conn is not None:
            conn.close()


def run_port_scan_pool(
    scan_id,
    domains,
    *,
    worker_count=None,
    cancel_event=None,
    target_worker=None,
):
    cancel_event = cancel_event or threading.Event()
    target_worker = target_worker or scan_target
    workers = configured_worker_count(worker_count)

    # The selection SQL already returns DISTINCT ON (d.id); this guard keeps
    # accidental duplicate input from launching duplicate Nmap processes.
    unique_targets = list({domain_id: (domain_id, domain, destination_ip)
                           for domain_id, domain, destination_ip in domains}.values())
    if not unique_targets:
        return []

    outcomes = []
    executor = ThreadPoolExecutor(max_workers=workers)
    futures = {
        executor.submit(
            target_worker, scan_id, domain_id, domain, destination_ip, cancel_event
        ): domain
        for domain_id, domain, destination_ip in unique_targets
    }
    try:
        for future in as_completed(futures):
            domain = futures[future]
            try:
                outcome = future.result()
            except Exception as exc:
                outcome = {"status": "failed", "domain": domain, "reason": str(exc)}
            outcomes.append(outcome)
    except KeyboardInterrupt as exc:
        cancel_event.set()
        for future in futures:
            future.cancel()
        executor.shutdown(wait=True, cancel_futures=True)
        raise PortScanStageError("port scan cancelled; incomplete work was not successful") from exc
    else:
        executor.shutdown(wait=True)

    incomplete = [item for item in outcomes if item.get("status") in ("failed", "cancelled")]
    if incomplete:
        examples = "; ".join(
            f"{item.get('domain')}: {item.get('reason', item['status'])}"
            for item in incomplete[:3]
        )
        raise PortScanStageError(
            f"port scan incomplete for {len(incomplete)} target(s): {examples}"
        )
    return outcomes


def _install_cancellation_handlers(cancel_event):
    previous = {}

    def request_cancellation(_signum, _frame):
        cancel_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        previous[sig] = signal.signal(sig, request_cancellation)
    return previous


def main():
    conn = get_conn()
    try:
        cur = conn.cursor()
        require_running_scan(cur, scan_id)
        domains = get_resolving_domains(cur, scan_id)
        conn.commit()
    finally:
        conn.close()

    print("Scan ID:", scan_id)
    print("Rows to scan:", len(domains))
    if not domains:
        print("No domains to scan for this run")
        print("Port scan enrichment complete")
        return

    cancel_event = threading.Event()
    previous_handlers = _install_cancellation_handlers(cancel_event)
    try:
        outcomes = run_port_scan_pool(
            scan_id,
            domains,
            cancel_event=cancel_event,
        )
    finally:
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)

    complete = sum(item["status"] == "complete" for item in outcomes)
    skipped = sum(item["status"] == "skipped" for item in outcomes)
    print(f"Port scan enrichment complete: {complete} scanned, {skipped} authorization skips")


if __name__ == "__main__":
    main()
