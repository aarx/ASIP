import logging
import ipaddress
import json
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
from ownership import reporting_asset_class_sql
from stage_progress import emit_stage_progress


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
MAX_REPORTED_DESTINATION_OBSERVATIONS = 16
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


class PortScanError(RuntimeError):
    """Nmap did not complete successfully; partial output is not persisted."""

    def __init__(self, message, partial_ports=()):
        super().__init__(message)
        self.partial_ports = tuple(partial_ports)


class PortScanTimeout(PortScanError):
    pass


class PortScanCancelled(PortScanError):
    pass


class PortScanHostUnavailable(PortScanError):
    """Nmap could not resolve or reach the approved hostname."""


class PortScanHostUnreachable(PortScanError):
    """Nmap completed its host check but reported the target unreachable."""


class PortScanStageError(RuntimeError):
    def __init__(self, message, outcomes=()):
        super().__init__(message)
        self.outcomes = tuple(outcomes)


def configured_worker_count(value=None):
    """Read a conservative worker limit, clamped to the supported range."""
    raw = os.environ.get("ASIP_NMAP_WORKERS") if value is None else value
    try:
        parsed = int(raw) if raw not in (None, "") else DEFAULT_PORT_SCAN_WORKERS
    except (TypeError, ValueError):
        parsed = DEFAULT_PORT_SCAN_WORKERS
    return min(MAX_PORT_SCAN_WORKERS, max(1, parsed))


def get_resolving_domains(cur, scan_id):
    asset_class = reporting_asset_class_sql("d.domain", "d.ownership_status")
    cur.execute(f"""
    SELECT DISTINCT ON (d.id) d.id, d.domain, s.ip, s.has_ip
    FROM domains d
    JOIN scan_results sr
      ON sr.domain_id = d.id
      AND sr.scan_id = %s
    LEFT JOIN domain_states s
      ON s.domain_id = d.id
      AND s.scan_id = sr.scan_id

    LEFT JOIN domain_ports dp
      ON d.id = dp.domain_id
      AND dp.scan_id = sr.scan_id

    WHERE dp.domain_id IS NULL
    AND ({asset_class}) IN ('KNOWN', 'SHADOW')
    AND {active_scan_authorization_sql("d", "PORT_SCAN")}
    ORDER BY d.id
    """, (scan_id,))
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


def validate_hostname(value):
    """Accept one normalized DNS hostname; never accept shell or Nmap syntax."""
    hostname = str(value or "").strip().lower().rstrip(".")
    if not _HOSTNAME_RE.fullmatch(hostname):
        raise PortScanError("Nmap destination is not a valid hostname")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return hostname
    raise PortScanError("Nmap destination must be a hostname, not a numeric IP")


def _known_destination_is_non_public(value):
    """Use a parseable current-scan DNS observation only as a safety hint.

    The observed address is never passed to Nmap and a changed public address
    does not deny an otherwise authorized hostname.  Non-IP placeholders are
    unknown rather than private.
    """
    try:
        address = ipaddress.ip_address(str(value or "").strip())
    except (TypeError, ValueError):
        return False
    return not address.is_global


def port_scan_ip_skip_reason(has_ip, value):
    """Require a usable address recorded for this scan and supported by Nmap."""
    if has_ip is not True or value is None or not str(value).strip():
        return "no_current_scan_ip"
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return "invalid_ip"
    if not address.is_global:
        return "non_public_ip"
    if address.version != 4:
        # This worker invokes Nmap without -6, so IPv6-only targets are not
        # eligible until the actual scan path supports IPv6.
        return "unsupported_ip_family"
    return None


def partition_port_scan_targets(rows):
    """Split authorized current-scan candidates into eligible and explicit skips."""
    targets = []
    skips = {}
    for domain_id, domain, ip, has_ip in rows:
        reason = port_scan_ip_skip_reason(has_ip, ip)
        if reason:
            skips[reason] = skips.get(reason, 0) + 1
        else:
            targets.append((domain_id, domain))
    return targets, skips


def _reported_destination_ip(stdout):
    """Extract the address Nmap reports for its hostname target, if present."""
    text = stdout.decode("utf-8", errors="replace") if isinstance(stdout, bytes) else str(stdout or "")
    for line in text.splitlines():
        match = re.match(r"^Nmap scan report for .+ \(([^()]+)\)\s*$", line.strip())
        if not match:
            continue
        try:
            return str(ipaddress.ip_address(match.group(1)))
        except ValueError:
            continue
    return None


class PortScanResult(list):
    """List-compatible parsed ports plus Nmap's reported destination IP."""

    def __init__(self, ports=(), destination_ip=None):
        super().__init__(ports)
        self.destination_ip = destination_ip


def scan_ports(hostname, cancel_event=None):
    """Run the existing bounded Nmap profile once, without retries."""
    hostname = validate_hostname(hostname)
    asm_ports = (
        "21,22,23,25,53,80,110,143,389,443,445,"
        "1521,3000,3306,3389,5000,5432,5900,"
        "5985,5986,6379,7001,7002,8000,8080,8443,"
        "8888,27017,11211"
    )
    # Do not use -n: targets are authorized hostnames and Nmap must resolve
    # them.  Omitting --resolve-all keeps this to Nmap's normal single-target
    # resolution behavior rather than expanding to every returned address.
    cmd = ["nmap", "-Pn", "-T3", "--open", "-p", asm_ports, hostname]

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
        raise PortScanError(f"could not start Nmap for {hostname}: {exc}") from exc

    deadline = time.monotonic() + PORT_SCAN_TIMEOUT_SECONDS
    while True:
        if cancel_event is not None and cancel_event.is_set():
            stdout = _terminate_process(process)
            partial_ports = _parse_ports(stdout)
            raise PortScanCancelled(
                f"cancelled Nmap for {hostname}; discarded {len(partial_ports)} partial ports",
                partial_ports,
            )

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            stdout = _terminate_process(process)
            partial_ports = _parse_ports(stdout)
            raise PortScanTimeout(
                f"Nmap timed out after {PORT_SCAN_TIMEOUT_SECONDS}s for {hostname}; "
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
    destination_ip = _reported_destination_ip(stdout)
    combined = f"{stdout or ''}\n{stderr or ''}"
    if re.search(r"failed to resolve|could not resolve|unable to resolve", combined, re.IGNORECASE):
        raise PortScanHostUnavailable(f"Nmap could not resolve hostname {hostname}")
    if re.search(r"host seems down|0 hosts? up|host is unreachable", combined, re.IGNORECASE):
        raise PortScanHostUnreachable(f"Nmap reported hostname unreachable: {hostname}")
    if process.returncode != 0:
        raise PortScanError(
            f"Nmap exited {process.returncode} for {hostname}: {stderr or ''}; "
            f"discarded {len(ports)} partial ports",
            ports,
        )
    return PortScanResult(ports, destination_ip)


def scan_target(scan_id, domain_id, domain, cancel_event):
    """Authorize, scan, and persist one target using its own DB connection."""
    conn = None
    nmap_attempted = False
    try:
        if cancel_event.is_set():
            return {"status": "cancelled", "domain_id": domain_id, "domain": domain}

        hostname = validate_hostname(domain)

        conn = get_conn()
        cur = conn.cursor()
        require_running_scan(cur, scan_id)
        asset_class = reporting_asset_class_sql("d.domain", "d.ownership_status")
        cur.execute(f"""
        SELECT d.domain, {asset_class}, ds.ip, ds.has_ip
        FROM domains d
        JOIN scan_results sr ON sr.domain_id = d.id AND sr.scan_id = %s
        JOIN scans scan ON scan.id = sr.scan_id AND scan.status = 'RUNNING'
        LEFT JOIN domain_states ds ON ds.domain_id = d.id AND ds.scan_id = sr.scan_id
        WHERE d.id = %s
        """, (scan_id, domain_id))
        target_state = cur.fetchone()
        if (target_state is None
                or validate_hostname(target_state[0]) != hostname
                or target_state[1] not in ("KNOWN", "SHADOW")):
            conn.rollback()
            return {
                "status": "skipped",
                "domain_id": domain_id,
                "domain": domain,
                "skip_reason": "authorization",
                "reason": "domain is not an authorized current-scan KNOWN/SHADOW member",
            }
        ip_skip_reason = port_scan_ip_skip_reason(target_state[3], target_state[2])
        if ip_skip_reason:
            conn.rollback()
            return {
                "status": "skipped",
                "domain_id": domain_id,
                "domain": domain,
                "skip_reason": ip_skip_reason,
                "reason": f"current-scan DNS IP is not usable for Port Scan: {ip_skip_reason}",
            }

        # Recheck the domain operation grant immediately before handing the
        # approved hostname to Nmap.
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
                    "domain_id": domain_id,
                    "domain": domain,
                    "reason": "runtime authorization could not be verified",
                }
            logging.info("Skipping port scan for %s: %s", domain, reason)
            return {"status": "skipped", "domain_id": domain_id, "domain": domain,
                    "skip_reason": "authorization", "reason": reason}
        conn.commit()

        # Authorization is checked independently in the worker immediately
        # before this single Nmap invocation. No batch decision is reused.
        if cancel_event.is_set():
            return {"status": "cancelled", "domain_id": domain_id, "domain": domain}
        logging.info("Scanning %s", domain)
        nmap_attempted = True
        try:
            ports = scan_ports(hostname, cancel_event=cancel_event)
        except PortScanHostUnavailable as exc:
            logging.info("Port scan target unavailable: %s", domain)
            return {"status": "dns_unresolved", "domain_id": domain_id, "domain": domain,
                    "reason": str(exc), "nmap_attempted": True}
        except PortScanTimeout as exc:
            logging.info("Port scan target timed out: %s", domain)
            return {"status": "timeout", "domain_id": domain_id, "domain": domain,
                    "reason": str(exc), "nmap_attempted": True}
        except PortScanHostUnreachable as exc:
            logging.info("Port scan target unreachable: %s", domain)
            return {"status": "unreachable", "domain_id": domain_id, "domain": domain,
                    "reason": str(exc), "nmap_attempted": True}

        if cancel_event.is_set():
            return {"status": "cancelled", "domain_id": domain_id, "domain": domain}

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
                "domain_id": domain_id,
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
        destination_ip = getattr(ports, "destination_ip", None)
        status = "complete" if ports else "no_sensitive_ports"
        logging.info(
            "Port scan completed domain=%s status=%s open_ports=%s destination_ip=%s",
            domain, status, len(ports), destination_ip or "unknown",
        )
        return {
            "status": status,
            "domain_id": domain_id,
            "domain": domain,
            "ports": len(ports),
            "destination_ip": destination_ip,
            "nmap_attempted": True,
        }
    except PortScanCancelled as exc:
        if conn is not None:
            conn.rollback()
        return {"status": "cancelled", "domain_id": domain_id, "domain": domain,
                "reason": str(exc), "nmap_attempted": nmap_attempted}
    except PortScanError as exc:
        if conn is not None:
            conn.rollback()
        logging.error("Port scan failed for %s: %s", domain, exc)
        return {"status": "failed", "domain_id": domain_id, "domain": domain,
                "reason": str(exc), "nmap_attempted": nmap_attempted}
    except Exception as exc:
        if conn is not None:
            try:
                conn.rollback()
            except Exception:
                pass
        logging.error("Port scan failed for %s: %s", domain, exc)
        return {"status": "failed", "domain_id": domain_id, "domain": domain,
                "reason": str(exc), "nmap_attempted": nmap_attempted}
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
    progress_callback=None,
):
    cancel_event = cancel_event or threading.Event()
    target_worker = target_worker or scan_target
    workers = configured_worker_count(worker_count)

    # The selection SQL already returns DISTINCT ON (d.id); this guard keeps
    # accidental duplicate input from launching duplicate Nmap processes.
    unique_targets = list({domain_id: (domain_id, domain)
                           for domain_id, domain, *_unused in domains}.values())
    if not unique_targets:
        return []

    outcomes = []
    executor = ThreadPoolExecutor(max_workers=workers)
    futures = {
        executor.submit(
            target_worker, scan_id, domain_id, domain, cancel_event
        ): (domain_id, domain)
        for domain_id, domain in unique_targets
    }
    try:
        for future in as_completed(futures):
            domain_id, domain = futures[future]
            try:
                outcome = future.result()
            except Exception as exc:
                outcome = {"status": "failed", "domain_id": domain_id,
                           "domain": domain, "reason": str(exc)}
            if isinstance(outcome, dict):
                outcome.setdefault("domain_id", domain_id)
                outcome.setdefault("domain", domain)
            outcomes.append(outcome)
            if progress_callback is not None:
                try:
                    progress_callback(outcomes)
                except Exception:
                    logging.exception("Noncritical port scan progress callback failed")
    except KeyboardInterrupt as exc:
        cancel_event.set()
        for future in futures:
            future.cancel()
        executor.shutdown(wait=True, cancel_futures=True)
        raise PortScanStageError("port scan cancelled; incomplete work was not successful") from exc
    else:
        executor.shutdown(wait=True)

    expected_ids = {domain_id for domain_id, _domain in unique_targets}
    outcome_ids = [item.get("domain_id") if isinstance(item, dict) else None
                   for item in outcomes]
    allowed_statuses = {
        "complete", "no_sensitive_ports", "dns_unresolved", "timeout",
        "unreachable", "skipped", "failed", "cancelled",
    }
    malformed = [item for item in outcomes
                 if not isinstance(item, dict)
                 or item.get("status") not in allowed_statuses
                 or item.get("domain_id") is None]
    duplicate_ids = len(outcome_ids) != len(set(outcome_ids))
    missing_ids = expected_ids - set(outcome_ids)
    unexpected_ids = set(outcome_ids) - expected_ids
    incomplete = [item for item in outcomes if isinstance(item, dict)
                  and item.get("status") in ("failed", "cancelled")]
    if malformed or duplicate_ids or missing_ids or unexpected_ids:
        raise PortScanStageError(
            "port scan could not account for every selected target exactly once "
            f"(missing={len(missing_ids)}, duplicate={duplicate_ids}, "
            f"unexpected={len(unexpected_ids)}, malformed={len(malformed)})",
            outcomes,
        )
    if incomplete:
        examples = "; ".join(
            f"{item.get('domain')}: {item.get('reason', item['status'])}"
            for item in incomplete[:3]
        )
        raise PortScanStageError(
            f"port scan had operationally incomplete work for {len(incomplete)} target(s): {examples}",
            outcomes,
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
    candidates = domains
    domains, ip_skips = partition_port_scan_targets(candidates)
    print("Port scan IP eligibility:", json.dumps({
        "candidates": len(candidates), "eligible": len(domains), "skipped": ip_skips,
    }, sort_keys=True))
    print("Rows to scan:", len(domains))
    if not domains:
        _emit_worker_summary([], [], 0.0, candidates=len(candidates),
                             ip_skips=ip_skips)
        print("No domains to scan for this run")
        print("Port scan enrichment complete")
        return

    cancel_event = threading.Event()
    previous_handlers = _install_cancellation_handlers(cancel_event)
    try:
        started = time.monotonic()
        last_progress = 0.0

        def report_progress(outcomes, force=False):
            nonlocal last_progress
            now = time.monotonic()
            if not force and now - last_progress < 30:
                return
            completed_count = len(outcomes)
            succeeded_count = sum(item.get("status") in ("complete", "no_sensitive_ports")
                                  for item in outcomes)
            emit_stage_progress(
                scan_id, "Port Scan", selected=len(domains), total=len(candidates),
                processed=len(outcomes) + sum(ip_skips.values()), completed=completed_count,
                succeeded=succeeded_count,
                failed=sum(item.get("status") == "failed" for item in outcomes),
                skipped=sum(ip_skips.values()) + sum(
                    item.get("status") in ("skipped", "cancelled") for item in outcomes
                ),
                elapsed_seconds=now - started,
            )
            last_progress = now

        report_progress([], force=True)
        try:
            outcomes = run_port_scan_pool(
                scan_id, domains, cancel_event=cancel_event,
                progress_callback=report_progress,
            )
        except PortScanStageError as exc:
            report_progress(exc.outcomes, force=True)
            _emit_worker_summary(domains, exc.outcomes, time.monotonic() - started,
                                 candidates=len(candidates), ip_skips=ip_skips)
            raise
        report_progress(outcomes, force=True)
        _emit_worker_summary(domains, outcomes, time.monotonic() - started,
                             candidates=len(candidates), ip_skips=ip_skips)
    finally:
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)

    complete = len(outcomes)
    skipped = sum(item["status"] == "skipped" for item in outcomes) + sum(ip_skips.values())
    print(f"Port scan enrichment complete: {complete} completed, {skipped} skipped")


def _emit_worker_summary(selected_targets, outcomes, elapsed_seconds, *, candidates=None,
                         ip_skips=None):
    reported = [
        {
            "domain_id": item["domain_id"],
            "status": item.get("status", "failed"),
            "destination_ip": item.get("destination_ip"),
        }
        for item in outcomes if item.get("domain_id") is not None
    ]
    summary = {
        "selected": len(selected_targets),
        "total_candidates": len(selected_targets) + sum((ip_skips or {}).values())
        if candidates is None else int(candidates),
        "processed": len(outcomes),
        "attempted": sum(item.get("nmap_attempted") is True for item in outcomes),
        "attempted_nmap_targets": sum(item.get("nmap_attempted") is True for item in outcomes),
        "ip_eligibility_skips": sum((ip_skips or {}).values()),
        "no_current_scan_ip_skips": (ip_skips or {}).get("no_current_scan_ip", 0),
        "invalid_ip_skips": (ip_skips or {}).get("invalid_ip", 0),
        "non_public_ip_skips": (ip_skips or {}).get("non_public_ip", 0),
        "unsupported_ip_family_skips": (ip_skips or {}).get("unsupported_ip_family", 0),
        "completed": len(outcomes),
        "succeeded": sum(item.get("status") in ("complete", "no_sensitive_ports") for item in outcomes),
        "successfully_probed_targets": sum(item.get("status") in ("complete", "no_sensitive_ports") for item in outcomes),
        "open_port_targets": sum(item.get("status") == "complete" for item in outcomes),
        "no_sensitive_ports": sum(item.get("status") == "no_sensitive_ports" for item in outcomes),
        "unavailable_targets": sum(item.get("status") == "unavailable" for item in outcomes),
        "dns_unresolved_targets": sum(item.get("status") == "dns_unresolved" for item in outcomes),
        "timeout_targets": sum(item.get("status") == "timeout" for item in outcomes),
        "unreachable_targets": sum(item.get("status") == "unreachable" for item in outcomes),
        "authorization_skips": sum(item.get("status") == "skipped"
                                     and item.get("skip_reason") == "authorization"
                                     for item in outcomes),
        "runtime_non_public_ip_skips": sum(item.get("status") == "skipped"
                                           and item.get("skip_reason") == "non_public_ip"
                                           for item in outcomes),
        "skipped": sum((ip_skips or {}).values()) + sum(
            item.get("status") in ("skipped", "cancelled") for item in outcomes
        ),
        "failed": sum(item.get("status") == "failed" for item in outcomes),
        "operational_failures": sum(item.get("status") == "failed" for item in outcomes),
        "accounted_targets": len(outcomes) + sum((ip_skips or {}).values()),
        "failed_targets": sum(item.get("status") == "failed" for item in outcomes),
        "cancelled_targets": sum(item.get("status") == "cancelled" for item in outcomes),
        "worker_errors": sum(item.get("status") == "failed" for item in outcomes),
        "elapsed_seconds": round(max(0.0, elapsed_seconds), 4),
        "nmap_destination_observations": reported[:MAX_REPORTED_DESTINATION_OBSERVATIONS],
        "nmap_destination_observations_truncated": max(
            0, len(reported) - MAX_REPORTED_DESTINATION_OBSERVATIONS
        ),
    }
    print("ASIP_WORKER_SUMMARY " + json.dumps(summary, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    main()
