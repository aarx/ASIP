"""Dedicated, explicitly allowlisted HTTP redirect observation for Brand Exposure."""

import http.client
import ipaddress
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from http_probe import (
    _connect_pinned,
    _normalize_http_url,
    _prohibited_address,
    _resolve_allowed_addresses,
    _title,
)
from ownership import normalize_hostname


BRAND_REDIRECT_SCOPE = "BRAND_REDIRECT_OBSERVATION"
MAX_REDIRECTS = 3
MAX_CONCURRENCY = 2
CONNECT_TIMEOUT_SECONDS = 5
OVERALL_TIMEOUT_SECONDS = 10
MAX_RESPONSE_BYTES = 64 * 1024
EVIDENCE_SOURCE = "BRAND_REDIRECT_INTELLIGENCE"
MAX_REQUESTS_PER_TARGET = 1 + MAX_REDIRECTS
MAX_REQUESTS_PER_SCAN = 100000

_host_locks = {}
_host_locks_guard = threading.Lock()
_resolver_pool = ThreadPoolExecutor(max_workers=MAX_CONCURRENCY, thread_name_prefix="brand-redirect-dns")
_resolver_slots = threading.BoundedSemaphore(MAX_CONCURRENCY)


class RedirectObservationError(RuntimeError):
    """A bounded monitor request could not be completed safely."""


class RequestBudgetExceeded(PermissionError):
    """The approved campaign's request budget has been consumed."""


def _origin(url):
    parsed = urlsplit(url)
    host = normalize_hostname(parsed.hostname, require_fqdn=True)
    if parsed.scheme not in {"http", "https"} or host is None:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    if port not in (None, 80 if parsed.scheme == "http" else 443):
        return None
    return f"{parsed.scheme}://{host}"


def optional_pipeline_stage(scan_id):
    """Add the stage only when at least one unexpired redirect scope exists."""
    from db import get_conn

    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT COUNT(*) FROM active_scan_scopes
             WHERE testing_level = %s AND status = 'ACTIVE'
               AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
               AND NULLIF(BTRIM(monitoring_purpose), '') IS NOT NULL
               AND COALESCE(cardinality(eligible_discovery_sources), 0) > 0
               AND eligible_discovery_sources <@ ARRAY['brand_tld', 'brand_pattern']::text[]
               AND max_requests_per_scan BETWEEN 1 AND 100000
        """, (BRAND_REDIRECT_SCOPE,))
        row = cur.fetchone()
        enabled = bool(row and row[0] == 1)
        conn.rollback()
    except Exception:
        conn.rollback()
        return None
    finally:
        conn.close()
    if not enabled:
        return None
    return (
        "Brand Redirect Intelligence",
        f"python -u brand_redirect_worker.py {int(scan_id)}",
    )


def _lock_for_host(host):
    with _host_locks_guard:
        return _host_locks.setdefault(host, threading.Lock())


def _interrupt_connection(connection):
    """Break any in-flight read when the absolute per-target deadline expires."""
    sock = getattr(connection, "sock", None)
    if sock is not None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
    connection.close()


def _resolve_before_deadline(host, port, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0 or not _resolver_slots.acquire(
        timeout=min(remaining, CONNECT_TIMEOUT_SECONDS)
    ):
        raise TimeoutError("DNS resolution slot timed out")
    try:
        future = _resolver_pool.submit(_resolve_allowed_addresses, host, port)
    except Exception:
        _resolver_slots.release()
        raise
    future.add_done_callback(lambda _future: _resolver_slots.release())
    try:
        addresses = future.result(timeout=max(0.001, deadline - time.monotonic()))
    except FutureTimeoutError as exc:
        raise TimeoutError("DNS resolution exceeded request deadline") from exc
    if time.monotonic() > deadline:
        raise TimeoutError("DNS resolution exceeded request deadline")
    return addresses


def _single_request(url, *, authorize, deadline, reserve_request=None, on_request=None,
                    max_body_bytes=MAX_RESPONSE_BYTES):
    """Issue one GET directly to a freshly resolved, pinned public IP."""
    normalized_url = _normalize_http_url(url)
    parsed = urlsplit(normalized_url)
    host = parsed.hostname
    scheme = parsed.scheme
    port = 443 if scheme == "https" else 80
    if not authorize(_origin(normalized_url)):
        raise PermissionError("brand redirect origin is not authorized")

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("overall request deadline exceeded")

    host_lock = _lock_for_host(host)
    remaining = deadline - time.monotonic()
    if remaining <= 0 or not host_lock.acquire(
        timeout=min(CONNECT_TIMEOUT_SECONDS, max(0.01, remaining))
    ):
        raise TimeoutError("per-host observation slot timed out")
    connection = None
    deadline_timer = None
    try:
        if reserve_request is not None:
            reserve_request()
        # Resolve inside the serialized host slot for every new connection.
        addresses = _resolve_before_deadline(host, port, deadline)
        if not addresses or any(_prohibited_address(item) for item in addresses):
            raise OSError("no permitted public destination address")
        address = addresses[0]
        if not authorize(_origin(normalized_url)):
            raise PermissionError("brand redirect origin is no longer authorized")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("overall request deadline exceeded")
        timeout = min(CONNECT_TIMEOUT_SECONDS, remaining)
        sock = _connect_pinned(host, scheme, address, timeout=timeout)
        sock.settimeout(max(0.01, min(CONNECT_TIMEOUT_SECONDS, deadline - time.monotonic())))
        connection = http.client.HTTPConnection(host, port=port, timeout=timeout)
        connection.sock = sock
        # Socket timeouts are idle timeouts. A peer could otherwise trickle
        # bytes and exceed the operation-wide deadline, so close the socket
        # at the absolute deadline as well.
        deadline_timer = threading.Timer(
            max(0.001, deadline - time.monotonic()),
            _interrupt_connection,
            args=(connection,),
        )
        deadline_timer.daemon = True
        deadline_timer.start()
        if not authorize(_origin(normalized_url)):
            raise PermissionError("brand redirect origin is no longer authorized")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("overall request deadline exceeded")
        sock.settimeout(max(0.01, min(CONNECT_TIMEOUT_SECONDS, remaining)))
        if on_request is not None:
            on_request()
        connection.request(
            "GET",
            urlunsplit(("", "", parsed.path or "/", parsed.query, "")),
            headers={
                "Host": host,
                "User-Agent": "ShadowRecon-BrandRedirect/1.0",
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.1",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("overall request deadline exceeded")
        sock.settimeout(max(0.01, min(CONNECT_TIMEOUT_SECONDS, remaining)))
        body = response.read(max_body_bytes)
        if time.monotonic() > deadline:
            raise TimeoutError("overall request deadline exceeded")
        text = body.decode("utf-8", errors="replace")
        return {
            "url": normalized_url,
            "status": int(response.status),
            "reason": response.reason or "",
            "location": response.getheader("Location"),
            "page_title": _title(text),
            "response_retrieved": True,
        }
    finally:
        if deadline_timer is not None:
            deadline_timer.cancel()
        if connection is not None:
            connection.close()
        host_lock.release()


def observe_redirect_chain(
    domain,
    initial_url,
    *,
    scan_id,
    operation_id,
    authorize,
    on_request=None,
    request_once=None,
    now=None,
    monotonic=None,
):
    """Observe one explicitly authorized URL and at most three redirect hops."""
    request_once = request_once or _single_request
    monotonic = monotonic or time.monotonic
    started = monotonic()
    deadline = started + OVERALL_TIMEOUT_SECONDS
    observed_at = now or datetime.now(timezone.utc)
    try:
        current_url = _normalize_http_url(initial_url)
    except ValueError:
        raise ValueError("Initial Brand Redirect URL is invalid")
    evidence = {
        "originating_domain": domain,
        "origin_url": current_url,
        "initial_http_status": None,
        "http_observation_status": "UNKNOWN",
        "requests_attempted": 0,
        "redirect_location": None,
        "observed_hops": [],
        "last_reported_destination_url": None,
        "verified_final_url": None,
        "final_status": None,
        "page_title": None,
        "page_title_url": None,
        "observed_at": observed_at.isoformat(),
        "scan_id": int(scan_id),
        "operation_id": str(operation_id),
        "evidence_source": EVIDENCE_SOURCE,
        "evidence_scope": "CURRENT",
        "completeness": "ERROR",
    }
    seen = {current_url}
    followed = 0
    pending_hop = None

    def mark_request_started():
        evidence["requests_attempted"] += 1
        if pending_hop is not None:
            pending_hop["followed"] = True

    try:
        while True:
            if monotonic() >= deadline:
                raise TimeoutError("overall request deadline exceeded")
            origin = _origin(current_url)
            if not authorize(origin):
                evidence["completeness"] = "STOPPED_AT_AUTHORIZATION_BOUNDARY"
                break
            response = request_once(
                current_url,
                authorize=authorize,
                deadline=deadline,
                on_request=mark_request_started,
                reserve_request=on_request,
            )
            pending_hop = None
            status = int(response["status"])
            evidence["http_observation_status"] = "RESPONDED"
            if evidence["initial_http_status"] is None:
                evidence["initial_http_status"] = status
                evidence["redirect_location"] = response.get("location")
            if response.get("response_retrieved"):
                evidence["page_title"] = response.get("page_title") or None
                evidence["page_title_url"] = current_url

            if not 300 <= status < 400:
                evidence["verified_final_url"] = current_url
                evidence["final_status"] = status
                evidence["completeness"] = (
                    "NO_REDIRECT" if not evidence["observed_hops"] else "COMPLETE"
                )
                break

            location = response.get("location")
            if not location:
                evidence["completeness"] = "ERROR"
                evidence["observed_hops"].append({
                    "source_url": current_url,
                    "status": status,
                    "reported_location": None,
                    "reported_destination_url": None,
                    "followed": False,
                })
                break
            try:
                destination = _normalize_http_url(location, current_url)
            except (TypeError, ValueError):
                evidence["completeness"] = "ERROR"
                evidence["observed_hops"].append({
                    "source_url": current_url,
                    "status": status,
                    "reported_location": str(location),
                    "reported_destination_url": None,
                    "followed": False,
                })
                break

            evidence["last_reported_destination_url"] = destination
            if evidence["redirect_location"] is None:
                evidence["redirect_location"] = str(location)
            hop = {
                "source_url": current_url,
                "status": status,
                "reported_location": str(location),
                "reported_destination_url": destination,
                "followed": False,
            }
            evidence["observed_hops"].append(hop)
            destination_origin = _origin(destination)
            if not authorize(destination_origin):
                evidence["completeness"] = "STOPPED_AT_AUTHORIZATION_BOUNDARY"
                break
            if destination in seen:
                evidence["completeness"] = "REDIRECT_LOOP"
                break
            if followed >= MAX_REDIRECTS:
                evidence["completeness"] = "MAX_REDIRECT_HOPS"
                break
            followed += 1
            pending_hop = hop
            seen.add(destination)
            current_url = destination
    except TimeoutError:
        evidence["completeness"] = "TIMEOUT"
        if evidence["requests_attempted"]:
            evidence["http_observation_status"] = "NO_RESPONSE"
    except RequestBudgetExceeded:
        evidence["completeness"] = "REQUEST_BUDGET_EXHAUSTED"
    except PermissionError:
        evidence["completeness"] = "STOPPED_AT_AUTHORIZATION_BOUNDARY"
    except Exception:
        evidence["completeness"] = (
            "TIMEOUT" if monotonic() >= deadline else "ERROR"
        )
        if evidence["requests_attempted"]:
            evidence["http_observation_status"] = "NO_RESPONSE"
    return evidence


def is_prohibited_address(address):
    """Public testable wrapper around the shared HTTP observer IP policy."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return True
    return _prohibited_address(str(parsed))


def run_bounded_targets(rows, target_runner, *, workers=MAX_CONCURRENCY):
    """Run target callbacks with the module's hard global concurrency cap."""
    worker_count = min(MAX_CONCURRENCY, max(1, int(workers)))
    selected = list(rows)
    with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="brand-redirect") as pool:
        return list(pool.map(target_runner, selected))
