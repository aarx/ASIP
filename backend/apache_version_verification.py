"""Offline Apache header verification helpers.

This module deliberately has no HTTP client, resolver, or socket dependency.
It validates a future request plan and classifies a supplied response. Live
verification remains unavailable until a separately approved CAPD execution
path binds the ADHOC_CHECK recheck to a trusted transport.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urljoin, urlsplit, urlunsplit

from apache_version_evidence import parse_apache_server_header
from authorization_policy import default_operation_enabled


DEFAULT_TIMEOUT_SECONDS = 3.0
MAX_TIMEOUT_SECONDS = 5.0
APACHE_EVIDENCE_SOURCE = "domain_technology_observations"


class ApacheVerificationError(ValueError):
    """Unsafe target, request plan, or authorization state."""


def _canonical_host(value):
    return str(value or "").strip().lower().rstrip(".")


def _target_is_product_candidate(target):
    if not isinstance(target, dict):
        return False
    if target.get("asset_class") not in {"KNOWN", "SHADOW"}:
        return False
    if target.get("scannable") is not True or target.get("inventory_eligible") is not True:
        return False
    if target.get("classification") not in {"VERSION_KNOWN", "VERSION_UNKNOWN"}:
        return False
    evidence = target.get("evidence")
    return isinstance(evidence, list) and any(
        isinstance(row, dict)
        and row.get("source") == APACHE_EVIDENCE_SOURCE
        and str(row.get("technology") or "").lower() == "apache"
        and row.get("evidence_type") == "server_header"
        for row in evidence
    )


def _apache_observed_url(target):
    evidence = target.get("evidence") or []
    for row in evidence:
        if (isinstance(row, dict)
                and row.get("source") == APACHE_EVIDENCE_SOURCE
                and str(row.get("technology") or "").lower() == "apache"
                and row.get("evidence_type") == "server_header"
                and row.get("observed_url")):
            return row["observed_url"]
    raise ApacheVerificationError("Apache candidate has no stored observed origin")


def _validated_origin(url, approved_domain):
    try:
        parsed = urlsplit(str(url))
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise ApacheVerificationError("Invalid observed HTTP origin") from exc
    host = _canonical_host(parsed.hostname)
    if (parsed.scheme.lower() not in {"http", "https"}
            or not host
            or host != _canonical_host(approved_domain)
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or (port is not None and not 1 <= port <= 65535)):
        raise ApacheVerificationError("Request origin is outside the selected asset boundary")
    netloc = host if port is None else f"{host}:{port}"
    return urlunsplit((parsed.scheme.lower(), netloc, "/", "", ""))


def validate_public_destination(url, approved_domain, resolved_addresses):
    """Validate an already-resolved destination without performing DNS or I/O."""
    origin = _validated_origin(url, approved_domain)
    if not isinstance(resolved_addresses, (list, tuple)) or not resolved_addresses:
        raise ApacheVerificationError("Destination resolution is unavailable")
    try:
        addresses = [ipaddress.ip_address(str(value)) for value in resolved_addresses]
    except ValueError as exc:
        raise ApacheVerificationError("Destination contains an invalid IP address") from exc
    if any(not address.is_global for address in addresses):
        raise ApacheVerificationError("Non-public destinations are not permitted")
    return origin


def validate_redirect_destination(location, request_url, approved_domain, resolved_addresses):
    """Check a redirect target against the selected origin; never follows it."""
    target_url = urljoin(request_url, str(location or ""))
    try:
        parsed_target = urlsplit(target_url)
        target_origin_url = urlunsplit((
            parsed_target.scheme, parsed_target.netloc, "/", "", "",
        ))
        origin = validate_public_destination(
            target_origin_url, approved_domain, resolved_addresses
        )
    except ApacheVerificationError:
        return {"allowed": False, "reason": "redirect_outside_approved_destination"}
    # Redirect following is disabled even for same-origin locations in this
    # milestone. This check only reports whether a future reviewed policy
    # could keep the target within the already selected origin.
    request_origin = urlsplit(request_url)
    target_origin = urlsplit(origin)
    same_origin = (request_origin.scheme.lower(), _canonical_host(request_origin.hostname), request_origin.port) == (
        target_origin.scheme.lower(), _canonical_host(target_origin.hostname), target_origin.port,
    )
    return {"allowed": same_origin, "reason": "same_origin_only" if same_origin else "redirect_origin_changed"}


def authorize_apache_target(target, revalidate_target):
    """Fail closed unless ADHOC_CHECK is enabled and the caller rechecks scope.

    ``revalidate_target`` must be bound by a future trusted execution path to
    the existing per-target authorization policy. No caller is wired in here.
    """
    if not _target_is_product_candidate(target):
        raise ApacheVerificationError("Target is not an eligible Apache product candidate")
    if not default_operation_enabled("ADHOC_CHECK"):
        raise ApacheVerificationError("ADHOC_CHECK operation is not enabled")
    if not callable(revalidate_target):
        raise ApacheVerificationError("Fresh ADHOC_CHECK target authorization is required")
    try:
        authorized = revalidate_target(target, testing_level="ADHOC_CHECK")
    except Exception as exc:
        raise ApacheVerificationError("ADHOC_CHECK authorization recheck failed") from exc
    if authorized is not True:
        raise ApacheVerificationError("Target is not currently authorized for ADHOC_CHECK")
    return _validated_origin(_apache_observed_url(target), target.get("domain"))


def build_apache_dry_run(target, *, timeout=DEFAULT_TIMEOUT_SECONDS):
    """Build an inert request plan; it never resolves, requests, or persists."""
    if not _target_is_product_candidate(target):
        raise ApacheVerificationError("Target is not an eligible Apache product candidate")
    try:
        bounded_timeout = float(timeout)
    except (TypeError, ValueError) as exc:
        raise ApacheVerificationError("Timeout must be numeric") from exc
    if not 0 < bounded_timeout <= MAX_TIMEOUT_SECONDS:
        raise ApacheVerificationError(f"Timeout must be between 0 and {MAX_TIMEOUT_SECONDS} seconds")
    origin = _validated_origin(_apache_observed_url(target), target.get("domain"))
    return {
        "method": "GET",
        "url": origin,
        "timeout_seconds": bounded_timeout,
        "follow_redirects": False,
        "network_requests": 0,
        "database_writes": 0,
        "live_execution_enabled": False,
        "authorization_required": "ADHOC_CHECK plus fresh per-target authorization revalidation",
    }


def classify_apache_http_response(target, response, *, request_url, resolved_addresses):
    """Classify a supplied HTTP response; performs no I/O and never follows redirects."""
    origin = validate_public_destination(request_url, target.get("domain"), resolved_addresses)
    if not _target_is_product_candidate(target):
        raise ApacheVerificationError("Target is not an eligible Apache product candidate")
    status = getattr(response, "status_code", None)
    if not isinstance(status, int) or not 100 <= status <= 599:
        return {"outcome": "ERROR", "error_code": "invalid_http_response", "request_url": origin}
    if 300 <= status <= 399:
        return {
            "outcome": "INSUFFICIENT_EVIDENCE", "http_status": status,
            "redirect_followed": False, "error_code": "redirect_not_followed",
            "request_url": origin,
        }
    headers = getattr(response, "headers", {})
    server_header = next((value for key, value in headers.items() if str(key).lower() == "server"), None) if hasattr(headers, "items") else None
    parsed = parse_apache_server_header(server_header)
    return {**parsed, "http_status": status, "redirect_followed": False, "request_url": origin}


def classify_request_error(error):
    """Return safe error metadata without retaining exception text or secrets."""
    name = type(error).__name__.lower()
    return {"outcome": "ERROR", "error_code": "timeout" if "timeout" in name else "request_failed"}
