"""Offline Apache header verification helpers.

This module deliberately has no HTTP client, resolver, or socket dependency.
It validates a future request plan and classifies a supplied response. Live
verification remains unavailable until a separately approved CAPD execution
path binds CAPD_HTTP_HEADER_VERIFY to a trusted transport.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import re
import uuid
from urllib.parse import urljoin, urlsplit, urlunsplit

from apache_version_evidence import parse_apache_server_header
from authorization_policy import default_operation_enabled
from capd_approval_contract import (
    APACHE_CHECK_ID,
    APACHE_CHECK_REVISION,
    CAPD_HTTP_HEADER_VERIFY,
    validate_apache_origin as _contract_validated_origin,
)


DEFAULT_TIMEOUT_SECONDS = 3.0
MAX_TIMEOUT_SECONDS = 5.0
AUTHORIZATION_CONTEXT_TTL = timedelta(minutes=5)
APACHE_EVIDENCE_SOURCE = "domain_technology_observations"


class ApacheVerificationError(ValueError):
    """Unsafe target, request plan, or authorization state."""


def _validated_origin(url, approved_domain):
    try:
        return _contract_validated_origin(url, approved_domain)
    except ValueError as exc:
        raise ApacheVerificationError(str(exc)) from exc


@dataclass(frozen=True)
class CapdAuthorizationContext:
    """Short-lived, local-CLI run context; context alone grants no authority."""

    run_id: str
    check_id: str
    check_revision: str
    source_scan_id: int
    issued_at: datetime
    expires_at: datetime
    invocation_source: str = "local_cli"

    def __post_init__(self):
        try:
            uuid.UUID(str(self.run_id))
        except (TypeError, ValueError, AttributeError) as exc:
            raise ApacheVerificationError("Invalid CAPD authorization run ID") from exc
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,120}", str(self.check_id or "")):
            raise ApacheVerificationError("Invalid CAPD check identifier")
        if not re.fullmatch(r"\d+\.\d+\.\d+", str(self.check_revision or "")):
            raise ApacheVerificationError("Invalid CAPD check revision")
        if not isinstance(self.source_scan_id, int) or self.source_scan_id <= 0:
            raise ApacheVerificationError("A source inventory scan is required")
        if (not isinstance(self.issued_at, datetime)
                or not isinstance(self.expires_at, datetime)
                or self.issued_at.tzinfo is None or self.expires_at.tzinfo is None
                or self.expires_at <= self.issued_at
                or self.expires_at - self.issued_at > AUTHORIZATION_CONTEXT_TTL):
            raise ApacheVerificationError("Invalid CAPD authorization context lifetime")


def create_authorization_context(check_id, check_revision, source_scan_id, *, now=None,
                                 run_id=None, expires_at=None):
    """Create an ephemeral context for one explicit local CLI dry-run/run."""
    check_id = str(check_id or "").strip()
    check_revision = str(check_revision or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,120}", check_id):
        raise ApacheVerificationError("Invalid CAPD check identifier")
    if not re.fullmatch(r"\d+\.\d+\.\d+", check_revision):
        raise ApacheVerificationError("Invalid CAPD check revision")
    try:
        source_scan_id = int(source_scan_id)
    except (TypeError, ValueError) as exc:
        raise ApacheVerificationError("A source inventory scan is required") from exc
    if source_scan_id <= 0:
        raise ApacheVerificationError("A source inventory scan is required")
    issued_at = now or datetime.now(timezone.utc)
    if issued_at.tzinfo is None:
        issued_at = issued_at.replace(tzinfo=timezone.utc)
    expires_at = expires_at or issued_at + AUTHORIZATION_CONTEXT_TTL
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return CapdAuthorizationContext(
        run_id=str(run_id or uuid.uuid4()), check_id=check_id,
        check_revision=check_revision, source_scan_id=source_scan_id,
        issued_at=issued_at, expires_at=expires_at,
    )


def evaluate_apache_authorization(
    context, target, *, trusted_operator_approval=None,
    fresh_target_recheck=None, now=None,
):
    """Return an auditable fail-closed decision for one run-scoped target.

    The two callbacks must be supplied only by a future trusted local
    execution boundary. No production caller or approval adapter currently
    exists, so ordinary CLI dry-runs cannot approve targets.
    """
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    reasons = []
    structural_ok = True
    if not isinstance(context, CapdAuthorizationContext):
        reasons.append("INVALID_RUN_AUTHORIZATION_CONTEXT")
        structural_ok = False
    else:
        if (context.check_id != APACHE_CHECK_ID
                or context.check_revision != APACHE_CHECK_REVISION):
            reasons.append("UNSUPPORTED_APACHE_CHECK_REVISION")
            structural_ok = False
        if context.invocation_source != "local_cli":
            reasons.append("UNTRUSTED_INVOCATION_SOURCE")
            structural_ok = False
        if now < context.issued_at or now >= context.expires_at:
            reasons.append("AUTHORIZATION_CONTEXT_EXPIRED_OR_STALE")
            structural_ok = False
        if not isinstance(target, dict) or target.get("source_scan_id") != context.source_scan_id:
            reasons.append("SOURCE_SCAN_CONTEXT_MISMATCH")
            structural_ok = False
    if not _target_is_product_candidate(target):
        reasons.append("TARGET_NOT_ELIGIBLE_APACHE_PRODUCT_CANDIDATE")
        structural_ok = False
    if isinstance(target, dict):
        try:
            _validated_origin(_apache_observed_url(target), target.get("domain"))
        except ApacheVerificationError:
            reasons.append("TARGET_DESTINATION_NOT_BOUND_TO_STORED_EVIDENCE")
            structural_ok = False
    operation_enabled = default_operation_enabled(CAPD_HTTP_HEADER_VERIFY)
    if not operation_enabled:
        reasons.append("CAPD_HTTP_HEADER_VERIFY_OPERATION_DISABLED")

    if not callable(trusted_operator_approval):
        reasons.append("TRUSTED_CAPD_OPERATOR_APPROVAL_UNAVAILABLE")
    elif structural_ok and operation_enabled:
        try:
            if trusted_operator_approval(context, target) is not True:
                reasons.append("TRUSTED_OPERATOR_APPROVAL_DENIED")
        except Exception:
            reasons.append("TRUSTED_OPERATOR_APPROVAL_FAILED")

    if not callable(fresh_target_recheck):
        reasons.append("FRESH_TARGET_AUTHORIZATION_RECHECK_UNAVAILABLE")
    elif structural_ok:
        try:
            if fresh_target_recheck(
                context, target, testing_level=CAPD_HTTP_HEADER_VERIFY
            ) is not True:
                reasons.append("TARGET_NOT_AUTHORIZED_FOR_CAPD_HTTP_HEADER_VERIFY")
        except Exception:
            reasons.append("TARGET_AUTHORIZATION_RECHECK_FAILED")

    decision = "AUTHORIZED" if not reasons else "NOT_AUTHORIZED"
    return {
        "decision": decision,
        "run_id": context.run_id if isinstance(context, CapdAuthorizationContext) else None,
        "check_id": context.check_id if isinstance(context, CapdAuthorizationContext) else None,
        "check_revision": context.check_revision if isinstance(context, CapdAuthorizationContext) else None,
        "source_scan_id": context.source_scan_id if isinstance(context, CapdAuthorizationContext) else None,
        "asset_id": target.get("domain_id") if isinstance(target, dict) else None,
        "asset_domain": target.get("domain") if isinstance(target, dict) else None,
        "operation": CAPD_HTTP_HEADER_VERIFY,
        "reason_codes": reasons or ["ALL_REQUIRED_GATES_PASSED"],
    }


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


def authorize_apache_target(context, target, *, trusted_operator_approval=None,
                            fresh_target_recheck=None, now=None):
    """Return the complete run-scoped decision; context alone never grants."""
    return evaluate_apache_authorization(
        context, target, trusted_operator_approval=trusted_operator_approval,
        fresh_target_recheck=fresh_target_recheck, now=now,
    )


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
        "authorization_required": "CAPD_HTTP_HEADER_VERIFY plus signed local approval and fresh per-target authorization revalidation",
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
