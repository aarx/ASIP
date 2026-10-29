"""Disabled-by-default safety foundation for future Adhoc campaign runs.

This module deliberately does not create campaigns, schedule work, resolve
DNS, or make HTTP requests.  It provides guards and pure network-safety
helpers for a future worker that supplies an authenticated operator, database
connection, lock lifetime, and transport implementation explicitly.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import re
from typing import Protocol

from adhoc_campaigns import (
    OperatorAuthorizationRequired,
    runtime_authorization_query,
)
from orchestration import ASIP_ORCHESTRATION_LOCK_ID
from php_cve_intelligence import evaluate_php_cve_applicability
from php_lifecycle import evaluate_php_lifecycle


RUNNER_ENABLED_BY_DEFAULT = False
DEFAULT_REQUEST_TIMEOUT_SECONDS = 4.0
DEFAULT_CAMPAIGN_TIMEOUT_SECONDS = 15 * 60
ALLOWED_SCHEMES = frozenset({"http", "https"})
DEFAULT_PORTS = {"http": 80, "https": 443}


class RunnerError(RuntimeError):
    """Base class for safe runner preparation failures."""


class RunnerDisabled(RunnerError):
    """Raised while live campaign execution is disabled."""


class RunnerExecutionUnavailable(RunnerError):
    """Raised because transport execution is not implemented in this batch."""


class CampaignNotFound(RunnerError):
    pass


class TargetNotFound(RunnerError):
    pass


class InvalidExecutionState(RunnerError):
    pass


class AuthorizationRevoked(RunnerError):
    pass


class CampaignCancelled(RunnerError):
    pass


class CampaignDeadlineExceeded(RunnerError):
    pass


class LockUnavailable(RunnerError):
    pass


class UnsafeHostname(RunnerError):
    pass


class UnsafeAddress(RunnerError):
    pass


class DNSRebindingDetected(RunnerError):
    pass


class RedirectRejected(RunnerError):
    pass


class UnsupportedRequest(RunnerError):
    pass


@dataclass(frozen=True)
class RunnerPolicy:
    enabled: bool = RUNNER_ENABLED_BY_DEFAULT
    request_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS
    campaign_timeout_seconds: int = DEFAULT_CAMPAIGN_TIMEOUT_SECONDS

    def __post_init__(self):
        if self.request_timeout_seconds <= 0:
            raise ValueError("request_timeout_seconds must be positive")
        if self.request_timeout_seconds > 30:
            raise ValueError("request_timeout_seconds exceeds the safety limit")
        if self.campaign_timeout_seconds <= 0:
            raise ValueError("campaign_timeout_seconds must be positive")


@dataclass(frozen=True)
class ExecutionContext:
    campaign_id: int
    target_id: int
    source_scan_id: int
    domain_id: int
    domain: str
    campaign_status: str
    target_status: str
    source_scan_status: str
    created_at: datetime
    ownership_status: str
    scannable: bool
    validation_source: str | None


@dataclass(frozen=True)
class PinnedResolution:
    hostname: str
    addresses: tuple[str, ...]


@dataclass(frozen=True)
class RequestPlan:
    hostname: str
    scheme: str
    port: int
    timeout_seconds: float
    pinned_resolution: PinnedResolution

    @property
    def url(self):
        return f"{self.scheme}://{self.hostname}"


class Transport(Protocol):
    """Future transport contract; this module never invokes it."""

    def request(self, plan: RequestPlan):  # pragma: no cover - interface only
        """Perform one request using the supplied pinned plan."""


def _as_datetime(value):
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    raise TypeError("timestamp must be a datetime or ISO timestamp")


def campaign_deadline(created_at, timeout_seconds=DEFAULT_CAMPAIGN_TIMEOUT_SECONDS):
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    return _as_datetime(created_at) + timedelta(seconds=timeout_seconds)


def validate_execution_context(context, *, now=None, deadline_at=None,
                               cancellation_requested=False,
                               timeout_seconds=DEFAULT_CAMPAIGN_TIMEOUT_SECONDS):
    """Apply all non-I/O execution guards to a loaded campaign target."""
    if context is None:
        raise CampaignNotFound("Campaign target context was not found")
    if context.campaign_status != "RUNNING":
        if context.campaign_status in {"CANCEL_REQUESTED", "CANCELLED"}:
            raise CampaignCancelled("Campaign is cancelled or cancellation was requested")
        raise InvalidExecutionState("Campaign must be RUNNING for target execution")
    if context.target_status not in {"PENDING", "RUNNING"}:
        raise InvalidExecutionState("Campaign target is not runnable")
    if context.source_scan_status != "SUCCEEDED":
        raise InvalidExecutionState("Campaign source scan is not successful")
    if (
        context.ownership_status != "CONFIRMED"
        or context.scannable is not True
        or context.validation_source != "manual"
    ):
        raise AuthorizationRevoked("Target no longer satisfies the authorization predicate")
    if cancellation_requested:
        raise CampaignCancelled("Campaign cancellation was requested")

    assessed = _as_datetime(now or datetime.now(timezone.utc))
    deadline = _as_datetime(deadline_at) if deadline_at else campaign_deadline(
        context.created_at, timeout_seconds
    )
    if assessed >= deadline:
        raise CampaignDeadlineExceeded("Campaign execution deadline has expired")
    return True


def load_execution_context(cur, campaign_id, target_id):
    """Load one scan-bound target without trusting its stored snapshot.

    The joins enforce campaign/target/source-scan membership.  The returned
    live domain fields are checked by ``validate_execution_context`` and must
    be rechecked immediately before any future transport call.
    """
    cur.execute(f"""
        SELECT c.id, c.status, c.source_scan_id, c.created_at,
               t.id, t.target_status, t.source_scan_id, t.domain_id,
               s.status, d.domain, d.ownership_status, d.scannable,
               d.validation_source
        FROM adhoc_campaigns c
        JOIN adhoc_campaign_targets t
          ON t.campaign_id = c.id
         AND t.source_scan_id = c.source_scan_id
        JOIN scans s ON s.id = t.source_scan_id
        JOIN scan_results sr
          ON sr.scan_id = t.source_scan_id
         AND sr.domain_id = t.domain_id
        JOIN domains d ON d.id = t.domain_id
        WHERE c.id = %s
          AND t.id = %s
        FOR UPDATE OF c, t
    """, (campaign_id, target_id))
    row = cur.fetchone()
    if row is None:
        raise TargetNotFound("Campaign target is not present in its source scan")
    return ExecutionContext(
        campaign_id=row[0], campaign_status=row[1], source_scan_id=row[2],
        created_at=_as_datetime(row[3]), target_id=row[4], target_status=row[5],
        domain_id=row[7], source_scan_status=row[8], domain=row[9],
        ownership_status=row[10], scannable=row[11], validation_source=row[12],
    )


def recheck_target_authorization(cur, domain_id, source_scan_id):
    """Recheck the live predicate immediately before future transport use."""
    query, params = runtime_authorization_query(domain_id, source_scan_id)
    cur.execute(query, params)
    row = cur.fetchone()
    if row is None:
        raise AuthorizationRevoked("Target no longer satisfies the authorization predicate")
    return row


def authorize_operator(operator_authorizer, operator_identity):
    if not callable(operator_authorizer) or not str(operator_identity or "").strip():
        raise OperatorAuthorizationRequired(
            "Runner preparation requires an authenticated operator"
        )
    identity = str(operator_identity).strip()
    try:
        allowed = bool(operator_authorizer(identity))
    except Exception as exc:
        raise OperatorAuthorizationRequired(
            "Operator authorization could not be established"
        ) from exc
    if not allowed:
        raise OperatorAuthorizationRequired("Operator is not authorized")
    return identity


def acquire_runner_lock(conn_factory, lock_id=ASIP_ORCHESTRATION_LOCK_ID):
    """Acquire the same session advisory lock used by full orchestration."""
    conn = conn_factory()
    try:
        cur = conn.cursor()
        cur.execute("SELECT pg_try_advisory_lock(%s)", (lock_id,))
        locked = bool(cur.fetchone()[0])
        conn.commit()
    except Exception:
        conn.rollback()
        conn.close()
        raise
    if not locked:
        conn.close()
        raise LockUnavailable("Full-scan orchestration lock is already held")
    return conn


def release_runner_lock(conn, lock_id=ASIP_ORCHESTRATION_LOCK_ID):
    try:
        cur = conn.cursor()
        cur.execute("SELECT pg_advisory_unlock(%s)", (lock_id,))
        cur.fetchone()
        conn.commit()
    finally:
        conn.close()


_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def validate_hostname(hostname):
    value = str(hostname or "").strip().lower().rstrip(".")
    if not value or len(value) > 253 or ".." in value:
        raise UnsafeHostname("Hostname is empty or malformed")
    try:
        if ipaddress.ip_address(value):
            raise UnsafeHostname("IP literals are not accepted as hostnames")
    except ValueError:
        pass
    try:
        ascii_value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise UnsafeHostname("Hostname cannot be IDNA-normalized") from exc
    if any(not _HOST_LABEL.fullmatch(label) for label in ascii_value.split(".")):
        raise UnsafeHostname("Hostname contains an unsafe label")
    return ascii_value


def validate_dns_answers(hostname, answers):
    normalized = validate_hostname(hostname)
    if not answers:
        raise UnsafeAddress("DNS returned no addresses")
    parsed = []
    seen = set()
    for answer in answers:
        try:
            address = ipaddress.ip_address(str(answer).strip())
        except ValueError as exc:
            raise UnsafeAddress("DNS returned a malformed address") from exc
        if not address.is_global:
            raise UnsafeAddress("DNS returned a non-public address")
        text = str(address)
        if text not in seen:
            parsed.append(text)
            seen.add(text)
    return PinnedResolution(normalized, tuple(parsed))


def validate_pinned_address(resolution, address):
    try:
        parsed = ipaddress.ip_address(str(address).strip())
    except ValueError as exc:
        raise DNSRebindingDetected("Connected address is malformed") from exc
    if not parsed.is_global or str(parsed) not in resolution.addresses:
        raise DNSRebindingDetected("Connected address was not pinned by DNS validation")
    return str(parsed)


def build_request_plan(hostname, resolution, *, scheme="https", port=None,
                       timeout_seconds=DEFAULT_REQUEST_TIMEOUT_SECONDS):
    normalized = validate_hostname(hostname)
    if resolution.hostname != normalized:
        raise DNSRebindingDetected("Pinned resolution belongs to another hostname")
    if scheme not in ALLOWED_SCHEMES:
        raise UnsupportedRequest("Only HTTP and HTTPS are allowed")
    expected_port = DEFAULT_PORTS[scheme]
    if port is not None and port != expected_port:
        raise UnsupportedRequest("Arbitrary ports are not allowed")
    if timeout_seconds <= 0 or timeout_seconds > 30:
        raise UnsupportedRequest("Request timeout is outside the bounded policy")
    return RequestPlan(
        hostname=normalized,
        scheme=scheme,
        port=expected_port,
        timeout_seconds=float(timeout_seconds),
        pinned_resolution=resolution,
    )


def reject_redirect(location):
    if location is not None and str(location).strip():
        raise RedirectRejected("Redirects are not followed by the Adhoc runner")
    return True


_SENSITIVE_KEY = re.compile(
    r"(?:authorization|cookie|set-cookie|x-api-key|api[_-]?key|token|secret|password)",
    re.IGNORECASE,
)
_SENSITIVE_VALUE = re.compile(
    r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+|"
    r"\b(?:api[_-]?key|token|secret|password)\s*[:=]\s*[^\s,;]+"
)


def sanitize_evidence(value, max_length=2048):
    """Return bounded evidence with credential-like fields and control bytes removed."""
    def clean(item):
        if isinstance(item, dict):
            return {
                str(key): "[REDACTED]" if _SENSITIVE_KEY.search(str(key)) else clean(val)
                for key, val in item.items()
            }
        if isinstance(item, (list, tuple)):
            return [clean(value) for value in item]
        text = str(item if item is not None else "")
        text = re.sub(r"[\x00-\x1f\x7f]", " ", text)
        return _SENSITIVE_VALUE.sub("[REDACTED]", text)

    cleaned = clean(value)
    if isinstance(cleaned, (dict, list)):
        rendered = json.dumps(cleaned, sort_keys=True, ensure_ascii=False)
    else:
        rendered = str(cleaned)
    return rendered[:max_length]


def evaluate_php_observation(observation, assessment_date):
    """Reuse the existing offline PHP lifecycle and CVE evaluators."""
    technology = observation.get("technology")
    version = observation.get("version")
    return {
        "technology": technology,
        "version": version,
        "lifecycle": evaluate_php_lifecycle(technology, version, assessment_date),
        "cve_intelligence": evaluate_php_cve_applicability(
            technology, version, assessment_date=assessment_date
        ),
    }


class AdhocCampaignRunner:
    """Preparation-only runner adapter; it has no execution path yet."""

    def __init__(self, *, policy=None, transport=None,
                 operator_authorizer=None, conn_factory=None):
        self.policy = policy or RunnerPolicy()
        self.transport = transport
        self.operator_authorizer = operator_authorizer
        self.conn_factory = conn_factory

    def prepare_target(self, conn, campaign_id, target_id, operator_identity,
                       *, now=None, cancellation_requested=False):
        if not self.policy.enabled:
            raise RunnerDisabled("Adhoc campaign execution is disabled")
        authorize_operator(self.operator_authorizer, operator_identity)
        cur = conn.cursor()
        context = load_execution_context(cur=cur, campaign_id=campaign_id,
                                         target_id=target_id)
        validate_execution_context(
            context,
            now=now,
            cancellation_requested=cancellation_requested,
            timeout_seconds=self.policy.campaign_timeout_seconds,
        )
        # This is the final live authorization check a future transport must
        # perform immediately before using the target.  The stored snapshot is
        # intentionally never used as authorization.
        recheck_target_authorization(cur, context.domain_id, context.source_scan_id)
        return context

    def execute_prepared(self, context):
        del context
        raise RunnerExecutionUnavailable(
            "Network execution is not implemented in Adhoc runner V1"
        )
