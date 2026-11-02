"""Disabled-by-default safety foundation for future Adhoc campaign runs.

This module deliberately does not create campaigns, schedule work, resolve
DNS, or make HTTP requests.  It provides guards and pure network-safety
helpers for a future worker that supplies an authenticated operator, database
connection, lock lifetime, and transport implementation explicitly.
"""

from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
import ipaddress
import json
import re
from typing import Protocol

from adhoc_campaigns import (
    OperatorAuthorizationRequired,
    runtime_authorization_query,
    validate_campaign_transition,
)
from orchestration import ASIP_ORCHESTRATION_LOCK_ID
from php_cve_intelligence import evaluate_php_cve_applicability
from php_lifecycle import evaluate_php_lifecycle


RUNNER_ENABLED_BY_DEFAULT = False
DEFAULT_REQUEST_TIMEOUT_SECONDS = 4.0
DEFAULT_CAMPAIGN_TIMEOUT_SECONDS = 15 * 60
ALLOWED_SCHEMES = frozenset({"http", "https"})
DEFAULT_PORTS = {"http": 80, "https": 443}
TRANSPORT_FAILURE_CODES = frozenset({
    "transport_timeout", "transport_error", "transport_unavailable",
})


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


class ResolverFailure(RunnerError):
    """Deterministic resolver failure supplied by a future resolver adapter."""


class TransportFailure(RunnerError):
    """Deterministic transport failure supplied by a future transport adapter."""


@dataclass(frozen=True)
class RunnerPolicy:
    enabled: bool = RUNNER_ENABLED_BY_DEFAULT
    request_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS
    campaign_timeout_seconds: int = DEFAULT_CAMPAIGN_TIMEOUT_SECONDS
    scheme: str = "https"

    def __post_init__(self):
        if self.request_timeout_seconds <= 0:
            raise ValueError("request_timeout_seconds must be positive")
        if self.request_timeout_seconds > 30:
            raise ValueError("request_timeout_seconds exceeds the safety limit")
        if self.campaign_timeout_seconds <= 0:
            raise ValueError("campaign_timeout_seconds must be positive")
        if self.scheme not in ALLOWED_SCHEMES:
            raise ValueError("scheme must be HTTP or HTTPS")


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
    assessment_date: date | None = None
    dataset_revision: str | None = None


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


@dataclass(frozen=True)
class TransportResponse:
    """Safe transport adapter response; no raw body is accepted."""

    http_status: int | None
    connected_peer_ip: str | None
    redirect_status: int | None
    redirect_location: str | None
    fingerprint_headers: dict
    observed_at: datetime | str | None
    failure_code: str | None = None


class Transport(Protocol):
    """Injected transport contract; the runner never supplies a default."""

    def request(self, plan: RequestPlan) -> TransportResponse:  # pragma: no cover
        """Return status, pinned peer, allowlisted headers, and timestamp."""


class Resolver(Protocol):
    """Injected resolver contract; no socket resolver is used by this module."""

    def resolve(self, hostname: str):  # pragma: no cover - interface only
        """Return DNS answer strings for the hostname."""


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
    ):
        raise AuthorizationRevoked("Target no longer satisfies technical eligibility")
    # Direct manual authorization and approved-scope authorization are both
    # checked by recheck_target_authorization immediately before transport.
    # This context guard must not reintroduce the legacy manual-only rule.
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
               d.validation_source, c.assessment_date, c.dataset_revision
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
        assessment_date=row[13], dataset_revision=row[14],
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


ALLOWLISTED_FINGERPRINT_HEADERS = {
    "server": "Server",
    "x-powered-by": "X-Powered-By",
    "x-aspnet-version": "X-AspNet-Version",
}


def sanitize_fingerprint_headers(headers):
    """Retain only parser-relevant headers and sanitize their values."""
    if not hasattr(headers, "items"):
        raise TransportFailure("transport_invalid_headers")
    cleaned = {}
    for key, value in headers.items():
        canonical = ALLOWLISTED_FINGERPRINT_HEADERS.get(str(key).lower())
        if canonical:
            cleaned[canonical] = sanitize_evidence(value, max_length=256)
    return cleaned


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
    """Disabled-by-default, serial campaign execution service."""

    def __init__(self, *, policy=None, transport=None,
                 resolver=None, fingerprinter=None, operator_authorizer=None,
                 conn_factory=None, clock=None):
        self.policy = policy or RunnerPolicy()
        self.transport = transport
        self.resolver = resolver
        self.fingerprinter = fingerprinter
        self.operator_authorizer = operator_authorizer
        self.conn_factory = conn_factory
        self.clock = clock or (lambda: datetime.now(timezone.utc))

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

    def run_campaign(self, campaign_id, operator_identity, *, cancel_check=None):
        """Run one existing RUNNING campaign with injected offline adapters.

        This method is intentionally not wired to FastAPI, startup, or a
        scheduler.  A caller must explicitly enable the policy and provide
        every dependency, including a resolver, transport, fingerprinter,
        operator authorizer, and database connection factory.
        """
        if not self.policy.enabled:
            raise RunnerDisabled("Adhoc campaign execution is disabled")
        authorize_operator(self.operator_authorizer, operator_identity)
        if not callable(self.resolver) and not hasattr(self.resolver, "resolve"):
            raise RunnerExecutionUnavailable("A resolver dependency is required")
        if not callable(self.transport) and not hasattr(self.transport, "request"):
            raise RunnerExecutionUnavailable("A transport dependency is required")
        if not callable(self.fingerprinter):
            raise RunnerExecutionUnavailable("A fingerprinter dependency is required")
        if not callable(self.conn_factory):
            raise RunnerExecutionUnavailable("A database connection factory is required")

        # Keep the session-level exclusion lock on a dedicated connection for
        # the complete run.  A separate work connection lets another trusted
        # connection record cancellation while DNS/transport is in flight.
        lock_conn = acquire_runner_lock(self.conn_factory)
        work_conn = None
        try:
            work_conn = self.conn_factory()
            result = self._run_locked(work_conn, campaign_id, cancel_check)
        except Exception:
            try:
                if work_conn is not None:
                    work_conn.rollback()
            finally:
                if work_conn is not None:
                    work_conn.close()
                try:
                    lock_conn.rollback()
                finally:
                    release_runner_lock(lock_conn)
            raise
        else:
            work_conn.close()
            release_runner_lock(lock_conn)
            return result

    def _run_locked(self, conn, campaign_id, cancel_check):
        cur = conn.cursor()
        campaign = self._load_campaign(cur, campaign_id)
        self._require_running_campaign(campaign)
        target_ids = self._load_pending_targets(cur, campaign_id)
        conn.commit()

        completed = 0
        failed = 0
        skipped = 0
        cancelled = False
        deadline_expired = False
        for target_id in target_ids:
            try:
                self._check_campaign_deadline(conn, campaign_id, cancel_check)
            except CampaignCancelled:
                self._cancel_pending_targets(conn, campaign_id, "campaign_cancelled")
                cancelled = True
                break
            except CampaignDeadlineExceeded:
                self._skip_pending_targets(conn, campaign_id, "campaign_deadline_exceeded")
                deadline_expired = True
                break

            outcome = self._process_target(conn, campaign_id, target_id)
            if outcome == "completed":
                completed += 1
            elif outcome == "skipped":
                skipped += 1
            else:
                failed += 1

        return self._finalize_campaign(
            conn,
            campaign_id,
            cancelled=cancelled,
            deadline_expired=deadline_expired,
            completed=completed,
            failed=failed,
            skipped=skipped,
        )

    @staticmethod
    def _load_campaign(cur, campaign_id):
        cur.execute("""
            SELECT id, status, source_scan_id, created_at,
                   assessment_date, dataset_revision
            FROM adhoc_campaigns
            WHERE id = %s
            FOR UPDATE
        """, (campaign_id,))
        row = cur.fetchone()
        if row is None:
            raise CampaignNotFound("Campaign does not exist")
        return {
            "campaign_id": row[0],
            "status": row[1],
            "source_scan_id": row[2],
            "created_at": _as_datetime(row[3]),
            "assessment_date": row[4],
            "dataset_revision": row[5],
        }

    @staticmethod
    def _require_running_campaign(campaign):
        if campaign["status"] in {"CANCEL_REQUESTED", "CANCELLED"}:
            raise CampaignCancelled("Campaign is cancelled or cancellation was requested")
        if campaign["status"] != "RUNNING":
            raise InvalidExecutionState("Campaign must be RUNNING for execution")

    @staticmethod
    def _load_pending_targets(cur, campaign_id):
        cur.execute("""
            SELECT t.id, t.target_status,
                   EXISTS (
                       SELECT 1 FROM adhoc_campaign_results r
                       WHERE r.campaign_id = t.campaign_id
                         AND r.target_id = t.id
                   ) AS has_result
            FROM adhoc_campaign_targets t
            WHERE t.campaign_id = %s
            ORDER BY t.id
        """, (campaign_id,))
        rows = cur.fetchall()
        pending = []
        for target_id, target_status, has_result in rows:
            if target_status == "RUNNING":
                raise InvalidExecutionState("A campaign target is already running")
            if target_status == "PENDING" and has_result:
                raise InvalidExecutionState("A pending target already has a result")
            if target_status == "PENDING":
                pending.append(target_id)
        if not rows:
            raise InvalidExecutionState("Campaign has no targets")
        return pending

    def _check_campaign_deadline(self, conn, campaign_id, cancel_check):
        if callable(cancel_check) and cancel_check():
            raise CampaignCancelled("Campaign cancellation was requested")
        cur = conn.cursor()
        campaign = self._load_campaign(cur, campaign_id)
        self._require_running_campaign(campaign)
        if _as_datetime(self.clock()) >= campaign_deadline(
            campaign["created_at"], self.policy.campaign_timeout_seconds
        ):
            raise CampaignDeadlineExceeded("Campaign execution deadline has expired")
        conn.commit()
        return campaign

    def _process_target(self, conn, campaign_id, target_id):
        context = None
        target_started = False
        try:
            cur = conn.cursor()
            context = load_execution_context(cur, campaign_id, target_id)
            validate_execution_context(
                context,
                now=self.clock(),
                timeout_seconds=self.policy.campaign_timeout_seconds,
            )
            recheck_target_authorization(cur, context.domain_id, context.source_scan_id)
            cur.execute("""
                UPDATE adhoc_campaign_targets
                SET target_status = 'RUNNING', started_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s AND campaign_id = %s AND target_status = 'PENDING'
            """, (target_id, campaign_id))
            if cur.rowcount != 1:
                raise InvalidExecutionState("Target could not be claimed")
            conn.commit()
            target_started = True

            try:
                answers = self.resolver.resolve(context.domain)
            except Exception as exc:
                raise ResolverFailure("dns_resolution_failed") from exc
            resolution = validate_dns_answers(context.domain, answers)

            current = self._reload_target_for_request(conn, campaign_id, target_id)
            validate_execution_context(
                current,
                now=self.clock(),
                timeout_seconds=self.policy.campaign_timeout_seconds,
            )
            recheck_target_authorization(
                conn.cursor(), current.domain_id, current.source_scan_id
            )
            plan = build_request_plan(
                current.domain,
                resolution,
                scheme=self.policy.scheme,
                timeout_seconds=self.policy.request_timeout_seconds,
            )
            # This is the final authorization/state check before dispatch.
            # Commit before transport so no SQL row lock or stale transaction
            # remains open while the injected transport is running.
            current = self._reload_target_for_request(conn, campaign_id, target_id)
            validate_execution_context(
                current,
                now=self.clock(),
                timeout_seconds=self.policy.campaign_timeout_seconds,
            )
            recheck_target_authorization(
                conn.cursor(), current.domain_id, current.source_scan_id
            )
            conn.commit()
            try:
                response = self.transport.request(plan)
            except TimeoutError as exc:
                raise TransportFailure("transport_timeout") from exc
            except Exception as exc:
                raise TransportFailure("transport_error") from exc
            self._validate_transport_response(response, resolution)

            after = self._reload_target_for_request(conn, campaign_id, target_id)
            validate_execution_context(
                after,
                now=self.clock(),
                timeout_seconds=self.policy.campaign_timeout_seconds,
            )
            recheck_target_authorization(
                conn.cursor(), after.domain_id, after.source_scan_id
            )
            headers = sanitize_fingerprint_headers(response.fingerprint_headers)
            try:
                raw_observations = self.fingerprinter(headers)
                observations = _normalize_fingerprint_observations(
                    raw_observations,
                    plan.url,
                )
            except RunnerError:
                raise
            except Exception as exc:
                raise TransportFailure("fingerprint_failed") from exc
            self._persist_success(conn, after, response, observations)
            return "completed"
        except Exception as exc:
            if context is None:
                raise
            self._persist_failure(
                conn,
                context,
                _failure_code(exc),
                target_status=(
                    "CANCELLED" if isinstance(exc, CampaignCancelled)
                    else "SKIPPED" if isinstance(exc, (AuthorizationRevoked, CampaignDeadlineExceeded))
                    else "FAILED"
                ),
            )
            return "skipped" if isinstance(exc, (AuthorizationRevoked, CampaignDeadlineExceeded)) else "failed"

    def _reload_target_for_request(self, conn, campaign_id, target_id):
        return load_execution_context(conn.cursor(), campaign_id, target_id)

    @staticmethod
    def _validate_transport_response(response, resolution):
        if not isinstance(response, TransportResponse):
            raise TransportFailure("transport_invalid_response")
        if response.failure_code:
            if response.failure_code not in TRANSPORT_FAILURE_CODES:
                raise TransportFailure("transport_invalid_failure_code")
            raise TransportFailure(response.failure_code)
        if response.http_status is None or response.observed_at is None:
            raise TransportFailure("transport_incomplete_response")
        validate_pinned_address(resolution, response.connected_peer_ip)
        if (
            response.redirect_status is not None
            and 300 <= response.redirect_status <= 399
        ) or response.redirect_location:
            raise RedirectRejected("Redirects are not followed by the Adhoc runner")

    def _persist_success(self, conn, context, response, observations):
        lifecycle, cve_intelligence = _php_evaluation_summary(
            observations, context
        )
        evaluation_status, classification = _classify_observations(observations)
        cur = conn.cursor()
        try:
            _insert_result(
                cur,
                context,
                execution_status="COMPLETED",
                evidence_status="COLLECTED",
                evaluation_status=evaluation_status,
                classification=classification,
                observations=observations,
                lifecycle=lifecycle,
                cve_intelligence=cve_intelligence,
                observed_at=_as_datetime(response.observed_at),
                dataset_revision=context.dataset_revision,
            )
            cur.execute("""
                UPDATE adhoc_campaign_targets
                SET target_status = 'COMPLETED', completed_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s AND campaign_id = %s
            """, (context.target_id, context.campaign_id))
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def _persist_failure(self, conn, context, failure_code, target_status="FAILED"):
        cur = conn.cursor()
        try:
            evidence_status = "BLOCKED" if failure_code in {
                "authorization_revoked", "unsafe_dns", "peer_ip_mismatch",
                "redirect_rejected", "campaign_cancelled",
                "campaign_deadline_exceeded",
            } else "FAILED"
            _insert_result(
                cur,
                context,
                execution_status=target_status,
                evidence_status=evidence_status,
                evaluation_status="NOT_EVALUATED",
                classification=None,
                observations=[],
                lifecycle=None,
                cve_intelligence=None,
                observed_at=None,
                dataset_revision=context.dataset_revision,
                failure_code=failure_code,
            )
            cur.execute("""
                UPDATE adhoc_campaign_targets
                SET target_status = %s, completed_at = CURRENT_TIMESTAMP,
                    skip_reason_code = %s, updated_at = CURRENT_TIMESTAMP
                WHERE id = %s AND campaign_id = %s
            """, (target_status, failure_code, context.target_id, context.campaign_id))
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def _cancel_pending_targets(self, conn, campaign_id, reason):
        self._skip_pending_targets(conn, campaign_id, reason, target_status="CANCELLED")

    def _skip_pending_targets(self, conn, campaign_id, reason, target_status="SKIPPED"):
        cur = conn.cursor()
        cur.execute("""
            SELECT t.id, t.source_scan_id, t.domain_id, t.domain_snapshot,
                   t.target_status, c.created_at, c.assessment_date,
                   c.dataset_revision
            FROM adhoc_campaign_targets t
            JOIN adhoc_campaigns c ON c.id = t.campaign_id
            WHERE t.campaign_id = %s AND t.target_status = 'PENDING'
            ORDER BY t.id
        """, (campaign_id,))
        rows = cur.fetchall()
        try:
            for row in rows:
                context = ExecutionContext(
                    campaign_id=campaign_id, target_id=row[0],
                    source_scan_id=row[1], domain_id=row[2],
                    domain=row[3], campaign_status="RUNNING",
                    target_status=row[4], source_scan_status="SUCCEEDED",
                    created_at=_as_datetime(row[5]), ownership_status="CONFIRMED",
                    scannable=True, validation_source="manual",
                    assessment_date=row[6], dataset_revision=row[7],
                )
                _insert_result(
                    cur, context, execution_status=target_status,
                    evidence_status="BLOCKED", evaluation_status="NOT_EVALUATED",
                    classification=None, observations=[], lifecycle=None,
                    cve_intelligence=None, observed_at=None,
                    dataset_revision=context.dataset_revision,
                    skip_reason_code=reason, failure_code=None,
                )
                cur.execute("""
                    UPDATE adhoc_campaign_targets
                    SET target_status = %s, completed_at = CURRENT_TIMESTAMP,
                        skip_reason_code = %s, updated_at = CURRENT_TIMESTAMP
                    WHERE id = %s AND campaign_id = %s
                """, (target_status, reason, row[0], campaign_id))
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def _finalize_campaign(self, conn, campaign_id, *, cancelled,
                           deadline_expired, completed, failed, skipped):
        cur = conn.cursor()
        cur.execute(
            "SELECT status FROM adhoc_campaigns WHERE id = %s FOR UPDATE",
            (campaign_id,),
        )
        current_status = cur.fetchone()[0]
        if current_status in {"CANCEL_REQUESTED", "CANCELLED"}:
            # A separate connection may request cancellation while transport
            # is active.  Convert remaining work before final status selection.
            self._cancel_pending_targets(conn, campaign_id, "campaign_cancelled")
            cancelled = True
        cur.execute("""
            SELECT
                COUNT(*),
                COUNT(*) FILTER (WHERE target_status = 'COMPLETED'),
                COUNT(*) FILTER (WHERE target_status = 'FAILED'),
                COUNT(*) FILTER (WHERE target_status = 'SKIPPED'),
                COUNT(*) FILTER (WHERE target_status = 'CANCELLED'),
                COUNT(*) FILTER (WHERE target_status IN ('PENDING', 'RUNNING'))
            FROM adhoc_campaign_targets
            WHERE campaign_id = %s
        """, (campaign_id,))
        total, done, failed_targets, skipped_targets, cancelled_targets, pending = cur.fetchone()
        if cancelled or cancelled_targets:
            status, failure_code = "CANCELLED", "campaign_cancelled"
        elif deadline_expired:
            status = "PARTIAL" if done or failed_targets else "FAILED"
            failure_code = "campaign_deadline_exceeded"
        elif pending:
            status, failure_code = "PARTIAL", "targets_incomplete"
        elif done == total and total and not skipped_targets and not failed_targets:
            status, failure_code = "SUCCEEDED", None
        elif not done and skipped_targets == total and total:
            status, failure_code = "FAILED", "all_targets_skipped"
        elif not done and failed_targets + skipped_targets == total and total:
            status, failure_code = "FAILED", "no_successful_evaluations"
        elif done or failed_targets or skipped_targets:
            status, failure_code = "PARTIAL", "partial_target_failure"
        else:
            status, failure_code = "FAILED", "no_targets"
        self._update_campaign_status(conn, campaign_id, status, failure_code)
        return {
            "campaign_id": campaign_id,
            "status": status,
            "targets": total,
            "completed": done,
            "failed": failed_targets,
            "skipped": skipped_targets,
            "cancelled": cancelled_targets,
            "processed": done + failed_targets + skipped_targets + cancelled_targets,
        }

    @staticmethod
    def _update_campaign_status(conn, campaign_id, next_status, failure_code):
        cur = conn.cursor()
        cur.execute(
            "SELECT status FROM adhoc_campaigns WHERE id = %s FOR UPDATE",
            (campaign_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise CampaignNotFound("Campaign does not exist")
        current_status = row[0]
        if current_status == "RUNNING" and next_status == "CANCELLED":
            cur.execute("""
                UPDATE adhoc_campaigns
                SET status = 'CANCEL_REQUESTED', cancel_requested_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (campaign_id,))
            current_status = "CANCEL_REQUESTED"
        validate_campaign_transition(current_status, next_status)
        cur.execute("""
            UPDATE adhoc_campaigns
            SET status = %s, failure_code = %s,
                completed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
        """, (next_status, failure_code, campaign_id))
        conn.commit()


def _failure_code(exc):
    mapping = {
        AuthorizationRevoked: "authorization_revoked",
        UnsafeAddress: "unsafe_dns",
        DNSRebindingDetected: "peer_ip_mismatch",
        RedirectRejected: "redirect_rejected",
        CampaignCancelled: "campaign_cancelled",
        CampaignDeadlineExceeded: "campaign_deadline_exceeded",
    }
    for error_type, code in mapping.items():
        if isinstance(exc, error_type):
            return code
    if isinstance(exc, ResolverFailure):
        return str(exc)
    if isinstance(exc, TransportFailure):
        return str(exc)
    if isinstance(exc, TimeoutError):
        return "transport_timeout"
    if isinstance(exc, UnsupportedRequest):
        return "unsafe_request_plan"
    return "runner_internal_error"


def _normalize_fingerprint_observations(raw_observations, observed_url):
    observations = []
    for item in raw_observations or ():
        if hasattr(item, "as_dict"):
            item = item.as_dict()
        if not isinstance(item, dict):
            raise TransportFailure("fingerprint_invalid_observation")
        technology = str(item.get("technology") or "").strip().lower()
        if not technology:
            continue
        observations.append({
            "technology": technology,
            "version": item.get("version"),
            "confidence": item.get("confidence", "unknown"),
            "evidence_type": item.get("evidence_type", "header"),
            "sanitized_evidence": sanitize_evidence(
                item.get("sanitized_evidence", item.get("evidence", ""))
            ),
            "observed_url": observed_url,
            "detector_version": item.get("detector_version", "sr-adhoc-runner-v1"),
        })
    return observations


def _php_evaluation_summary(observations, context):
    evaluations = []
    for observation in observations:
        if observation["technology"] != "php":
            continue
        evaluation = evaluate_php_observation(
            observation, context.assessment_date or date.today()
        )
        observation["lifecycle"] = evaluation["lifecycle"]
        observation["cve_intelligence"] = evaluation["cve_intelligence"]
        evaluations.append(evaluation)
    if not evaluations:
        return None, None
    lifecycle = evaluations[0]["lifecycle"] if len(evaluations) == 1 else [
        item["lifecycle"] for item in evaluations
    ]
    merged = evaluations[0]["cve_intelligence"].copy()
    candidates = []
    seen = set()
    for item in evaluations:
        for candidate in item["cve_intelligence"]["candidates"]:
            if candidate["cve_id"] not in seen:
                candidates.append(candidate)
                seen.add(candidate["cve_id"])
    merged["candidates"] = candidates
    return lifecycle, merged


def _classify_observations(observations):
    php = [item for item in observations if item["technology"] == "php"]
    if not php:
        return "NOT_EVALUATED", "no_php_observation"
    statuses = {
        candidate["applicability_status"]
        for item in php
        for candidate in item.get("cve_intelligence", {}).get("candidates", [])
    }
    if "potentially_affected" in statuses:
        return "EVALUATED", "potential_cve"
    if "insufficient_evidence" in statuses:
        return "EVALUATED", "insufficient_evidence"
    if statuses and statuses <= {"not_affected_by_version"}:
        return "EVALUATED", "not_affected_by_reported_version"
    return "EVALUATED", "unknown"


def _insert_result(
    cur, context, *, execution_status, evidence_status, evaluation_status,
    classification, observations, lifecycle, cve_intelligence, observed_at,
    dataset_revision, failure_code=None, skip_reason_code=None,
):
    cur.execute("""
        INSERT INTO adhoc_campaign_results(
            campaign_id, target_id, attempt_number, execution_status,
            evidence_status, evaluation_status, classification, failure_code,
            skip_reason_code, observations, lifecycle, cve_intelligence,
            observed_at, dataset_revision
        ) VALUES (
            %s, %s, 1, %s, %s, %s, %s, %s, %s,
            %s::jsonb, %s::jsonb, %s::jsonb, %s, %s
        )
    """, (
        context.campaign_id, context.target_id, execution_status,
        evidence_status, evaluation_status, classification, failure_code,
        skip_reason_code, json.dumps(observations), json.dumps(lifecycle),
        json.dumps(cve_intelligence), observed_at, dataset_revision,
    ))
