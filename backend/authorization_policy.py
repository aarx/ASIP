from dataclasses import dataclass
from datetime import datetime, timezone
import os
import re

from ownership import is_within_trusted_boundary, trusted_boundary_sql


SCOPE_STATUS_ACTIVE = "ACTIVE"
SCOPE_STATUS_REVOKED = "REVOKED"
SCOPE_TESTING_LEVELS = frozenset({
    "TECHNOLOGY_HTTP",
    "PORT_SCAN",
    "ADHOC_CHECK",
    "HTTP_TLS_OBSERVATION",
    "DNS_SECURITY",
})
DEFAULT_SCAN_OPERATIONS_ENV = "ASIP_DEFAULT_SCAN_OPERATIONS"

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


class ScopePolicyError(ValueError):
    """Raised when a scope or authorization decision is invalid."""


def normalize_scope_domain(value):
    """Return a conservative canonical DNS name or raise."""
    domain = str(value or "").strip().lower().rstrip(".")
    if not domain or not _DOMAIN_RE.fullmatch(domain):
        raise ScopePolicyError("scope domain must be a normalized DNS name")
    return domain


def normalize_scope_exclusions(values):
    values = values or ()
    normalized = tuple(sorted({normalize_scope_domain(value) for value in values}))
    return normalized


def _as_utc(value):
    if value is None:
        return None
    if not isinstance(value, datetime):
        raise ScopePolicyError("scope timestamps must be datetime values")
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class ScopeApproval:
    """Immutable, validated representation of one approved scan scope."""

    scope_domain: str
    include_subdomains: bool
    testing_level: str
    approved_by: str
    approved_at: datetime
    status: str = SCOPE_STATUS_ACTIVE
    expires_at: datetime | None = None
    excluded_domains: tuple = ()
    revoked_by: str | None = None
    revoked_at: datetime | None = None
    revocation_reason: str | None = None

    def __post_init__(self):
        object.__setattr__(self, "scope_domain", normalize_scope_domain(self.scope_domain))
        object.__setattr__(self, "testing_level", str(self.testing_level or "").strip().upper())
        object.__setattr__(self, "approved_by", str(self.approved_by or "").strip())
        object.__setattr__(self, "approved_at", _as_utc(self.approved_at))
        object.__setattr__(self, "expires_at", _as_utc(self.expires_at))
        object.__setattr__(self, "revoked_at", _as_utc(self.revoked_at))
        object.__setattr__(self, "excluded_domains", normalize_scope_exclusions(self.excluded_domains))

        if self.testing_level not in SCOPE_TESTING_LEVELS:
            raise ScopePolicyError("unsupported scope testing level")
        if not self.approved_by or self.approved_at is None:
            raise ScopePolicyError("scope approval actor and timestamp are required")
        if self.status not in {SCOPE_STATUS_ACTIVE, SCOPE_STATUS_REVOKED}:
            raise ScopePolicyError("invalid scope status")
        if self.expires_at and self.expires_at <= self.approved_at:
            raise ScopePolicyError("scope expiry must be after approval")
        if self.status == SCOPE_STATUS_ACTIVE and (self.revoked_by or self.revoked_at):
            raise ScopePolicyError("active scope cannot contain revocation metadata")
        if self.status == SCOPE_STATUS_REVOKED and (not self.revoked_by or not self.revoked_at):
            raise ScopePolicyError("revoked scope requires revocation metadata")


def scope_covers_domain(scope, domain):
    domain = normalize_scope_domain(domain)
    if domain in scope.excluded_domains:
        return False
    if domain == scope.scope_domain:
        return True
    return scope.include_subdomains and domain.endswith("." + scope.scope_domain)


def scope_is_active(scope, now=None):
    if scope.status != SCOPE_STATUS_ACTIVE:
        return False
    now = _as_utc(now or datetime.now(timezone.utc))
    return scope.expires_at is None or now < scope.expires_at


def scope_authorizes(scopes, domain, testing_level, now=None):
    """Evaluate only approved scopes; ownership/eligibility are separate."""
    testing_level = str(testing_level or "").strip().upper()
    if testing_level not in SCOPE_TESTING_LEVELS:
        return False
    domain = normalize_scope_domain(domain)
    matching = [
        scope for scope in scopes
        if scope.testing_level == testing_level
        and scope_is_active(scope, now)
        and (
            domain == scope.scope_domain
            or (scope.include_subdomains and domain.endswith("." + scope.scope_domain))
        )
    ]
    if any(domain in scope.excluded_domains for scope in matching):
        return False
    return bool(matching)


def scope_excludes_domain(scopes, domain, testing_level, now=None):
    """Return whether an active operation scope explicitly excludes domain."""
    testing_level = str(testing_level or "").strip().upper()
    if testing_level not in SCOPE_TESTING_LEVELS:
        return False
    domain = normalize_scope_domain(domain)
    return any(
        scope.testing_level == testing_level
        and scope_is_active(scope, now)
        and domain in scope.excluded_domains
        and (
            domain == scope.scope_domain
            or (scope.include_subdomains and domain.endswith("." + scope.scope_domain))
        )
        for scope in scopes
    )


def scope_revokes_domain(scopes, domain, testing_level):
    """Treat persisted revoked grants as operation-specific denials."""
    testing_level = str(testing_level or "").strip().upper()
    if testing_level not in SCOPE_TESTING_LEVELS:
        return False
    domain = normalize_scope_domain(domain)
    return any(
        scope.testing_level == testing_level
        and scope.status == SCOPE_STATUS_REVOKED
        and (
            domain == scope.scope_domain
            or (scope.include_subdomains and domain.endswith("." + scope.scope_domain))
        )
        for scope in scopes
    )


def configured_scan_operations(value=None):
    """Parse the organization default operation allowlist, failing closed."""
    if value is None:
        value = os.environ.get(DEFAULT_SCAN_OPERATIONS_ENV)
    if value is None:
        return frozenset()
    entries = value.split(",")
    normalized = [entry.strip().upper() for entry in entries]
    if not normalized or any(not item or item not in SCOPE_TESTING_LEVELS for item in normalized):
        return frozenset()
    return frozenset(normalized)


def default_operation_enabled(testing_level, value=None):
    level = str(testing_level or "").strip().upper()
    return level in SCOPE_TESTING_LEVELS and level in configured_scan_operations(value)


def is_authorized(
    *, ownership_status, scannable, validation_source,
    domain, testing_level, scopes=(), now=None, trusted_domains=None,
    confidence_reasons=(),
):
    """Apply the complete local decision without database or network access."""
    if ownership_status != "CONFIRMED" or scannable is not True:
        return False
    if isinstance(confidence_reasons, str):
        confidence_reasons = (confidence_reasons,)
    if any(str(reason).strip().lower() == "manually rejected" for reason in confidence_reasons or ()):
        return False
    if trusted_domains is None or not is_within_trusted_boundary(domain, trusted_domains):
        return False
    normalized_level = str(testing_level or "").strip().upper()
    if not default_operation_enabled(normalized_level):
        return False
    if (
        scope_excludes_domain(scopes, domain, normalized_level, now)
        or scope_revokes_domain(scopes, domain, normalized_level)
    ):
        return False
    return True


def explicit_t2_authorization_sql(domain_alias="d"):
    """Return the legacy direct/manual authorization predicate.

    Kept stable for callers and compatibility tests. Active workers use
    ``active_scan_authorization_sql`` below.
    """
    return (
        f"{domain_alias}.ownership_status = 'CONFIRMED' "
        f"AND {domain_alias}.scannable IS TRUE "
        f"AND {domain_alias}.validation_source = 'manual'"
    )


def active_scan_authorization_sql(domain_alias="d", testing_level="TECHNOLOGY_HTTP"):
    """Return trusted, technically eligible, centrally permitted SQL."""
    level = str(testing_level or "").strip().upper()
    if level not in SCOPE_TESTING_LEVELS:
        raise ScopePolicyError("unsupported scope testing level")

    base = (
        f"{domain_alias}.ownership_status = 'CONFIRMED' "
        f"AND {domain_alias}.scannable IS TRUE "
        f"AND {trusted_boundary_sql(f'{domain_alias}.domain')} "
        f"AND NOT COALESCE('manually rejected' = ANY({domain_alias}.confidence_reasons), FALSE) "
        f"AND {default_operation_policy_sql(level)} "
        f"AND NOT ({active_scope_exclusion_sql(domain_alias, level)}) "
    )
    return base


def default_operation_policy_sql(testing_level):
    """Generate the current allowlist decision so each recheck sees changes."""
    level = str(testing_level or "").strip().upper()
    if level not in SCOPE_TESTING_LEVELS:
        raise ScopePolicyError("unsupported scope testing level")
    return "TRUE" if default_operation_enabled(level) else "FALSE"


def active_scope_exclusion_sql(domain_alias="d", testing_level="TECHNOLOGY_HTTP"):
    """Return SQL for active, matching operation-specific exclusions."""
    level = str(testing_level or "").strip().upper()
    if level not in SCOPE_TESTING_LEVELS:
        raise ScopePolicyError("unsupported scope testing level")
    canonical_domain = f"LOWER(TRIM(TRAILING '.' FROM {domain_alias}.domain))"
    return f"""
        EXISTS (
            SELECT 1
            FROM active_scan_scopes scope_block
            WHERE (scope_block.status = 'REVOKED'
              OR (scope_block.status = 'ACTIVE'
                  AND (scope_block.expires_at IS NULL
                       OR scope_block.expires_at > CURRENT_TIMESTAMP)
                  AND {canonical_domain} = ANY(scope_block.excluded_domains))
              )
              AND scope_block.testing_level = '{level}'
              AND (
                    {canonical_domain} = scope_block.scope_domain
                    OR (
                        scope_block.include_subdomains
                        AND RIGHT({canonical_domain}, LENGTH(scope_block.scope_domain) + 1)
                            = '.' || scope_block.scope_domain
                    )
              )
        )
    """


def active_scope_coverage_sql(domain_alias="d", testing_level=None):
    """Return SQL for active scope coverage with exclusions applied.

    This deliberately excludes ownership and scannability predicates so the
    automatic eligibility pass can use the same scope semantics before a row
    becomes technically eligible.  A testing level may be supplied for a
    worker-specific authorization decision; ``None`` means any supported
    active testing level.
    """
    level = None if testing_level is None else str(testing_level or "").strip().upper()
    if level is not None and level not in SCOPE_TESTING_LEVELS:
        raise ScopePolicyError("unsupported scope testing level")

    canonical_domain = f"LOWER(TRIM(TRAILING '.' FROM {domain_alias}.domain))"
    level_filter = "" if level is None else f"AND scope_allow.testing_level = '{level}'"
    block_level_filter = (
        "AND scope_block.testing_level = scope_allow.testing_level"
    )
    return f"""
        EXISTS (
            SELECT 1
            FROM active_scan_scopes scope_allow
            WHERE scope_allow.status = 'ACTIVE'
              AND (scope_allow.expires_at IS NULL
                   OR scope_allow.expires_at > CURRENT_TIMESTAMP)
              {level_filter}
              AND (
                    {canonical_domain} = scope_allow.scope_domain
                    OR (
                        scope_allow.include_subdomains
                        AND RIGHT({canonical_domain}, LENGTH(scope_allow.scope_domain) + 1)
                            = '.' || scope_allow.scope_domain
                    )
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM active_scan_scopes scope_block
                  WHERE scope_block.status = 'ACTIVE'
                    AND (scope_block.expires_at IS NULL
                         OR scope_block.expires_at > CURRENT_TIMESTAMP)
                    {block_level_filter}
                    AND (
                          {canonical_domain} = scope_block.scope_domain
                          OR (
                              scope_block.include_subdomains
                              AND RIGHT({canonical_domain}, LENGTH(scope_block.scope_domain) + 1)
                                  = '.' || scope_block.scope_domain
                          )
                    )
                    AND {canonical_domain} = ANY(scope_block.excluded_domains)
              )
        )
    """


def recheck_active_authorization(
    cur, *, scan_id, domain_id=None, domain_name=None, testing_level,
    required_scan_status="RUNNING"
):
    """Perform a fresh, fail-closed authorization check before network I/O."""
    try:
        if domain_name is None:
            identity_sql = "d.id = %s"
            identity_params = (domain_id,)
        else:
            identity_sql = "LOWER(TRIM(TRAILING '.' FROM d.domain)) = %s"
            identity_params = (str(domain_name).strip().lower().rstrip("."),)
        cur.execute(
            f"""
            SELECT 1
            FROM domains d
            JOIN scan_results sr
              ON sr.domain_id = d.id
             AND sr.scan_id = %s
            JOIN scans scan
              ON scan.id = sr.scan_id
            WHERE {identity_sql}
              AND scan.status = %s
              AND {active_scan_authorization_sql('d', testing_level)}
            LIMIT 1
            """,
            (scan_id, *identity_params, required_scan_status),
        )
        if cur.fetchone() is None:
            return False, "authorization no longer valid"
        return True, "authorized"
    except Exception:
        connection = getattr(cur, "connection", None)
        if connection is not None:
            try:
                connection.rollback()
            except Exception:
                pass
        return False, "authorization check failed"
