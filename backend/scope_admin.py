"""Callback-gated local administration for active scan scopes.

No API route calls this module. A future deployment adapter must supply an
authenticated operator callback; a caller-provided username alone is never
accepted as proof of identity.
"""

from datetime import datetime, timezone

from authorization_policy import (
    SCOPE_STATUS_ACTIVE,
    SCOPE_STATUS_REVOKED,
    SCOPE_TESTING_LEVELS,
    ScopePolicyError,
    normalize_scope_domain,
    normalize_scope_exclusions,
)


class ScopeAdministrationError(PermissionError):
    """Raised when scope administration lacks a trusted operator."""


def _require_operator(operator_authorizer, actor):
    actor = str(actor or "").strip()
    if not actor or not callable(operator_authorizer):
        raise ScopeAdministrationError("authenticated local operator is required")
    try:
        allowed = bool(operator_authorizer(actor))
    except Exception as exc:
        raise ScopeAdministrationError("operator authentication failed") from exc
    if not allowed:
        raise ScopeAdministrationError("operator is not authorized to manage scopes")
    return actor


def _validate_expiry(approved_at, expires_at):
    approved_at = approved_at or datetime.now(timezone.utc)
    if approved_at.tzinfo is None:
        approved_at = approved_at.replace(tzinfo=timezone.utc)
    if expires_at is not None:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= approved_at:
            raise ScopePolicyError("scope expiry must be after approval")
    return approved_at, expires_at


def create_scope(
    conn, *, scope_domain, include_subdomains, testing_level,
    approved_by, operator_authorizer, approved_at=None, expires_at=None,
    excluded_domains=(), monitoring_purpose=None,
    eligible_discovery_sources=(), max_requests_per_scan=None,
):
    """Create one active scope after an external trusted-operator check."""
    actor = _require_operator(operator_authorizer, approved_by)
    domain = normalize_scope_domain(scope_domain)
    level = str(testing_level or "").strip().upper()
    if level not in SCOPE_TESTING_LEVELS:
        raise ScopePolicyError("unsupported scope testing level")
    exclusions = normalize_scope_exclusions(excluded_domains)
    approved_at, expires_at = _validate_expiry(approved_at, expires_at)
    purpose = str(monitoring_purpose or "").strip() or None
    sources = tuple(sorted({str(source).strip().lower()
                            for source in (eligible_discovery_sources or ())}))
    if level == "BRAND_REDIRECT_OBSERVATION":
        if not purpose:
            raise ScopePolicyError("brand monitoring purpose is required")
        if not sources or not set(sources) <= {"brand_tld", "brand_pattern"}:
            raise ScopePolicyError(
                "eligible discovery sources must include brand_tld and/or brand_pattern"
            )
        if not isinstance(max_requests_per_scan, int) or not 1 <= max_requests_per_scan <= 100000:
            raise ScopePolicyError(
                "brand redirect request budget must be between 1 and 100000"
            )
    elif purpose is not None or sources or max_requests_per_scan is not None:
        raise ScopePolicyError("brand monitoring policy fields require the brand redirect scope")

    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO active_scan_scopes(
                scope_domain, include_subdomains, testing_level,
                approved_by, approved_at, status, expires_at, excluded_domains,
                monitoring_purpose, eligible_discovery_sources, max_requests_per_scan
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                domain, bool(include_subdomains), level, actor, approved_at,
                SCOPE_STATUS_ACTIVE, expires_at, list(exclusions), purpose,
                list(sources), max_requests_per_scan,
            ),
        )
        scope_id = cur.fetchone()[0]
        conn.commit()
        return scope_id
    except Exception:
        conn.rollback()
        raise


def revoke_scope(conn, *, scope_id, revoked_by, operator_authorizer,
                 revoked_at=None, reason=None):
    """Revoke a scope; future authorization checks observe it immediately."""
    actor = _require_operator(operator_authorizer, revoked_by)
    revoked_at = revoked_at or datetime.now(timezone.utc)
    if revoked_at.tzinfo is None:
        revoked_at = revoked_at.replace(tzinfo=timezone.utc)

    cur = conn.cursor()
    try:
        cur.execute(
            """
            UPDATE active_scan_scopes
            SET status = %s, revoked_by = %s, revoked_at = %s,
                revocation_reason = %s
            WHERE id = %s AND status = %s
            RETURNING id
            """,
            (
                SCOPE_STATUS_REVOKED, actor, revoked_at, reason,
                scope_id, SCOPE_STATUS_ACTIVE,
            ),
        )
        row = cur.fetchone()
        if row is None:
            raise ScopeAdministrationError("active scope was not found")
        conn.commit()
        return row[0]
    except Exception:
        conn.rollback()
        raise
