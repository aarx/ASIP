"""Provider-neutral operator identity and permission checks.

This module does not authenticate HTTP requests.  A future trusted identity
adapter must construct ``VerifiedPrincipal`` values after validating an
identity provider assertion.  Direct request headers, query parameters, and
client-supplied role values are intentionally not accepted here.
"""

from dataclasses import dataclass
from datetime import datetime, timezone


ROLE_ANALYST = "analyst"
ROLE_ADMINISTRATOR = "administrator"

PERMISSION_READ_ADHOC = "adhoc:read"
PERMISSION_CREATE_CAMPAIGN = "adhoc:create"
PERMISSION_CANCEL_CAMPAIGN = "adhoc:cancel"
PERMISSION_RUN_CAMPAIGN = "adhoc:run"

KNOWN_ROLES = frozenset({ROLE_ANALYST, ROLE_ADMINISTRATOR})
ROLE_PERMISSIONS = {
    ROLE_ANALYST: frozenset({PERMISSION_READ_ADHOC}),
    ROLE_ADMINISTRATOR: frozenset({
        PERMISSION_READ_ADHOC,
        PERMISSION_CREATE_CAMPAIGN,
        PERMISSION_CANCEL_CAMPAIGN,
        PERMISSION_RUN_CAMPAIGN,
    }),
}


class OperatorAuthError(PermissionError):
    """Base class for fail-closed operator authentication decisions."""


class AuthenticationRequired(OperatorAuthError):
    """No verified, non-expired principal was supplied."""


class PermissionDenied(OperatorAuthError):
    """The verified principal does not have the requested permission."""


@dataclass(frozen=True)
class VerifiedPrincipal:
    """An immutable identity produced by a trusted authentication adapter.

    ``verified`` is a provenance assertion, not a client-controlled request
    field.  Production code must only construct this object after verifying
    an IdP token/session on a trusted server boundary.  Tests may inject a
    verified principal directly.
    """

    subject: str
    roles: frozenset[str]
    authentication_source: str
    verified: bool = False
    expires_at: datetime | None = None

    def __post_init__(self):
        subject = str(self.subject or "").strip()
        source = str(self.authentication_source or "").strip()
        roles = frozenset(str(role or "").strip().lower() for role in self.roles)
        object.__setattr__(self, "subject", subject)
        object.__setattr__(self, "authentication_source", source)
        object.__setattr__(self, "roles", roles)


def _utc(value):
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def require_verified_principal(principal, *, now=None):
    """Validate identity provenance and expiry without granting permissions."""

    if not isinstance(principal, VerifiedPrincipal):
        raise AuthenticationRequired("A verified operator principal is required")
    if not principal.verified:
        raise AuthenticationRequired("Operator identity has not been verified")
    if not principal.subject or not principal.authentication_source:
        raise AuthenticationRequired("Verified operator identity is incomplete")
    if not principal.roles or not principal.roles.issubset(KNOWN_ROLES):
        raise PermissionDenied("Operator roles are not recognized")
    expires_at = _utc(principal.expires_at)
    current_time = _utc(now) or datetime.now(timezone.utc)
    if expires_at is not None and current_time >= expires_at:
        raise AuthenticationRequired("Operator identity has expired")
    return principal


def authorize_permission(principal, permission, *, now=None, audit_sink=None):
    """Require one permission and optionally emit a safe audit event.

    Audit failures are deliberately fail-closed: if an injected audit sink
    cannot accept the event, authorization is denied rather than proceeding
    without an audit record.
    """

    try:
        principal = require_verified_principal(principal, now=now)
        permission = str(permission or "").strip().lower()
        if not permission:
            raise PermissionDenied("A permission is required")
        granted = any(
            permission in ROLE_PERMISSIONS[role] for role in principal.roles
        )
        if not granted:
            raise PermissionDenied("Operator is not authorized for this action")
        event = build_audit_event(
            principal,
            action=permission,
            outcome="allowed",
            reason_code="permission_granted",
        )
        _emit_audit(audit_sink, event)
        return principal
    except OperatorAuthError as exc:
        _emit_audit(audit_sink, build_audit_event(
                principal if isinstance(principal, VerifiedPrincipal) else None,
                action=str(permission or "unknown"),
                outcome="denied",
                reason_code=_reason_code(exc),
            ))
        raise
    except Exception as exc:
        _emit_audit(audit_sink, build_audit_event(
                principal if isinstance(principal, VerifiedPrincipal) else None,
                action=str(permission or "unknown"),
                outcome="denied",
                reason_code="audit_or_authorization_error",
            ))
        raise AuthenticationRequired("Operator authorization failed closed") from exc


def _emit_audit(audit_sink, event):
    if audit_sink is None:
        return
    try:
        audit_sink(event)
    except Exception as exc:
        raise AuthenticationRequired("Authorization audit is unavailable") from exc


def build_audit_event(principal, *, action, outcome, reason_code):
    """Return an audit-safe event without tokens, claims, or request data."""

    return {
        "event": "operator_authorization",
        "subject": principal.subject if isinstance(principal, VerifiedPrincipal) else None,
        "authentication_source": (
            principal.authentication_source
            if isinstance(principal, VerifiedPrincipal) else None
        ),
        "action": str(action or "unknown"),
        "outcome": str(outcome or "denied"),
        "reason_code": str(reason_code or "unknown"),
    }


def _reason_code(exc):
    if isinstance(exc, AuthenticationRequired):
        return "authentication_required"
    if isinstance(exc, PermissionDenied):
        return "permission_denied"
    return "operator_auth_failed"


def reject_unverified_identity_input(_identity, *, source="untrusted_request"):
    """Reject headers/query values until a trusted IdP adapter exists."""

    del source
    raise AuthenticationRequired(
        "Client-supplied identity is not a trusted authentication boundary"
    )
