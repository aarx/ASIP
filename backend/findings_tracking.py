"""Safe primitives for future analyst-controlled finding tracking.

This module intentionally does not persist observations or provide HTTP
mutation handlers. Those require a verified request identity adapter.
"""

import hashlib
import json


TRACKING_STATUSES = frozenset({
    "OPEN", "IN_REVIEW", "REMEDIATED", "FALSE_POSITIVE", "RISK_ACCEPTED",
})
TERMINAL_ANALYST_STATUSES = frozenset({
    "REMEDIATED", "FALSE_POSITIVE", "RISK_ACCEPTED",
})
TRACKABLE_CATEGORIES = frozenset({"FINDING", "NEEDS_VERIFICATION"})
TRACKING_MUTATIONS_ENABLED = False


class FindingTrackingError(ValueError):
    """Invalid or unsafe tracking identity/state input."""


def _required_text(value, field):
    result = str(value or "").strip()
    if not result:
        raise FindingTrackingError(f"{field} is required")
    return result


def is_trackable_record(*, category, asset_class):
    """Only actionable/verification records on organizational assets qualify."""
    return (
        str(category or "").strip().upper() in TRACKABLE_CATEGORIES
        and str(asset_class or "").strip().upper() in {"KNOWN", "SHADOW"}
    )


def stable_issue_identity(*, domain_id, source, finding_type, discriminator):
    """Return a scan-independent, reproducible identity for one issue key.

    The discriminator is required: source/type alone can collapse distinct
    ports, DNS targets, or same-type findings on a single asset.
    """
    try:
        asset_id = int(domain_id)
    except (TypeError, ValueError) as exc:
        raise FindingTrackingError("domain_id must be a positive integer") from exc
    if asset_id <= 0:
        raise FindingTrackingError("domain_id must be a positive integer")
    source_key = _required_text(source, "source").casefold()
    type_key = _required_text(finding_type, "finding_type").casefold()
    if discriminator is None or discriminator == "" or discriminator == {} or discriminator == []:
        raise FindingTrackingError("an evidence discriminator is required")
    try:
        canonical_discriminator = json.dumps(
            discriminator, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise FindingTrackingError("discriminator must be deterministic JSON data") from exc
    identity = {
        "version": 1,
        "domain_id": asset_id,
        "source": source_key,
        "finding_type": type_key,
        "discriminator": canonical_discriminator,
    }
    payload = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"sfi:v1:{digest}"


def validate_status_transition(current_status, next_status):
    """Validate analyst status changes; source observations never set status."""
    current = _required_text(current_status, "current_status").upper()
    next_value = _required_text(next_status, "next_status").upper()
    if current not in TRACKING_STATUSES:
        raise FindingTrackingError("unknown current tracking status")
    if next_value not in TRACKING_STATUSES:
        raise FindingTrackingError("unknown next tracking status")
    if current == next_value:
        raise FindingTrackingError("tracking status is unchanged")
    if current in TERMINAL_ANALYST_STATUSES and next_value != "OPEN":
        raise FindingTrackingError("handled issues can only be reopened to OPEN")
    return "REOPENED" if current in TERMINAL_ANALYST_STATUSES else "STATUS_CHANGED"


def was_reobserved_after_handling(*, analyst_status, observation_at, status_changed_at):
    """Flag later evidence without changing the analyst-controlled status."""
    status = str(analyst_status or "").strip().upper()
    return bool(
        status in TERMINAL_ANALYST_STATUSES
        and observation_at is not None
        and status_changed_at is not None
        and observation_at > status_changed_at
    )
