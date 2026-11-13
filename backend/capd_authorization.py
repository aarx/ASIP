"""Run-scoped CAPD authorization checks over completed inventory evidence.

This module contains no transport. It reuses the current ADHOC_CHECK policy
and deliberately leaves trusted operator approval to a future approved local
execution boundary.
"""

from __future__ import annotations

from datetime import datetime, timezone

from apache_version_verification import (
    CapdAuthorizationContext,
    _apache_observed_url,
    _validated_origin,
)
from authorization_policy import (
    active_scope_exclusion_sql,
    default_operation_policy_sql,
)
from ownership import reporting_asset_class_sql, trusted_boundary_sql


def recheck_apache_target_from_inventory(cur, context, target, *, now=None):
    """Freshly recheck source membership and ADHOC_CHECK eligibility.

    Unlike ``recheck_active_authorization`` this CAPD-specific check does not
    require a RUNNING recon scan. It requires membership in the selected
    successful source scan and evaluates current asset/policy state.
    """
    if not isinstance(context, CapdAuthorizationContext):
        return {"inventory_policy_passed": False, "reason_codes": ["INVALID_RUN_AUTHORIZATION_CONTEXT"]}
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    if now < context.issued_at or now >= context.expires_at:
        return {"inventory_policy_passed": False, "reason_codes": ["AUTHORIZATION_CONTEXT_EXPIRED_OR_STALE"]}
    if (not isinstance(target, dict)
            or target.get("source_scan_id") != context.source_scan_id
            or not target.get("domain_id")
            or not target.get("domain")):
        return {"inventory_policy_passed": False, "reason_codes": ["SOURCE_SCAN_CONTEXT_MISMATCH"]}
    try:
        observed_url = _apache_observed_url(target)
    except (AttributeError, TypeError, ValueError):
        return {"inventory_policy_passed": False, "reason_codes": ["APACHE_EVIDENCE_MISSING"]}
    try:
        _validated_origin(observed_url, target["domain"])
    except (KeyError, TypeError, ValueError):
        return {"inventory_policy_passed": False, "reason_codes": ["TARGET_DESTINATION_NOT_BOUND_TO_STORED_EVIDENCE"]}

    class_sql = reporting_asset_class_sql("d.domain", "d.ownership_status")
    boundary_sql = trusted_boundary_sql("d.domain")
    exclusion_sql = active_scope_exclusion_sql("d", "ADHOC_CHECK")
    operation_sql = default_operation_policy_sql("ADHOC_CHECK")
    try:
        cur.execute(f"""
            SELECT scan.status,
               d.ownership_status,
               d.scannable,
               ({class_sql}) AS asset_class,
               ({boundary_sql}) AS trusted_boundary,
               NOT COALESCE('manually rejected' = ANY(d.confidence_reasons), FALSE) AS not_rejected,
               ({operation_sql}) AS operation_enabled,
               NOT ({exclusion_sql}) AS scope_allowed,
               EXISTS (
                   SELECT 1 FROM scan_results sr
                    WHERE sr.scan_id = scan.id AND sr.domain_id = d.id
               ) AS source_member,
               EXISTS (
                   SELECT 1 FROM domain_technology_observations obs
                    WHERE obs.scan_id = scan.id
                      AND obs.domain_id = d.id
                      AND LOWER(obs.technology) = 'apache'
                      AND obs.evidence_type = 'server_header'
                      AND obs.confidence IN ('medium', 'high')
                      AND obs.observed_url = %s
               ) AS apache_evidence_current
          FROM scans scan
          JOIN domains d ON d.id = %s
         WHERE scan.id = %s
           AND LOWER(TRIM(TRAILING '.' FROM d.domain)) = %s
              LIMIT 1
        """, (observed_url, target["domain_id"], context.source_scan_id,
              str(target["domain"]).strip().lower().rstrip(".")))
        row = cur.fetchone()
    except Exception:
        connection = getattr(cur, "connection", None)
        if connection is not None:
            try:
                connection.rollback()
            except Exception:
                pass
        return {"inventory_policy_passed": False, "reason_codes": ["AUTHORIZATION_RECHECK_FAILED"]}
    if row is None:
        return {"inventory_policy_passed": False, "reason_codes": ["SOURCE_SCAN_OR_ASSET_NOT_FOUND"]}

    (scan_status, ownership_status, scannable, asset_class, trusted,
     not_rejected, operation_enabled, scope_allowed, source_member,
     apache_evidence_current) = row
    reasons = []
    if scan_status != "SUCCEEDED":
        reasons.append("SOURCE_SCAN_NOT_SUCCESSFUL")
    if not source_member:
        reasons.append("SOURCE_SCAN_MEMBERSHIP_MISSING")
    if ownership_status != "CONFIRMED" or asset_class not in {"KNOWN", "SHADOW"}:
        reasons.append("OUTSIDE_KNOWN_SHADOW_OWNERSHIP_SCOPE")
    if scannable is not True:
        reasons.append("TARGET_NOT_SCANNABLE")
    if not trusted:
        reasons.append("TARGET_OUTSIDE_TRUSTED_BOUNDARY")
    if not not_rejected:
        reasons.append("TARGET_MANUALLY_REJECTED")
    if not operation_enabled:
        reasons.append("ADHOC_CHECK_OPERATION_DISABLED")
    if not scope_allowed:
        reasons.append("ADHOC_CHECK_SCOPE_EXCLUDED_OR_REVOKED")
    if not apache_evidence_current:
        reasons.append("APACHE_SERVICE_EVIDENCE_MISSING_OR_STALE")
    return {
        "inventory_policy_passed": not reasons,
        "reason_codes": reasons or ["INVENTORY_AND_OPERATION_POLICY_PASSED"],
        "run_id": context.run_id,
        "check_id": context.check_id,
        "check_revision": context.check_revision,
        "source_scan_id": context.source_scan_id,
        "asset_id": target["domain_id"],
        "asset_class": asset_class,
        "operation": "ADHOC_CHECK",
    }
