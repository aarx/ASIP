"""Persistent Adhoc campaign foundation.

This module deliberately contains no network execution. Campaign creation
requires an explicit operator-authorizer callback; the current application
has no such middleware, so no production caller is wired to it yet.
"""

from datetime import date

from authorization_policy import explicit_t2_authorization_sql


OPERATOR_AUTHENTICATION_AVAILABLE = False

CAMPAIGN_STATES = frozenset({
    "QUEUED", "RUNNING", "CANCEL_REQUESTED", "CANCELLED",
    "SUCCEEDED", "PARTIAL", "FAILED",
})
TERMINAL_CAMPAIGN_STATES = frozenset({"CANCELLED", "SUCCEEDED", "PARTIAL", "FAILED"})
TARGET_STATES = frozenset({"PENDING", "RUNNING", "COMPLETED", "SKIPPED", "FAILED", "CANCELLED"})

CAMPAIGN_TRANSITIONS = {
    "QUEUED": frozenset({"RUNNING", "CANCEL_REQUESTED", "CANCELLED", "FAILED"}),
    "RUNNING": frozenset({"CANCEL_REQUESTED", "SUCCEEDED", "PARTIAL", "FAILED"}),
    "CANCEL_REQUESTED": frozenset({"CANCELLED", "PARTIAL", "FAILED"}),
    "CANCELLED": frozenset(),
    "SUCCEEDED": frozenset(),
    "PARTIAL": frozenset(),
    "FAILED": frozenset(),
}


class CampaignError(ValueError):
    """Expected campaign request or lifecycle error."""


class OperatorAuthorizationRequired(PermissionError):
    """Raised when campaign creation lacks an enforceable operator identity."""


class CampaignSchemaUnavailable(RuntimeError):
    """Raised when migration 005 has not been applied."""


def campaign_schema_unavailable(exc):
    """Return whether a database exception indicates a missing campaign table."""
    if getattr(exc, "pgcode", None) == "42P01":
        return True
    message = str(exc).lower()
    return "adhoc_campaign" in message and "does not exist" in message


def validate_campaign_transition(current_status, next_status):
    if current_status not in CAMPAIGN_STATES:
        raise CampaignError(f"Unknown campaign state: {current_status}")
    if next_status not in CAMPAIGN_STATES:
        raise CampaignError(f"Unknown campaign state: {next_status}")
    if current_status == next_status:
        return True
    if next_status not in CAMPAIGN_TRANSITIONS[current_status]:
        raise CampaignError(
            f"Invalid campaign transition: {current_status} -> {next_status}"
        )
    return True


def _normalize_domain(value):
    return str(value or "").strip().lower().rstrip(".")


def _authorized_member(row):
    return (
        row[2] == "CONFIRMED"
        and row[3] is True
        and row[4] == "manual"
    )


def validate_explicit_target_selection(requested_domains, member_rows, max_targets=50):
    """Validate explicit targets against one successful scan's members.

    ``member_rows`` contains ``(domain_id, domain, ownership_status,
    scannable, validation_source)``. The returned snapshots are immutable
    request data; a future worker must recheck the live predicate.
    """
    if not requested_domains:
        raise CampaignError("At least one explicit target is required")

    normalized = [_normalize_domain(value) for value in requested_domains]
    if any(not value for value in normalized):
        raise CampaignError("Target domains must be non-empty")
    if len(set(normalized)) != len(normalized):
        raise CampaignError("Target domains must be unique")
    if len(normalized) > max_targets:
        raise CampaignError(f"Target limit exceeded: maximum is {max_targets}")

    by_domain = {_normalize_domain(row[1]): row for row in member_rows}
    snapshots = []
    for domain in normalized:
        row = by_domain.get(domain)
        if row is None:
            raise CampaignError("Target is not a member of the selected scan")
        if not _authorized_member(row):
            raise CampaignError("Target does not satisfy the authorization predicate")
        snapshots.append({
            "domain_id": row[0],
            "domain_snapshot": _normalize_domain(row[1]),
            "ownership_status_snapshot": row[2],
            "scannable_snapshot": bool(row[3]),
            "validation_source_snapshot": row[4],
        })
    return snapshots


def runtime_authorization_query(domain_id, source_scan_id):
    """Return the future worker's parameterized authorization recheck query."""
    return f"""
        SELECT d.id, d.domain, d.ownership_status, d.scannable,
               d.validation_source
        FROM domains d
        JOIN scan_results sr
          ON sr.domain_id = d.id
         AND sr.scan_id = %s
        WHERE d.id = %s
          AND {explicit_t2_authorization_sql('d')}
    """, (source_scan_id, domain_id)


def _require_operator(operator_authorizer, requested_by):
    if not callable(operator_authorizer) or not requested_by:
        raise OperatorAuthorizationRequired(
            "Campaign creation requires an authenticated operator"
        )
    try:
        authorized = bool(operator_authorizer(requested_by))
    except Exception as exc:
        raise OperatorAuthorizationRequired(
            "Operator authorization could not be established"
        ) from exc
    if not authorized:
        raise OperatorAuthorizationRequired(
            "Campaign creation requires an authorized operator"
        )


def _successful_scan(cur, source_scan_id):
    cur.execute(
        "SELECT id, status, completed_at FROM scans WHERE id = %s",
        (source_scan_id,),
    )
    row = cur.fetchone()
    if row is None:
        raise CampaignError("Source scan not found")
    if row[1] != "SUCCEEDED":
        raise CampaignError("Source scan is not successful")
    return row


def _member_rows(cur, source_scan_id):
    cur.execute(f"""
        SELECT d.id, d.domain, d.ownership_status, d.scannable,
               d.validation_source
        FROM scan_results sr
        JOIN domains d ON d.id = sr.domain_id
        WHERE sr.scan_id = %s
        ORDER BY d.domain, d.id
    """, (source_scan_id,))
    return cur.fetchall()


def create_campaign(
    conn,
    *,
    check_id,
    source_scan_id,
    target_domains,
    requested_by,
    idempotency_key,
    assessment_date=None,
    dataset_revision="",
    operator_authorizer=None,
    max_targets=50,
):
    """Persist a queued campaign when a trusted operator is supplied.

    No API route currently supplies ``operator_authorizer``. Tests and a
    future authenticated adapter may provide one explicitly.
    """
    _require_operator(operator_authorizer, requested_by)
    if not check_id or not idempotency_key or not dataset_revision:
        raise CampaignError("check_id, idempotency_key, and dataset_revision are required")
    assessment_date = assessment_date or date.today()
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT id, check_id, source_scan_id, requested_by, status "
            "FROM adhoc_campaigns WHERE idempotency_key = %s FOR UPDATE",
            (idempotency_key,),
        )
        existing = cur.fetchone()
        if existing is not None:
            if existing[1:4] != (check_id, source_scan_id, requested_by):
                raise CampaignError("Idempotency key conflicts with an existing campaign")
            conn.commit()
            return {"campaign_id": existing[0], "status": existing[4], "idempotent": True}

        scan = _successful_scan(cur, source_scan_id)
        members = _member_rows(cur, source_scan_id)
        snapshots = validate_explicit_target_selection(target_domains, members, max_targets)

        cur.execute("""
            INSERT INTO adhoc_campaigns(
                check_id, source_scan_id, requested_by, idempotency_key,
                assessment_date, dataset_revision, status
            ) VALUES (%s, %s, %s, %s, %s, %s, 'QUEUED')
            RETURNING id
        """, (
            check_id, source_scan_id, requested_by, idempotency_key,
            assessment_date, dataset_revision,
        ))
        campaign_id = cur.fetchone()[0]
        for snapshot in snapshots:
            cur.execute("""
                INSERT INTO adhoc_campaign_targets(
                    campaign_id, source_scan_id, domain_id, domain_snapshot,
                    ownership_status_snapshot, scannable_snapshot,
                    validation_source_snapshot
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                campaign_id, source_scan_id, snapshot["domain_id"],
                snapshot["domain_snapshot"], snapshot["ownership_status_snapshot"],
                snapshot["scannable_snapshot"], snapshot["validation_source_snapshot"],
            ))
        conn.commit()
        return {
            "campaign_id": campaign_id,
            "status": "QUEUED",
            "source_scan_id": scan[0],
            "target_count": len(snapshots),
            "idempotent": False,
        }
    except Exception as exc:
        conn.rollback()
        if campaign_schema_unavailable(exc):
            raise CampaignSchemaUnavailable() from exc
        raise


def transition_campaign(conn, campaign_id, next_status):
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT status FROM adhoc_campaigns WHERE id = %s FOR UPDATE",
            (campaign_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise CampaignError("Campaign not found")
        validate_campaign_transition(row[0], next_status)
        if row[0] != next_status:
            cur.execute("""
                UPDATE adhoc_campaigns
                SET status = %s,
                    started_at = CASE WHEN %s = 'RUNNING' THEN CURRENT_TIMESTAMP ELSE started_at END,
                    completed_at = CASE
                        WHEN %s IN ('CANCELLED', 'SUCCEEDED', 'PARTIAL', 'FAILED')
                        THEN CURRENT_TIMESTAMP ELSE completed_at END,
                    cancel_requested_at = CASE
                        WHEN %s = 'CANCEL_REQUESTED' THEN CURRENT_TIMESTAMP
                        ELSE cancel_requested_at END,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (next_status, next_status, next_status, next_status, campaign_id))
        conn.commit()
        return next_status
    except Exception:
        conn.rollback()
        raise


def _iso(value):
    return value.isoformat() if value is not None else None


def _progress(cur, campaign_id):
    cur.execute("""
        SELECT
            COUNT(*),
            COUNT(*) FILTER (WHERE target_status = 'PENDING'),
            COUNT(*) FILTER (WHERE target_status = 'RUNNING'),
            COUNT(*) FILTER (WHERE target_status = 'COMPLETED'),
            COUNT(*) FILTER (WHERE target_status = 'SKIPPED'),
            COUNT(*) FILTER (WHERE target_status = 'FAILED'),
            COUNT(*) FILTER (WHERE target_status = 'CANCELLED')
        FROM adhoc_campaign_targets
        WHERE campaign_id = %s
    """, (campaign_id,))
    row = cur.fetchone()
    keys = ("targets", "pending", "running", "completed", "skipped", "failed", "cancelled")
    return dict(zip(keys, row))


def list_campaigns(conn, *, page=1, limit=50, status=None, check_id=None, source_scan_id=None):
    page = max(int(page), 1)
    limit = min(max(int(limit), 1), 200)
    if status and status not in CAMPAIGN_STATES:
        raise CampaignError("Invalid campaign status filter")
    offset = (page - 1) * limit
    conditions = []
    params = []
    if status:
        conditions.append("c.status = %s")
        params.append(status)
    if check_id:
        conditions.append("c.check_id = %s")
        params.append(check_id)
    if source_scan_id is not None:
        conditions.append("c.source_scan_id = %s")
        params.append(source_scan_id)
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    cur = conn.cursor()
    try:
        cur.execute(f"SELECT COUNT(*) FROM adhoc_campaigns c {where}", tuple(params))
        count = cur.fetchone()[0]
        cur.execute(f"""
            SELECT c.id, c.check_id, c.source_scan_id, c.requested_by,
                   c.assessment_date, c.dataset_revision, c.status,
                   c.failure_code, c.created_at, c.started_at,
                   c.completed_at, c.cancel_requested_at,
                   COUNT(t.id),
                   COUNT(t.id) FILTER (WHERE t.target_status = 'COMPLETED'),
                   COUNT(t.id) FILTER (WHERE t.target_status IN ('FAILED', 'SKIPPED'))
            FROM adhoc_campaigns c
            LEFT JOIN adhoc_campaign_targets t ON t.campaign_id = c.id
            {where}
            GROUP BY c.id
            ORDER BY c.created_at DESC, c.id DESC
            LIMIT %s OFFSET %s
        """, tuple(params + [limit, offset]))
        rows = cur.fetchall()
        campaigns = []
        for row in rows:
            campaigns.append({
                "campaign_id": row[0], "check_id": row[1], "source_scan_id": row[2],
                "assessment_date": _iso(row[4]),
                "dataset_revision": row[5], "status": row[6], "failure_code": row[7],
                "created_at": _iso(row[8]), "started_at": _iso(row[9]),
                "completed_at": _iso(row[10]), "cancel_requested_at": _iso(row[11]),
                "progress": {"targets": row[12], "completed": row[13], "failed_or_skipped": row[14]},
            })
        return {"page": page, "limit": limit, "count": count, "campaigns": campaigns}
    except Exception as exc:
        if campaign_schema_unavailable(exc):
            raise CampaignSchemaUnavailable() from exc
        raise


def get_campaign(conn, campaign_id):
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT c.id, c.check_id, c.source_scan_id, c.requested_by,
                   c.assessment_date, c.dataset_revision, c.status,
                   c.failure_code, c.created_at, c.started_at,
                   c.completed_at, c.cancel_requested_at,
                   s.status, s.completed_at
            FROM adhoc_campaigns c
            JOIN scans s ON s.id = c.source_scan_id
            WHERE c.id = %s
        """, (campaign_id,))
        row = cur.fetchone()
        if row is None:
            return None
        progress = _progress(cur, campaign_id)
        return {
            "campaign_id": row[0], "check_id": row[1], "source_scan_id": row[2],
            "assessment_date": _iso(row[4]),
            "dataset_revision": row[5], "status": row[6], "failure_code": row[7],
            "created_at": _iso(row[8]), "started_at": _iso(row[9]),
            "completed_at": _iso(row[10]), "cancel_requested_at": _iso(row[11]),
            "source_scan": {"scan_id": row[2], "status": row[12], "completed_at": _iso(row[13])},
            "progress": progress,
        }
    except Exception as exc:
        if campaign_schema_unavailable(exc):
            raise CampaignSchemaUnavailable() from exc
        raise


def get_campaign_results(
    conn, campaign_id, *, page=1, limit=50, target_status=None,
    evaluation_status=None, classification=None, cve_status=None,
):
    page = max(int(page), 1)
    limit = min(max(int(limit), 1), 200)
    if target_status and target_status not in TARGET_STATES:
        raise CampaignError("Invalid target status filter")
    if evaluation_status and evaluation_status not in {"EVALUATED", "NOT_EVALUATED", "UNKNOWN"}:
        raise CampaignError("Invalid evaluation status filter")
    offset = (page - 1) * limit
    conditions = ["t.campaign_id = %s"]
    params = [campaign_id]
    if target_status:
        conditions.append("t.target_status = %s")
        params.append(target_status)
    if evaluation_status:
        conditions.append("r.evaluation_status = %s")
        params.append(evaluation_status)
    if classification:
        conditions.append("r.classification = %s")
        params.append(classification)
    if cve_status:
        conditions.append("EXISTS (SELECT 1 FROM jsonb_array_elements(COALESCE(r.cve_intelligence->'candidates', '[]'::jsonb)) c WHERE c->>'applicability_status' = %s)")
        params.append(cve_status)
    where = " AND ".join(conditions)
    cur = conn.cursor()
    try:
        cur.execute(f"""
            SELECT COUNT(*)
            FROM adhoc_campaign_targets t
            LEFT JOIN LATERAL (
                SELECT r.* FROM adhoc_campaign_results r
                WHERE r.campaign_id = t.campaign_id AND r.target_id = t.id
                ORDER BY r.attempt_number DESC LIMIT 1
            ) r ON TRUE
            WHERE {where}
        """, tuple(params))
        count = cur.fetchone()[0]
        cur.execute(f"""
            SELECT t.id, t.domain_id, t.domain_snapshot, t.source_scan_id,
                   t.target_status, t.skip_reason_code, t.selected_at,
                   t.started_at, t.completed_at,
                   r.execution_status, r.evidence_status, r.evaluation_status,
                   r.classification, r.failure_code, r.skip_reason_code,
                   r.observations, r.lifecycle, r.cve_intelligence,
                   r.observed_at, r.persisted_at, r.dataset_revision
            FROM adhoc_campaign_targets t
            LEFT JOIN LATERAL (
                SELECT r.* FROM adhoc_campaign_results r
                WHERE r.campaign_id = t.campaign_id AND r.target_id = t.id
                ORDER BY r.attempt_number DESC LIMIT 1
            ) r ON TRUE
            WHERE {where}
            ORDER BY t.id
            LIMIT %s OFFSET %s
        """, tuple(params + [limit, offset]))
        results = []
        for row in cur.fetchall():
            results.append({
                "domain": row[2], "source_scan_id": row[3],
                "target_status": row[4], "skip_reason_code": row[5],
                "selected_at": _iso(row[6]), "started_at": _iso(row[7]),
                "completed_at": _iso(row[8]), "execution_status": row[9],
                "evidence_status": row[10], "evaluation_status": row[11],
                "classification": row[12], "failure_code": row[13],
                "result_skip_reason_code": row[14], "observations": row[15] or [],
                "lifecycle": row[16], "cve_intelligence": row[17],
                "observed_at": _iso(row[18]), "persisted_at": _iso(row[19]),
                "dataset_revision": row[20],
            })
        return {"campaign_id": campaign_id, "page": page, "limit": limit, "count": count, "results": results}
    except Exception as exc:
        if campaign_schema_unavailable(exc):
            raise CampaignSchemaUnavailable() from exc
        raise
