"""Bounded, runner-owned scan stage diagnostics.

Diagnostics are intentionally aggregate-only. They are not scan evidence and
must never contain raw logs, target names, response data, or credentials.
"""

import json
import math
from datetime import datetime, timezone


CONTRACT_VERSION = 1
MAX_STAGE_ATTEMPTS = 34  # 16 base stages + optional DNS Security, at most two attempts each.
MAX_SUMMARY_FIELDS = 32
MAX_SUMMARY_JSON_BYTES = 2048
MAX_STAGE_NAME_LENGTH = 80
MAX_COUNTER_VALUE = 1_000_000_000_000

STAGE_OUTCOMES = {"RUNNING", "SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELLED"}
ERROR_CATEGORIES = {
    "STAGE_TIMEOUT",
    "RETRYABLE_INCOMPLETE",
    "NONZERO_EXIT",
    "INTERRUPTED",
    "STAGE_LAUNCH_ERROR",
    "STAGE_RUNNER_ERROR",
    "SCAN_FAILED",
}

# Only numeric counters/flags from the existing SAN and HTTP JSON summaries
# may cross into persistent diagnostics. Unknown fields are discarded.
WORKER_SUMMARY_FIELDS = {
    "selected", "selected_parent_targets", "completed_parent_targets",
    "successful_tls_retrievals", "no_permitted_destinations", "tls_timeouts",
    "other_tls_failures", "authorization_skips", "worker_errors",
    "cancelled_targets", "raw_san_names_observed", "unique_normalized_san_names",
    "newly_created_domain_identities", "existing_domain_identities_reused",
    "persisted_parent_san_records", "persisted_provenance_relationships",
    "persisted_scan_memberships", "persisted_domain_identity_upserts",
    "persisted_row_writes", "successful", "no_permitted_destination",
    "timeout", "other_failure", "persisted_records", "maximum_concurrency",
    "completed_observations", "persisted_results", "http_no_response",
    "failed_incomplete", "unresolved_redirects", "maximum_observed_concurrency",
    "configured_workers", "workers", "elapsed_seconds", "interrupted", "failed",
    "completed", "checks_persisted", "policy_stops", "disabled",
    "run_scoped", "run_scope_target_count", "query_attempts",
    "query_budget_exhausted",
}

SUMMARY_MARKERS = (
    "ASIP_WORKER_SUMMARY ",
    "san_stage ",
    "http_stage_summary ",
    "dns_security_stage ",
)


def empty_diagnostics():
    return {
        "version": CONTRACT_VERSION,
        "current_stage": None,
        "attempts": [],
        "scan_outcome": None,
        "last_updated_at": None,
    }


def sanitize_worker_summary(value):
    if not isinstance(value, dict):
        return None
    result = {}
    for key, item in value.items():
        if key not in WORKER_SUMMARY_FIELDS or len(result) >= MAX_SUMMARY_FIELDS:
            continue
        if isinstance(item, bool):
            result[key] = item
        elif isinstance(item, int) and 0 <= item <= MAX_COUNTER_VALUE:
            result[key] = item
        elif isinstance(item, float) and math.isfinite(item) and 0 <= item <= MAX_COUNTER_VALUE:
            result[key] = round(item, 4)
    if not result or len(json.dumps(result, separators=(",", ":"))) > MAX_SUMMARY_JSON_BYTES:
        return None
    return result


def extract_worker_summary(output):
    """Read only known one-line structured summary records from stage output."""
    if not isinstance(output, str):
        return None
    found = None
    for line in output.splitlines():
        for marker in SUMMARY_MARKERS:
            position = line.find(marker)
            if position < 0:
                continue
            payload = line[position + len(marker):].strip()
            try:
                parsed = json.loads(payload)
            except (TypeError, ValueError):
                continue
            safe = sanitize_worker_summary(parsed)
            if safe:
                found = safe
    return found


def _as_document(value):
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            value = None
    if value is None:
        return empty_diagnostics()
    if not isinstance(value, dict) or value.get("version") != CONTRACT_VERSION:
        raise ValueError("unsupported scan diagnostics contract")
    attempts = value.get("attempts")
    if not isinstance(attempts, list) or len(attempts) > MAX_STAGE_ATTEMPTS:
        raise ValueError("invalid or oversized scan diagnostics attempts")
    return value


def _load_locked(conn, scan_id, runner_token):
    cur = conn.cursor()
    cur.execute(
        """SELECT stage_diagnostics, clock_timestamp()
             FROM scans
            WHERE id = %s AND status = 'RUNNING' AND runner_token = %s
            FOR UPDATE""",
        (scan_id, runner_token),
    )
    row = cur.fetchone()
    if row is None:
        conn.rollback()
        return None, None, None
    return cur, _as_document(row[0]), row[1]


def _commit_document(conn, cur, scan_id, runner_token, document):
    document["last_updated_at"] = datetime.now(timezone.utc).isoformat()
    cur.execute(
        """UPDATE scans SET stage_diagnostics = %s::jsonb
            WHERE id = %s AND status = 'RUNNING' AND runner_token = %s""",
        (json.dumps(document, separators=(",", ":")), scan_id, runner_token),
    )
    if cur.rowcount != 1:
        conn.rollback()
        return False
    conn.commit()
    return True


def start_stage_attempt(conn, scan_id, runner_token, stage, stage_order, attempt):
    cur, document, now = _load_locked(conn, scan_id, runner_token)
    if cur is None:
        return False
    attempts = document["attempts"]
    if len(attempts) >= MAX_STAGE_ATTEMPTS:
        conn.rollback()
        raise ValueError("scan diagnostics attempt limit reached")
    if any(item.get("stage") == str(stage)[:MAX_STAGE_NAME_LENGTH]
           and item.get("order") == int(stage_order)
           and item.get("attempt") == int(attempt) for item in attempts):
        conn.rollback()
        return False
    record = {
        "stage": str(stage)[:MAX_STAGE_NAME_LENGTH],
        "order": int(stage_order),
        "attempt": int(attempt),
        "status": "RUNNING",
        "started_at": now.isoformat(),
        "completed_at": None,
        "duration_seconds": None,
        "error_category": None,
        "worker_summary": None,
    }
    attempts.append(record)
    document["current_stage"] = {
        "stage": record["stage"], "order": record["order"],
        "attempt": record["attempt"], "started_at": record["started_at"],
    }
    return _commit_document(conn, cur, scan_id, runner_token, document)


def finish_stage_attempt(
    conn, scan_id, runner_token, stage, stage_order, attempt, status,
    duration_seconds, error_category=None, worker_summary=None,
):
    if status not in STAGE_OUTCOMES - {"RUNNING"}:
        raise ValueError("invalid stage outcome")
    if error_category is not None and error_category not in ERROR_CATEGORIES:
        raise ValueError("invalid diagnostics error category")
    cur, document, now = _load_locked(conn, scan_id, runner_token)
    if cur is None:
        return False
    record = next((item for item in reversed(document["attempts"])
                   if item.get("stage") == str(stage)[:MAX_STAGE_NAME_LENGTH]
                   and item.get("order") == int(stage_order)
                   and item.get("attempt") == int(attempt)
                   and item.get("status") == "RUNNING"), None)
    if record is None:
        conn.rollback()
        return False
    record["status"] = status
    record["completed_at"] = now.isoformat()
    try:
        duration = float(duration_seconds)
    except (TypeError, ValueError):
        duration = None
    record["duration_seconds"] = (
        round(max(0.0, duration), 4)
        if duration is not None and math.isfinite(duration) else None
    )
    record["error_category"] = error_category
    record["worker_summary"] = sanitize_worker_summary(worker_summary)
    current = document.get("current_stage")
    if isinstance(current, dict) and current.get("order") == int(stage_order) \
            and current.get("attempt") == int(attempt):
        document["current_stage"] = None
    return _commit_document(conn, cur, scan_id, runner_token, document)


def api_diagnostics(value, scan_status):
    """Return a strict, bounded public projection; never expose raw errors/logs."""
    if value is None:
        return None
    try:
        document = _as_document(value)
    except ValueError:
        return None
    safe_attempts = []
    for item in document["attempts"]:
        if not isinstance(item, dict) or len(safe_attempts) >= MAX_STAGE_ATTEMPTS:
            continue
        status = item.get("status")
        if status not in STAGE_OUTCOMES:
            continue
        category = item.get("error_category")
        safe_attempts.append({
            "stage": str(item.get("stage", ""))[:MAX_STAGE_NAME_LENGTH],
            "order": item.get("order") if isinstance(item.get("order"), int) else None,
            "attempt": item.get("attempt") if isinstance(item.get("attempt"), int) else None,
            "status": status,
            "started_at": item.get("started_at"),
            "completed_at": item.get("completed_at"),
            "duration_seconds": item.get("duration_seconds")
            if isinstance(item.get("duration_seconds"), (int, float)) else None,
            "error_category": category if category in ERROR_CATEGORIES else None,
            "worker_summary": sanitize_worker_summary(item.get("worker_summary")),
        })
    raw_current = document.get("current_stage") if scan_status == "RUNNING" else None
    current = None
    if isinstance(raw_current, dict):
        current = {
            "stage": str(raw_current.get("stage", ""))[:MAX_STAGE_NAME_LENGTH],
            "order": raw_current.get("order")
            if isinstance(raw_current.get("order"), int) else None,
            "attempt": raw_current.get("attempt")
            if isinstance(raw_current.get("attempt"), int) else None,
            "started_at": str(raw_current.get("started_at"))[:64]
            if raw_current.get("started_at") is not None else None,
        }
    scan_outcome = document.get("scan_outcome")
    safe_scan_outcome = None
    if (isinstance(scan_outcome, dict)
            and scan_outcome.get("status") == scan_status
            and scan_status in {"SUCCEEDED", "FAILED"}):
        safe_scan_outcome = {
            "status": scan_outcome["status"],
            "completed_at": scan_outcome.get("completed_at"),
            "error_category": scan_outcome.get("error_category")
            if scan_outcome.get("error_category") in ERROR_CATEGORIES else None,
        }
    return {
        "version": CONTRACT_VERSION,
        "current_stage": current,
        "attempts": safe_attempts,
        "scan_outcome": safe_scan_outcome,
        "last_updated_at": document.get("last_updated_at"),
    }
