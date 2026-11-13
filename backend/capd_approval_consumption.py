"""Atomic, fail-closed consumption of signed CAPD Apache approvals.

This module records authorization consumption only. It has no HTTP transport;
callers may proceed to a separately implemented one-request transport only
after this function returns a committed receipt.
"""

from __future__ import annotations

import hashlib
import json

from apache_version_verification import evaluate_apache_authorization
from capd_authorization import recheck_apache_target_from_inventory
from capd_approval_contract import CAPD_HTTP_HEADER_VERIFY
from capd_local_approval import (
    approval_matches_target,
    verify_approval,
)


class ApprovalConsumptionError(ValueError):
    """Approval was invalid, unauthorized, already consumed, or not persisted."""


def consume_approval(conn, document, public_key, context, target, *,
                     now=None):
    """Validate, reauthorize, then atomically consume one approval.

    The receipt commit is the execution boundary. A receipt is never rolled
    back after a caller receives it, including if a later network attempt
    fails. The current inventory check is performed by the existing CAPD
    authorization adapter immediately before receipt insertion.
    """
    if isinstance(document, str):
        document = document.encode("utf-8")
    try:
        payload = verify_approval(document, public_key, now=now)
    except Exception as exc:
        raise ApprovalConsumptionError("signed approval verification failed") from exc
    if not approval_matches_target(payload, context, target):
        raise ApprovalConsumptionError("approval does not match the run, asset, or service")

    try:
        with conn.cursor() as cursor:
            cursor.execute("SET LOCAL lock_timeout = '5s'")
            cursor.execute("SET LOCAL statement_timeout = '10s'")
            recheck = recheck_apache_target_from_inventory(
                cursor, context, target, now=now,
            )
    except Exception as exc:
        try:
            conn.rollback()
        except Exception:
            pass
        raise ApprovalConsumptionError("fresh authorization recheck failed") from exc
    if not isinstance(recheck, dict):
        try:
            conn.rollback()
        except Exception:
            pass
        raise ApprovalConsumptionError("fresh authorization recheck returned no decision")

    decision = evaluate_apache_authorization(
        context, target,
        trusted_operator_approval=lambda _context, _target: approval_matches_target(
            payload, _context, _target
        ),
        fresh_target_recheck=lambda _context, _target, testing_level: (
            testing_level == CAPD_HTTP_HEADER_VERIFY
            and recheck.get("inventory_policy_passed") is True
        ),
        now=now,
    )
    if decision["decision"] != "AUTHORIZED":
        try:
            conn.rollback()
        except Exception:
            pass
        raise ApprovalConsumptionError(
            "authorization denied: " + ",".join(decision["reason_codes"])
        )

    asset = payload["asset"]
    receipt = {
        "decision": "AUTHORIZED",
        "run_id": payload["run_id"],
        "check_id": payload["check_id"],
        "check_revision": payload["check_revision"],
        "operation": payload["operation"],
        "source_scan_id": payload["source_scan_id"],
        "asset_id": asset["asset_id"],
        "domain": asset["domain"],
        "origin": asset["origin"],
        "method": payload["method"],
        "request_budget": payload["max_requests"],
        "operator_uid": payload["operator_uid"],
        "operator_name": payload["operator_name"],
        "fresh_policy_passed": True,
        "fresh_policy_reason_codes": list(recheck.get("reason_codes") or []),
    }
    consumed_at = None
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO public.capd_approval_consumptions (
                    run_id, approval_sha256, check_id, check_revision,
                    source_scan_id, domain_id, domain_snapshot, origin,
                    http_method, request_budget, operator_uid, operator_name,
                    authorization_receipt
                ) VALUES (
                    %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb
                ) ON CONFLICT DO NOTHING
                RETURNING consumed_at
                """,
                (
                    payload["run_id"], hashlib.sha256(document).hexdigest(),
                    payload["check_id"], payload["check_revision"],
                    payload["source_scan_id"], asset["asset_id"], asset["domain"],
                    asset["origin"], payload["method"], payload["max_requests"],
                    payload["operator_uid"], payload["operator_name"],
                    json.dumps(receipt, sort_keys=True, separators=(",", ":")),
                ),
            )
            row = cursor.fetchone()
        if row is None:
            conn.rollback()
            raise ApprovalConsumptionError("approval was already consumed")
        consumed_at = row[0]
        conn.commit()
    except ApprovalConsumptionError:
        raise
    except Exception as exc:
        try:
            conn.rollback()
        except Exception:
            pass
        raise ApprovalConsumptionError("approval consumption could not be persisted") from exc

    return {
        **receipt,
        "approval_sha256": hashlib.sha256(document).hexdigest(),
        "consumed_at": consumed_at,
        "consumption_committed": True,
        "network_requests": 0,
    }
