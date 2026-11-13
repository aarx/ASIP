"""Explicit local CLI for passive CAPD assessment; no scheduled entry point."""

import argparse
import json
import sys

from capd import (
    CapdError,
    MAX_TARGETS,
    execute_passive,
    get_check,
    get_run,
    list_runs,
    list_results,
    load_checks,
    preview_targets,
    preview_product_targets,
    public_check,
)
from db import get_conn
from apache_version_verification import (
    APACHE_CHECK_ID,
    APACHE_CHECK_REVISION,
    create_authorization_context,
    evaluate_apache_authorization,
)
from capd_authorization import recheck_apache_target_from_inventory


def _json(value):
    print(json.dumps(value, default=str, indent=2, sort_keys=True))


def build_parser():
    parser = argparse.ArgumentParser(prog="capd", description="On-demand passive CVE assessment")
    commands = parser.add_subparsers(dest="command", required=True)
    checks = commands.add_parser("checks", help="inspect inert local check definitions")
    checks.add_argument("action", choices=("list",))
    targets = commands.add_parser("targets", help="preview eligible inventory assets")
    target_selector = targets.add_mutually_exclusive_group(required=True)
    target_selector.add_argument("--check")
    target_selector.add_argument("--product", choices=("apache",))
    targets.add_argument("--scan-id", type=int)
    targets.add_argument("--limit", type=int, default=MAX_TARGETS)
    run = commands.add_parser("run", help="execute a passive stored-evidence assessment")
    run.add_argument("--check", required=True)
    run.add_argument("--scan-id", type=int)
    run.add_argument("--mode", choices=("passive", "active"), default="passive")
    run.add_argument("--limit", type=int, default=MAX_TARGETS)
    run.add_argument("--dry-run", action="store_true")
    runs = commands.add_parser("runs", help="list persisted CAPD runs")
    runs.add_argument("action", choices=("list",))
    runs.add_argument("--check")
    runs.add_argument("--status")
    runs.add_argument("--page", type=int, default=1)
    runs.add_argument("--limit", type=int, default=50)
    results = commands.add_parser("results", help="list results for one CAPD run")
    results.add_argument("--run", required=True)
    results.add_argument("--status")
    results.add_argument("--page", type=int, default=1)
    results.add_argument("--limit", type=int, default=50)
    apache = commands.add_parser(
        "apache-version", help="preview a future Apache version-header check; dry-run only"
    )
    apache.add_argument("--scan-id", type=int)
    apache.add_argument("--limit", type=int, default=MAX_TARGETS)
    apache.add_argument("--dry-run", action="store_true", required=True)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.command == "checks":
            _schema, checks = load_checks()
            _json({"catalog_schema_version": _schema, "checks": [public_check(value) for value in checks.values()]})
            return 0
        if args.command == "run" and args.mode != "passive":
            raise CapdError("Active CAPD execution is not implemented")
        if args.command == "targets" and args.product:
            conn = get_conn()
            try:
                _json(preview_product_targets(conn, args.product, scan_id=args.scan_id, limit=args.limit))
                return 0
            finally:
                conn.close()
        if args.command == "apache-version":
            conn = get_conn()
            try:
                preview = preview_product_targets(
                    conn, "apache", scan_id=args.scan_id, limit=args.limit
                )
                candidates = [
                    target for target in preview["targets"]
                    if target["classification"] in {"VERSION_KNOWN", "VERSION_UNKNOWN"}
                ]
                context = create_authorization_context(
                    APACHE_CHECK_ID, APACHE_CHECK_REVISION,
                    preview["source_scan"]["scan_id"],
                )
                decisions = []
                for target in candidates:
                    scoped_target = {
                        **target, "source_scan_id": preview["source_scan"]["scan_id"],
                    }
                    inventory_recheck = recheck_apache_target_from_inventory(
                        conn.cursor(), context, scoped_target,
                    )
                    decision = evaluate_apache_authorization(
                        context, scoped_target,
                        fresh_target_recheck=lambda _context, _target, testing_level, result=inventory_recheck: (
                            testing_level == "ADHOC_CHECK" and result["inventory_policy_passed"]
                        ),
                    )
                    decision["inventory_recheck"] = inventory_recheck
                    decisions.append(decision)
                reason_counts = {}
                for decision in decisions:
                    all_reasons = list(decision["reason_codes"])
                    all_reasons.extend(
                        decision.get("inventory_recheck", {}).get("reason_codes", [])
                    )
                    for reason in set(all_reasons):
                        reason_counts[reason] = reason_counts.get(reason, 0) + 1
                _json({
                    "mode": "dry-run",
                    "authorization_context": {
                        "run_id": context.run_id,
                        "check_id": context.check_id,
                        "check_revision": context.check_revision,
                        "source_scan_id": context.source_scan_id,
                        "invocation_source": context.invocation_source,
                        "expires_at": context.expires_at.isoformat(),
                    },
                    "source_scan": preview["source_scan"],
                    "product": preview["product"],
                    "selection": preview["selection"],
                    "populations": preview["populations"],
                    "candidate_count": len(candidates),
                    "planned_requests": [
                        {
                            "domain_id": target["domain_id"],
                            "domain": target["domain"],
                            "asset_class": target["asset_class"],
                            "classification": target["classification"],
                            "plan": "bounded GET to stored Apache observation origin",
                        }
                        for target in candidates
                    ],
                    "network_requests": 0,
                    "database_writes": 0,
                    "live_execution_enabled": False,
                    "authorization": {
                        "operation": "ADHOC_CHECK",
                        "state": "NOT_AUTHORIZED" if candidates else "NO_TARGETS",
                        "authorization_evaluated": False,
                        "inventory_policy_gates_evaluated": True,
                        "approved_target_count": sum(
                            decision["decision"] == "AUTHORIZED" for decision in decisions
                        ),
                        "blocked_target_count": sum(
                            decision["decision"] == "NOT_AUTHORIZED" for decision in decisions
                        ),
                        "reason_counts": reason_counts,
                        "trusted_operator_approval_evaluated": False,
                        "inventory_target_recheck_evaluated": bool(candidates),
                        "full_authorization_grant_evaluated": False,
                        "required_before_live_execution": True,
                        "requires_fresh_target_revalidation": True,
                    },
                    "target_authorization_decisions": decisions,
                })
                return 0
            finally:
                conn.close()
        if args.command in {"targets", "run"}:
            get_check(args.check, include_disabled=False)
        conn = get_conn()
        try:
            if args.command == "targets":
                _json(preview_targets(conn, args.check, scan_id=args.scan_id, limit=args.limit))
            elif args.command == "run":
                _json(execute_passive(
                    conn, args.check, scan_id=args.scan_id, limit=args.limit,
                    dry_run=args.dry_run,
                ))
            elif args.command == "runs":
                _json(list_runs(
                    conn, check_id=args.check, status=args.status,
                    page=args.page, limit=args.limit,
                ))
            elif args.command == "results":
                _json(list_results(
                    conn, args.run, result_status=args.status,
                    page=args.page, limit=args.limit,
                ))
            return 0
        finally:
            conn.close()
    except CapdError as exc:
        print(f"CAPD error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"CAPD execution failed ({type(exc).__name__})", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
