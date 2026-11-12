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
    public_check,
)
from db import get_conn


def _json(value):
    print(json.dumps(value, default=str, indent=2, sort_keys=True))


def build_parser():
    parser = argparse.ArgumentParser(prog="capd", description="On-demand passive CVE assessment")
    commands = parser.add_subparsers(dest="command", required=True)
    checks = commands.add_parser("checks", help="inspect inert local check definitions")
    checks.add_argument("action", choices=("list",))
    targets = commands.add_parser("targets", help="preview eligible inventory assets")
    targets.add_argument("--check", required=True)
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
