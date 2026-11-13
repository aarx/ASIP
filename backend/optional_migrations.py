"""Explicit, ledger-backed application of approved optional migrations.

Only explicitly allowlisted optional migrations are supported here.
Sequential historical migrations remain governed by the operator procedure
in docs/OPERATIONS.md.
"""

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from db import get_conn


MIGRATION_DIR = Path(__file__).resolve().parent / "migrations"
OPTIONAL_MIGRATIONS = {
    "015_add_capd_runs": MIGRATION_DIR / "015_add_capd_runs.sql",
    "016_add_capd_http_header_verify_operation": (
        MIGRATION_DIR / "016_add_capd_http_header_verify_operation.sql"
    ),
    "017_add_capd_approval_consumptions": MIGRATION_DIR / "017_add_capd_approval_consumptions.sql",
}
MIGRATION_OBJECTS = {
    "015_add_capd_runs": ("public.capd_runs", "public.capd_results"),
    "017_add_capd_approval_consumptions": (
        "public.capd_approval_consumptions",
    ),
}
LEDGER = "public.asip_optional_migration_ledger"
LEDGER_DDL = f"""
CREATE TABLE IF NOT EXISTS {LEDGER} (
    migration_id text PRIMARY KEY,
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{{64}}$'),
    source_file text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
)
"""


class OptionalMigrationError(RuntimeError):
    """A migration is unknown, changed, already applied, or failed safely."""


@dataclass(frozen=True)
class Migration:
    migration_id: str
    source_file: str
    checksum: str
    body: str


def load_migration(migration_id):
    path = OPTIONAL_MIGRATIONS.get(migration_id)
    if path is None:
        raise OptionalMigrationError(
            f"Migration {migration_id!r} is not in the optional migration allowlist"
        )
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise OptionalMigrationError("Migration SQL file is unavailable") from exc
    try:
        sql = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OptionalMigrationError("Migration SQL must be UTF-8") from exc

    # The checked-in 015 file is transaction-wrapped for its historical manual
    # procedure. Strip only those exact outer statements so the ledger receipt
    # and DDL share this runner's single PostgreSQL transaction.
    match = re.fullmatch(r"\s*BEGIN\s*;\s*(.*?)\s*COMMIT\s*;\s*", sql,
                         flags=re.IGNORECASE | re.DOTALL)
    if not match:
        raise OptionalMigrationError(
            "Optional migration must have one outer BEGIN/COMMIT pair"
        )
    body = match.group(1)
    if re.search(r"(?im)^\s*(BEGIN|COMMIT|ROLLBACK)\s*;", body):
        raise OptionalMigrationError("Nested transaction control is not supported")
    return Migration(
        migration_id=migration_id,
        source_file=path.name,
        checksum=hashlib.sha256(raw).hexdigest(),
        body=body,
    )


def _ledger_exists(cursor):
    cursor.execute("SELECT to_regclass(%s)", (LEDGER,))
    return cursor.fetchone()[0] is not None


def _read_receipt(cursor, migration):
    cursor.execute(
        f"SELECT sha256, source_file, applied_at FROM {LEDGER} WHERE migration_id=%s",
        (migration.migration_id,),
    )
    row = cursor.fetchone()
    if row is None:
        return None
    if row[0] != migration.checksum:
        raise OptionalMigrationError(
            f"Checksum mismatch for applied migration {migration.migration_id}; "
            "do not reapply or alter the receipt"
        )
    return {"sha256": row[0], "source_file": row[1], "applied_at": row[2]}


def _migration_objects(cursor, migration_id):
    if migration_id == "016_add_capd_http_header_verify_operation":
        cursor.execute("SELECT to_regclass(%s)", ("public.active_scan_scopes",))
        if cursor.fetchone()[0] is None:
            raise OptionalMigrationError(
                "Migration 016 prerequisite public.active_scan_scopes is absent"
            )
        cursor.execute(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conrelid=%s::regclass AND conname=%s",
            ("public.active_scan_scopes", "active_scan_scopes_testing_level"),
        )
        row = cursor.fetchone()
        if row is None:
            raise OptionalMigrationError(
                "Migration 016 prerequisite testing-level constraint is absent"
            )
        return ("CAPD_HTTP_HEADER_VERIFY" in row[0],)

    objects = MIGRATION_OBJECTS[migration_id]
    cursor.execute(
        "SELECT " + ", ".join("to_regclass(%s)" for _ in objects), objects
    )
    return cursor.fetchone()


def plan(conn, migration_id):
    """Read-only status check; does not create the ledger or write a receipt."""
    migration = load_migration(migration_id)
    with conn.cursor() as cursor:
        cursor.execute("SET TRANSACTION READ ONLY")
        exists = _ledger_exists(cursor)
        receipt = _read_receipt(cursor, migration) if exists else None
        objects = _migration_objects(cursor, migration_id)
    if receipt:
        if not all(objects):
            raise OptionalMigrationError(
                f"Migration {migration_id} has a receipt but its expected schema state is absent"
            )
        state = "APPLIED"
    elif any(objects):
        raise OptionalMigrationError(
            "Expected migration schema state exists without an optional-migration receipt; "
            "manual reconciliation is required"
        )
    else:
        state = "PENDING"
    return {
        "migration_id": migration.migration_id,
        "source_file": migration.source_file,
        "sha256": migration.checksum,
        "state": state,
        "receipt": receipt,
        "ledger_present": exists,
        "capd_objects_present": any(objects),
        "expected_schema_present": all(objects),
    }


def apply(conn, migration_id, *, approval_checksum=None):
    """Apply one explicitly approved migration and receipt atomically."""
    migration = load_migration(migration_id)
    if approval_checksum != migration.checksum:
        raise OptionalMigrationError(
            "Explicit approval must provide the exact SHA-256 from the reviewed plan"
        )
    try:
        with conn.cursor() as cursor:
            cursor.execute("SET LOCAL lock_timeout = '5s'")
            cursor.execute("SET LOCAL statement_timeout = '120s'")
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtext('asip_optional_migrations'))"
            )
            cursor.execute(LEDGER_DDL)
            receipt = _read_receipt(cursor, migration)
            if receipt:
                raise OptionalMigrationError(
                    f"Migration {migration_id} is already applied"
                )
            if any(_migration_objects(cursor, migration_id)):
                raise OptionalMigrationError(
                    "Expected migration schema state exists without a receipt; refusing to adopt it"
                )
            cursor.execute(migration.body)
            if not all(_migration_objects(cursor, migration_id)):
                raise OptionalMigrationError(
                    f"Migration {migration_id} did not produce its expected schema state"
                )
            cursor.execute(
                f"INSERT INTO {LEDGER}(migration_id, sha256, source_file) "
                "VALUES (%s, %s, %s) RETURNING applied_at",
                (migration.migration_id, migration.checksum, migration.source_file),
            )
            applied_at = cursor.fetchone()[0]
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return {
        "migration_id": migration.migration_id,
        "source_file": migration.source_file,
        "sha256": migration.checksum,
        "state": "APPLIED",
        "applied_at": applied_at,
    }


def build_parser():
    parser = argparse.ArgumentParser(
        description="Plan or apply explicitly approved optional schema migrations"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    plan_parser = commands.add_parser("plan", help="read-only migration/checksum preview")
    plan_parser.add_argument("--migration", choices=tuple(OPTIONAL_MIGRATIONS), required=True)
    apply_parser = commands.add_parser("apply", help="apply an approved optional migration")
    apply_parser.add_argument("--migration", choices=tuple(OPTIONAL_MIGRATIONS), required=True)
    apply_parser.add_argument("--approve-sha256", required=True,
                              help="exact SHA-256 reviewed from the read-only plan")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    conn = get_conn()
    try:
        result = (plan(conn, args.migration) if args.command == "plan"
                  else apply(conn, args.migration,
                             approval_checksum=args.approve_sha256))
        if args.command == "plan":
            conn.rollback()
        print(json.dumps(result, default=str, sort_keys=True, indent=2))
        return 0
    except OptionalMigrationError as exc:
        conn.rollback()
        print(f"Optional migration stopped: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        conn.rollback()
        print(f"Optional migration failed ({type(exc).__name__}); transaction rolled back",
              file=sys.stderr)
        return 1
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
