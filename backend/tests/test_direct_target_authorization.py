import importlib.util
import pathlib
import sys
import types
import unittest
from datetime import datetime, timezone
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from authorization_policy import (  # noqa: E402
    ScopeApproval,
    is_authorized,
)


class FakeCursor:
    def __init__(self, rows):
        self.rows = rows
        self.executions = []
        self.rowcount = 1

    def execute(self, sql, params=None):
        self.executions.append((sql, params))

    def fetchall(self):
        return list(self.rows)


class FakeConnection:
    def __init__(self, cursor):
        self._cursor = cursor
        self.commits = 0

    def cursor(self):
        return self._cursor

    def commit(self):
        self.commits += 1

    def close(self):
        pass


def load_worker(filename, rows):
    spec = importlib.util.spec_from_file_location(
        f"direct_auth_{filename}_{id(rows)}", BACKEND / filename
    )
    module = importlib.util.module_from_spec(spec)
    cursor = FakeCursor(rows)
    connection = FakeConnection(cursor)
    fake_db = types.ModuleType("db")
    fake_db.get_conn = lambda: connection
    fake_db.require_running_scan = mock.Mock()
    previous = sys.modules.get("db")
    old_argv = sys.argv[:]
    try:
        sys.modules["db"] = fake_db
        sys.argv = [filename, "42"]
        spec.loader.exec_module(module)
    finally:
        sys.argv = old_argv
        if previous is None:
            sys.modules.pop("db", None)
        else:
            sys.modules["db"] = previous
    return module, cursor, connection


class DirectTargetAuthorizationTests(unittest.TestCase):
    def test_http_tls_is_a_distinct_scope_level_and_manual_path_is_not_broadened(self):
        scope = ScopeApproval(
            scope_domain="example.com",
            include_subdomains=True,
            testing_level="HTTP_TLS_OBSERVATION",
            approved_by="operator",
            approved_at=datetime.now(timezone.utc),
        )
        self.assertTrue(is_authorized(
            ownership_status="CONFIRMED", scannable=True,
            validation_source=None, domain="app.example.com",
            testing_level="HTTP_TLS_OBSERVATION", scopes=[scope],
        ))
        self.assertFalse(is_authorized(
            ownership_status="CONFIRMED", scannable=True,
            validation_source="manual", domain="app.example.com",
            testing_level="HTTP_TLS_OBSERVATION", scopes=[],
        ))
        self.assertTrue(is_authorized(
            ownership_status="CONFIRMED", scannable=True,
            validation_source="manual", domain="app.example.com",
            testing_level="TECHNOLOGY_HTTP", scopes=[],
        ))

    def test_observation_worker_skips_revoked_target_and_continues(self):
        module, cursor, connection = load_worker(
            "http_observation_worker.py",
            [(1, "revoked.example.com", "203.0.113.1"),
             (2, "allowed.example.com", "203.0.113.2")],
        )
        module.recheck_active_authorization = mock.Mock(
            side_effect=[(False, "scope revoked"), (True, "authorized")]
        )
        module.http_probe = mock.Mock(return_value={
            "http_observation_status": "RESPONDED",
            "http_status": 204,
            "http_reason": "No Content",
            "final_url": "https://allowed.example.com/",
            "final_status": 204,
            "title": "",
        })

        with mock.patch("builtins.print"):
            module.main()

        module.http_probe.assert_called_once()
        self.assertEqual(module.http_probe.call_args.args[0], "allowed.example.com")
        self.assertTrue(any("HTTP_TLS_OBSERVATION" in sql for sql, _ in cursor.executions))
        self.assertGreaterEqual(connection.commits, 2)

    def test_observation_worker_database_authorization_error_fails_closed(self):
        module, _, _ = load_worker(
            "http_observation_worker.py", [(1, "denied.example.com", "203.0.113.4")]
        )
        module.recheck_active_authorization = mock.Mock(
            side_effect=RuntimeError("database unavailable")
        )
        module.http_probe = mock.Mock()
        with self.assertRaisesRegex(RuntimeError, "database unavailable"):
            module.main()
        module.http_probe.assert_not_called()

    def test_takeover_http_is_disabled_until_its_own_permission_exists(self):
        module, _, _ = load_worker("takeover_worker.py", [])
        with mock.patch.object(module.requests, "get") as request:
            self.assertIsNone(module.check_takeover("target.example"))
        request.assert_not_called()

    def test_recon_contains_no_direct_http_probe(self):
        source = (BACKEND / "recon.py").read_text(encoding="utf-8")
        self.assertNotIn("from http_probe import", source)
        self.assertNotIn("HTTP probing", source)
        self.assertIn('"http_observation_status": "UNKNOWN"', source)

    def test_migration_008_is_additive_and_contains_only_the_new_level(self):
        source = (BACKEND / "migrations/008_add_http_tls_observation_scope.sql").read_text()
        self.assertIn("BEGIN;", source)
        self.assertIn("COMMIT;", source)
        self.assertIn("HTTP_TLS_OBSERVATION", source)
        for old_level in ("TECHNOLOGY_HTTP", "PORT_SCAN", "ADHOC_CHECK"):
            self.assertIn(old_level, source)
        self.assertNotIn("INSERT INTO", source.upper())
        self.assertNotIn("UPDATE DOMAINS", source.upper())

    def test_destination_filter_rejects_non_global_addresses(self):
        import http_probe

        for address in ("127.0.0.1", "10.1.2.3", "192.0.2.10", "::1"):
            with self.subTest(address=address):
                self.assertTrue(http_probe._prohibited_address(address))


if __name__ == "__main__":
    unittest.main()
