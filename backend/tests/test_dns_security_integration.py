import os
import pathlib
import sys
import unittest
from unittest import mock

BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

import dns_security_worker  # noqa: E402
import main  # noqa: E402
from scan_diagnostics import extract_worker_summary  # noqa: E402


class WorkerCursor:
    def __init__(self, targets=()):
        self.targets = list(targets)
        self.sql = []
        self.fetchone_values = [("RUNNING",)]

    def execute(self, query, params=None):
        self.sql.append((query, params))

    def fetchone(self):
        return self.fetchone_values.pop(0) if self.fetchone_values else None

    def fetchall(self):
        return self.targets


class WorkerConnection:
    def __init__(self, cursor):
        self.cursor_value = cursor
        self.closed = False
        self.autocommit = False

    def cursor(self):
        return self.cursor_value

    def rollback(self):
        pass

    def close(self):
        self.closed = True


class DnsSecurityWorkerTests(unittest.TestCase):
    def test_disabled_stage_does_not_open_database_or_resolve(self):
        with mock.patch.object(dns_security_worker, "default_operation_enabled", return_value=False), \
             mock.patch.object(dns_security_worker, "get_conn") as get_conn, \
             mock.patch.object(dns_security_worker, "_emit") as emit:
            self.assertEqual(dns_security_worker.run_dns_security_stage(91), 0)
        get_conn.assert_not_called()
        self.assertTrue(emit.call_args.args[0]["disabled"])
        self.assertEqual(emit.call_args.args[0]["checks_persisted"], 0)

    def test_orchestration_registers_dns_stage_only_under_operation_gate(self):
        source = (BACKEND / "orchestration.py").read_text(encoding="utf-8")
        self.assertIn('if default_operation_enabled("DNS_SECURITY"):', source)
        self.assertIn('dns_stage = ("DNS Security",', source)
        self.assertIn('insertion = next(i for i, item in enumerate(pipeline)', source)
        self.assertIn('if item[0] == "HTTP/TLS Observation"', source)

    def test_enabled_stage_selects_only_authorized_current_scan_members(self):
        cursor = WorkerCursor([(4, "known.example")])
        selection_conn = WorkerConnection(cursor)
        target_conn = WorkerConnection(WorkerCursor())
        connections = iter((selection_conn, target_conn))
        with mock.patch.dict(os.environ, {"ASIP_DEFAULT_SCAN_OPERATIONS": "DNS_SECURITY"}), \
             mock.patch.object(dns_security_worker, "default_operation_enabled", return_value=True), \
             mock.patch.object(dns_security_worker, "get_conn", side_effect=lambda: next(connections)), \
             mock.patch.object(dns_security_worker, "dns_security_query_authorizer", return_value=lambda _name: True), \
             mock.patch.object(dns_security_worker, "persist_dns_security_check", return_value=True) as persist, \
             mock.patch.object(dns_security_worker, "_emit") as emit:
            result = dns_security_worker.run_dns_security_stage(91, resolver_factory=lambda: _EmptyResolver())
        self.assertEqual(result, 0)
        self.assertEqual(len(cursor.sql), 2)
        selection_sql = cursor.sql[1][0]
        self.assertIn("sr.scan_id = %s", selection_sql)
        self.assertIn("d.scannable IS TRUE", selection_sql)
        self.assertIn("'KNOWN', 'SHADOW'", selection_sql)
        self.assertIn("DNS_SECURITY", selection_sql)
        self.assertEqual(persist.call_count, 6)
        self.assertTrue(selection_conn.closed)
        self.assertTrue(target_conn.closed)
        self.assertEqual(emit.call_args.args[0]["completed"], 1)
        self.assertEqual(emit.call_args.args[0]["checks_persisted"], 6)


class _EmptyResolver:
    def __init__(self):
        self.timeout = None
        self.lifetime = None
        self.retry_servfail = True

    def resolve(self, name, rrtype, **kwargs):
        return []


class ApiCursor:
    def __init__(self, responses):
        self.responses = list(responses)
        self.executions = []

    def execute(self, query, params=None):
        self.executions.append((query, params))

    def fetchone(self):
        value = self.responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return value

    def fetchall(self):
        return self.responses.pop(0)


class ApiConnection:
    def __init__(self, cursor):
        self.cursor_value = cursor
        self.closed = False
        self.rolled_back = False

    def cursor(self):
        return self.cursor_value

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


class MissingTableError(Exception):
    pgcode = "42P01"


class DnsSecurityApiTests(unittest.TestCase):
    def setUp(self):
        self.old_env = os.environ.get("ASIP_DEFAULT_SCAN_OPERATIONS")
        os.environ.pop("ASIP_DEFAULT_SCAN_OPERATIONS", None)

    def tearDown(self):
        if self.old_env is None:
            os.environ.pop("ASIP_DEFAULT_SCAN_OPERATIONS", None)
        else:
            os.environ["ASIP_DEFAULT_SCAN_OPERATIONS"] = self.old_env

    def test_summary_distinguishes_checked_unchecked_findings_and_disabled(self):
        cursor = ApiCursor([
            ("SUCCEEDED", {"version": 1, "attempts": []}),
            (10, 3, 9, 2),
            [("CLEAR", 5), ("WARNING", 2), ("INCONCLUSIVE", 2)],
            [("INFO", 5), ("LOW", 4)],
            [("dns_a_resolution", 5), ("cname_health", 4)],
        ])
        conn = ApiConnection(cursor)
        with mock.patch.object(main, "get_conn", return_value=conn):
            result = main.dns_security_summary(scan_id=91)
        self.assertEqual(result["execution_state"], "DISABLED")
        self.assertEqual((result["eligible_assets"], result["checked_assets"],
                          result["unchecked_assets"], result["affected_assets"]), (10, 3, 7, 2))
        self.assertEqual(result["dns_finding_records"], 2)
        self.assertEqual(result["checks_executed"], 9)
        self.assertEqual(result["counts_by_outcome"]["CLEAR"], 5)
        self.assertTrue(all("'KNOWN','SHADOW'" in sql or "'KNOWN', 'SHADOW'" in sql
                            for sql, _ in cursor.executions[1:]))
        self.assertTrue(conn.closed)

    def test_findings_pagination_filter_scope_and_order_are_bound(self):
        row = (7, 4, "synthetic.example", "SHADOW", "cname_health", "WARNING",
               "LOW", "MEDIUM", "CNAME", "alias.synthetic.example", {}, "Review the CNAME.", "2026-01-01T00:00:00Z")
        cursor = ApiCursor([
            ("SUCCEEDED", {"version": 1, "attempts": []}),
            (1,), [row],
        ])
        conn = ApiConnection(cursor)
        with mock.patch.object(main, "get_conn", return_value=conn):
            result = main.dns_security_findings(
                scan_id=91, category="cname_health", outcome="warning",
                asset_class="shadow", page=2, limit=1,
            )
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["findings"][0]["domain"], "synthetic.example")
        self.assertEqual(cursor.executions[1][1], (91, "cname_health", "WARNING", "SHADOW"))
        self.assertIn("JOIN scan_results sr ON sr.scan_id = c.scan_id", cursor.executions[1][0])
        self.assertIn("ORDER BY c.checked_at DESC, d.domain ASC", cursor.executions[2][0])
        self.assertEqual(cursor.executions[2][1][-2:], (1, 1))

    def test_candidate_filter_is_rejected_before_database_access(self):
        with mock.patch.object(main, "get_conn") as get_conn:
            with self.assertRaises(main.HTTPException) as raised:
                main.dns_security_findings(asset_class="CANDIDATE")
        self.assertEqual(raised.exception.status_code, 400)
        get_conn.assert_not_called()

    def test_missing_migration_returns_explicit_unavailable_response(self):
        cursor = ApiCursor([("SUCCEEDED", {"version": 1, "attempts": []}), MissingTableError("missing")])
        conn = ApiConnection(cursor)
        with mock.patch.object(main, "get_conn", return_value=conn):
            result = main.dns_security_summary(scan_id=91)
        self.assertEqual(result.status_code, 503)
        self.assertEqual(result.body, b'{"scan_id":91,"availability_state":"SCHEMA_UNAVAILABLE","detail":"DNS Security storage is not installed"}')
        self.assertTrue(conn.rolled_back)

    def test_domain_evidence_is_stable_id_and_current_scan_scoped(self):
        cursor = ApiCursor([
            ("SUCCEEDED", {"version": 1, "attempts": []}),
            (4, "synthetic.example", "SHADOW"),
            [("cname_health", "POTENTIAL_EXPOSURE", "LOW", "LOW", "CNAME",
              "alias.synthetic.example", {"takeover_confirmed": False}, "Review target.",
              "2026-01-01T00:00:00Z")],
        ])
        conn = ApiConnection(cursor)
        with mock.patch.object(main, "get_conn", return_value=conn):
            result = main.dns_security_domain_evidence(4, scan_id=91)
        self.assertEqual(result["domain_id"], 4)
        self.assertEqual(result["execution_state"], "CHECKED")
        self.assertEqual(result["checks"][0]["verification_status"], "POTENTIAL_EXPOSURE")
        self.assertEqual(cursor.executions[1][1], (91, 4))
        self.assertEqual(cursor.executions[2][1], (91, 4))
        self.assertIn("WHERE scan_id = %s AND domain_id = %s", cursor.executions[2][0])

    def test_dns_stage_worker_summary_is_available_to_diagnostics(self):
        summary = extract_worker_summary(
            '2026-01-01 INFO dns_security_stage {"selected":3,"completed":2,"checks_persisted":14,"disabled":false}'
        )
        self.assertEqual(summary, {"selected": 3, "completed": 2,
                                   "checks_persisted": 14, "disabled": False})


if __name__ == "__main__":
    unittest.main()
