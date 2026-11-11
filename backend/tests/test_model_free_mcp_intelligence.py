import importlib.util
import pathlib
import sys
import types
import unittest
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))


class Cursor:
    def __init__(self, one=None, many=None):
        self.one = one
        self.many = many or []
        self.executions = []

    def execute(self, sql, params=None):
        self.executions.append((sql, params))

    def fetchone(self):
        return self.one

    def fetchall(self):
        return self.many


class Connection:
    def __init__(self, cursor):
        self.value = cursor
        self.closed = False

    def cursor(self):
        return self.value

    def close(self):
        self.closed = True


def load_mcp():
    fake_db = types.ModuleType("db")
    fake_db.get_conn = lambda: None
    fake_db.get_latest_authoritative_scan_id = lambda cursor: 19
    spec = importlib.util.spec_from_file_location("mcp_model_free_under_test", BACKEND / "mcp_server.py")
    module = importlib.util.module_from_spec(spec)
    old = {name: sys.modules.get(name) for name in ("db",)}
    try:
        sys.modules["db"] = fake_db
        spec.loader.exec_module(module)
    finally:
        if old["db"] is None:
            sys.modules.pop("db", None)
        else:
            sys.modules["db"] = old["db"]
    return module


class ModelFreeMcpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mcp = load_mcp()

    def test_tool_inventory_registers_existing_and_added_deterministic_tools(self):
        paths = {route.path for route in self.mcp.app.routes}
        self.assertTrue({
            "/tools/summary", "/tools/shadow-assets", "/tools/domain",
            "/tools/findings", "/tools/high-risk", "/tools/priority-targets",
            "/tools/investigation-guide", "/tools/scan-health",
            "/tools/scan-comparison", "/tools/evidence", "/tools/dns-security",
        }.issubset(paths))

    def test_scan_health_uses_persisted_stage_diagnostics(self):
        diagnostics = {"version": 1, "attempts": [{"stage": "PORT_SCAN", "status": "FAILED"}]}
        cursor = Cursor(one=("SUCCEEDED", "2026-11-10T03:00:00Z", "2026-11-10T03:05:00Z", 2133, diagnostics))
        connection = Connection(cursor)
        self.mcp.get_conn = lambda: connection
        result = self.mcp.scan_health()
        self.assertEqual(result["context"]["scan_id"], 19)
        self.assertEqual(result["data"]["asset_count"], 2133)
        sql, params = cursor.executions[0]
        self.assertIn("COUNT(DISTINCT sr.domain_id)", sql)
        self.assertIn("FROM scan_results sr WHERE sr.scan_id = s.id", sql)
        self.assertNotIn("s.asset_count", sql)
        self.assertEqual(params, (19,))
        self.assertEqual(result["coverage"]["stage_attempts"], 1)
        self.assertIn("does not mean every optional stage", result["coverage"]["interpretation"])
        self.assertTrue(connection.closed)

    def test_scan_health_selects_requested_historical_scan(self):
        diagnostics = {"version": 1, "attempts": []}
        cursor = Cursor(one=("SUCCEEDED", "2026-11-01", "2026-11-01", 10, diagnostics))
        connection = Connection(cursor)
        self.mcp.get_conn = lambda: connection

        result = self.mcp.scan_health(scan_id=15)

        self.assertEqual(result["context"]["scan_id"], 15)
        self.assertEqual(cursor.executions[0][1], (15,))
        self.assertEqual(result["data"]["asset_count"], 10)

    def test_scan_health_reports_missing_diagnostics_without_fabrication(self):
        cursor = Cursor(one=("SUCCEEDED", "2026-11-10", "2026-11-10", 0, None))
        connection = Connection(cursor)
        self.mcp.get_conn = lambda: connection

        result = self.mcp.scan_health(scan_id=19)

        self.assertEqual(result["data"]["asset_count"], 0)
        self.assertIsNone(result["data"]["stage_diagnostics"])
        self.assertFalse(result["coverage"]["diagnostics_available"])
        self.assertEqual(result["coverage"]["stage_attempts"], 0)

    def test_scan_health_returns_404_for_unknown_scan(self):
        cursor = Cursor(one=None)
        connection = Connection(cursor)
        self.mcp.get_conn = lambda: connection

        with self.assertRaises(self.mcp.HTTPException) as raised:
            self.mcp.scan_health(scan_id=999)

        self.assertEqual(raised.exception.status_code, 404)
        self.assertTrue(connection.closed)

    def test_scan_health_preserves_failed_scan_status(self):
        cursor = Cursor(one=("FAILED", "2026-11-10", "2026-11-10", 3, None))
        connection = Connection(cursor)
        self.mcp.get_conn = lambda: connection

        result = self.mcp.scan_health(scan_id=20)

        self.assertEqual(result["data"]["status"], "FAILED")
        self.assertEqual(result["data"]["asset_count"], 3)

    def test_scan_comparison_is_explicitly_historical_and_bounded(self):
        cursor = Cursor()
        cursor.fetchall = mock.Mock(side_effect=[
            [("ADDED", 4, "new.example"), ("REMOVED", 2, "old.example")],
            [("shared.example", "UNKNOWN", None, False, "RESPONDED", 200, True)],
        ])
        cursor.one = ("SUCCEEDED", "2026-11-01", "2026-11-01", 10, {"attempts": []})
        connection = Connection(cursor)
        self.mcp.get_conn = lambda: connection
        result = self.mcp.scan_comparison(18, 19)
        self.assertEqual(result["data"]["added"], [{"domain_id": 4, "domain": "new.example"}])
        self.assertEqual(result["data"]["removed"], [{"domain_id": 2, "domain": "old.example"}])
        self.assertTrue(any("domain_states" in sql and "a.scan_id = %s AND b.scan_id = %s" in sql
                            for sql, _ in cursor.executions))
        self.assertIn("not reconstructed from current ownership", " ".join(result["limitations"]))

    def test_evidence_category_is_fixed_and_pagination_is_bounded(self):
        with self.assertRaises(Exception):
            self.mcp.evidence("arbitrary_table")

        cursor = Cursor(one=("SUCCEEDED", "2026-11-10", "2026-11-10", 10, {"attempts": []}),
                        many=[(1, "asset.example", "KNOWN", 443, "https")])
        connection = Connection(cursor)
        self.mcp.get_conn = lambda: connection
        cursor.fetchone = mock.Mock(side_effect=[
            ("SUCCEEDED", "2026-11-10", "2026-11-10", 10, {"attempts": []}), (1,),
        ])
        result = self.mcp.evidence("ports", scan_id=19, page=1, limit=10)
        self.assertEqual(result["data"]["total"], 1)
        self.assertIn("EXISTS (SELECT 1 FROM scan_results", cursor.executions[1][0])
        self.assertEqual(cursor.executions[2][1], (19, 10, 0))

    def test_investigation_guide_contains_no_active_testing_or_claim_advice(self):
        result = self.mcp.investigation_guide("dangling_dns")
        text = " ".join(result["steps"]).lower()
        self.assertEqual(result["mode"], "deterministic_advisory")
        for unsafe in ("run:", "nmap", "brute force", "attempt to claim", "default credentials"):
            self.assertNotIn(unsafe, text)


if __name__ == "__main__":
    unittest.main()
