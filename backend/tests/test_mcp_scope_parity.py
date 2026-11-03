import importlib.util
import pathlib
import sys
import types
import unittest
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))


class QueueCursor:
    def __init__(self, *, fetchone=None, fetchall=None):
        self.fetchone_value = fetchone
        self.fetchall_value = fetchall
        self.executions = []

    def execute(self, sql, params=None):
        self.executions.append((sql, params))

    def fetchone(self):
        return self.fetchone_value

    def fetchall(self):
        return self.fetchall_value or []


class FakeConnection:
    def __init__(self, cursor):
        self.cursor_value = cursor
        self.closed = False

    def cursor(self):
        return self.cursor_value

    def close(self):
        self.closed = True


class McpScopeParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fake_db = types.ModuleType("db")
        fake_db.get_conn = lambda: None
        fake_db.get_latest_authoritative_scan_id = lambda cursor: 17
        spec = importlib.util.spec_from_file_location(
            "mcp_scope_parity_under_test", BACKEND / "mcp_server.py"
        )
        cls.mcp = importlib.util.module_from_spec(spec)
        previous_db = sys.modules.get("db")
        try:
            sys.modules["db"] = fake_db
            spec.loader.exec_module(cls.mcp)
        finally:
            if previous_db is None:
                sys.modules.pop("db", None)
            else:
                sys.modules["db"] = previous_db

        import asset_reporting
        cls.reporting = asset_reporting

    def setUp(self):
        self.classes = {
            **{asset_id: "KNOWN" for asset_id in range(1, 58)},
            **{asset_id: "SHADOW" for asset_id in range(58, 571)},
            **{asset_id: "CANDIDATE" for asset_id in range(571, 653)},
        }

    def test_shared_reporting_classification_is_scan_member_bound_and_uses_trusted_inventory(self):
        cursor = QueueCursor(fetchall=[(11, "KNOWN"), (12, "SHADOW"), (13, "CANDIDATE")])
        result = self.reporting.current_scan_asset_classes(cursor, 17)
        self.assertEqual(result, {11: "KNOWN", 12: "SHADOW", 13: "CANDIDATE"})
        sql, params = cursor.executions[0]
        self.assertIn("FROM scan_results sr", sql)
        self.assertIn("WHERE sr.scan_id = %s", sql)
        self.assertIn("FROM seed_domains seed_root", sql)
        self.assertIn("FROM known_domains known_host", sql)
        self.assertEqual(params, (17,))

    def connect(self, cursor):
        connection = FakeConnection(cursor)
        self.mcp.get_conn = lambda: connection
        self.mcp.get_latest_authoritative_scan_id = lambda _cursor: 17
        return connection

    def test_summary_separates_current_class_totals_from_ip_present_counts(self):
        state_rows = (
            [(asset_id, True) for asset_id in range(1, 58)]
            + [(asset_id, asset_id < 558) for asset_id in range(58, 571)]
            + [(asset_id, asset_id < 651) for asset_id in range(571, 653)]
        )
        cursor = QueueCursor(fetchall=state_rows)
        connection = self.connect(cursor)
        with mock.patch.object(
            self.mcp, "current_scan_asset_classes", return_value=self.classes
        ):
            result = self.mcp.get_summary()

        self.assertEqual(result, {
            "scan_id": 17,
            "live_domains": 557,
            "shadow_assets": 500,
            "total_domains": 652,
            "organizational_assets": 570,
            "known_assets": 57,
            "total_shadow_assets": 513,
            "candidate_assets": 82,
            "external_assets": 0,
        })
        sql, params = cursor.executions[0]
        self.assertIn("FROM scan_results sr", sql)
        self.assertIn("WHERE sr.scan_id = %s", sql)
        self.assertEqual(params, (17,))
        self.assertTrue(connection.closed)

    def test_shadow_assets_are_current_scope_shadows_and_keep_ip_present_contract(self):
        cursor = QueueCursor(fetchall=[
            (1, "known.example", "192.0.2.1"),
            (58, "shadow.example", "192.0.2.58"),
            (571, "legacy-confirmed-outside.example", "192.0.2.571"),
        ])
        self.connect(cursor)
        with mock.patch.object(
            self.mcp, "current_scan_asset_classes", return_value=self.classes
        ):
            result = self.mcp.get_shadow_assets()
        self.assertEqual(result, [{"domain": "shadow.example", "ip": "192.0.2.58"}])
        sql, params = cursor.executions[0]
        self.assertIn("FROM scan_results sr", sql)
        self.assertIn("ds.scan_id = sr.scan_id", sql)
        self.assertEqual(params, (17,))

    def test_high_risk_uses_shared_current_scope_risk_filter(self):
        risks = [
            types.SimpleNamespace(
                domain_id=1, domain="known.example",
                result=types.SimpleNamespace(score=9, priority="High", reasons=("known",)),
            ),
            types.SimpleNamespace(
                domain_id=58, domain="shadow.example",
                result=types.SimpleNamespace(score=8, priority="High", reasons=("shadow",)),
            ),
            types.SimpleNamespace(
                domain_id=571, domain="legacy-confirmed-outside.example",
                result=types.SimpleNamespace(score=12, priority="High", reasons=("historical",)),
            ),
        ]
        with mock.patch.object(
            self.reporting, "current_scan_asset_classes", return_value=self.classes
        ), mock.patch.object(
            self.reporting, "calculate_scan_risks", return_value=risks
        ) as calculate:
            self.connect(QueueCursor())
            result = self.mcp.high_risk()

        self.assertEqual({item["domain"] for item in result}, {
            "known.example", "shadow.example"
        })
        self.assertNotIn("legacy-confirmed-outside.example", {
            item["domain"] for item in result
        })
        calculate.assert_called_once()

    def test_domain_detail_preserves_historical_ownership_without_outside_risk(self):
        cursor = QueueCursor(fetchone=(571, "legacy-confirmed-outside.example", False,
                                      "CONFIRMED", "192.0.2.571", 200))
        risks = [types.SimpleNamespace(domain_id=571, result=types.SimpleNamespace(
            score=12, priority="High", reasons=("historical",)
        ))]
        with mock.patch.object(
            self.mcp, "current_scan_asset_classes", return_value=self.classes
        ), mock.patch.object(self.mcp, "current_scan_risks", return_value=[]):
            self.connect(cursor)
            result = self.mcp.get_domain("legacy-confirmed-outside.example")

        self.assertEqual(result["ownership_status"], "CONFIRMED")
        self.assertEqual(result["asset_class"], "CANDIDATE")
        self.assertIsNone(result["risk_score"])
        self.assertIsNone(result["priority"])
        self.assertEqual(result["reasons"], [])
        self.assertIn("sr.scan_id = %s", cursor.executions[0][0])

    def test_priority_targets_include_current_candidates_without_organizational_risk(self):
        cursor = QueueCursor(fetchall=[
            ("legacy-confirmed-outside.example", False, 95, "high", 571),
            ("shadow.example", True, 99, "high", 58),
        ])
        with mock.patch.object(
            self.mcp, "current_scan_asset_classes", return_value=self.classes
        ):
            self.connect(cursor)
            result = self.mcp.priority_targets()

        self.assertEqual(result, [{
            "domain": "legacy-confirmed-outside.example",
            "scannable": False,
            "confidence_score": 95,
            "confidence_label": "high",
            "asset_class": "CANDIDATE",
            "risk_score": None,
            "priority": None,
        }])
        sql, params = cursor.executions[0]
        self.assertIn("FROM scan_results sr", sql)
        self.assertIn("ds.scan_id = sr.scan_id", sql)
        self.assertIn("WHERE sr.scan_id = %s", sql)
        self.assertEqual(params, (17,))


if __name__ == "__main__":
    unittest.main()
