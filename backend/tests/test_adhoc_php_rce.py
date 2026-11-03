import importlib.util
import logging
import os
import pathlib
import sys
import types
import unittest
from datetime import date, datetime
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))


def load_main():
    fake_db = types.ModuleType("db")
    fake_db.get_conn = lambda: None
    fake_db.get_latest_authoritative_scan_id = lambda cursor: 16
    fake_db.get_previous_authoritative_scan_id = lambda cursor, current=None: 15
    fake_llm = types.ModuleType("llm_service")
    fake_llm.ask_llm = lambda prompt: "unused"
    path = BACKEND / "main.py"
    spec = importlib.util.spec_from_file_location("adhoc_php_rce_main", path)
    module = importlib.util.module_from_spec(spec)
    previous = {name: sys.modules.get(name) for name in ("db", "llm_service")}
    try:
        sys.modules.update({"db": fake_db, "llm_service": fake_llm})
        with mock.patch("logging.FileHandler", return_value=logging.NullHandler()), mock.patch.dict(
            os.environ, {"ASIP_DEFAULT_SCAN_OPERATIONS": "ADHOC_CHECK"}
        ):
            spec.loader.exec_module(module)
    finally:
        for name, value in previous.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value
    return module


class QueueCursor:
    def __init__(self, fetchones=(), fetchalls=()):
        self.fetchones = iter(fetchones)
        self.fetchalls = iter(fetchalls)
        self.executions = []

    def execute(self, sql, params=None):
        self.executions.append((sql, params))

    def fetchone(self):
        return next(self.fetchones)

    def fetchall(self):
        return next(self.fetchalls)


class FakeConnection:
    def __init__(self, cursor):
        self.cursor_obj = cursor
        self.closed = False
        self.commit_count = 0

    def cursor(self):
        return self.cursor_obj

    def close(self):
        self.closed = True

    def commit(self):
        self.commit_count += 1


def fixture_connection(scan=(16, "SUCCEEDED", datetime(2026, 10, 4, 12, 0))):
    observations = [
        (
            1, "PHP", "8.2.34", "high", "x-powered-by_header", "PHP/8.2.34",
            "https://potential.example", "sr-tech-02",
            datetime(2026, 10, 4, 12, 1),
        ),
        (
            2, "php", "8.2.35", "high", "x-powered-by_header", "PHP/8.2.35",
            "https://fixed.example", "sr-tech-02",
            datetime(2026, 10, 4, 12, 2),
        ),
        (
            3, "php", None, "medium", "server_header", "marker=php",
            "https://unknown.example", "sr-tech-02",
            datetime(2026, 10, 4, 12, 3),
        ),
    ]
    authorized_rows = [
        (1, "potential.example", True),
        (2, "fixed.example", True),
        (3, "unknown.example", False),
        (4, "legacy.example", True),
    ]
    legacy_rows = [(4, "legacy.example", "PHP")]
    cursor = QueueCursor(
        fetchones=[scan, (4,)],
        fetchalls=[authorized_rows, observations, legacy_rows],
    )
    return FakeConnection(cursor)


class AdhocPHPRceEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = load_main()

    def call(self, connection, **kwargs):
        self.main.get_conn = lambda: connection
        with mock.patch.object(self.main, "date") as date_type:
            date_type.today.return_value = date(2026, 10, 28)
            return self.main.adhoc_php_rce(**kwargs)

    def test_default_selection_is_scan_bound_and_classifies_authorized_scope(self):
        connection = fixture_connection()
        result = self.call(connection)

        self.assertEqual(result["check"], {
            "id": "php-rce",
            "assessment_date": "2026-10-28",
            "dataset_revision": "2026-10-28",
            "coverage": "partial",
        })
        self.assertEqual(result["scan"]["scan_id"], 16)
        self.assertTrue(result["scan"]["authoritative"])
        self.assertEqual(result["scope"], {
            "scan_members": 4,
            "authorized_assets": 4,
            "http_eligible_assets": 3,
            "evaluated_assets": 3,
            "not_evaluated_assets": 1,
        })
        self.assertEqual(result["count"], 4)
        by_domain = {item["domain"]: item for item in result["results"]}
        self.assertEqual(by_domain["potential.example"]["classification"], "Potential CVE")
        self.assertEqual(by_domain["fixed.example"]["classification"], "Not affected by reported version")
        self.assertEqual(by_domain["unknown.example"]["classification"], "Insufficient evidence")
        self.assertEqual(by_domain["legacy.example"]["classification"], "No PHP observation")
        self.assertEqual(by_domain["legacy.example"]["evaluation_status"], "Not evaluated")
        self.assertTrue(by_domain["legacy.example"]["legacy_php_lead"])
        self.assertEqual(len(result["legacy_leads"]), 1)
        self.assertEqual(result["legacy_leads"][0]["scan_id"], 16)

        potential_observation = by_domain["potential.example"]["observations"][0]
        self.assertEqual(potential_observation["persisted_at"], "2026-10-04T12:01:00")
        self.assertEqual(
            potential_observation["cve_intelligence"]["candidates"][0]["patch_status"],
            "unknown",
        )
        self.assertNotIn("domain_id", potential_observation)
        self.assertEqual(connection.commit_count, 0)
        self.assertTrue(connection.closed)

    def test_authorization_and_scan_isolation_are_enforced_in_all_queries(self):
        connection = fixture_connection()
        result = self.call(connection, scan_id=16)
        self.assertTrue(all(item["scan_id"] == 16 for item in result["results"]))

        for sql, params in connection.cursor_obj.executions[2:]:
            self.assertIn("d.ownership_status = 'CONFIRMED'", sql)
            self.assertIn("d.scannable IS TRUE", sql)
            self.assertIn("manually rejected", sql)
            self.assertIn("AND TRUE", sql)
            self.assertIn("FROM seed_domains seed_root", sql)
            self.assertEqual(params, (16,))

    def test_filters_are_applied_before_pagination(self):
        result = self.call(
            fixture_connection(),
            classification="Potential CVE",
            page=1,
            limit=1,
        )
        self.assertEqual(result["count"], 1)
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["results"][0]["domain"], "potential.example")

        result = self.call(
            fixture_connection(),
            cve_status="not_affected_by_version",
        )
        self.assertEqual(
            [item["domain"] for item in result["results"]],
            ["fixed.example"],
        )

        result = self.call(fixture_connection(), lifecycle="security_support")
        self.assertEqual(
            {item["domain"] for item in result["results"]},
            {"potential.example", "fixed.example"},
        )

    def test_failed_running_unknown_and_missing_scans_are_rejected(self):
        for scan in (None, (14, "FAILED", None), (13, "RUNNING", None), (12, "UNKNOWN", None)):
            with self.subTest(scan=scan):
                cursor = QueueCursor(fetchones=[scan])
                connection = FakeConnection(cursor)
                self.main.get_conn = lambda: connection
                with self.assertRaises(self.main.HTTPException) as raised:
                    self.main.adhoc_php_rce(scan_id=scan[0] if scan else 99)
                self.assertIn(raised.exception.status_code, (404, 409))
                self.assertTrue(connection.closed)

    def test_invalid_filters_are_rejected_without_database_access(self):
        self.main.get_conn = mock.Mock(side_effect=AssertionError("database access"))
        for parameter in (
            {"classification": "safe"},
            {"lifecycle": "safe"},
            {"cve_status": "confirmed"},
        ):
            with self.subTest(parameter=parameter):
                with self.assertRaises(self.main.HTTPException) as raised:
                    self.main.adhoc_php_rce(**parameter)
                self.assertEqual(raised.exception.status_code, 400)

    def test_endpoint_does_not_touch_findings_or_risk_calculation(self):
        connection = fixture_connection()
        risk_calculator = mock.Mock(side_effect=AssertionError("risk calculation"))
        self.main.calculate_scan_risks = risk_calculator
        self.call(connection)
        self.assertFalse(risk_calculator.called)
        self.assertFalse(any("domain_findings" in sql for sql, _ in connection.cursor_obj.executions))
        self.assertEqual(connection.commit_count, 0)


if __name__ == "__main__":
    unittest.main()
