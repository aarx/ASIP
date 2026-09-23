"""Package 2B1 scan-pair selection and API contracts, without a database."""

import importlib.util
import logging
import pathlib
import sys
import types
import unittest
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
ENDPOINTS = {
    "disappeared": "disappeared_domains",
    "new_domains_delta": "new_domains",
    "newly_live": "newly_live_domains",
    "newly_dead": "newly_dead_domains",
}
SCENARIOS = {
    "none": ({1: "UNKNOWN", 11: "UNKNOWN"}, None, None),
    "one": ({1: "UNKNOWN", 11: "UNKNOWN", 12: "SUCCEEDED"}, 12, None),
    "consecutive": ({12: "SUCCEEDED", 13: "SUCCEEDED"}, 13, 12),
    "failed_gap": ({12: "SUCCEEDED", 13: "FAILED", 14: "SUCCEEDED"}, 14, 12),
    "running_after": ({12: "SUCCEEDED", 13: "RUNNING"}, 12, None),
    "failed_after": ({12: "SUCCEEDED", 13: "FAILED"}, 12, None),
}


def load_module(path, replacements):
    name = f"pkg2b1_{path.stem}_{len(sys.modules)}"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    old_modules = {key: sys.modules.get(key) for key in replacements}
    try:
        sys.modules.update(replacements)
        with mock.patch("logging.FileHandler", return_value=logging.NullHandler()):
            spec.loader.exec_module(module)
    finally:
        for key, previous in old_modules.items():
            if previous is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = previous
    return module


class ScanCursor:
    def __init__(self, statuses):
        self.statuses = statuses
        self.executions = []
        self.result = None

    def execute(self, sql, params=None):
        self.executions.append((sql, params))
        if "FROM scans" in sql:
            self.assert_authoritative_sql(sql)
            candidates = [scan_id for scan_id, status in self.statuses.items()
                          if status == "SUCCEEDED"]
            if "id < %s" in sql:
                candidates = [scan_id for scan_id in candidates if scan_id < params[0]]
            self.result = (max(candidates),) if candidates else None
        elif "SELECT COUNT(*)" in sql:
            self.result = (3,) if len(self.executions) % 2 else (4,)
        else:
            self.result = [("asset.example.test",)]

    @staticmethod
    def assert_authoritative_sql(sql):
        assert "status = 'SUCCEEDED'" in sql
        assert "ORDER BY id DESC" in sql
        assert "LIMIT 1" in sql

    def fetchone(self):
        return self.result

    def fetchall(self):
        return self.result


class FakeConnection:
    def __init__(self, cursor):
        self._cursor = cursor
        self.closed = False

    def cursor(self):
        return self._cursor

    def close(self):
        self.closed = True


class PreviousAuthoritativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fake_config = types.SimpleNamespace(
            DB_HOST="unused", DB_NAME="unused", DB_USER="unused", DB_PASSWORD="unused"
        )
        cls.db = load_module(BACKEND / "db.py", {"config": fake_config})

    def test_scenarios_a_through_f(self):
        for name, (statuses, expected_current, expected_previous) in SCENARIOS.items():
            with self.subTest(name=name):
                cursor = ScanCursor(statuses)
                current = self.db.get_latest_authoritative_scan_id(cursor)
                previous = self.db.get_previous_authoritative_scan_id(cursor, current)
                self.assertEqual((current, previous), (expected_current, expected_previous))
                self.assertEqual(len(cursor.executions), 2)

    def test_omitted_current_looks_up_current_then_previous(self):
        cursor = ScanCursor({12: "SUCCEEDED", 13: "FAILED", 14: "SUCCEEDED"})
        self.assertEqual(self.db.get_previous_authoritative_scan_id(cursor), 12)
        self.assertEqual(len(cursor.executions), 2)
        sql, params = cursor.executions[1]
        self.assertIn("status = 'SUCCEEDED'", sql)
        self.assertIn("id < %s", sql)
        self.assertIn("ORDER BY id DESC", sql)
        self.assertIn("LIMIT 1", sql)
        self.assertEqual(params, (14,))

    def test_omitted_current_without_success_returns_none(self):
        cursor = ScanCursor({11: "UNKNOWN", 12: "FAILED"})
        self.assertIsNone(self.db.get_previous_authoritative_scan_id(cursor))
        self.assertEqual(len(cursor.executions), 1)

    def test_supplied_current_does_not_query_current_again(self):
        cursor = ScanCursor({12: "SUCCEEDED", 13: "RUNNING", 14: "SUCCEEDED"})
        self.assertEqual(self.db.get_previous_authoritative_scan_id(cursor, 14), 12)
        self.assertEqual(len(cursor.executions), 1)
        sql, params = cursor.executions[0]
        self.assertIn("status = 'SUCCEEDED'", sql)
        self.assertIn("id < %s", sql)
        self.assertEqual(params, (14,))


class EndpointContractsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fake_config = types.SimpleNamespace(
            DB_HOST="unused", DB_NAME="unused", DB_USER="unused", DB_PASSWORD="unused"
        )
        cls.db = load_module(BACKEND / "db.py", {"config": fake_config})
        fake_db = types.ModuleType("db")
        fake_db.get_conn = lambda: None
        fake_db.get_latest_authoritative_scan_id = cls.db.get_latest_authoritative_scan_id
        fake_db.get_previous_authoritative_scan_id = cls.db.get_previous_authoritative_scan_id
        fake_llm = types.ModuleType("llm_service")
        fake_llm.ask_llm = lambda prompt: "unused"
        cls.main = load_module(BACKEND / "main.py", {
            "db": fake_db, "llm_service": fake_llm
        })

    def run_endpoint(self, name, statuses):
        cursor = ScanCursor(statuses)
        connection = FakeConnection(cursor)
        self.main.get_conn = lambda: connection
        response = getattr(self.main, name)()
        self.assertTrue(connection.closed, name)
        return response, cursor.executions

    def test_scenarios_a_through_f_preserve_list_shapes_and_query_order(self):
        for scenario, (statuses, current, previous) in SCENARIOS.items():
            for endpoint, result_key in ENDPOINTS.items():
                with self.subTest(scenario=scenario, endpoint=endpoint):
                    response, executions = self.run_endpoint(endpoint, statuses)
                    expected_domains = ["asset.example.test"] if previous is not None else []
                    self.assertEqual(response, {
                        "from_scan": previous,
                        "to_scan": current,
                        result_key: expected_domains,
                    })
                    comparisons = [(sql, params) for sql, params in executions
                                   if "FROM scans" not in sql]
                    if previous is None:
                        self.assertEqual(comparisons, [])
                    else:
                        expected_params = ((current, previous) if endpoint == "new_domains_delta"
                                           else (previous, current))
                        self.assertEqual(len(comparisons), 1)
                        self.assertEqual(comparisons[0][1], expected_params)

    def test_scenarios_a_through_f_preserve_drift_contract(self):
        for scenario, (statuses, current, previous) in SCENARIOS.items():
            with self.subTest(scenario=scenario):
                response, executions = self.run_endpoint("exposure_drift", statuses)
                comparisons = [(sql, params) for sql, params in executions
                               if "FROM scans" not in sql]
                if previous is None:
                    self.assertEqual(response, {"new": 0, "disappeared": 0})
                    self.assertEqual(comparisons, [])
                else:
                    self.assertEqual(response, {
                        "new": 3, "disappeared": 4,
                        "latest_scan": current, "previous_scan": previous,
                    })
                    self.assertEqual([params for _, params in comparisons], [
                        (current, previous), (previous, current)
                    ])

    def test_all_five_call_shared_helpers_without_arithmetic_predecessor(self):
        source = (BACKEND / "main.py").read_text()
        for name in (*ENDPOINTS, "exposure_drift"):
            with self.subTest(endpoint=name):
                start = source.index(f"def {name}(")
                end = source.find("\n@app.get", start)
                block = source[start:end if end != -1 else None]
                self.assertIn("get_latest_authoritative_scan_id(cur)", block)
                self.assertIn("get_previous_authoritative_scan_id(cur, current)", block)
                self.assertNotIn("MAX(id)", block)
                self.assertNotIn("latest - 1", block)
                self.assertNotIn("current - 1", block)
                self.assertNotIn("scan_id - 1", block)
                self.assertNotIn("OFFSET 1", block.upper())


if __name__ == "__main__":
    unittest.main()
