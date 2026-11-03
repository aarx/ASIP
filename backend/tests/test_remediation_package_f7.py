import importlib.util
import logging
import pathlib
import sys
import types
import unittest
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]


def load_main():
    fake_db = types.ModuleType("db")
    fake_db.get_conn = lambda: None
    fake_db.get_latest_authoritative_scan_id = lambda cursor: 42
    fake_db.get_previous_authoritative_scan_id = lambda cursor, current=None: 41
    fake_llm = types.ModuleType("llm_service")
    fake_llm.ask_llm = lambda prompt: "unused"
    spec = importlib.util.spec_from_file_location("pkgf7_main", BACKEND / "main.py")
    module = importlib.util.module_from_spec(spec)
    previous = {name: sys.modules.get(name) for name in ("db", "llm_service")}
    old_path = sys.path[:]
    try:
        sys.modules.update({"db": fake_db, "llm_service": fake_llm})
        sys.path.insert(0, str(BACKEND))
        with mock.patch("logging.FileHandler", return_value=logging.NullHandler()):
            spec.loader.exec_module(module)
    finally:
        sys.path[:] = old_path
        for name, value in previous.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value
    return module


class QueueCursor:
    def __init__(self, fetchalls):
        self.fetchalls = iter(fetchalls)
        self.executions = []

    def execute(self, sql, params=None):
        self.executions.append((sql, params))

    def fetchall(self):
        return next(self.fetchalls)


class FakeConnection:
    def __init__(self, cursor):
        self.cursor_obj = cursor
        self.closed = False

    def cursor(self):
        return self.cursor_obj

    def close(self):
        self.closed = True


class ReviewIndicatorContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = load_main()

    def setUp(self):
        self.main.get_latest_authoritative_scan_id = lambda cursor: 42

    def test_cross_host_redirects_are_current_observed_review_evidence(self):
        redirect_rows = [
            (
                "same.example", "CONFIRMED", True, "RESPONDED", 302,
                "https://same.example/path", 200, None,
            ),
            (
                "shadow.example", "CONFIRMED", False, "RESPONDED", 302,
                "https://external.example/login", 200, None,
            ),
            (
                "candidate.example", "CANDIDATE", False, "RESPONDED", 301,
                "https://known.example/home", 200, None,
            ),
            (
                "unknown.example", "CONFIRMED", True, "UNKNOWN", 302,
                "https://external.example/unknown", 200, None,
            ),
        ]
        current_assets = [
            (1, "same.example", "CONFIRMED", True),
            (2, "shadow.example", "CONFIRMED", False),
            (3, "candidate.example", "CANDIDATE", False),
            (4, "known.example", "CONFIRMED", True),
            (5, "external.example", "EXTERNAL", False),
        ]
        cursor = QueueCursor([redirect_rows, current_assets])
        connection = FakeConnection(cursor)
        self.main.get_conn = lambda: connection

        with mock.patch.object(self.main, "_current_scan_asset_classes", return_value={
            1: "KNOWN", 2: "SHADOW", 3: "CANDIDATE",
            4: "KNOWN", 5: "EXTERNAL",
        }):
            result = self.main.frontend_v2_review_indicators()

        self.assertEqual(result["scan_id"], 42)
        self.assertEqual(result["count"], 2)
        self.assertEqual(
            [item["domain"] for item in result["indicators"]],
            ["shadow.example", "candidate.example"],
        )
        shadow, candidate = result["indicators"]
        self.assertEqual(shadow["asset_class"], "SHADOW")
        self.assertEqual(shadow["final_hostname"], "external.example")
        self.assertEqual(shadow["final_url_verification"], "LEGACY_UNKNOWN")
        self.assertIsNone(shadow["observed_redirect_destination"])
        self.assertFalse(shadow["destination_confirmed"])
        self.assertEqual(shadow["destination_ownership_status"], "EXTERNAL")
        self.assertEqual(candidate["asset_class"], "CANDIDATE")
        self.assertTrue(candidate["destination_confirmed"])
        self.assertEqual(candidate["destination_asset_class"], "KNOWN")
        self.assertTrue(connection.closed)

        redirect_sql, redirect_params = cursor.executions[0]
        self.assertIn("FROM scan_results sr", redirect_sql)
        self.assertIn("ds.scan_id = sr.scan_id", redirect_sql)
        self.assertIn("http_observation_status = 'RESPONDED'", redirect_sql)
        self.assertIn("http_status BETWEEN 300 AND 399", redirect_sql)
        self.assertEqual(redirect_params, (42,))
        self.assertEqual(cursor.executions[1][1], (42,))

    def test_no_authoritative_scan_has_a_truthful_empty_contract(self):
        cursor = QueueCursor([])
        connection = FakeConnection(cursor)
        self.main.get_conn = lambda: connection
        self.main.get_latest_authoritative_scan_id = lambda cur: None

        result = self.main.frontend_v2_review_indicators()

        self.assertEqual(result, {"scan_id": None, "count": 0, "indicators": []})
        self.assertEqual(cursor.executions, [])
        self.assertTrue(connection.closed)

    def test_structured_first_hop_is_returned_as_observed_not_final(self):
        evidence = {
            "requested_url": "https://source.example/",
            "http_status": 302,
            "first_hop_location": "https://vendor.example/login",
            "first_hop_destination": "https://vendor.example/login",
            "observed_hops": [{
                "source_url": "https://source.example/",
                "http_status": 302,
                "location": "https://vendor.example/login",
                "destination_url": "https://vendor.example/login",
                "followed": False,
            }],
            "verified_terminal_url": None,
            "completion_status": "UNRESOLVED",
            "stop_reason": "redirect_traversal_disabled",
        }
        rows = [(
            "source.example", "CONFIRMED", True, "RESPONDED", 302,
            None, None, evidence,
        )]
        cursor = QueueCursor([rows, [(1, "source.example", "CONFIRMED", True)]])
        connection = FakeConnection(cursor)
        self.main.get_conn = lambda: connection
        with mock.patch.object(self.main, "_current_scan_asset_classes", return_value={1: "KNOWN"}):
            result = self.main.frontend_v2_review_indicators()
        self.assertEqual(result["count"], 1)
        item = result["indicators"][0]
        self.assertIsNone(item["final_url"])
        self.assertEqual(item["observed_redirect_destination"], "https://vendor.example/login")
        self.assertEqual(item["final_url_verification"], "UNRESOLVED")
        self.assertIsNone(item["redirect_evidence"]["verified_terminal_url"])

    def test_review_indicator_contract_is_read_only_and_does_not_change_risk(self):
        source = (BACKEND / "main.py").read_text(encoding="utf-8")
        start = source.index("def frontend_v2_review_indicators(")
        end = source.index("\n@app.get(\"/chat\")", start)
        block = source[start:end].upper()

        for mutation in ("UPDATE ", "INSERT ", "DELETE ", "SCANNABLE ="):
            self.assertNotIn(mutation, block)
        self.assertNotIn("CALCULATE_SCAN_RISKS", block)
        self.assertNotIn("RISK_SCORE", block)

    def test_review_indicator_route_is_available(self):
        paths = {route.path for route in self.main.app.routes}
        self.assertIn("/v2/review-indicators", paths)


if __name__ == "__main__":
    unittest.main()
