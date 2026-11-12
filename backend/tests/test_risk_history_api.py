import pathlib
import sys
import unittest
from datetime import datetime
from unittest import mock

BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

import main  # noqa: E402


class RiskHistoryCursor:
    def __init__(self, *, scans=None, unique=(19, 19, 19), total=19, assets=()):
        self.scans = list(scans or [])
        self.unique = unique
        self.total = total
        self.assets = list(assets)
        self.executions = []
        self.result = None

    def execute(self, sql, params=None):
        self.executions.append((sql, params))
        if "GROUP BY scan_id, scan_time" in sql:
            self.result = self.scans
        elif "COUNT(DISTINCT h.domain_id), COUNT(*)" in sql:
            self.result = self.unique
        elif "SELECT COUNT(*), (SELECT MAX(id) FROM successful_scans)" in sql:
            self.result = (self.total, self.scans[-1][0] if self.scans else None)
        elif "FROM history h" in sql:
            self.result = self.assets
        else:
            raise AssertionError("Unexpected risk-history SQL")

    def fetchone(self):
        return self.result

    def fetchall(self):
        return self.result


class RiskHistoryConnection:
    def __init__(self, cursor):
        self.value = cursor
        self.closed = False
        self.rolled_back = False

    def cursor(self):
        return self.value

    def close(self):
        self.closed = True

    def rollback(self):
        self.rolled_back = True


class RiskHistoryApiTests(unittest.TestCase):
    def setUp(self):
        self.scan_rows = [
            (12, datetime(2025, 1, 1), 197, 91, 0, 0),
            (13, datetime(2025, 2, 1), 200, 92, 0, 0),
            (15, datetime(2025, 4, 1), 214, 214, 1, 1),
            (17, datetime(2025, 6, 1), 570, 570, 18, 18),
            (19, datetime(2025, 8, 1), 829, 829, 0, 0),
        ]

    def test_summary_distinguishes_unique_assets_observations_and_coverage(self):
        cursor = RiskHistoryCursor(scans=self.scan_rows, unique=(19, 19, 19))
        conn = RiskHistoryConnection(cursor)
        with mock.patch.object(main, "get_conn", return_value=conn):
            result = main.risk_history_summary()

        self.assertEqual(result["latest_successful_scan_id"], 19)
        self.assertEqual(result["current_high_assets"], 0)
        self.assertEqual(result["historical_unique_high_assets"], 19)
        self.assertEqual(result["historical_high_observations"], 19)
        self.assertEqual(result["formerly_high_scoring_assets"], 19)
        self.assertEqual(result["historical_high_assets_current_status_unknown"], 0)
        self.assertTrue(result["current_risk_data_coverage"]["complete"])
        self.assertEqual(result["per_scan"][0]["assets_missing_risk_observation"], 106)
        self.assertFalse(result["per_scan"][0]["coverage_complete"])
        self.assertEqual(result["per_scan"][-1]["assets_missing_risk_observation"], 0)
        self.assertEqual(result["threshold"]["minimum_risk_score"], 8)
        all_sql = "\n".join(sql for sql, _ in cursor.executions)
        self.assertIn("status = 'SUCCEEDED'", all_sql)
        self.assertIn("risk_score >= 8", all_sql)
        self.assertIn("seed_domains", all_sql)
        self.assertIn("ownership_status = 'CANDIDATE'", all_sql)
        self.assertTrue(conn.closed)

    def test_no_successful_scan_is_explicitly_unavailable(self):
        cursor = RiskHistoryCursor(scans=[])
        conn = RiskHistoryConnection(cursor)
        with mock.patch.object(main, "get_conn", return_value=conn):
            result = main.risk_history_summary()
        self.assertEqual(result["availability_state"], "UNAVAILABLE")
        self.assertIsNone(result["latest_successful_scan_id"])
        self.assertEqual(result["historical_unique_high_assets"], 0)
        self.assertEqual(len(cursor.executions), 1)

    def test_missing_latest_risk_row_is_not_called_formerly_high(self):
        scans = [(19, datetime(2025, 8, 1), 829, 827, 0, 0)]
        cursor = RiskHistoryCursor(scans=scans, unique=(19, 19, 17))
        conn = RiskHistoryConnection(cursor)
        with mock.patch.object(main, "get_conn", return_value=conn):
            result = main.risk_history_summary()
        self.assertEqual(result["formerly_high_scoring_assets"], 17)
        self.assertEqual(result["historical_high_assets_current_status_unknown"], 2)
        self.assertEqual(result["current_risk_data_coverage"]["assets_missing_risk_observation"], 2)

    def test_assets_are_bounded_stably_and_include_current_persisted_risk(self):
        asset = (11, "shadow.example", "SHADOW", 15, datetime(2025, 4, 1),
                 17, datetime(2025, 6, 1), 10, 2, True, 6)
        cursor = RiskHistoryCursor(scans=self.scan_rows, total=19, assets=[asset])
        conn = RiskHistoryConnection(cursor)
        with mock.patch.object(main, "get_conn", return_value=conn):
            result = main.risk_history_assets(page=2, limit=999)
        self.assertEqual(result["total"], 19)
        self.assertEqual(result["limit"], 200)
        self.assertEqual(result["latest_successful_scan_id"], 19)
        self.assertEqual(result["assets"][0]["first_recorded_high_scan_id"], 15)
        self.assertEqual(result["assets"][0]["current_priority"], "Elevated")
        query, params = cursor.executions[-1]
        self.assertEqual(params, (200, 200))
        self.assertIn("LOWER(h.domain), h.domain_id", query)
        self.assertIn("latest_members", query)
        self.assertTrue(conn.closed)

    def test_invalid_pagination_is_rejected(self):
        with self.assertRaises(main.HTTPException) as raised:
            main.risk_history_assets(page=0, limit=10)
        self.assertEqual(raised.exception.status_code, 400)

    def test_assets_without_successful_scan_are_unavailable(self):
        cursor = RiskHistoryCursor(scans=[], total=0)
        conn = RiskHistoryConnection(cursor)
        with mock.patch.object(main, "get_conn", return_value=conn):
            result = main.risk_history_assets()
        self.assertEqual(result["availability_state"], "UNAVAILABLE")
        self.assertIsNone(result["latest_successful_scan_id"])
        self.assertEqual(result["assets"], [])


if __name__ == "__main__":
    unittest.main()
