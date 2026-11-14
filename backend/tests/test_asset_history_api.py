import pathlib
import sys
import unittest

BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from asset_history import identity_sql, retained_inventory_cte, list_retained_assets


class Cursor:
    def __init__(self):
        self.executions = []

    def execute(self, sql, params=None):
        self.executions.append((sql, params))

    def fetchone(self):
        return (0,)

    def fetchall(self):
        return []


class HistoricalAssetInventoryTests(unittest.TestCase):
    def test_identity_policy_strips_root_dot_only_for_valid_dns(self):
        sql = identity_sql("d.domain")
        self.assertIn("TRIM(TRAILING '.'", sql)
        self.assertIn("ELSE LOWER(BTRIM(d.domain))", sql)
        self.assertIn("~ '", sql)

    def test_shared_population_uses_all_recorded_memberships_and_stable_evidence(self):
        sql = retained_inventory_cte()
        self.assertIn("FROM scan_results sr", sql)
        self.assertNotIn("status = 'SUCCEEDED'", sql)
        self.assertIn("s.scan_time DESC NULLS LAST, sr.scan_id DESC, d.id DESC", sql)
        self.assertIn("domain_risk", sql)
        self.assertIn("ds.http_observation_status='RESPONDED'", sql)
        self.assertIn("ds.http_observation_status='NO_RESPONSE'", sql)
        self.assertIn("ELSE NULL END AS http_live", sql)

    def test_count_and_page_apply_identical_filters_in_sql(self):
        cursor = Cursor()
        total, assets = list_retained_assets(
            cursor, page=2, limit=25,
            filters={"search": "example", "asset_class": "SHADOW",
                     "http_status": 418, "risk_min": 4},
            sort_by="risk_score", sort_dir="desc",
        )
        self.assertEqual((total, assets), (0, []))
        count_sql, count_params = cursor.executions[0]
        page_sql, page_params = cursor.executions[1]
        self.assertIn("POSITION(LOWER(%s) IN LOWER(domain))", count_sql)
        self.assertIn("asset_class=UPPER(%s)", count_sql)
        self.assertIn("risk_score >= %s", count_sql)
        self.assertIn("LIMIT %s OFFSET %s", page_sql)
        self.assertEqual(count_params, page_params[:-2])
        self.assertEqual(page_params[-2:], (25, 25))


if __name__ == "__main__":
    unittest.main()
