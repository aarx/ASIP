import pathlib
import sys
import unittest

BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from asset_history import (
    historical_identity_lookup_sql,
    identity_sql,
    list_retained_assets,
    normalize_historical_http_payload,
    retained_inventory_cte,
    scan_identity_lookup_sql,
)


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

    def test_detail_identity_queries_bind_requested_domain_once(self):
        identity_query = historical_identity_lookup_sql()
        scan_query = scan_identity_lookup_sql()
        self.assertEqual(identity_query.count("%s"), 1)
        self.assertEqual(scan_query.count("%s"), 2)
        self.assertIn("CROSS JOIN (SELECT %s::text AS domain) requested", identity_query)
        self.assertIn("CROSS JOIN (SELECT %s::text AS domain) requested", scan_query)
        self.assertIn("SELECT e.domain, e.scan_id", identity_query)

    def test_detail_http_unknown_and_invalid_status_remain_unavailable(self):
        unknown = normalize_historical_http_payload({
            "observation_status": "UNKNOWN", "live": False, "status": 200,
        })
        self.assertIsNone(unknown["live"])
        self.assertIsNone(unknown["status"])
        no_response = normalize_historical_http_payload({
            "observation_status": "NO_RESPONSE", "live": True, "status": 0,
        })
        self.assertFalse(no_response["live"])
        self.assertIsNone(no_response["status"])


if __name__ == "__main__":
    unittest.main()
