import pathlib
import inspect
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from brand_history import HISTORY_CTE, history_assets, history_summary
from backend.tests.test_remediation_package_4c import load_main


class Cursor:
    def __init__(self, one=(), all_rows=()):
        self.one = iter(one)
        self.all_rows = iter(all_rows)
        self.queries = []

    def execute(self, query, params=None):
        self.queries.append((query, params))

    def fetchone(self):
        return next(self.one)

    def fetchall(self):
        return next(self.all_rows)


class BrandHistoryTests(unittest.TestCase):
    def test_asset_detail_route_exposes_only_validated_historical_selector(self):
        main = load_main()
        self.assertEqual(list(inspect.signature(main.frontend_v2_asset_detail).parameters),
                         ['domain_name', 'scope', 'scan_id'])
        self.assertNotIn('_historical_scan_id', inspect.signature(main.frontend_v2_asset_detail).parameters)

    def test_summary_reconciles_and_marks_legacy_retention(self):
        cursor = Cursor(
            one=[(512, 16, 1, 19, None, None, 7, 9)],
            all_rows=[[('NEEDS_VERIFICATION', 29), ('KNOWN', 2), ('SHADOW', 1)]],
        )
        result = history_summary(cursor)
        self.assertEqual(result['total'], 32)
        self.assertEqual(sum(result['counts'].values()), 32)
        self.assertEqual(result['retention']['legacy_unknown_status_scan_count'], 9)
        self.assertIn('GROUP BY review_class', cursor.queries[0][0])

    def test_listing_count_and_page_share_population_and_filters(self):
        cursor = Cursor(one=[(2,)], all_rows=[[('a.example', 'a.example', 'CANDIDATE',
                                                  'CANDIDATE', 'NEEDS_VERIFICATION',
                                                  1, 19, None, None, 16, 16,
                                                  ['brand_tld'], 19)]])
        result = history_assets(cursor, page=2, limit=1,
                                classification='NEEDS_VERIFICATION',
                                search='A.EXAMPLE', sort_by='last_seen',
                                sort_dir='desc')
        self.assertEqual(result['count'], 2)
        self.assertEqual(result['assets'][0]['identity'], 'a.example')
        self.assertEqual(cursor.queries[0][1],
                         ('NEEDS_VERIFICATION', 'NEEDS_VERIFICATION',
                          'a.example', 'a.example'))
        self.assertEqual(cursor.queries[1][1][-2:], (1, 1))
        self.assertTrue(all(query.startswith(HISTORY_CTE)
                            for query, _ in cursor.queries))
        self.assertIn('ORDER BY last_evidence_scan_id DESC, identity ASC',
                      cursor.queries[1][0])

    def test_historical_only_detail_marks_missing_persisted_scan_evidence(self):
        main = load_main()
        cursor = Cursor(one=[('old.example', 'old.example', 'CANDIDATE',
                              'NEEDS_VERIFICATION', 1, 3, None, None,
                              ['brand_pattern'], 2), None])

        class Connection:
            def close(self):
                pass

        main._brand_history_cursor = lambda: (Connection(), cursor)
        main.get_latest_authoritative_scan_id = lambda cur: 19
        result = main.frontend_v2_brand_history_detail('OLD.EXAMPLE.')
        self.assertEqual(result['detail_availability'], 'UNAVAILABLE')
        self.assertIsNone(result['detail'])
        self.assertFalse(result['current_scan_member'])
        self.assertEqual(cursor.queries[0][1], ('old.example',))

    def test_historical_detail_reuses_persisted_scan_and_never_claims_current(self):
        main = load_main()
        cursor = Cursor(one=[('old.example', 'old.example', 'KNOWN', 'KNOWN',
                              1, 4, None, None, ['brand_tld'], 3),
                             (4, 'UNKNOWN', 'old.example')])

        class Connection:
            def close(self):
                pass

        main._brand_history_cursor = lambda: (Connection(), cursor)
        main.get_latest_authoritative_scan_id = lambda cur: 19
        calls = []
        main._frontend_v2_asset_detail = lambda domain, _historical_scan_id=None: (
            calls.append((domain, _historical_scan_id)) or {'scan_id': 4})
        result = main.frontend_v2_brand_history_detail('old.example')
        self.assertEqual(calls, [('old.example', 4)])
        self.assertEqual(result['detail_evidence_scan_status'], 'UNKNOWN')
        self.assertFalse(result['current_scan_member'])
        self.assertEqual(result['detail']['scan_id'], 4)


if __name__ == '__main__':
    unittest.main()
