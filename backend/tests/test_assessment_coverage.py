"""Search and pagination contracts for assessment coverage drill-downs."""

import sys
import unittest
from datetime import date
from pathlib import Path
from unittest import mock

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

import main  # noqa: E402


class Cursor:
    def __init__(self, one=(), many=()):
        self.one = list(one)
        self.many = list(many)
        self.executions = []

    def execute(self, query, params=None):
        self.executions.append((query, params))

    def fetchone(self):
        return self.one.pop(0)

    def fetchall(self):
        return self.many.pop(0)


class Connection:
    def __init__(self, cursor):
        self.value = cursor
        self.closed = False

    def cursor(self):
        return self.value

    def rollback(self):
        pass

    def close(self):
        self.closed = True


class AssessmentCoverageTests(unittest.TestCase):
    def test_parent_domain_search_uses_dot_boundary_and_parameters(self):
        predicate, params = main._assessment_host_search("Example.COM", "domain")
        self.assertIn("LOWER(d.domain) = %s", predicate)
        self.assertIn("RIGHT(LOWER(d.domain)", predicate)
        self.assertEqual(params, ["example.com"] * 3)

    def test_exact_and_fragment_search_are_bounded_and_parameterized(self):
        exact, exact_params = main._assessment_host_search("app.example.com", "exact")
        fragment, fragment_params = main._assessment_host_search("EXAMPLE", "fragment")
        self.assertEqual((exact, exact_params), ("LOWER(d.domain) = %s", ["app.example.com"]))
        self.assertEqual(fragment_params, ["example"])
        self.assertIn("POSITION(%s IN LOWER(d.domain))", fragment)
        with self.assertRaises(main.HTTPException):
            main._assessment_host_search("example.com", "bogus")
        with self.assertRaises(main.HTTPException):
            main._assessment_host_search("x", "fragment")

    def test_certificate_host_detail_preserves_scan_time_and_unknown_semantics(self):
        cursor = Cursor(
            one=[("SUCCEEDED",), (1,)],
            many=[[(7, "cert.example.com", "KNOWN")],
                  [(7, date(2027, 1, 1), 48, "warning")]],
        )
        conn = Connection(cursor)
        with mock.patch.object(main, "get_conn", return_value=conn):
            result = main.certificate_assessment_hosts(scan_id=19, search="example.com", limit=1)
        self.assertEqual(result["total"], 1)
        host = result["hosts"][0]
        self.assertEqual(host["assessment_state"], "OBSERVATION_RECORDED")
        self.assertEqual(host["evidence_count"], 1)
        self.assertEqual(host["certificates"][0]["days_to_expiry_at_scan"], 48)
        self.assertIsNone(host["certificates"][0]["observed_at"])
        self.assertIn("not evidence that TLS was assessed", result["coverage_note"])
        self.assertIn("RIGHT(LOWER(d.domain)", cursor.executions[1][0])
        self.assertEqual(cursor.executions[1][1], (19, 19, "example.com", "example.com", "example.com"))
        self.assertNotIn("d.scannable IS TRUE", cursor.executions[1][0])
        self.assertTrue(conn.closed)

    def test_unobserved_certificate_host_is_not_called_clear(self):
        cursor = Cursor(one=[("SUCCEEDED",), (1,)], many=[[(8, "no-cert.example.com", "SHADOW")], []])
        with mock.patch.object(main, "get_conn", return_value=Connection(cursor)):
            result = main.certificate_assessment_hosts(scan_id=19, include_unobserved=True)
        host = result["hosts"][0]
        self.assertEqual(host["assessment_state"], "NO_PERSISTED_OBSERVATION")
        self.assertEqual(host["certificates"], [])
        self.assertEqual(host["evidence_count"], 0)

    def test_sensitive_port_results_are_positive_only_with_unknown_coverage(self):
        cursor = Cursor(
            one=[("SUCCEEDED",), (1,)],
            many=[[(9, "port.example.com", "SHADOW", 5, 1)],
                  [(9, 8443, "https-alt", 5, "Sensitive management service")]],
        )
        with mock.patch.object(main, "get_conn", return_value=Connection(cursor)):
            result = main.sensitive_port_assessment_hosts(scan_id=19, limit=1)
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["assessment_coverage"], "UNKNOWN")
        self.assertEqual(result["hosts"][0]["assessment_state"], "POSITIVE_OBSERVATION")
        self.assertEqual(result["hosts"][0]["highest_sensitivity"], 5)
        self.assertEqual(result["hosts"][0]["distinct_port_count"], 1)
        self.assertEqual(result["hosts"][0]["ports"][0]["port"], 8443)
        self.assertIn("positive sensitive-port observations", result["coverage_note"])
        self.assertNotIn("d.scannable IS TRUE", cursor.executions[1][0])
        query = cursor.executions[2][0]
        self.assertIn("MAX(sp.risk) DESC NULLS LAST", query)
        self.assertIn("COUNT(DISTINCT dp.port) DESC", query)
        self.assertIn('LOWER(TRIM(TRAILING \'.\' FROM d.domain)) COLLATE "C" ASC', query)
        self.assertLess(query.index("GROUP BY"), query.index("ORDER BY"))
        self.assertLess(query.index("ORDER BY"), query.index("LIMIT %s OFFSET %s"))

    def test_sensitive_port_priority_order_is_applied_before_host_pagination(self):
        cursor = Cursor(
            one=[("SUCCEEDED",), (3,)],
            many=[[(12, "middle.example.com", "KNOWN", 4, 3)],
                  [(12, 22, "ssh", 4, "SSH")]],
        )
        with mock.patch.object(main, "get_conn", return_value=Connection(cursor)):
            result = main.sensitive_port_assessment_hosts(scan_id=19, page=2, limit=1)

        self.assertEqual(result["total"], 3)
        self.assertEqual(result["page"], 2)
        self.assertEqual(result["hosts"][0]["hostname"], "middle.example.com")
        self.assertEqual(result["hosts"][0]["highest_sensitivity"], 4)
        self.assertEqual(result["hosts"][0]["distinct_port_count"], 3)
        query, params = cursor.executions[2]
        self.assertEqual(params, (19, 1, 1))
        order = query.index("ORDER BY")
        sensitivity = query.index("MAX(sp.risk) DESC NULLS LAST", order)
        port_count = query.index("COUNT(DISTINCT dp.port) DESC", order)
        hostname = query.index('LOWER(TRIM(TRAILING \'.\' FROM d.domain)) COLLATE "C" ASC', order)
        stable_id = query.index("d.id ASC", order)
        page_limit = query.index("LIMIT %s OFFSET %s", order)
        self.assertLess(sensitivity, port_count)
        self.assertLess(port_count, hostname)
        self.assertLess(hostname, stable_id)
        self.assertLess(stable_id, page_limit)

    def test_incomplete_scan_is_rejected_for_new_coverage_routes(self):
        cursor = Cursor(one=[("RUNNING",)])
        with mock.patch.object(main, "get_conn", return_value=Connection(cursor)):
            with self.assertRaises(main.HTTPException) as raised:
                main.sensitive_port_assessment_hosts(scan_id=20)
        self.assertEqual(raised.exception.status_code, 409)


if __name__ == "__main__":
    unittest.main()
