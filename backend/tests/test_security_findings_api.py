import pathlib
import sys
import unittest
from unittest import mock

BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

import main  # noqa: E402
from ownership import reporting_asset_class_sql  # noqa: E402
from security_findings import (  # noqa: E402
    base_query_params,
    normalize_security_record,
    normalized_findings_cte,
)


class Cursor:
    def __init__(self, *, scan_id=19, count=0, rows=(), grouped=()):
        self.scan_id = scan_id
        self.count = count
        self.rows = list(rows)
        self.grouped = list(grouped)
        self.executions = []
        self._result = None

    def execute(self, sql, params=None):
        self.executions.append((sql, params))
        if "SELECT id" in sql and "FROM scans" in sql:
            self._result = (self.scan_id,) if self.scan_id is not None else None
        elif "SELECT COUNT(*) FROM records" in sql:
            self._result = (self.count,)
        elif "FROM records" in sql and "LIMIT %s OFFSET %s" in sql:
            self._result = self.rows
        else:
            self._result = None

    def fetchone(self):
        return self._result

    def fetchall(self):
        return self._result or []


class Connection:
    def __init__(self, cursor):
        self.value = cursor
        self.closed = False

    def cursor(self):
        return self.value

    def close(self):
        self.closed = True

    def rollback(self):
        pass


class MissingSchemaError(Exception):
    pgcode = "42P01"


class MissingSchemaCursor(Cursor):
    def execute(self, sql, params=None):
        self.executions.append((sql, params))
        raise MissingSchemaError("synthetic missing evidence table")


class SecurityFindingsApiTests(unittest.TestCase):
    def test_normalized_record_preserves_source_semantics_and_inferred_naming(self):
        row = (
            "dns_security_checks:14", "dns_security_checks", "14", 19, 7,
            "admin-dev.example", "SHADOW", "NEEDS_VERIFICATION", "spf_policy — WARNING",
            "spf_policy", "LOW", "WARNING", "UNKNOWN", "WARNING",
            {"record_type": "TXT"}, "Review the recorded policy.", None, None,
            ["Does not establish exploitability."],
        )
        result = normalize_security_record(row)
        self.assertEqual(result["category"], "NEEDS_VERIFICATION")
        self.assertEqual(result["severity"], "LOW")
        self.assertEqual(result["verification_state"], "WARNING")
        self.assertEqual(result["asset_class"], "SHADOW")
        self.assertEqual(result["environment_indicators"], ["DEV"])
        self.assertEqual(result["role_indicators"], ["ADMIN"])
        self.assertIn("does not by itself establish exploitability", result["why_it_matters"])
        self.assertTrue(result["indicators_inferred"])
        self.assertIsNone(result["provider"])

    def test_source_query_is_scan_scoped_and_preserves_nonfinding_semantics(self):
        sql = normalized_findings_cte(
            reporting_asset_class_sql("d.domain", "d.ownership_status")
        )
        self.assertIn("SELECT DISTINCT d.id AS domain_id", sql)
        self.assertIn("WHERE sr.scan_id = %s", sql)
        self.assertIn("('KNOWN', 'SHADOW')", sql)
        self.assertIn("c.outcome NOT IN ('CLEAR', 'NOT_CHECKED')", sql)
        self.assertIn("WHEN 'CONFIRMED_ISSUE' THEN 'FINDING'", sql)
        self.assertIn("WHEN 'INFORMATIONAL' THEN 'EXPOSURE_SIGNAL'", sql)
        self.assertIn("'NEEDS_VERIFICATION'", sql)
        self.assertIn("'EXPOSURE_SIGNAL'", sql)
        self.assertIn("first_seen_scan", sql)
        self.assertIn("sensitive_ports sp", sql)
        self.assertIn("http_redirect_evidence", sql)
        self.assertEqual(len(base_query_params(19)), sql.count("%s"))

    def test_absent_source_severity_confidence_and_provider_stay_null(self):
        row = (
            "domain_ports:19:7:443", "domain_ports", "443", 19, 7,
            "known.example", "KNOWN", "EXPOSURE_SIGNAL", "Sensitive port observed",
            "sensitive_port", None, None, None, None,
            {"port": 443}, "Validate expected service.", None, None, [],
        )
        result = normalize_security_record(row)
        self.assertIsNone(result["severity"])
        self.assertIsNone(result["confidence"])
        self.assertIsNone(result["provider"])
        self.assertEqual(result["category"], "EXPOSURE_SIGNAL")
        self.assertIn("not itself a vulnerability", result["why_it_matters"])

    def test_findings_default_attention_has_exact_total_and_bounded_pagination(self):
        row = (
            "domain_findings:19:3:dangling_dns", "domain_findings", "dangling_dns",
            19, 3, "api.example", "KNOWN", "FINDING", "dangling_dns", "dangling_dns",
            "HIGH", None, None, None, {"source_evidence": "fingerprint"}, None, None,
            "AWS", ["Source-recorded; not independently verified."],
        )
        cursor = Cursor(count=17, rows=[row])
        conn = Connection(cursor)
        with mock.patch.object(main, "get_conn", return_value=conn), \
             mock.patch.object(main, "get_latest_authoritative_scan_id", return_value=19):
            result = main.security_findings(page=2, limit=999)

        self.assertEqual(result["scan_id"], 19)
        self.assertEqual(result["total"], 17)
        self.assertEqual(result["limit"], 200)
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["finding_id"], row[0])
        self.assertTrue(all(
            "CANDIDATE" in sql and "KNOWN" in sql and "SHADOW" in sql
            for sql, _ in cursor.executions
        ))
        self.assertIn("category IN ('FINDING', 'NEEDS_VERIFICATION')", cursor.executions[0][0])
        self.assertEqual(cursor.executions[1][1][-2:], (200, 200))
        self.assertTrue(conn.closed)

    def test_category_source_and_class_filters_are_validated_and_parameterized(self):
        where, params = main._security_findings_where(
            "NEEDS_VERIFICATION", "SHADOW", "dns_security_checks", "all"
        )
        self.assertEqual(
            params,
            ["NEEDS_VERIFICATION", "SHADOW", "dns_security_checks"],
        )
        self.assertIn("category = %s", where)
        self.assertIn("asset_class = %s", where)
        self.assertIn("source = %s", where)
        for args in (("MADE_UP", None, None, "all"), (None, "CANDIDATE", None, "all"),
                     (None, None, "arbitrary_sql", "all"), (None, None, None, "unknown")):
            with self.subTest(args=args), self.assertRaises(main.HTTPException):
                main._security_findings_where(*args)

    def test_no_successful_scan_returns_unavailable_not_clear(self):
        cursor = Cursor(scan_id=None)
        conn = Connection(cursor)
        with mock.patch.object(main, "get_conn", return_value=conn), \
             mock.patch.object(main, "get_latest_authoritative_scan_id", return_value=None):
            result = main.security_findings()
        self.assertEqual(result["availability_state"], "UNAVAILABLE")
        self.assertEqual(result["findings"], [])
        self.assertIn("No successful authoritative scan", result["limitations"][0])

    def test_missing_evidence_schema_returns_explicit_unavailable(self):
        conn = Connection(MissingSchemaCursor())
        with mock.patch.object(main, "get_conn", return_value=conn), \
             mock.patch.object(main, "get_latest_authoritative_scan_id", return_value=19):
            result = main.security_findings()
        self.assertEqual(result.status_code, 503)
        self.assertIn(b"SCHEMA_UNAVAILABLE", result.body)

    def test_empty_matching_page_keeps_exact_zero_total(self):
        cursor = Cursor(count=0, rows=[])
        conn = Connection(cursor)
        with mock.patch.object(main, "get_conn", return_value=conn), \
             mock.patch.object(main, "get_latest_authoritative_scan_id", return_value=19):
            result = main.security_findings(view="signals", source="domain_ports")
        self.assertEqual(result["total"], 0)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["view"], "signals")

    def test_summary_keeps_sensitive_port_coverage_unknown(self):
        cursor = Cursor(scan_id=19)
        conn = Connection(cursor)

        def fetchone_side_effect():
            if not hasattr(fetchone_side_effect, "calls"):
                fetchone_side_effect.calls = 0
            fetchone_side_effect.calls += 1
            return {1: (37,), 2: (0, 0)}.get(
                fetchone_side_effect.calls
            )

        with mock.patch.object(main, "get_conn", return_value=conn), \
             mock.patch.object(main, "get_latest_authoritative_scan_id", return_value=19), \
             mock.patch.object(cursor, "fetchone", side_effect=fetchone_side_effect), \
             mock.patch.object(cursor, "fetchall", side_effect=[
                 [
                     (3, None, None, 12, 8),
                     (1, "FINDING", None, 3, 2),
                     (1, "NEEDS_VERIFICATION", None, 5, 3),
                     (2, None, "domain_findings", 3, 2),
                 ],
             ]), \
             mock.patch.object(main, "dns_security_summary", return_value={
                 "availability_state": "AVAILABLE", "eligible_assets": 829,
                 "checked_assets": 2, "unchecked_assets": 827,
                 "execution_state": "PARTIAL",
             }):
            result = main.security_findings_summary()

        self.assertEqual(result["total_records"], 12)
        self.assertEqual(result["affected_assets"], 8)
        self.assertEqual(result["coverage"]["dns_security"]["unassessed_assets"], 827)
        self.assertIsNone(result["coverage"]["sensitive_ports"]["assessed_assets"])
        self.assertEqual(result["coverage"]["sensitive_ports"]["assessment_state"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
