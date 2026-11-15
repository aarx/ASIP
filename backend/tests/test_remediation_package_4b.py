import csv
import importlib.util
import io
import logging
import pathlib
import sys
import types
import unittest
from types import SimpleNamespace
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))


def load_module(filename, replacements):
    path = BACKEND / filename
    name = f"pkg4b_{path.stem}_{len(sys.modules)}"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    previous = {key: sys.modules.get(key) for key in replacements}
    try:
        sys.modules.update(replacements)
        with mock.patch("logging.FileHandler", return_value=logging.NullHandler()):
            spec.loader.exec_module(module)
    finally:
        for key, value in previous.items():
            if value is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = value
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

    def cursor(self):
        return self.cursor_obj

    def close(self):
        self.closed = True


class CapturedStreamingResponse:
    def __init__(self, content, media_type):
        self.content = list(content)
        self.media_type = media_type
        self.headers = {}


class Package4BApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fake_db = types.ModuleType("db")
        fake_db.get_conn = lambda: None
        fake_db.get_latest_authoritative_scan_id = lambda cursor: 42
        fake_db.get_previous_authoritative_scan_id = lambda cursor, current=None: 41
        fake_llm = types.ModuleType("llm_service")
        fake_llm.ask_llm = lambda prompt: "unused"
        cls.main = load_module(
            "main.py", {"db": fake_db, "llm_service": fake_llm}
        )
        cls.mcp = load_module("mcp_server.py", {"db": fake_db})

    def test_summary_uses_current_confirmed_membership_and_explicit_no_response(self):
        cursor = QueueCursor(
            fetchones=[(3,), (2,), (1,), (0,), (1,), (1,), (1,), (4,)],
            fetchalls=[[('CANDIDATE', 4), ('EXTERNAL', 2)]],
        )
        self.main.get_conn = lambda: FakeConnection(cursor)

        result = self.main.summary()

        self.assertEqual(result["total_domains"], 3)
        self.assertEqual(result["non_web_assets"], 1)
        total_sql, total_params = cursor.executions[0]
        self.assertIn("FROM scan_results sr", total_sql)
        self.assertIn("d.ownership_status = 'CONFIRMED'", total_sql)
        self.assertEqual(total_params, (42,))
        non_web_sql, _ = cursor.executions[5]
        self.assertIn("http_observation_status = 'NO_RESPONSE'", non_web_sql)
        self.assertNotIn("http_live = FALSE", non_web_sql)

    def test_redirect_summary_is_current_confirmed_only(self):
        cursor = QueueCursor(
            fetchalls=[
                [("example.com",)],
                [
                    ("app.organization.test", 302, "https://example.com/path", None),
                    ("shop.example.com", 301, "https://vendor.example/path", None),
                ],
            ]
        )
        self.main.get_conn = lambda: FakeConnection(cursor)

        result = self.main.redirect_summary()

        self.assertEqual(result, {
            "total": 2,
            "internal": 0,
            "trusted_external": 0,
            "untrusted_external": 0,
            "legacy_unverified": 2,
        })
        redirect_sql, params = cursor.executions[1]
        self.assertIn("JOIN scan_results sr", redirect_sql)
        self.assertIn("d.ownership_status = 'CONFIRMED'", redirect_sql)
        self.assertEqual(params, (42,))

    def test_main_and_mcp_domain_detail_require_current_membership(self):
        main_cursor = QueueCursor(fetchones=[None])
        self.main.get_conn = lambda: FakeConnection(main_cursor)
        self.assertEqual(
            self.main.domain_detail("historical.example"),
            {"error": "domain not found in current authoritative scan"},
        )
        main_sql, main_params = main_cursor.executions[0]
        self.assertIn("FROM scan_results sr", main_sql)
        self.assertEqual(main_params, (42, "historical.example"))

        mcp_cursor = QueueCursor(fetchones=[None])
        self.mcp.get_conn = lambda: FakeConnection(mcp_cursor)
        self.assertEqual(
            self.mcp.get_domain("historical.example"),
            {"error": "domain not found"},
        )
        mcp_sql, mcp_params = mcp_cursor.executions[0]
        self.assertIn("FROM scan_results sr", mcp_sql)
        self.assertEqual(mcp_params, (42, "historical.example"))

    def test_export_is_membership_anchored_and_blank_ports_are_not_none(self):
        row = (
            "candidate.example", False, "CANDIDATE", 40, 42, None, None,
            "192.0.2.4", 200, "", "https://candidate.example", "Candidate",
            "Unknown", "Unknown", "unknown", -1, True, True,
            False, 0, "low", [],
        )
        cursor = QueueCursor(
            fetchalls=[
                [row],
                [("example.com",)],
                [],
                [],
                [],
            ]
        )
        self.main.get_conn = lambda: FakeConnection(cursor)
        self.main.calculate_scan_risks = mock.Mock(return_value=[])

        with mock.patch.object(
            self.main, "_current_scan_asset_classes", return_value={}
        ), mock.patch(
            "fastapi.responses.StreamingResponse", CapturedStreamingResponse
        ):
            response = self.main.export_enriched_csv()

        exported = list(csv.DictReader(io.StringIO("".join(response.content))))
        self.assertEqual(len(exported), 1)
        self.assertEqual(exported[0]["Domain"], "candidate.example")
        self.assertEqual(exported[0]["Ownership Status"], "CANDIDATE")
        self.assertEqual(exported[0]["Open Ports"], "")
        self.assertEqual(exported[0]["Exposure"], "web")
        self.assertEqual(exported[0]["Risk Score"], "")
        export_sql, params = cursor.executions[0]
        self.assertIn("FROM scan_results sr", export_sql)
        self.assertIn("WHERE sr.scan_id = %s", export_sql)
        self.assertEqual(params, (42, 42, 42, 42, 42))

    def test_investigation_returns_total_and_keeps_missing_enrichment(self):
        cursor = QueueCursor(
            fetchones=[(2,)],
            fetchalls=[[
                (
                    "a.example", True, "CONFIRMED", "192.0.2.1", True,
                    200, "Unknown", "Unknown", "", "",
                ),
                (
                    "b.example", False, "CONFIRMED", "192.0.2.2", True,
                    404, "Cloud", "AS64500", "React,Vite", "443,8443",
                ),
            ]],
        )
        self.main.get_conn = lambda: FakeConnection(cursor)
        self.main.calculate_scan_risks = mock.Mock(return_value=[])

        with mock.patch.object(
            self.main, "_current_scan_asset_classes", return_value={1: "KNOWN", 2: "SHADOW"}
        ):
            result = self.main.investigation_assets(page=1, limit=20)

        self.assertEqual(result["count"], 2)
        self.assertEqual(len(result["assets"]), 2)
        self.assertEqual(result["assets"][0]["provider"], "Unknown")
        query, params = cursor.executions[0]
        self.assertNotIn("dp.provider IS NOT NULL", query)
        self.assertIn("STRING_AGG(DISTINCT dt.tech", query)
        self.assertIn("ORDER BY d.domain ASC, d.id ASC", query)
        self.assertNotIn("LIMIT", query.upper())
        self.assertEqual(params, (42, None, None, None))

    def test_investigation_sorts_full_filtered_population_before_pagination(self):
        rows = [
            ("a.example", True, "CONFIRMED", "192.0.2.1", True, 200, "Cloud", "AS1", "", ""),
            ("b.example", True, "CONFIRMED", "192.0.2.2", True, 200, "Cloud", "AS1", "", ""),
            ("c.example", True, "CONFIRMED", "192.0.2.3", True, 200, "Cloud", "AS1", "", ""),
        ]
        cursor = QueueCursor(fetchalls=[rows])
        self.main.get_conn = lambda: FakeConnection(cursor)
        risks = [
            SimpleNamespace(domain=domain, result=SimpleNamespace(
                score=score, priority="Review", reasons=[]
            ))
            for domain, score in (("a.example", 1), ("b.example", 3), ("c.example", 2))
        ]
        with mock.patch.object(self.main, "_current_scan_risks", return_value=risks):
            result = self.main.investigation_assets(
                page=2, limit=1, sort_by="risk", sort_dir="desc"
            )

        self.assertEqual(result["count"], 3)
        self.assertEqual([item["domain"] for item in result["assets"]], ["c.example"])
        self.assertEqual(result["assets"][0]["risk"], 2)
        sql, _params = cursor.executions[0]
        self.assertNotIn("LIMIT", sql.upper())

    def test_investigation_rejects_unallowlisted_sort(self):
        with self.assertRaises(self.main.HTTPException) as raised:
            self.main.investigation_assets(sort_by="domain; DROP TABLE domains")
        self.assertEqual(raised.exception.status_code, 400)

    def test_dashboard_organizational_queries_use_effective_known_shadow_scope(self):
        text = (BACKEND / "main.py").read_text(encoding="utf-8")
        for name in (
            "http_status", "exposure_summary", "sensitive_exposure",
            "hygiene_score", "provider_clusters", "providers", "tech",
            "exposure_drift", "export_targets", "findings", "cert_expiry",
            "naming_asset_exposure",
        ):
            with self.subTest(endpoint=name):
                start = text.index(f"def {name}(")
                end = text.find("\n@app.get", start)
                block = text[start:end if end != -1 else None]
                if name in {
                    "http_status", "exposure_summary", "sensitive_exposure",
                    "findings", "cert_expiry", "naming_asset_exposure",
                }:
                    # Current reporting uses the shared effective class. A
                    # historical CONFIRMED decision alone must not include
                    # an out-of-scope Candidate in organizational metrics.
                    self.assertIn("reporting_asset_class_sql(", block)
                    self.assertIn("IN ('KNOWN', 'SHADOW')", block)
                    self.assertNotIn("ownership_status = 'CONFIRMED'", block)
                else:
                    self.assertIn("ownership_status = 'CONFIRMED'", block)

    def test_legacy_evidence_routes_keep_current_scan_membership_and_contracts(self):
        cases = {
            "findings": ("scan_results sr", "sr.scan_id = df.scan_id", "df.finding"),
            "sensitive_exposure": (
                "scan_results sr", "sr.scan_id = dp.scan_id", "dp.port",
            ),
            "cert_expiry": (
                "scan_results sr", "sr.scan_id = dc.scan_id", "dc.expiry_date",
            ),
            "naming_asset_exposure": (
                "scan_results sr", "sr.scan_id = %s", "count(distinct d.domain)",
            ),
        }
        text = (BACKEND / "main.py").read_text(encoding="utf-8").lower()
        for name, required in cases.items():
            with self.subTest(endpoint=name):
                start = text.index(f"def {name}(")
                end = text.find("\n@app.get", start)
                block = text[start:end if end != -1 else None]
                for fragment in required:
                    self.assertIn(fragment, block)
                self.assertIn("in ('known', 'shadow')", block)
                self.assertIn("reporting_asset_class_sql(\"d.domain\", \"d.ownership_status\")", block)
                self.assertNotIn("ownership_status = 'confirmed'", block)


if __name__ == "__main__":
    unittest.main()
