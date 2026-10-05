import csv
import importlib.util
import io
import logging
import pathlib
import sys
import types
import unittest
from datetime import datetime
from types import SimpleNamespace
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))


def load_main():
    fake_db = types.ModuleType("db")
    fake_db.get_conn = lambda: None
    fake_db.get_latest_authoritative_scan_id = lambda cursor: 42
    fake_db.get_previous_authoritative_scan_id = lambda cursor, current=None: 41
    fake_llm = types.ModuleType("llm_service")
    fake_llm.ask_llm = lambda prompt: "unused"
    path = BACKEND / "main.py"
    spec = importlib.util.spec_from_file_location("pkg4c_main", path)
    module = importlib.util.module_from_spec(spec)
    previous = {name: sys.modules.get(name) for name in ("db", "llm_service")}
    try:
        sys.modules.update({"db": fake_db, "llm_service": fake_llm})
        with mock.patch("logging.FileHandler", return_value=logging.NullHandler()):
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

    def cursor(self):
        return self.cursor_obj

    def close(self):
        self.closed = True


class CapturedStreamingResponse:
    def __init__(self, content, media_type):
        self.content = list(content)
        self.media_type = media_type
        self.headers = {}


def risk(domain_id, domain, score, priority, reasons=()):
    return SimpleNamespace(
        domain_id=domain_id,
        domain=domain,
        result=SimpleNamespace(
            score=score, priority=priority, reasons=tuple(reasons)
        ),
    )


class FrontendV2ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = load_main()

    def test_overview_combines_current_counts_changes_and_canonical_risk(self):
        cursor = QueueCursor(
            fetchones=[(5, 2, 3, 1, 1), (2,), (1,)],
        )
        self.main.get_conn = lambda: FakeConnection(cursor)
        self.main.calculate_scan_risks = mock.Mock(return_value=[
            risk(1, "high.example", 9, "High", ("finding",)),
            risk(2, "low.example", 0, "Low"),
            risk(3, "review.example", 4, "Review", ("shadow_asset",)),
        ])

        result = self.main.frontend_v2_overview()

        self.assertEqual(result["current_scan_id"], 42)
        self.assertEqual(result["previous_scan_id"], 41)
        self.assertEqual(result["counts"], {
            "organizational": 5,
            "known": 2,
            "shadow": 3,
            "candidate": 1,
            "external": 1,
        })
        self.assertEqual(result["changes"], {
            "new_assets": 2, "disappeared_assets": 1,
        })
        self.assertEqual(result["risk_distribution"], {
            "High": 1, "Elevated": 0, "Review": 1, "Low": 1,
        })
        self.assertEqual(result["needs_attention"][0]["domain"], "high.example")
        count_sql, count_params = cursor.executions[0]
        self.assertIn("FROM scan_results sr", count_sql)
        self.assertEqual(count_params, (42,))

    def test_asset_explorer_filters_current_assets_and_has_no_candidate_risk(self):
        rows = [
            (
                1, "known.example", True, "CONFIRMED", 10, 42,
                "192.0.2.1", True, "RESPONDED", 200, "Known", None,
                "Cloud", "AS64500",
            ),
            (
                2, "shadow.example", False, "CONFIRMED", 40, 42,
                "192.0.2.2", True, "NO_RESPONSE", 0, None, None,
                "Cloud", "AS64501",
            ),
            (
                3, "candidate.example", False, "CANDIDATE", 42, 42,
                None, False, "UNKNOWN", 0, None, None,
                "Unknown", None,
            ),
        ]
        cursor = QueueCursor(fetchalls=[rows])
        self.main.get_conn = lambda: FakeConnection(cursor)
        self.main.calculate_scan_risks = mock.Mock(return_value=[
            risk(1, "known.example", 1, "Low", ("http_exposed",)),
            risk(2, "shadow.example", 6, "Elevated", ("shadow_asset",)),
        ])

        result = self.main.frontend_v2_assets(asset_class="SHADOW")

        self.assertEqual(result["count"], 1)
        self.assertEqual(result["assets"][0]["domain"], "shadow.example")
        self.assertEqual(result["assets"][0]["risk"]["priority"], "Elevated")
        sql, params = cursor.executions[0]
        self.assertIn("FROM scan_results sr", sql)
        self.assertIn("ORDER BY d.domain ASC, d.id ASC", sql)
        self.assertEqual(params, (42,))

        cursor = QueueCursor(fetchalls=[rows])
        self.main.get_conn = lambda: FakeConnection(cursor)
        self.main.calculate_scan_risks = mock.Mock(return_value=[])
        candidate = self.main.frontend_v2_assets(ownership="candidate")
        self.assertEqual(candidate["assets"][0]["asset_class"], "CANDIDATE")
        self.assertIsNone(candidate["assets"][0]["risk"])

    def test_asset_export_is_authoritative_filtered_escaped_and_classified(self):
        rows = [
            (
                1, "known.example", True, "CONFIRMED", 10, 42,
                "192.0.2.1", True, "RESPONDED", 200,
                'Title, "quoted"\nline', "https://known.example/path?a=1,2",
                "Cloud", "AS64500", "80,443", "React,Vite",
                'finding, HIGH: evidence "quoted"\nline',
            ),
            (
                2, "shadow.example", False, "CONFIRMED", 40, 42,
                "192.0.2.2", True, "NO_RESPONSE", None, None, None,
                "Cloud", "AS64501", "22", "", "",
            ),
            (
                3, "candidate.example", False, "CANDIDATE", 42, 42,
                None, False, "UNKNOWN", None, None, None,
                "Unknown", None, "", "", "",
            ),
            (
                4, "external.example", False, "EXTERNAL", 42, 42,
                None, False, "UNKNOWN", None, None, None,
                "Unknown", None, "", "", "",
            ),
        ]
        cursor = QueueCursor(fetchalls=[rows])
        self.main.get_conn = lambda: FakeConnection(cursor)
        self.main.calculate_scan_risks = mock.Mock(return_value=[
            risk(1, "known.example", 4, "Review", ("finding",)),
            risk(2, "shadow.example", 8, "High", ("shadow_asset",)),
        ])

        with mock.patch.object(
            self.main, "StreamingResponse", CapturedStreamingResponse
        ):
            response = self.main.frontend_v2_assets_export(
                search="example", http_observation_status="RESPONDED"
            )

        exported = list(csv.DictReader(io.StringIO("".join(response.content))))
        self.assertEqual(response.media_type, "text/csv")
        self.assertEqual(response.headers["Content-Disposition"],
                         'attachment; filename="shadowrecon-assets-scan-42.csv"')
        self.assertEqual(len(exported), 1)
        self.assertEqual(exported[0]["Inventory Status"], "Known")
        self.assertEqual(exported[0]["Risk Reasons"], "finding")
        self.assertEqual(exported[0]["Title"], 'Title, "quoted"\nline')
        self.assertEqual(exported[0]["Technologies"], "React,Vite")
        export_sql, params = cursor.executions[0]
        self.assertIn("FROM scan_results sr", export_sql)
        self.assertIn("WHERE sr.scan_id = %s", export_sql)
        self.assertEqual(params, (42,))

        cursor = QueueCursor(fetchalls=[rows])
        self.main.get_conn = lambda: FakeConnection(cursor)
        self.main.calculate_scan_risks = mock.Mock(return_value=[])
        with mock.patch.object(
            self.main, "StreamingResponse", CapturedStreamingResponse
        ):
            response = self.main.frontend_v2_assets_export()
        exported = list(csv.DictReader(io.StringIO("".join(response.content))))
        self.assertEqual(
            [row["Inventory Status"] for row in exported],
            ["Candidate", "External", "Known", "Shadow"],
        )

    def test_asset_explorer_sorting_is_filtered_before_pagination(self):
        rows = [
            (1, "zulu.example", False, "CONFIRMED", 10, 42, "192.0.2.1", True, "RESPONDED", 200, None, None, "Cloud", "AS64501"),
            (2, "beta.example", True, "CONFIRMED", 10, 42, "192.0.2.2", True, "RESPONDED", 200, None, None, "Cloud", "AS64502"),
            (3, "alpha.example", False, "CONFIRMED", 10, 42, "192.0.2.3", True, "RESPONDED", 200, None, None, "Cloud", "AS64503"),
            (4, "charlie.example", True, "CONFIRMED", 10, 42, "192.0.2.4", True, "RESPONDED", 200, None, None, "Cloud", "AS64504"),
            (5, "delta.example", True, "CONFIRMED", 10, 42, "192.0.2.5", True, "RESPONDED", 200, None, None, "Cloud", "AS64505"),
            (6, "candidate.example", False, "CANDIDATE", 42, 42, None, False, "UNKNOWN", None, None, None, "Unknown", None),
        ]
        risks = [
            risk(1, "zulu.example", 4, "Review"),
            risk(2, "beta.example", 8, "High"),
            risk(3, "alpha.example", 8, "High"),
            risk(4, "charlie.example", 6, "Elevated"),
            risk(5, "delta.example", 1, "Low"),
        ]

        def query(**kwargs):
            cursor = QueueCursor(fetchalls=[rows])
            self.main.get_conn = lambda: FakeConnection(cursor)
            self.main.calculate_scan_risks = mock.Mock(return_value=risks)
            return self.main.frontend_v2_assets(**kwargs)

        self.assertEqual(
            [asset["domain"] for asset in query(limit=2)["assets"]],
            ["alpha.example", "beta.example"],
        )
        self.assertEqual(
            [asset["domain"] for asset in query(sort_by="domain", sort_dir="desc")["assets"]],
            ["zulu.example", "delta.example", "charlie.example", "candidate.example", "beta.example", "alpha.example"],
        )
        self.assertEqual(
            [asset["domain"] for asset in query(sort_by="risk_score", sort_dir="desc")["assets"]],
            ["alpha.example", "beta.example", "charlie.example", "zulu.example", "delta.example", "candidate.example"],
        )
        self.assertEqual(
            [asset["domain"] for asset in query(sort_by="risk_score", sort_dir="asc")["assets"]],
            ["delta.example", "zulu.example", "charlie.example", "alpha.example", "beta.example", "candidate.example"],
        )
        self.assertEqual(
            [asset["domain"] for asset in query(sort_by="priority", sort_dir="desc")["assets"]],
            ["alpha.example", "beta.example", "charlie.example", "zulu.example", "delta.example", "candidate.example"],
        )
        self.assertEqual(
            [asset["domain"] for asset in query(sort_by="priority", sort_dir="asc")["assets"]],
            ["delta.example", "zulu.example", "charlie.example", "alpha.example", "beta.example", "candidate.example"],
        )
        self.assertEqual(
            [asset["domain"] for asset in query(sort_by="risk_score", sort_dir="desc", page=2, limit=2)["assets"]],
            ["charlie.example", "zulu.example"],
        )
        self.assertEqual(
            [asset["domain"] for asset in query(asset_class="SHADOW", sort_by="priority", sort_dir="desc")["assets"]],
            ["alpha.example", "zulu.example"],
        )

        with self.assertRaisesRegex(self.main.HTTPException, "sort_by"):
            query(sort_by="provider")
        with self.assertRaisesRegex(self.main.HTTPException, "sort_dir"):
            query(sort_by="domain", sort_dir="sideways")

    def test_asset_export_respects_selected_sort_order_without_pagination(self):
        rows = [
            (*row, "", "", "")
            for row in [
                (1, "zulu.example", False, "CONFIRMED", 10, 42, "192.0.2.1", True, "RESPONDED", 200, None, None, "Cloud", "AS64501"),
                (2, "beta.example", True, "CONFIRMED", 10, 42, "192.0.2.2", True, "RESPONDED", 200, None, None, "Cloud", "AS64502"),
                (3, "alpha.example", False, "CONFIRMED", 10, 42, "192.0.2.3", True, "RESPONDED", 200, None, None, "Cloud", "AS64503"),
                (4, "charlie.example", True, "CONFIRMED", 10, 42, "192.0.2.4", True, "RESPONDED", 200, None, None, "Cloud", "AS64504"),
                (5, "delta.example", True, "CONFIRMED", 10, 42, "192.0.2.5", True, "RESPONDED", 200, None, None, "Cloud", "AS64505"),
                (6, "candidate.example", False, "CANDIDATE", 42, 42, None, False, "UNKNOWN", None, None, None, "Unknown", None),
            ]
        ]
        cursor = QueueCursor(fetchalls=[rows])
        self.main.get_conn = lambda: FakeConnection(cursor)
        self.main.calculate_scan_risks = mock.Mock(return_value=[
            risk(1, "zulu.example", 4, "Review"),
            risk(2, "beta.example", 8, "High"),
            risk(3, "alpha.example", 8, "High"),
            risk(4, "charlie.example", 6, "Elevated"),
            risk(5, "delta.example", 1, "Low"),
        ])

        with mock.patch.object(self.main, "StreamingResponse", CapturedStreamingResponse):
            response = self.main.frontend_v2_assets_export(
                sort_by="priority", sort_dir="asc"
            )

        exported = list(csv.DictReader(io.StringIO("".join(response.content))))
        self.assertEqual(
            [row["Domain"] for row in exported],
            ["delta.example", "zulu.example", "charlie.example", "alpha.example", "beta.example", "candidate.example"],
        )

    def test_asset_export_requires_an_authoritative_scan(self):
        cursor = QueueCursor()
        self.main.get_conn = lambda: FakeConnection(cursor)
        self.main.get_latest_authoritative_scan_id = lambda current: None

        with self.assertRaisesRegex(self.main.HTTPException, "no authoritative scan"):
            self.main.frontend_v2_assets_export()

        self.assertEqual(cursor.executions, [])
        self.main.get_latest_authoritative_scan_id = lambda current: 42

    def test_asset_detail_consolidates_current_scan_evidence(self):
        now = datetime(2026, 9, 25, 12, 0, 0)
        cursor = QueueCursor(
            fetchones=[
                (7, False, "CONFIRMED", 40, 42, now, now, "example.com"),
                (
                    "192.0.2.7", True, "ptr.example", "RESPONDED",
                    True, 302, "redirect", "https://target.example", 200,
                    "Title",
                ),
                ("AS64500", "Example Org", "192.0.2.7"),
                ("Cloud",),
                (datetime(2027, 1, 1), 98, "valid"),
            ],
            fetchalls=[
                [(443, "https"), (8443, "https-alt")],
                [("React",), ("Vite",)],
                [("subfinder", "example.com")],
                [("takeover_candidate", "MEDIUM", "404")],
            ],
        )
        self.main.get_conn = lambda: FakeConnection(cursor)
        self.main.calculate_scan_risks = mock.Mock(return_value=[
            risk(7, "app.example", 8, "High", ("finding", "shadow_asset")),
        ])

        result = self.main.frontend_v2_asset_detail("app.example")

        self.assertEqual(result["asset_class"], "SHADOW")
        self.assertEqual(result["risk"]["score"], 8)
        self.assertEqual(result["http"]["observation_status"], "RESPONDED")
        self.assertEqual(result["ports"][0], {"port": 443, "service": "https"})
        self.assertEqual(result["technologies"], ["React", "Vite"])
        self.assertEqual(result["discovery"]["sources"][0]["source"], "subfinder")
        self.assertEqual(result["findings"][0]["severity"], "MEDIUM")
        identity_sql, params = cursor.executions[0]
        self.assertIn("FROM scan_results sr", identity_sql)
        self.assertEqual(params, (42, "app.example"))

    def test_scan_centre_identifies_authoritative_scans(self):
        now = datetime(2026, 9, 25, 12, 0, 0)
        cursor = QueueCursor(fetchalls=[[
            (43, "RUNNING", now, now, None, "example.com", 4, None),
            (42, "SUCCEEDED", now, now, now, "example.com", 10, 12.5),
            (41, "SUCCEEDED", now, now, now, "example.com", 9, 10),
        ]])
        self.main.get_conn = lambda: FakeConnection(cursor)

        result = self.main.frontend_v2_scans()

        self.assertEqual(result["current_authoritative_scan_id"], 42)
        self.assertEqual(result["previous_authoritative_scan_id"], 41)
        self.assertFalse(result["scans"][0]["is_current_authoritative"])
        self.assertTrue(result["scans"][1]["is_current_authoritative"])
        self.assertTrue(result["scans"][2]["is_previous_authoritative"])
        sql, params = cursor.executions[0]
        self.assertIn("LEFT JOIN scan_results sr", sql)
        self.assertIn("ORDER BY s.id DESC", sql)
        self.assertEqual(params, (100,))

    def test_brand_perimeter_retains_current_candidate_external_evidence(self):
        rows = [
            (
                "candidate.example", "CANDIDATE", "192.0.2.8", True,
                "RESPONDED", 404, "https://vendor.example", 404, "Candidate",
                "brand_tld,crtsh", "example.com",
            ),
            (
                "external.example", "EXTERNAL", None, False,
                "UNKNOWN", 0, None, None, None,
                "brand_pattern", "example.com",
            ),
        ]
        cursor = QueueCursor(fetchalls=[rows])
        self.main.get_conn = lambda: FakeConnection(cursor)

        result = self.main.frontend_v2_brand_assets(ownership="candidate")

        self.assertEqual(result["count"], 1)
        asset = result["assets"][0]
        self.assertEqual(asset["ownership_status"], "CANDIDATE")
        self.assertEqual(asset["discovery_sources"], ["brand_tld", "crtsh"])
        self.assertIsNone(asset["risk"])
        sql, params = cursor.executions[0]
        self.assertIn("FROM scan_results sr", sql)
        self.assertIn("IN ('CANDIDATE', 'EXTERNAL')", sql)
        self.assertEqual(params, (42,))

    def test_v2_routes_reuse_existing_current_contracts_without_schema_changes(self):
        paths = {route.path for route in self.main.app.routes}
        self.assertTrue({
            "/summary", "/new-domains-delta", "/disappeared-domains",
            "/risk-leaderboard", "/findings", "/cert-expiry",
            "/v2/overview", "/v2/assets", "/v2/assets/export",
            "/v2/assets/{domain_name}",
            "/v2/scans", "/v2/brand-assets",
        }.issubset(paths))


if __name__ == "__main__":
    unittest.main()
