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

    def reporting_classes(self, values):
        return mock.patch.object(
            self.main, "_current_scan_asset_classes", return_value=values
        )

    def test_overview_combines_current_counts_changes_and_canonical_risk(self):
        cursor = QueueCursor(
            fetchones=[(2,), (1,)],
            fetchalls=[[]],
        )
        self.main.get_conn = lambda: FakeConnection(cursor)
        self.main.calculate_scan_risks = mock.Mock(return_value=[
            risk(1, "high.example", 9, "High", ("finding",)),
            risk(2, "low.example", 0, "Low"),
            risk(3, "review.example", 4, "Review", ("shadow_asset",)),
        ])

        with self.reporting_classes({
            1: "KNOWN", 2: "SHADOW", 3: "SHADOW",
            4: "CANDIDATE", 5: "EXTERNAL",
        }):
            result = self.main.frontend_v2_overview()

        self.assertEqual(result["current_scan_id"], 42)
        self.assertEqual(result["previous_scan_id"], 41)
        self.assertEqual(result["counts"], {
            "organizational": 3,
            "known": 1,
            "shadow": 2,
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
        count_sql, count_params = next(
            (sql, params) for sql, params in cursor.executions
            if "FROM scan_results current_sr" in sql
        )
        self.assertIn("FROM scan_results current_sr", count_sql)
        self.assertEqual(count_params, (42, 41))

    def test_overview_uses_current_scope_counts_and_risk_only(self):
        classes = {
            **{domain_id: "KNOWN" for domain_id in range(1, 58)},
            **{domain_id: "SHADOW" for domain_id in range(58, 571)},
            **{domain_id: "CANDIDATE" for domain_id in range(571, 653)},
        }
        cursor = QueueCursor(fetchalls=[[]])
        self.main.get_conn = lambda: FakeConnection(cursor)
        self.main.calculate_scan_risks = mock.Mock(return_value=[
            risk(1, "known.example", 8, "High"),
            risk(58, "shadow.example", 6, "Elevated"),
            risk(571, "legacy-outside.example", 10, "High"),
        ])

        with self.reporting_classes(classes), mock.patch.object(
            self.main, "get_previous_authoritative_scan_id", return_value=None
        ):
            result = self.main.frontend_v2_overview()

        self.assertEqual(result["counts"], {
            "organizational": 570,
            "known": 57,
            "shadow": 513,
            "candidate": 82,
            "external": 0,
        })
        self.assertEqual(result["risk_distribution"], {
            "High": 1, "Elevated": 1, "Review": 0, "Low": 0,
        })
        self.assertEqual(result["needs_attention"], [
            {"domain": "known.example", "score": 8, "priority": "High", "reasons": []},
            {"domain": "shadow.example", "score": 6, "priority": "Elevated", "reasons": []},
        ])
        self.assertEqual(set(result), {
            "current_scan_id", "previous_scan_id", "counts", "brand_discovery", "risk_distribution",
            "changes", "needs_attention",
        })

    def test_brand_discovery_overview_deduplicates_sources_and_classifies_union(self):
        cursor = QueueCursor(fetchalls=[[
            (1, "brand_tld"), (1, "brand_tld"), (1, "brand_pattern"),
            (2, "brand_tld"), (3, "brand_pattern"), (99, "brand_tld"),
        ]])
        classes = {1: "CANDIDATE", 2: "EXTERNAL", 3: "KNOWN", 4: "SHADOW"}
        result = self.main._brand_discovery_overview(cursor, 42, classes)

        self.assertEqual(result["scan_id"], 42)
        self.assertEqual(result["source_counts"]["brand_tld"], {
            "domains": 2,
            "by_asset_class": {"candidate": 1, "external": 1, "known": 0, "shadow": 0},
        })
        self.assertEqual(result["source_counts"]["brand_pattern"], {
            "domains": 2,
            "by_asset_class": {"candidate": 1, "external": 0, "known": 1, "shadow": 0},
        })
        self.assertEqual(result["source_counts"]["brand_union"], {
            "domains": 3,
            "by_asset_class": {"candidate": 1, "external": 1, "known": 1, "shadow": 0},
        })
        self.assertEqual(result["brand_review_inventory"]["domains"], 2)
        self.assertEqual(result["brand_review_inventory"]["candidate"], 1)
        self.assertEqual(result["brand_review_inventory"]["external"], 1)
        self.assertEqual(cursor.executions[0][1], (42,))
        self.assertIn("SELECT DISTINCT domain_id, source", cursor.executions[0][0])

    def test_assets_discovery_source_filter_is_current_scan_exact_and_paginates(self):
        source_rows = [
            (1, "brand_tld"), (1, "brand_tld"), (2, "brand_pattern"),
            (3, "brand_tld"), (4, "brand_pattern"),
        ]
        asset_rows = [
            (1, "a-candidate.example", False, "CONFIRMED", 1, 42, None, False,
             False, "UNKNOWN", None, None, None, None, None, "Unknown", None),
            (4, "b-candidate.example", False, "CONFIRMED", 1, 42, None, False,
             False, "UNKNOWN", None, None, None, None, None, "Unknown", None),
            (2, "external.example", False, "EXTERNAL", 1, 42, None, False,
             False, "UNKNOWN", None, None, None, None, None, "Unknown", None),
            (3, "shadow.example", False, "CONFIRMED", 1, 42, None, False,
             False, "UNKNOWN", None, None, None, None, None, "Unknown", None),
        ]
        cursor = QueueCursor(fetchalls=[source_rows, asset_rows])
        self.main.get_conn = lambda: FakeConnection(cursor)
        with self.reporting_classes({1: "CANDIDATE", 2: "EXTERNAL", 3: "SHADOW"}), mock.patch.object(
            self.main, "_current_scan_risks", return_value=[]
        ):
            result = self.main.frontend_v2_assets(
                discovery_source="brand_union", asset_class="CANDIDATE",
                search="candidate", page=2, limit=1,
            )

        self.assertEqual(result["count"], 2)
        self.assertEqual([asset["domain"] for asset in result["assets"]], ["b-candidate.example"])
        self.assertEqual(cursor.executions[0][1], (42,))
        self.assertIn("scan_id = %s", cursor.executions[0][0])

    def test_brand_assets_source_filter_keeps_review_inventory_scope_and_count(self):
        rows = [
            (1, "candidate.example", "CONFIRMED", None, False, "UNKNOWN", None,
             None, None, None, "brand_tld,subfinder", "example.com", None),
            (2, "external.example", "EXTERNAL", None, False, "UNKNOWN", None,
             None, None, None, "brand_pattern", "example.com", None),
            (3, "known.example", "CONFIRMED", None, False, "UNKNOWN", None,
             None, None, None, "brand_tld", "example.com", None),
        ]
        with self.reporting_classes({1: "CANDIDATE", 2: "EXTERNAL", 3: "KNOWN"}):
            results = {}
            for source in ("brand_tld", "brand_pattern", "brand_union"):
                cursor = QueueCursor(fetchalls=[rows])
                self.main.get_conn = lambda cursor=cursor: FakeConnection(cursor)
                results[source] = self.main.frontend_v2_brand_assets(discovery_source=source)
        tld = results["brand_tld"]
        pattern = results["brand_pattern"]
        union = results["brand_union"]
        # Effective KNOWN is outside the Candidate/External review inventory.
        self.assertEqual(tld["count"], 1)
        self.assertEqual([asset["domain"] for asset in tld["assets"]], ["candidate.example"])
        self.assertEqual(pattern["count"], 1)
        self.assertEqual([asset["domain"] for asset in pattern["assets"]], ["external.example"])
        self.assertEqual(union["count"], 2)
        self.assertEqual({asset["domain"] for asset in union["assets"]}, {
            "candidate.example", "external.example",
        })

    def test_discovery_source_filter_rejects_unsupported_source(self):
        with self.assertRaises(self.main.HTTPException) as raised:
            self.main._normalize_brand_discovery_filter("subfinder")
        self.assertEqual(raised.exception.status_code, 400)

    def test_asset_explorer_filters_current_assets_and_has_no_candidate_risk(self):
        rows = [
            (
                1, "known.example", True, "CONFIRMED", 10, 42,
                "192.0.2.1", True, True, "RESPONDED", 200, "Known", None,
                None, None, "Cloud", "AS64500",
            ),
            (
                2, "shadow.example", False, "CONFIRMED", 40, 42,
                "192.0.2.2", True, False, "NO_RESPONSE", 0, None, None,
                None, None, "Cloud", "AS64501",
            ),
            (
                3, "candidate.example", False, "CANDIDATE", 42, 42,
                None, False, None, "UNKNOWN", 0, None, None,
                None, None, "Unknown", None,
            ),
        ]
        cursor = QueueCursor(fetchalls=[rows])
        self.main.get_conn = lambda: FakeConnection(cursor)
        self.main.calculate_scan_risks = mock.Mock(return_value=[
            risk(1, "known.example", 1, "Low", ("http_exposed",)),
            risk(2, "shadow.example", 6, "Elevated", ("shadow_asset",)),
        ])

        with self.reporting_classes({
            1: "KNOWN", 2: "SHADOW", 3: "CANDIDATE",
        }):
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
        with self.reporting_classes({
            1: "KNOWN", 2: "SHADOW", 3: "CANDIDATE",
        }):
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
                None, None,
            ),
            (
                2, "shadow.example", False, "CONFIRMED", 40, 42,
                "192.0.2.2", True, "NO_RESPONSE", None, None, None,
                "Cloud", "AS64501", "22", "", "", None, None,
            ),
            (
                3, "candidate.example", False, "CANDIDATE", 42, 42,
                None, False, "UNKNOWN", None, None, None,
                "Unknown", None, "", "", "", None, None,
            ),
            (
                4, "external.example", False, "EXTERNAL", 42, 42,
                None, False, "UNKNOWN", None, None, None,
                "Unknown", None, "", "", "", None, None,
            ),
        ]
        cursor = QueueCursor(fetchalls=[rows])
        self.main.get_conn = lambda: FakeConnection(cursor)
        self.main.calculate_scan_risks = mock.Mock(return_value=[
            risk(1, "known.example", 4, "Review", ("finding",)),
            risk(2, "shadow.example", 8, "High", ("shadow_asset",)),
        ])

        with self.reporting_classes({
            1: "KNOWN", 2: "SHADOW", 3: "CANDIDATE", 4: "EXTERNAL",
        }), mock.patch.object(
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
        with self.reporting_classes({
            1: "KNOWN", 2: "SHADOW", 3: "CANDIDATE", 4: "EXTERNAL",
        }), mock.patch.object(
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
            (1, "zulu.example", False, "CONFIRMED", 10, 42, "192.0.2.1", True, True, "RESPONDED", 200, None, None, None, None, "Cloud", "AS64501"),
            (2, "beta.example", True, "CONFIRMED", 10, 42, "192.0.2.2", True, True, "RESPONDED", 200, None, None, None, None, "Cloud", "AS64502"),
            (3, "alpha.example", False, "CONFIRMED", 10, 42, "192.0.2.3", True, True, "RESPONDED", 200, None, None, None, None, "Cloud", "AS64503"),
            (4, "charlie.example", True, "CONFIRMED", 10, 42, "192.0.2.4", True, True, "RESPONDED", 200, None, None, None, None, "Cloud", "AS64504"),
            (5, "delta.example", True, "CONFIRMED", 10, 42, "192.0.2.5", True, True, "RESPONDED", 200, None, None, None, None, "Cloud", "AS64505"),
            (6, "candidate.example", False, "CANDIDATE", 42, 42, None, False, None, "UNKNOWN", None, None, None, None, None, "Unknown", None),
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
            with self.reporting_classes({
                1: "SHADOW", 2: "KNOWN", 3: "SHADOW",
                4: "KNOWN", 5: "KNOWN", 6: "CANDIDATE",
            }):
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

    def test_positive_risk_count_pagination_and_deterministic_order(self):
        rows = [
            (i, f"host-{i:03}.example", False, "CONFIRMED", 1, 42,
             "192.0.2.1", True, True, "RESPONDED", 200, None, None,
             None, None, "Unknown", None)
            for i in range(1, 142)
        ]
        rows.append(rows[0])
        risks = [
            risk(i, f"host-{i:03}.example", 0 if i == 141 else (i % 8) + 1,
                 "High" if i % 8 >= 6 else "Review")
            for i in range(1, 142)
        ]
        cursor = QueueCursor(fetchalls=[rows])
        self.main.get_conn = lambda: FakeConnection(cursor)
        self.main.calculate_scan_risks = mock.Mock(return_value=risks)
        with self.reporting_classes({i: "KNOWN" if i % 2 else "SHADOW" for i in range(1, 142)}):
            result = self.main.frontend_v2_assets(risk_positive=True, page=2, limit=50)

        self.assertEqual(result["count"], 140)
        self.assertEqual(result["sort_by"], "risk_score")
        self.assertEqual(result["sort_dir"], "desc")
        self.assertEqual(len(result["assets"]), 50)
        self.assertEqual(result["assets"], sorted(
            result["assets"],
            key=lambda item: (-item["risk"]["score"], item["domain"].casefold(), item["domain"]),
        ))
        self.assertIn("FROM scan_results sr", cursor.executions[0][0])

    def test_dns_and_http_filters_keep_exact_null_and_scope_semantics(self):
        rows = [
            (1, "known.example", True, "CONFIRMED", 1, 42, "192.0.2.1", True, True, "RESPONDED", 200, None, None, None, None, "Unknown", None),
            (2, "shadow-no-response.example", False, "CONFIRMED", 1, 42, None, False, False, "NO_RESPONSE", None, None, None, None, None, "Unknown", None),
            (3, "shadow-unknown.example", False, "CONFIRMED", 1, 42, None, None, None, "UNKNOWN", None, None, None, None, None, "Unknown", None),
            (4, "candidate.example", False, "CANDIDATE", 1, 42, "192.0.2.4", True, True, "RESPONDED", 503, None, None, None, None, "Unknown", None),
            (5, "shadow-error.example", False, "CONFIRMED", 1, 42, "192.0.2.5", True, True, "RESPONDED", 503, None, None, None, None, "Unknown", None),
        ]
        classes = {1: "KNOWN", 2: "SHADOW", 3: "SHADOW", 4: "CANDIDATE", 5: "SHADOW"}
        cases = (
            ({"has_ip": True}, ["known.example", "shadow-error.example"]),
            ({"has_ip": False}, ["shadow-no-response.example"]),
            ({"http_live": False}, ["shadow-no-response.example"]),
            ({"http_status": 200}, ["known.example"]),
            ({"http_status_group": "5xx"}, ["shadow-error.example"]),
            ({"http_status_group": "4xx"}, []),
        )
        for filters, expected in cases:
            with self.subTest(filters=filters):
                cursor = QueueCursor(fetchalls=[rows])
                self.main.get_conn = lambda: FakeConnection(cursor)
                self.main.calculate_scan_risks = mock.Mock(return_value=[])
                with self.reporting_classes(classes):
                    result = self.main.frontend_v2_assets(**filters)
                self.assertEqual([item["domain"] for item in result["assets"]], expected)
                self.assertEqual(result["count"], len(expected))
        cursor = QueueCursor(fetchalls=[rows])
        self.main.get_conn = lambda: FakeConnection(cursor)
        self.main.calculate_scan_risks = mock.Mock(return_value=[])
        with self.reporting_classes(classes):
            unknown = self.main.frontend_v2_assets(http_observation_status="UNKNOWN")
        self.assertEqual([item["domain"] for item in unknown["assets"]], ["shadow-unknown.example"])
        self.assertIsNone(unknown["assets"][0]["http_live"])
        self.assertIsNone(unknown["assets"][0]["http_status"])

    def test_risky_domains_legacy_list_has_total_and_pagination_headers(self):
        cursor = QueueCursor()
        self.main.get_conn = lambda: FakeConnection(cursor)
        self.main._current_scan_risks = mock.Mock(return_value=[
            risk(i, f"asset-{i:03}.example", 5, "Review") for i in range(1, 126)
        ])
        response = self.main.Response()
        result = self.main.risky_domains(response, page=2, limit=40)
        self.assertEqual(len(result), 40)
        self.assertEqual(response.headers["X-Total-Count"], "125")
        self.assertEqual(response.headers["X-Page"], "2")
        self.assertEqual(response.headers["X-Page-Size"], "40")
        self.assertEqual(result[0]["domain"], "asset-041.example")

    def test_malformed_status_filters_are_rejected(self):
        for kwargs in ({"http_status": 99}, {"http_status": 600}, {"http_status_group": "1xx"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(self.main.HTTPException):
                self.main.frontend_v2_assets(**kwargs)

    def test_exposure_and_http_totals_share_current_confirmed_scope(self):
        cursor = QueueCursor(fetchones=[(570, 119, 100)], fetchalls=[[
            ("2xx", 65), ("3xx", 8), ("4xx", 4), ("5xx", 3),
            ("no_response", 20), ("unknown", 470),
        ]])
        self.main.get_conn = lambda: FakeConnection(cursor)
        exposure = self.main.exposure_summary()
        http = self.main.http_status()
        self.assertEqual(exposure["total_domains"], 570)
        self.assertEqual(exposure["resolving_domains"], 119)
        self.assertEqual(exposure["http_responding_domains"], 100)
        self.assertEqual(http, {
            "2xx": 65, "3xx": 8, "4xx": 4, "5xx": 3,
            "no_response": 20, "unknown": 470,
        })
        exposure_sql = cursor.executions[0][0]
        http_sql = cursor.executions[1][0]
        self.assertIn("COUNT(DISTINCT sr.domain_id)", exposure_sql)
        self.assertIn("IN ('KNOWN', 'SHADOW')", exposure_sql)
        self.assertIn("LEFT JOIN domain_states", http_sql)
        self.assertIn("IN ('KNOWN', 'SHADOW')", http_sql)

    def test_priority_filter_populations_match_overview_distribution(self):
        rows = [
            (1, "high.example", True, "CONFIRMED", 1, 42, "192.0.2.1", True, True, "RESPONDED", 200, None, None, None, None, "Unknown", None),
            (2, "elevated.example", False, "CONFIRMED", 1, 42, "192.0.2.2", True, True, "RESPONDED", 200, None, None, None, None, "Unknown", None),
            (3, "review.example", False, "CONFIRMED", 1, 42, "192.0.2.3", True, True, "RESPONDED", 200, None, None, None, None, "Unknown", None),
            (4, "low.example", True, "CONFIRMED", 1, 42, "192.0.2.4", True, True, "RESPONDED", 200, None, None, None, None, "Unknown", None),
        ]
        risks = [
            risk(1, "high.example", 8, "High"),
            risk(2, "elevated.example", 6, "Elevated"),
            risk(3, "review.example", 4, "Review"),
            risk(4, "low.example", 1, "Low"),
        ]
        classes = {i: "KNOWN" for i in range(1, 5)}
        for priority in ("High", "Elevated", "Review", "Low"):
            cursor = QueueCursor(fetchalls=[rows])
            self.main.get_conn = lambda: FakeConnection(cursor)
            self.main.calculate_scan_risks = mock.Mock(return_value=risks)
            with self.reporting_classes(classes):
                result = self.main.frontend_v2_assets(priority=priority)
            self.assertEqual(result["count"], sum(item.result.priority == priority for item in risks))
    def test_asset_export_respects_selected_sort_order_without_pagination(self):
        rows = [
            (*row, "", "", "")
            for row in [
                (1, "zulu.example", False, "CONFIRMED", 10, 42, "192.0.2.1", True, "RESPONDED", 200, None, None, None, None, "Cloud", "AS64501"),
                (2, "beta.example", True, "CONFIRMED", 10, 42, "192.0.2.2", True, "RESPONDED", 200, None, None, None, None, "Cloud", "AS64502"),
                (3, "alpha.example", False, "CONFIRMED", 10, 42, "192.0.2.3", True, "RESPONDED", 200, None, None, None, None, "Cloud", "AS64503"),
                (4, "charlie.example", True, "CONFIRMED", 10, 42, "192.0.2.4", True, "RESPONDED", 200, None, None, None, None, "Cloud", "AS64504"),
                (5, "delta.example", True, "CONFIRMED", 10, 42, "192.0.2.5", True, "RESPONDED", 200, None, None, None, None, "Cloud", "AS64505"),
                (6, "candidate.example", False, "CANDIDATE", 42, 42, None, False, "UNKNOWN", None, None, None, None, None, "Unknown", None),
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

        with self.reporting_classes({
            1: "SHADOW", 2: "KNOWN", 3: "SHADOW",
            4: "KNOWN", 5: "KNOWN", 6: "CANDIDATE",
        }), mock.patch.object(self.main, "StreamingResponse", CapturedStreamingResponse):
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
                (7, False, "CONFIRMED", 40, 42, now, now, "example.com", True, now),
                (
                    "192.0.2.7", True, "ptr.example", "RESPONDED",
                    True, 302, "redirect", "https://target.example", 200,
                    "Title", None,
                ),
                ("AS64500", "Example Org", "192.0.2.7"),
                ("Cloud",),
                (datetime(2027, 1, 1), 98, "valid"),
            ],
            fetchalls=[
                [(443, "https"), (8443, "https-alt")],
                [("React",), ("Vite",)],
                [(
                    "php", "8.2.12", "high", "x-powered-by_header",
                    "PHP/8.2.12", "http://app.example", "sr-tech-02",
                )],
                [("subfinder", "example.com")],
                [("takeover_candidate", "MEDIUM", "404")],
                [],
            ],
        )
        self.main.get_conn = lambda: FakeConnection(cursor)
        self.main.calculate_scan_risks = mock.Mock(return_value=[
            risk(7, "app.example", 8, "High", ("finding", "shadow_asset")),
        ])

        with mock.patch.object(self.main, "date") as date_type:
            date_type.today.return_value = datetime(2026, 10, 28).date()
            with self.reporting_classes({7: "SHADOW"}):
                result = self.main.frontend_v2_asset_detail("app.example")

        self.assertEqual(result["asset_class"], "SHADOW")
        self.assertEqual(result["risk"]["score"], 8)
        self.assertEqual(result["http"]["observation_status"], "RESPONDED")
        self.assertEqual(result["ports"][0], {"port": 443, "service": "https"})
        self.assertEqual(result["technologies"], ["React", "Vite"])
        self.assertEqual(result["technology_observations"], [{
            "technology": "php",
            "version": "8.2.12",
            "confidence": "high",
            "evidence_type": "x-powered-by_header",
            "sanitized_evidence": "PHP/8.2.12",
            "observed_url": "http://app.example",
            "detector_version": "sr-tech-02",
            "lifecycle": {
                "status": "security_support",
                "matched_release_branch": "8.2",
                "active_support_until": "2024-12-31",
                "security_support_until": "2026-12-31",
                "end_of_life": "2026-12-31",
                "source_url": "https://www.php.net/supported-versions.php",
                "dataset_revision": "2026-10-28",
                "assessment_date": "2026-10-28",
                "explanation_code": "php_security_support",
            },
            "cve_intelligence": {
                "assessment_date": "2026-10-28",
                "dataset_revision": "2026-10-28",
                "coverage": "partial",
                "candidates": [
                    {
                        "cve_id": "CVE-2026-109618",
                        "applicability_status": "potentially_affected",
                        "reported_version": "8.2.12",
                        "affected_version_range": "< 8.2.35 (PHP 8.2 branch)",
                        "fixed_version": "8.2.35",
                        "source_url": (
                            "https://github.com/php/php-src/security/advisories/"
                            "GHSA-w8hw-w9fx-j79w"
                        ),
                        "dataset_revision": "2026-10-28",
                        "evidence_confidence": "high_version_range_match",
                        "patch_status": "unknown",
                        "explanation_code": "php_version_within_verified_affected_range",
                    },
                    {
                        "cve_id": "CVE-2026-109619",
                        "applicability_status": "potentially_affected",
                        "reported_version": "8.2.12",
                        "affected_version_range": "< 8.2.35 (PHP 8.2 branch)",
                        "fixed_version": "8.2.35",
                        "source_url": (
                            "https://github.com/php/php-src/security/advisories/"
                            "GHSA-6wmf-4rv5-p3rp"
                        ),
                        "dataset_revision": "2026-10-28",
                        "evidence_confidence": "high_version_range_match",
                        "patch_status": "unknown",
                        "explanation_code": "php_version_within_verified_affected_range",
                    },
                ],
            },
        }])
        self.assertEqual(result["discovery"]["sources"][0]["source"], "subfinder")
        self.assertEqual(result["findings"][0]["severity"], "MEDIUM")
        identity_sql, params = cursor.executions[0]
        self.assertIn("FROM scan_results sr", identity_sql)
        self.assertEqual(params, (42, "app.example"))
        observation_sql, observation_params = cursor.executions[6]
        self.assertIn("FROM domain_technology_observations dto", observation_sql)
        self.assertIn("JOIN scan_results sr", observation_sql)
        self.assertNotIn("dto.id", observation_sql.split("SELECT", 1)[1].split("FROM", 1)[0])
        self.assertEqual(observation_params, (7, 42))

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
                1, "candidate.example", "CANDIDATE", "192.0.2.8", True,
                "RESPONDED", 404, "https://vendor.example", 404, "Candidate",
                "brand_tld,crtsh", "example.com", None,
            ),
            (
                2, "external.example", "EXTERNAL", None, False,
                "UNKNOWN", 0, None, None, None,
                "brand_pattern", "example.com", None,
            ),
        ]
        cursor = QueueCursor(fetchalls=[rows])
        self.main.get_conn = lambda: FakeConnection(cursor)

        with self.reporting_classes({1: "CANDIDATE", 2: "EXTERNAL"}):
            result = self.main.frontend_v2_brand_assets(ownership="candidate")

        self.assertEqual(result["count"], 1)
        asset = result["assets"][0]
        self.assertEqual(asset["ownership_status"], "CANDIDATE")
        self.assertEqual(asset["asset_class"], "CANDIDATE")
        self.assertEqual(asset["discovery_sources"], ["brand_tld", "crtsh"])
        self.assertIsNone(asset["risk"])
        sql, params = cursor.executions[0]
        self.assertIn("FROM scan_results sr", sql)
        self.assertIn("WHERE sr.scan_id = %s", sql)
        self.assertIn("GROUP BY d.id", sql)
        self.assertIn("IN ('CANDIDATE', 'EXTERNAL')", sql)
        self.assertEqual(params, (42,))

    def test_brand_asset_class_is_separate_from_stored_ownership_and_filters_effectively(self):
        # Mirrors scan 17's legacy rows: stored CONFIRMED, current effective CANDIDATE.
        candidate_row = (
            17, "abc.ai", "CONFIRMED", None, False, "UNKNOWN", None,
            None, None, None, "brand_tld", "abc.com", None,
        )
        external_row = (
            18, "external.example", "EXTERNAL", None, False, "UNKNOWN", None,
            None, None, None, "brand_pattern", "example.com", None,
        )
        effective_classes = {17: "CANDIDATE", 18: "EXTERNAL"}

        cursor = QueueCursor(fetchalls=[[candidate_row, external_row]])
        self.main.get_conn = lambda: FakeConnection(cursor)
        with self.reporting_classes(effective_classes):
            candidates = self.main.frontend_v2_brand_assets(asset_class="candidate")
        self.assertEqual(candidates["count"], 1)
        self.assertEqual(candidates["assets"][0]["domain"], "abc.ai")
        self.assertEqual(candidates["assets"][0]["ownership_status"], "CONFIRMED")
        self.assertEqual(candidates["assets"][0]["asset_class"], "CANDIDATE")

        asset_cursor = QueueCursor(fetchalls=[[
            (17, "abc.ai", False, "CONFIRMED", 1, 17, None, False,
             False, "UNKNOWN", None, None, None, None, None, "Unknown", None),
        ]])
        self.main.get_conn = lambda: FakeConnection(asset_cursor)
        with self.reporting_classes(effective_classes), mock.patch.object(
            self.main, "_current_scan_risks", return_value=[]
        ):
            v2_assets = self.main.frontend_v2_assets(asset_class="CANDIDATE")
        self.assertEqual(v2_assets["count"], 1)
        self.assertEqual(v2_assets["assets"][0]["asset_class"], "CANDIDATE")

        cursor = QueueCursor(fetchalls=[[candidate_row, external_row]])
        self.main.get_conn = lambda: FakeConnection(cursor)
        with self.reporting_classes(effective_classes):
            externals = self.main.frontend_v2_brand_assets(asset_class="EXTERNAL")
        self.assertEqual(externals["count"], 1)
        self.assertEqual(externals["assets"][0]["domain"], "external.example")
        self.assertEqual(externals["assets"][0]["asset_class"], "EXTERNAL")

        # The legacy ownership filter still examines the stored column.
        cursor = QueueCursor(fetchalls=[[candidate_row, external_row]])
        self.main.get_conn = lambda: FakeConnection(cursor)
        with self.reporting_classes(effective_classes):
            legacy = self.main.frontend_v2_brand_assets(ownership="CONFIRMED")
        self.assertEqual(legacy["count"], 1)
        self.assertEqual(legacy["assets"][0]["ownership_status"], "CONFIRMED")
        self.assertEqual(legacy["assets"][0]["asset_class"], "CANDIDATE")

    def test_brand_asset_class_count_pagination_and_zero_results(self):
        rows = [
            (domain_id, f"host{domain_id}.example", "CONFIRMED", None, False,
             "UNKNOWN", None, None, None, None, None, None, None)
            for domain_id in range(1, 4)
        ]
        cursor = QueueCursor(fetchalls=[rows])
        self.main.get_conn = lambda: FakeConnection(cursor)
        with self.reporting_classes({1: "CANDIDATE", 2: "CANDIDATE", 3: "EXTERNAL"}):
            page = self.main.frontend_v2_brand_assets(
                asset_class="CANDIDATE", page=2, limit=1
            )
        self.assertEqual(page["count"], 2)
        self.assertEqual(len(page["assets"]), 1)
        self.assertEqual(page["assets"][0]["domain"], "host2.example")

        cursor = QueueCursor(fetchalls=[rows])
        self.main.get_conn = lambda: FakeConnection(cursor)
        with self.reporting_classes({1: "CANDIDATE", 2: "CANDIDATE", 3: "EXTERNAL"}):
            empty = self.main.frontend_v2_brand_assets(asset_class="KNOWN")
        self.assertEqual(empty["count"], 0)
        self.assertEqual(empty["assets"], [])

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
