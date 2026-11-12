import pathlib
import sys
import unittest
from unittest import mock

BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

import main  # noqa: E402
from http_title_intelligence import classify_title, normalize_title, signal_identity  # noqa: E402


class TitleCursor:
    def __init__(self, rows=(), scan_id=19, grouped=()):
        self.rows = list(rows)
        self.scan_id = scan_id
        self.grouped = list(grouped)
        self.result = None
        self.executions = []

    def execute(self, sql, params=None):
        self.executions.append((sql, params))
        if "SELECT id" in sql and "FROM scans" in sql:
            self.result = (self.scan_id,) if self.scan_id is not None else None
        elif "COUNT(DISTINCT id) FILTER" in sql:
            self.result = (829, 35, 15, 794)
        elif "GROUP BY COALESCE(http_observation_status" in sql:
            self.result = self.grouped
        elif "FROM domain_states ds" in sql and "LIMIT %s OFFSET %s" in sql:
            _, limit, offset = params
            eligible = [row for row in self.rows if row[2] in {"KNOWN", "SHADOW"}]
            self.result = eligible[offset:offset + limit]
        else:
            self.result = None

    def fetchone(self):
        return self.result

    def fetchall(self):
        return self.result or []


class TitleConnection:
    def __init__(self, cursor):
        self.value = cursor
        self.closed = False
        self.session_args = None

    def set_session(self, **kwargs):
        self.session_args = kwargs

    def cursor(self):
        return self.value

    def rollback(self):
        pass

    def close(self):
        self.closed = True


def title_row(domain_id, domain, asset_class, title, final_url=None):
    return (domain_id, domain, asset_class, title, 200, "RESPONDED", final_url, None)


class HttpTitleClassifierTests(unittest.TestCase):
    def test_specific_products_and_categories(self):
        cases = {
            "Jenkins": ("http-title-jenkins", "ADMIN_INTERFACE"),
            "phpMyAdmin - Login": ("http-title-phpmyadmin", "ADMIN_INTERFACE"),
            "Apache Tomcat Manager Application": ("http-title-tomcat-manager", "ADMIN_INTERFACE"),
            "Portainer": ("http-title-portainer", "ADMIN_INTERFACE"),
            "Kubernetes Dashboard": ("http-title-kubernetes-dashboard", "ADMIN_INTERFACE"),
            "JupyterLab": ("http-title-jupyter", "DEVELOPER_TOOL"),
            "Grafana": ("http-title-grafana", "MONITORING_DASHBOARD"),
            "Prometheus": ("http-title-prometheus", "MONITORING_DASHBOARD"),
            "Kibana": ("http-title-kibana", "MONITORING_DASHBOARD"),
            "Swagger UI": ("http-title-swagger-ui", "API_DOCUMENTATION"),
            "OpenAPI documentation": ("http-title-openapi-docs", "API_DOCUMENTATION"),
            "ReDoc API": ("http-title-redoc", "API_DOCUMENTATION"),
            "Index of /private": ("http-title-directory-listing", "DIRECTORY_LISTING"),
            "Welcome to nginx!": ("http-title-default-nginx", "DEFAULT_SERVER_PAGE"),
        }
        for title, expected in cases.items():
            with self.subTest(title=title):
                match = classify_title(title)[0]
                self.assertEqual((match["rule_id"], match["category"]), expected)
                self.assertIn(match["signal_classification"], {"EXPOSURE_SIGNAL", "INFORMATIONAL"})

    def test_casefold_entities_unicode_and_markup_are_safe(self):
        self.assertEqual(classify_title("gRaFaNa" )[0]["rule_id"], "http-title-grafana")
        self.assertEqual(classify_title("Swagger&#32;UI")[0]["rule_id"], "http-title-swagger-ui")
        self.assertEqual(normalize_title("<b>Grafana</b>"), "grafana")
        self.assertEqual(classify_title("<script>Grafana</script>"), [])
        self.assertEqual(classify_title("<style>Jenkins</style>"), [])

    def test_generic_titles_and_near_matches_are_not_flagged(self):
        for title in (None, "", "Login", "Dashboard", "Home", "Welcome", "Welcome to our site",
                      "The grafana team", "Index of resources", "Apache server"):
            with self.subTest(title=title):
                self.assertEqual(classify_title(title), [])

    def test_multiple_specific_matches_and_stable_identity(self):
        matches = classify_title("Grafana - Swagger UI")
        self.assertEqual({item["rule_id"] for item in matches}, {"http-title-grafana", "http-title-swagger-ui"})
        one = signal_identity(scan_id=19, domain_id=3, rule_id="http-title-grafana", service_url="https://x/")
        self.assertEqual(one, signal_identity(scan_id=19, domain_id=3, rule_id="http-title-grafana", service_url="https://x/"))
        self.assertNotEqual(one, signal_identity(scan_id=20, domain_id=3, rule_id="http-title-grafana", service_url="https://x/"))


class HttpTitleApiTests(unittest.TestCase):
    def setUp(self):
        self.rows = [
            title_row(1, "known.example", "KNOWN", "Jenkins", "https://known.example/"),
            title_row(2, "shadow.example", "SHADOW", "Index of /", "https://shadow.example/"),
            title_row(3, "candidate.example", "CANDIDATE", "Grafana"),
            title_row(4, "known.example", "KNOWN", "Grafana - Swagger UI", "https://known.example/"),
            title_row(4, "known.example", "KNOWN", "Grafana - Swagger UI", "https://known.example/"),
            title_row(5, "generic.example", "KNOWN", "Dashboard"),
            title_row(6, "markup.example", "KNOWN", "<script>Grafana</script>"),
        ]
        self.cursor = TitleCursor(self.rows, grouped=[("UNKNOWN", 2), ("NO_RESPONSE", 3)])
        self.conn = TitleConnection(self.cursor)

    def _patch_conn(self):
        return mock.patch.object(main, "get_conn", return_value=self.conn)

    def test_list_is_current_scan_scoped_deduplicated_and_known_shadow_only(self):
        with self._patch_conn(), mock.patch.object(main, "get_latest_authoritative_scan_id", return_value=19):
            result = main.http_title_intelligence()
        self.assertEqual(result["scan_id"], 19)
        self.assertEqual(result["total"], 4)
        self.assertEqual(result["returned"], 4)
        self.assertEqual({item["asset_class"] for item in result["signals"]}, {"KNOWN", "SHADOW"})
        self.assertTrue(all(item["classification"] in {"EXPOSURE_SIGNAL", "INFORMATIONAL"} for item in result["signals"]))
        self.assertIn("Grafana - Swagger UI", {item["title"] for item in result["signals"]})
        self.assertTrue(any("CANDIDATE" in sql and "SHADOW" in sql for sql, _ in self.cursor.executions))
        self.assertTrue(any("EXISTS" in sql and "scan_results" in sql for sql, _ in self.cursor.executions))
        self.assertTrue(self.conn.session_args["readonly"])
        self.assertTrue(self.conn.closed)

    def test_filter_pagination_and_exact_signal_total(self):
        with self._patch_conn(), mock.patch.object(main, "get_latest_authoritative_scan_id", return_value=19):
            result = main.http_title_intelligence(page=1, limit=1, category="admin_interface")
        self.assertEqual(result["category"], "ADMIN_INTERFACE")
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["returned"], 1)
        with self._patch_conn(), mock.patch.object(main, "get_latest_authoritative_scan_id", return_value=19):
            result = main.http_title_intelligence(page=2, limit=2)
        self.assertEqual(result["total"], 4)
        self.assertEqual(len(result["signals"]), 2)
        self.assertNotEqual(result["signals"][0]["signal_id"], result["signals"][1]["signal_id"])

    def test_invalid_filters_and_pagination_are_rejected(self):
        with self.assertRaises(main.HTTPException):
            main.http_title_intelligence(category="NOT_A_CATEGORY")
        with self.assertRaises(main.HTTPException):
            main.http_title_intelligence(page=0)

    def test_summary_reports_coverage_separately_from_signals(self):
        with self._patch_conn(), mock.patch.object(main, "get_latest_authoritative_scan_id", return_value=19):
            result = main.http_title_intelligence_summary()
        self.assertEqual(result["coverage"]["organizational_assets"], 829)
        self.assertEqual(result["assets_with_persisted_titles"], 35)
        self.assertEqual(result["coverage"]["assets_without_nonempty_titles"], 794)
        self.assertEqual(result["total_signals"], 4)
        self.assertEqual(result["distinct_assets_with_title_signals"], 3)
        self.assertEqual(result["coverage"]["collection_completeness"], "UNKNOWN")

    def test_no_successful_scan_returns_unavailable(self):
        with self._patch_conn(), mock.patch.object(main, "get_latest_authoritative_scan_id", return_value=None):
            result = main.http_title_intelligence()
        self.assertEqual(result["availability_state"], "UNAVAILABLE")
        self.assertEqual(result["signals"], [])


if __name__ == "__main__":
    unittest.main()
