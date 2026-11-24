import csv
import asyncio
from decimal import Decimal
import importlib
import io
import json
import logging
import pathlib
import sys
import unittest
import zipfile
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from scan_report import (  # noqa: E402
    ScanReportNotFound,
    ScanReportNotReady,
    _brand_redirect_coverage,
    build_scan_report,
    write_adhoc_campaign_csv,
)


class _Cursor:
    def __init__(self, connection, name=None):
        self.connection = connection
        self.name = name
        self.one = None
        self.rows = []
        self.offset = 0
        self.query = ""
        self.params = ()
        self.closed = False

    def execute(self, query, params=None):
        self.query = query
        self.params = tuple(params or ())
        self.connection.queries.append((query, self.params))
        if "FROM scans s" in query:
            self.one = self.connection.scans.get(self.params[0])
        elif "to_regclass" in query:
            self.one = tuple(self.connection.optional_tables) + (None,) * max(
                0, 3 - len(self.connection.optional_tables)
            )
        elif "COUNT(*) FILTER" in query and "brand_redirect_observations" in query:
            self.one = self.connection.brand_redirect_stats.get(
                self.params[0], (0, 0, 0, 0, 0)
            )
        elif "COUNT(DISTINCT ds.domain_id)" in query:
            self.one = (self.connection.state_counts.get(self.params[0], 0),)
        else:
            key = next((key for key, marker in self.connection.dataset_markers.items()
                        if marker in query), None)
            self.rows = list(self.connection.datasets.get((self.params[0], key), []))

    def fetchone(self):
        return self.one

    def fetchmany(self, size):
        batch = self.rows[self.offset:self.offset + size]
        self.offset += len(batch)
        return batch

    def close(self):
        self.closed = True


class _Connection:
    dataset_markers = {
        "assets": "WITH membership AS",
        "dns": "FROM domain_dns",
        "http": "FROM domain_states ds",
        "tls": "FROM domain_cert c",
        "technology-labels": "FROM domain_tech t",
        "ports": "FROM domain_ports p",
        "findings": "FROM domain_findings f",
        "risk": "FROM domain_risk r",
        "dns-security": "FROM dns_security_checks x",
        "technology-observations": "FROM domain_technology_observations x",
        "brand-redirects": "JOIN domains d ON d.id = br.domain_id",
    }

    def __init__(self, scans=None, datasets=None, state_counts=None, optional_tables=None,
                 brand_redirect_stats=None):
        self.scans = scans or {}
        self.datasets = datasets or {}
        self.state_counts = state_counts or {}
        self.optional_tables = optional_tables or (None, None, None)
        self.brand_redirect_stats = brand_redirect_stats or {}
        self.queries = []

    def cursor(self, name=None):
        return _Cursor(self, name)

    def close(self):
        pass


def _scan(scan_id, status="SUCCEEDED", completed="2026-11-10T03:00:00", members=1,
          diagnostics=None):
    return (scan_id, status, "2026-11-10T02:00:00", "2026-11-10T02:00:01",
            completed, "seed.example", diagnostics, members)


def _asset_row(scan_id, domain):
    return (scan_id, domain, "seed.example", False, "CONFIRMED", "CANDIDATE",
            False, None, None, None, None, None, None, None, None, None, None,
            None, None, [], [])


def _diagnostics(stage, selected, completed):
    return {"version": 1, "attempts": [{
        "stage": stage, "order": 9, "attempt": 1, "status": "SUCCEEDED",
        "worker_summary": {"selected": selected, "completed": completed},
    }]}


class ScanReportTests(unittest.TestCase):
    def test_historical_scans_are_isolated_and_candidate_class_is_explicit(self):
        conn = _Connection(
            scans={15: _scan(15), 16: _scan(16)},
            datasets={(15, "assets"): [_asset_row(15, "fifteen.example")],
                      (16, "assets"): [_asset_row(16, "sixteen.example")]},
            optional_tables=(None, None),
        )
        reports = [build_scan_report(conn, scan_id) for scan_id in (15, 16)]
        try:
            decoded = []
            for report in reports:
                with zipfile.ZipFile(report) as archive:
                    summary = list(csv.DictReader(io.StringIO(
                        archive.read("scan-summary.csv").decode("utf-8")
                    )))[0]
                    assets = list(csv.DictReader(io.StringIO(
                        archive.read("assets.csv").decode("utf-8")
                    )))[0]
                    self.assertIn("brand-redirects.csv", archive.namelist())
                    self.assertEqual(
                        next(csv.reader(io.StringIO(archive.read("http.csv").decode("utf-8"))))[:12],
                        ["domain_id", "domain", "ip", "has_ip", "http_observation_status",
                         "http_status", "http_live", "http_reason", "final_url", "final_status",
                         "title", "reverse_dns"],
                    )
                    decoded.append((summary, assets))
            self.assertEqual([row[0]["scan_id"] for row in decoded], ["15", "16"])
            self.assertEqual([row[1]["domain"] for row in decoded],
                             ["fifteen.example", "sixteen.example"])
            self.assertEqual(decoded[0][1]["effective_asset_class_at_export"], "CANDIDATE")
            self.assertEqual(decoded[0][1]["scan_state_record_available"], "False")
            self.assertIn("brand_discovery_sources", decoded[0][1])
            self.assertIn("brand_discovery_seed_attributions_json", decoded[0][1])
            data_queries = [(query, params) for query, params in conn.queries
                            if "WITH membership AS" in query or "FROM domain_dns" in query]
            self.assertTrue(data_queries)
            self.assertTrue(all(params[0] in (15, 16) for _, params in data_queries))
            asset_sql, asset_params = next(
                (query, params) for query, params in conn.queries
                if "WITH membership AS" in query
            )
            self.assertIn("SELECT DISTINCT scan_id, domain_id, source, BTRIM(seed)", asset_sql)
            self.assertIn("GROUP BY scan_id, domain_id", asset_sql)
            self.assertEqual(asset_params, (15, 15, 15, 15, 15))
        finally:
            for report in reports:
                report.close()

    def test_unknown_scan_and_unfinalized_scan_are_rejected(self):
        with self.assertRaises(ScanReportNotFound):
            build_scan_report(_Connection(), 404)
        with self.assertRaises(ScanReportNotReady):
            build_scan_report(_Connection(scans={15: _scan(15, "FAILED")}), 15)
        with self.assertRaises(ScanReportNotReady):
            build_scan_report(_Connection(scans={15: _scan(15, completed=None)}), 15)
        with self.assertRaises(ScanReportNotReady):
            build_scan_report(_Connection(scans={15: _scan(15, members=0)}), 15)

    def test_no_observations_are_not_exported_as_successful_negative(self):
        conn = _Connection(scans={15: _scan(15)}, optional_tables=(None, None))
        report = build_scan_report(conn, 15)
        try:
            with zipfile.ZipFile(report) as archive:
                coverage = list(csv.DictReader(io.StringIO(
                    archive.read("coverage.csv").decode("utf-8")
                )))
                dns_rows = list(csv.reader(io.StringIO(
                    archive.read("dns.csv").decode("utf-8")
                )))
                summary = list(csv.DictReader(io.StringIO(
                    archive.read("scan-summary.csv").decode("utf-8")
                )))[0]
            self.assertEqual(len(dns_rows), 1)  # header only
            dns = next(row for row in coverage if row["evidence_category"] == "DNS")
            self.assertEqual(dns["availability"], "NO_PERSISTED_ROWS")
            self.assertIn("does not prove", dns["interpretation"])
            self.assertEqual(summary["stage_diagnostics_available"], "False")
        finally:
            report.close()

    def test_export_has_no_page_cap_and_csv_escaping_is_valid(self):
        dns_rows = [(1, "comma,quote\".example", "TXT", 'v=spf1; note="a,b"')
                    for _ in range(503)]
        conn = _Connection(scans={15: _scan(15)},
                           datasets={(15, "dns"): dns_rows},
                           optional_tables=(None, None))
        report = build_scan_report(conn, 15)
        try:
            with zipfile.ZipFile(report) as archive:
                rows = list(csv.DictReader(io.StringIO(
                    archive.read("dns.csv").decode("utf-8")
                )))
            self.assertEqual(len(rows), 503)
            self.assertEqual(rows[0]["domain"], 'comma,quote".example')
            self.assertEqual(rows[0]["value"], 'v=spf1; note="a,b"')
        finally:
            report.close()

    def test_text_cells_are_formula_safe_and_numeric_negatives_stay_numeric(self):
        from scan_report import _csv_value

        self.assertEqual(_csv_value("=1+1"), "'=1+1")
        self.assertEqual(_csv_value("  @SUM(A1:A2)"), "'  @SUM(A1:A2)")
        self.assertEqual(_csv_value("ordinary text"), "ordinary text")
        self.assertEqual(_csv_value(-12), -12)
        self.assertEqual(_csv_value(Decimal("-0.5")), Decimal("-0.5"))

        conn = _Connection(
            scans={15: _scan(15)},
            datasets={
                (15, "dns"): [(1, "dns.example", "TXT", "=1+1,\"quoted\" ☃")],
                (15, "http"): [(1, "web.example", None, None, None, None, None,
                                None, None, None, "-cmd|payload,\"title\" ☃", None)],
            },
            optional_tables=(None, None),
        )
        report = build_scan_report(conn, 15)
        try:
            with zipfile.ZipFile(report) as archive:
                dns = list(csv.DictReader(io.StringIO(
                    archive.read("dns.csv").decode("utf-8")
                )))
                http = list(csv.DictReader(io.StringIO(
                    archive.read("http.csv").decode("utf-8")
                )))
            self.assertEqual(dns[0]["value"], "'=1+1,\"quoted\" ☃")
            self.assertEqual(http[0]["title"], "'-cmd|payload,\"title\" ☃")
            self.assertEqual(dns[0]["domain"], "dns.example")
        finally:
            report.close()

    def test_legacy_http_final_url_is_not_promoted_to_verified_terminal(self):
        legacy_http = (1, "legacy.example", None, None, "RESPONDED", 302,
                       True, "Found", "https://historical.example/", 200,
                       "title", None, "https://first-hop.example/", None,
                       "UNKNOWN", "UNKNOWN", None)
        conn = _Connection(
            scans={15: _scan(15)}, datasets={(15, "http"): [legacy_http]},
            optional_tables=(None, None, "public.brand_redirect_observations"),
            brand_redirect_stats={15: (0, 0, 0, 0, 0)},
        )
        report = build_scan_report(conn, 15)
        try:
            with zipfile.ZipFile(report) as archive:
                row = next(csv.DictReader(io.StringIO(
                    archive.read("http.csv").decode("utf-8")
                )))
            self.assertEqual(row["final_url"], "https://historical.example/")
            self.assertEqual(row["first_hop_destination"], "https://first-hop.example/")
            self.assertEqual(row["terminal_destination"], "")
            self.assertEqual(row["terminal_verification_status"], "UNKNOWN")
        finally:
            report.close()

    def test_brand_observations_are_scan_scoped_and_exported_once(self):
        verified = (901, 15, "operation-15", "2026-11-10T03:00:00Z",
                    "lookalike.example", ["brand_pattern"],
                    [{"source": "brand_pattern", "seed": "example.com"}],
                    "RESPONDED", "COMPLETE", "VERIFIED", "https://first.example/",
                    "https://terminal.example/", "VERIFIED_REDIRECT_CHAIN", None,
                    {"observed_hops": [{"status": 302}]})
        incomplete = (902, 15, "operation-15", "2026-11-10T03:01:00Z",
                      "timeout.example", ["brand_tld"],
                      [{"source": "brand_tld", "seed": "example.com"}],
                      "NO_RESPONSE", "TIMEOUT", "UNVERIFIED", "https://first.example/", None,
                      "INCOMPLETE_OR_UNVERIFIED", "TIMEOUT", {"observed_hops": []})
        other_scan = (903, 16, "operation-16", "2026-11-10T04:00:00Z",
                      "other.example", [], [], "RESPONDED", "NO_REDIRECT", "VERIFIED", None,
                      "https://other.example/", "VERIFIED_NO_REDIRECT", None, {})
        conn = _Connection(
            scans={15: _scan(15, diagnostics=_diagnostics(
                "Brand Redirect Intelligence", 2, 2)), 16: _scan(16)},
            datasets={(15, "brand-redirects"): [verified, incomplete],
                      (16, "brand-redirects"): [other_scan]},
            optional_tables=(None, None, "public.brand_redirect_observations"),
            brand_redirect_stats={15: (2, 1, 1, 0, 1), 16: (1, 1, 0, 1, 0)},
        )
        report = build_scan_report(conn, 15)
        try:
            with zipfile.ZipFile(report) as archive:
                rows = list(csv.DictReader(io.StringIO(
                    archive.read("brand-redirects.csv").decode("utf-8")
                )))
                coverage = list(csv.DictReader(io.StringIO(
                    archive.read("coverage.csv").decode("utf-8")
                )))
            self.assertEqual([row["observation_id"] for row in rows], ["901", "902"])
            self.assertEqual(rows[0]["source_domain"], "lookalike.example")
            self.assertEqual(rows[0]["terminal_destination"], "https://terminal.example/")
            self.assertEqual(rows[0]["classification"], "VERIFIED_REDIRECT_CHAIN")
            self.assertEqual(rows[1]["terminal_destination"], "")
            self.assertEqual(rows[1]["failure_or_stop_reason"], "TIMEOUT")
            status = next(row for row in coverage
                          if row["evidence_category"] == "Brand Redirect Intelligence")
            self.assertEqual(status["availability"], "MIXED_VERIFIED_AND_INCOMPLETE")
            bri_queries = [query for query, params in conn.queries
                           if "brand_redirect_observations" in query]
            # One streaming observation query plus one aggregate coverage query; no N+1.
            self.assertEqual(len(bri_queries), 2)
            self.assertTrue(all(params[0] == 15 for query, params in conn.queries
                                if "brand_redirect_observations" in query))
        finally:
            report.close()

    def test_brand_zero_observation_states_are_not_misreported_as_clean(self):
        selected_zero = _diagnostics("Brand Redirect Intelligence", 0, 0)
        no_targets = _brand_redirect_coverage(
            selected_zero["attempts"], (0, 0, 0, 0, 0), True
        )
        self.assertEqual(no_targets[0], "NO_ELIGIBLE_TARGETS")
        self.assertIn("selected no current-scan eligible", no_targets[1])

        eligible_unassessed = _brand_redirect_coverage(
            _diagnostics("Brand Redirect Intelligence", 3, 0)["attempts"],
            (0, 0, 0, 0, 0), True,
        )
        self.assertEqual(eligible_unassessed[0], "ELIGIBLE_BUT_NOT_ASSESSED")

        no_redirects = _brand_redirect_coverage(
            _diagnostics("Brand Redirect Intelligence", 2, 2)["attempts"],
            (2, 2, 0, 2, 0), True,
        )
        self.assertEqual(no_redirects[0], "ASSESSED_WITH_NO_REDIRECT_FINDINGS")

        unknown_stage = _brand_redirect_coverage([], (0, 0, 0, 0, 0), True)
        self.assertEqual(unknown_stage[0], "STAGE_NOT_RECORDED")

        repeated_attempts = _brand_redirect_coverage(
            _diagnostics("Brand Redirect Intelligence", 1, 1)["attempts"] * 2,
            (1, 1, 0, 1, 0), True,
        )
        self.assertEqual(repeated_attempts[0], "MULTIPLE_STAGE_ATTEMPTS_EVIDENCE_AGGREGATED")

    def test_brand_export_formula_protects_text_and_preserves_existing_zip_members(self):
        hostile = (901, 15, "operation-15", "2026-11-10T03:00:00Z",
                   "=host.example", ["brand_pattern"],
                   [{"source": "brand_pattern", "seed": "@brand.example"}],
                   "TIMEOUT", "UNVERIFIED", None, None,
                   "INCOMPLETE_OR_UNVERIFIED", "TIMEOUT", {"evidence": "=1+1"})
        conn = _Connection(
            scans={15: _scan(15, diagnostics=_diagnostics(
                "Brand Redirect Intelligence", 1, 1))},
            datasets={(15, "brand-redirects"): [hostile]},
            optional_tables=(None, None, "public.brand_redirect_observations"),
            brand_redirect_stats={15: (1, 0, 0, 0, 1)},
        )
        report = build_scan_report(conn, 15)
        try:
            with zipfile.ZipFile(report) as archive:
                self.assertTrue({"scan-summary.csv", "assets.csv", "http.csv", "coverage.csv",
                                 "stage-attempts.csv", "brand-redirects.csv"}.issubset(
                                     set(archive.namelist())
                                 ))
                row = next(csv.DictReader(io.StringIO(
                    archive.read("brand-redirects.csv").decode("utf-8")
                )))
            self.assertEqual(row["source_domain"], "'=host.example")
            self.assertTrue(row["associated_seed_brand_json"].startswith("["))
        finally:
            report.close()

    def test_optional_evidence_table_absence_is_explicit(self):
        conn = _Connection(scans={15: _scan(15)}, optional_tables=(None, None))
        report = build_scan_report(conn, 15)
        try:
            with zipfile.ZipFile(report) as archive:
                coverage = list(csv.DictReader(io.StringIO(
                    archive.read("coverage.csv").decode("utf-8")
                )))
                self.assertEqual(archive.read("dns-security.csv").count(b"\n"), 1)
                self.assertEqual(archive.read("brand-redirects.csv").count(b"\n"), 1)
                dns_security = next(row for row in coverage
                                    if row["evidence_category"] == "DNS Security assessments")
                brand = next(row for row in coverage
                             if row["evidence_category"] == "Brand Redirect Intelligence")
            self.assertEqual(dns_security["availability"], "SCHEMA_UNAVAILABLE")
            self.assertEqual(brand["availability"], "SCHEMA_UNAVAILABLE")
        finally:
            report.close()


class AdhocCampaignExportTests(unittest.TestCase):
    def test_campaign_csv_identifies_execution_and_preserves_json_csv_fields(self):
        stream = io.StringIO(newline="")
        campaign = {
            "campaign_id": 27, "check_id": "php-rce", "source_scan_id": 15,
            "status": "SUCCEEDED", "assessment_date": "2026-11-10",
            "dataset_revision": "dataset-r1", "created_at": "created",
            "started_at": "started", "completed_at": "completed",
        }
        result = {
            "domain": "quoted,domain.example",
            "target_status": "COMPLETED", "execution_status": "COMPLETED",
            "evidence_status": "COLLECTED", "evaluation_status": "EVALUATED",
            "classification": "Potential CVE", "observations": [{"evidence": "a,b"}],
            "persisted_at": "persisted", "dataset_revision": "dataset-r1",
        }
        write_adhoc_campaign_csv(stream, campaign, [result])
        rows = list(csv.DictReader(io.StringIO(stream.getvalue())))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["campaign_id"], "27")
        self.assertEqual(rows[0]["source_scan_id"], "15")
        self.assertEqual(rows[0]["domain"], "quoted,domain.example")
        self.assertEqual(json.loads(rows[0]["observations_json"]), result["observations"])

    def test_export_route_requires_terminal_campaign(self):
        with mock.patch("logging.FileHandler", return_value=logging.NullHandler()):
            main = importlib.import_module("main")
        conn = mock.Mock()
        with mock.patch.object(main, "get_conn", return_value=conn), \
             mock.patch.object(main, "get_campaign", return_value={"status": "RUNNING"}):
            with self.assertRaises(main.HTTPException) as raised:
                main.export_adhoc_campaign(4)
        self.assertEqual(raised.exception.status_code, 409)
        conn.close.assert_called_once_with()

    def test_finalized_campaign_export_is_bound_to_campaign_and_scan(self):
        with mock.patch("logging.FileHandler", return_value=logging.NullHandler()):
            main = importlib.import_module("main")
        conn = mock.Mock()
        campaign = {
            "campaign_id": 27, "check_id": "php-rce", "source_scan_id": 15,
            "status": "SUCCEEDED", "assessment_date": "2026-11-10",
            "dataset_revision": "dataset-r1", "created_at": "created",
            "started_at": "started", "completed_at": "completed",
            "failure_code": None,
        }
        page = {"count": 1, "results": [{
            "domain": "target.example", "target_status": "COMPLETED",
            "execution_status": "COMPLETED", "evidence_status": "COLLECTED",
            "evaluation_status": "EVALUATED",
            "observations": [{"version": "8.2.0"}], "dataset_revision": "dataset-r1",
        }]}
        with mock.patch.object(main, "get_conn", return_value=conn), \
             mock.patch.object(main, "get_campaign", return_value=campaign), \
             mock.patch.object(main, "get_campaign_results", return_value=page) as results:
            response = main.export_adhoc_campaign(27)
        async def collect_body():
            return "".join([chunk async for chunk in response.body_iterator])

        body = asyncio.run(collect_body())
        rows = list(csv.DictReader(io.StringIO(body)))
        self.assertEqual(response.headers["content-disposition"],
                         'attachment; filename="asip_adhoc_campaign_27_report.csv"')
        self.assertEqual(rows[0]["campaign_id"], "27")
        self.assertEqual(rows[0]["source_scan_id"], "15")
        results.assert_called_once_with(conn, 27, page=1, limit=200)
        conn.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
