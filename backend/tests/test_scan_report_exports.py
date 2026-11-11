import csv
import asyncio
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
            self.one = self.connection.optional_tables
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
    }

    def __init__(self, scans=None, datasets=None, state_counts=None, optional_tables=None):
        self.scans = scans or {}
        self.datasets = datasets or {}
        self.state_counts = state_counts or {}
        self.optional_tables = optional_tables or (None, None)
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
            None, None)


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
                    decoded.append((summary, assets))
            self.assertEqual([row[0]["scan_id"] for row in decoded], ["15", "16"])
            self.assertEqual([row[1]["domain"] for row in decoded],
                             ["fifteen.example", "sixteen.example"])
            self.assertEqual(decoded[0][1]["effective_asset_class_at_export"], "CANDIDATE")
            self.assertEqual(decoded[0][1]["scan_state_record_available"], "False")
            data_queries = [(query, params) for query, params in conn.queries
                            if "WITH membership AS" in query or "FROM domain_dns" in query]
            self.assertTrue(data_queries)
            self.assertTrue(all(params[0] in (15, 16) for _, params in data_queries))
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

    def test_optional_evidence_table_absence_is_explicit(self):
        conn = _Connection(scans={15: _scan(15)}, optional_tables=(None, None))
        report = build_scan_report(conn, 15)
        try:
            with zipfile.ZipFile(report) as archive:
                coverage = list(csv.DictReader(io.StringIO(
                    archive.read("coverage.csv").decode("utf-8")
                )))
                self.assertEqual(archive.read("dns-security.csv").count(b"\n"), 1)
            dns_security = next(row for row in coverage
                                if row["evidence_category"] == "DNS Security assessments")
            self.assertEqual(dns_security["availability"], "SCHEMA_UNAVAILABLE")
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
