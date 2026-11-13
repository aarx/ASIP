import importlib
import ast
import json
import pathlib
import sys
import unittest
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
REPOSITORY = BACKEND.parent
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(BACKEND / "tests"))

import capd  # noqa: E402
from capd_authorization import recheck_apache_target_from_inventory  # noqa: E402
from capd_cli import main as capd_cli_main  # noqa: E402
from apache_version_evidence import parse_apache_server_header  # noqa: E402
from apache_version_verification import (  # noqa: E402
    APACHE_CHECK_ID, APACHE_CHECK_REVISION, create_authorization_context,
)
from authorization_policy import CAPD_HTTP_HEADER_VERIFY  # noqa: E402
_remediation_fixture = importlib.import_module("test_remediation_package_2d1c")


class CapdDefinitionTests(unittest.TestCase):
    def test_apache_preview_uses_separate_operation_without_changing_passive_capd(self):
        passive_exclusions = capd._eligibility_sql()[2]
        apache_exclusions = capd._eligibility_sql(CAPD_HTTP_HEADER_VERIFY)[2]
        self.assertIn("ADHOC_CHECK", passive_exclusions)
        self.assertNotIn("CAPD_HTTP_HEADER_VERIFY", passive_exclusions)
        self.assertIn("CAPD_HTTP_HEADER_VERIFY", apache_exclusions)
        self.assertNotIn("ADHOC_CHECK", apache_exclusions)

    def test_apache_header_parser_requires_specific_product_evidence(self):
        versioned = parse_apache_server_header("Apache/2.4.58 (Unix)")
        self.assertEqual(versioned["outcome"], "VERSION_IDENTIFIED")
        self.assertEqual(versioned["version"], "2.4.58")
        self.assertEqual(parse_apache_server_header("Apache")["outcome"],
                         "PRODUCT_IDENTIFIED_VERSION_UNKNOWN")
        self.assertEqual(parse_apache_server_header("Apache-Coyote/1.1")["outcome"],
                         "PRODUCT_NOT_CONFIRMED")
        self.assertEqual(parse_apache_server_header("nginx/1.25.0")["outcome"],
                         "PRODUCT_NOT_CONFIRMED")
        self.assertNotIn("secret-value", parse_apache_server_header(
            "nginx/1.25.0 token=secret-value")["evidence"])
        self.assertEqual(parse_apache_server_header(None)["outcome"],
                         "INSUFFICIENT_EVIDENCE")

    def test_versioned_php_checks_reconcile_with_existing_advisory_catalog(self):
        schema, checks = capd.load_checks()
        self.assertEqual(schema, 1)
        self.assertEqual(set(checks), {"CVE-2026-109618", "CVE-2026-109619"})
        for check in checks.values():
            self.assertEqual(check["version_scheme"], "php_semver3")
            self.assertEqual(check["verification_method"], "PASSIVE_VERSION_RANGE_MATCH")
            self.assertTrue(check["enabled"])
            self.assertTrue(check["advisory_reference"].startswith("https://"))
            self.assertNotIn("command", check)
            self.assertNotIn("probe", check)
        expected = {
            item.cve_id: sorted((rng.branch, rng.fixed_version) for rng in item.affected_ranges)
            for item in capd.PHP_CVE_ADVISORIES
        }
        actual = {
            item["cve_id"]: sorted((rng["branch"], rng["fixed"]) for rng in item["affected_ranges"])
            for item in checks.values()
        }
        self.assertEqual(actual, expected)

    def test_invalid_comparison_scheme_and_generic_service_alias_are_rejected(self):
        with pathlib.Path(capd.CHECKS_PATH).open(encoding="utf-8") as handle:
            payload = json.load(handle)
        payload["checks"][0]["version_scheme"] = "shell"
        with self._temporary_catalog(payload) as path, mock.patch.object(capd, "CHECKS_PATH", path):
            with self.assertRaises(capd.CapdError):
                capd.load_checks()
        payload["checks"][0]["version_scheme"] = "php_semver3"
        payload["checks"][0]["service_aliases"] = ["https"]
        with self._temporary_catalog(payload) as path, mock.patch.object(capd, "CHECKS_PATH", path):
            with self.assertRaises(capd.CapdError):
                capd.load_checks()
        payload["checks"][0].pop("service_aliases")
        payload["checks"][0]["command"] = "unsafe"
        with self._temporary_catalog(payload) as path, mock.patch.object(capd, "CHECKS_PATH", path):
            with self.assertRaises(capd.CapdError):
                capd.load_checks()

    @staticmethod
    def _temporary_catalog(payload):
        import tempfile
        from contextlib import contextmanager

        @contextmanager
        def temporary():
            with tempfile.TemporaryDirectory() as directory:
                path = pathlib.Path(directory) / "checks.json"
                path.write_text(json.dumps(payload), encoding="utf-8")
                yield path
        return temporary()

    def test_php_version_range_boundaries(self):
        check = capd.get_check("CVE-2026-109618")
        self.assertEqual(capd._version_candidate(check, "8.2.34")[:2], ("POTENTIAL_MATCH", "VERSION_MATCHED"))
        self.assertEqual(capd._version_candidate(check, "8.2.35")[:2], ("NOT_APPLICABLE", "NOT_APPLICABLE"))
        self.assertEqual(capd._version_candidate(check, "8.6.0")[:2], ("INSUFFICIENT_EVIDENCE", "INSUFFICIENT_EVIDENCE"))
        self.assertEqual(capd._version_candidate(check, "8.2")[:2], ("INSUFFICIENT_EVIDENCE", "INSUFFICIENT_EVIDENCE"))
        self.assertEqual(capd._version_candidate(check, None)[:2], ("INSUFFICIENT_EVIDENCE", "INSUFFICIENT_EVIDENCE"))

    def test_result_classification_distinguishes_unknown_product_version_and_no_evidence(self):
        check = capd.get_check("CVE-2026-109618")
        target = {"domain_id": 10, "domain": "host.example", "asset_class": "KNOWN"}
        unknown = capd._assess_asset(check, target, [{
            "source": "domain_technology_observations", "technology": "php",
            "version": None, "confidence": "medium", "evidence_type": "server_header",
        }])[0]
        self.assertEqual(unknown["candidate_classification"], "PRODUCT_MATCHED_VERSION_UNKNOWN")
        self.assertEqual(unknown["result_status"], "INSUFFICIENT_EVIDENCE")
        absent = capd._assess_asset(check, target, [])[0]
        self.assertEqual(absent["result_status"], "INSUFFICIENT_EVIDENCE")
        self.assertIn("not evidence", absent["limitations"][-1])
        legacy = capd._assess_asset(check, target, [{
            "source": "domain_tech", "technology": "php", "version": None,
            "confidence": "none", "evidence_type": "legacy_label",
        }])[0]
        self.assertEqual(legacy["candidate_classification"], "PRODUCT_MATCHED_VERSION_UNKNOWN")

    def test_stored_service_evidence_is_candidate_not_product_identification(self):
        check = dict(capd.get_check("CVE-2026-109618"))
        check["service_aliases"] = ["php-fpm"]
        target = {"domain_id": 10, "domain": "host.example", "asset_class": "KNOWN"}
        result = capd._assess_asset(check, target, [{
            "source": "domain_ports", "service": "php-fpm", "port": 9000,
            "technology": None, "version": None, "confidence": "low",
        }])[0]
        self.assertEqual(result["candidate_classification"], "SERVICE_CANDIDATE")
        self.assertEqual(result["result_status"], "INSUFFICIENT_EVIDENCE")

    def test_duplicate_observations_preserve_evidence_without_duplicate_results(self):
        check = capd.get_check("CVE-2026-109618")
        target = {"domain_id": 10, "domain": "host.example", "asset_class": "KNOWN"}
        evidence = {
            "source": "domain_technology_observations", "technology": "php",
            "version": "8.2.34", "confidence": "medium", "evidence_type": "server_header",
            "observed_url": "https://host.example", "evidence": "PHP/8.2.34",
        }
        records = [{**evidence, "persisted_at": "2026-11-01T00:00:00+00:00"},
                   {**evidence, "persisted_at": "2026-11-02T00:00:00+00:00"}]
        results = capd._assess_asset(check, target, records)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["result_status"], "POTENTIAL_MATCH")
        self.assertEqual(len(results[0]["evidence"]), 2)

    def test_cli_rejects_active_mode_and_checks_listing_needs_no_database(self):
        with mock.patch("capd_cli.get_conn", side_effect=AssertionError("DB should not be opened")):
            self.assertEqual(capd_cli_main(["checks", "list"]), 0)
            self.assertEqual(capd_cli_main(["run", "--check", "CVE-2026-109618", "--mode", "active"]), 2)

    def test_no_http_or_socket_execution_is_present_in_passive_module(self):
        tree = ast.parse((BACKEND / "capd.py").read_text(encoding="utf-8"))
        imports = {
            alias.name.split(".")[0]
            for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertFalse(imports & {"requests", "socket", "subprocess"})

    def test_only_get_capd_routes_are_declared(self):
        source = (BACKEND / "main.py").read_text(encoding="utf-8")
        self.assertIn('@app.get("/v2/capd/checks")', source)
        self.assertIn('@app.get("/v2/capd/runs")', source)
        self.assertIn('@app.get("/v2/capd/runs/{run_id}/results")', source)
        self.assertNotIn('@app.post("/v2/capd', source)


class CapdPostgreSQLTests(unittest.TestCase):
    """Exercise CAPD migration and isolated write path on disposable PostgreSQL."""

    @classmethod
    def setUpClass(cls):
        _remediation_fixture.PostgreSQLIngestConvergenceTests.setUpClass.__func__(cls)
        connection = cls.connect()
        try:
            with connection:
                with connection.cursor() as cursor:
                    cursor.execute("ALTER TABLE scans ADD COLUMN completed_at timestamptz")
                    cursor.execute("ALTER TABLE domains ALTER COLUMN ownership_status DROP NOT NULL")
                    cursor.execute("""
                        CREATE TABLE active_scan_scopes (
                            scope_domain text, include_subdomains boolean,
                            testing_level text, status text, expires_at timestamptz,
                            excluded_domains text[] DEFAULT ARRAY[]::text[]
                        )
                    """)
                    cursor.execute("ALTER TABLE domain_ports ADD COLUMN service text")
                    cursor.execute(
                        (REPOSITORY / "backend/migrations/015_add_capd_runs.sql")
                        .read_text(encoding="utf-8")
                    )
                    cursor.execute("INSERT INTO seed_domains(domain) VALUES ('org.example')")
                    cursor.execute("INSERT INTO known_domains(domain) VALUES ('known.example')")
                    cursor.execute("INSERT INTO known_domains(domain) VALUES ('nullable.example')")
        except Exception:
            _remediation_fixture.PostgreSQLIngestConvergenceTests.tearDownClass.__func__(cls)
            raise
        finally:
            connection.close()

    @classmethod
    def tearDownClass(cls):
        _remediation_fixture.PostgreSQLIngestConvergenceTests.tearDownClass.__func__(cls)

    @classmethod
    def connect(cls):
        return cls.psycopg2.connect(**cls.connection_args)

    def setUp(self):
        connection = self.connect()
        with connection:
            with connection.cursor() as cursor:
                cursor.execute("DELETE FROM known_domains")
                cursor.execute("DELETE FROM seed_domains")
                cursor.execute("INSERT INTO seed_domains(domain) VALUES ('org.example')")
                cursor.execute("INSERT INTO known_domains(domain) VALUES ('known.example')")
                cursor.execute("INSERT INTO known_domains(domain) VALUES ('nullable.example')")
                cursor.execute("TRUNCATE capd_results, capd_runs RESTART IDENTITY")
                cursor.execute("DELETE FROM scan_results")
                cursor.execute("DELETE FROM domain_technology_observations")
                cursor.execute("DELETE FROM domain_tech")
                cursor.execute("DELETE FROM domains")
                cursor.execute("DELETE FROM scans")
                cursor.execute("INSERT INTO scans(id,status,completed_at) VALUES (19,'SUCCEEDED',CURRENT_TIMESTAMP),(20,'FAILED',CURRENT_TIMESTAMP)")
                cursor.execute("""
                    INSERT INTO domains(id,domain,ownership_status,scannable,validation_source,confidence_reasons)
                    VALUES
                      (701,'known.example','CONFIRMED',TRUE,'manual',ARRAY[]::text[]),
                      (702,'app.org.example','CONFIRMED',TRUE,'discovery',ARRAY[]::text[]),
                      (703,'candidate.other','CONFIRMED',TRUE,'discovery',ARRAY[]::text[]),
                      (704,'offline.org.example','CONFIRMED',FALSE,'discovery',ARRAY[]::text[]),
                      (705,'rejected.org.example','CONFIRMED',TRUE,'discovery',ARRAY['manually rejected']),
                      (706,'fixed.known.example','CONFIRMED',TRUE,'manual',ARRAY[]::text[]),
                      (707,'external.org.example','EXTERNAL',TRUE,'discovery',ARRAY[]::text[]),
                      (708,'nullable.example',NULL,TRUE,'manual',ARRAY[]::text[]),
                      (709,'no-evidence.org.example','CONFIRMED',TRUE,'discovery',ARRAY[]::text[])
                """)
                cursor.execute("INSERT INTO known_domains(domain) VALUES ('fixed.known.example')")
                cursor.execute("INSERT INTO scan_results(scan_id,domain_id,seed) VALUES (19,701,'known.example'),(19,702,'org.example'),(19,703,'org.example'),(19,704,'org.example'),(19,705,'org.example'),(19,706,'fixed.known.example'),(19,707,'org.example'),(19,708,'nullable.example'),(19,709,'org.example'),(20,701,'known.example')")
                cursor.execute("""
                    INSERT INTO domain_technology_observations(
                        scan_id,domain_id,technology,version,confidence,evidence_type,
                        sanitized_evidence,observed_url,detector_version
                    ) VALUES
                      (19,701,'php','8.2.34','high','server_header','PHP/8.2.34','https://known.example','fixture'),
                      (19,702,'php',NULL,'medium','server_header','marker=php','https://app.org.example','fixture'),
                      (19,703,'php','8.2.34','high','server_header','PHP/8.2.34','https://candidate.other','fixture'),
                      (19,706,'php','8.2.35','high','x-powered-by_header','PHP/8.2.35','https://fixed.known.example','fixture')
                """)
                cursor.execute("INSERT INTO domain_tech(scan_id,domain_id,tech) VALUES (19,701,'php'),(19,702,'php'),(19,703,'php'),(19,706,'php')")
        connection.close()

    def test_migration_creates_separate_persistence_without_scan_mutation(self):
        rows = self.fetchall("SELECT id,status FROM scans ORDER BY id")
        self.assertEqual(rows, [(19, "SUCCEEDED"), (20, "FAILED")])
        self.assertEqual(self.fetchall("SELECT COUNT(*) FROM capd_runs"), [(0,)])
        self.assertEqual(self.fetchall("SELECT COUNT(*) FROM capd_results"), [(0,)])
        self.assertEqual(self.fetchall("SELECT to_regclass('public.tracked_security_issues')"), [(None,)])

    def test_preview_separates_eligible_inventory_from_relevant_candidates(self):
        connection = self.connect()
        try:
            preview = capd.preview_targets(connection, "CVE-2026-109618", scan_id=19)
            self.assertEqual(preview["selection"]["eligible_targets"], 4)
            self.assertEqual(preview["relevance"]["eligible_inventory_assets"], 4)
            self.assertEqual(preview["relevance"]["product_matched_candidate_assets"], 3)
            self.assertEqual(preview["relevance"]["version_matched_candidate_assets"], 1)
            self.assertEqual(preview["relevance"]["potential_cve_match_assets"], 1)
            self.assertEqual(preview["relevance"]["assets_without_relevant_product_or_service_evidence"], 1)
            self.assertEqual(
                next(item for item in preview["targets"] if item["domain_id"] == 709)["relevance"],
                "NO_RELEVANT_PRODUCT_OR_SERVICE_EVIDENCE",
            )
        finally:
            connection.close()

    def test_zero_php_evidence_remains_eligible_but_is_not_a_php_candidate(self):
        connection = self.connect()
        with connection:
            with connection.cursor() as cursor:
                cursor.execute("DELETE FROM domain_technology_observations")
                cursor.execute("DELETE FROM domain_tech")
        connection.close()
        connection = self.connect()
        try:
            preview = capd.preview_targets(connection, "CVE-2026-109618", scan_id=19)
            self.assertEqual(preview["selection"]["eligible_targets"], 4)
            self.assertEqual(preview["relevance"]["product_matched_candidate_assets"], 0)
            self.assertEqual(preview["relevance"]["service_candidate_assets"], 0)
            self.assertEqual(preview["relevance"]["potential_cve_match_assets"], 0)
            self.assertEqual(preview["relevance"]["assets_without_relevant_product_or_service_evidence"], 4)
        finally:
            connection.close()

    def test_apache_product_preview_separates_versioned_unknown_and_service_only(self):
        connection = self.connect()
        with connection:
            with connection.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO domain_technology_observations(
                        scan_id,domain_id,technology,version,confidence,evidence_type,
                        sanitized_evidence,observed_url,detector_version
                    ) VALUES
                      (19,701,'apache','2.4.58','high','server_header','apache/2.4.58','https://known.example','fixture'),
                      (19,702,'apache',NULL,'medium','server_header','marker=apache','https://app.org.example','fixture'),
                      (19,703,'apache','2.4.58','high','server_header','apache/2.4.58','https://candidate.other','fixture'),
                      (19,707,'apache','2.4.58','high','server_header','apache/2.4.58','https://external.org.example','fixture')
                """)
                cursor.execute("INSERT INTO domain_ports(domain_id,scan_id,port,service) VALUES (706,19,8080,'httpd'),(704,19,443,'httpd'),(709,19,443,'https')")
        connection.close()
        connection = self.connect()
        try:
            preview = capd.preview_product_targets(connection, "apache", scan_id=19)
            populations = preview["populations"]
            counts = populations["selected_candidate_counts"]
            self.assertEqual(populations["eligible_inventory_total"], 4)
            self.assertEqual(populations["selected_inventory_total"], 4)
            self.assertEqual(populations["candidate_counts_scope"], "SELECTED_INVENTORY")
            self.assertTrue(populations["candidate_counts_complete"])
            self.assertFalse(populations["truncated"])
            self.assertEqual(counts["product_matched_candidates"], 2)
            self.assertEqual(counts["version_known_candidates"], 1)
            self.assertEqual(counts["version_unknown_candidates"], 1)
            self.assertEqual(counts["service_only_candidates"], 1)
            self.assertEqual(counts["insufficient_evidence"], 1)
            self.assertEqual({row["classification"] for row in preview["targets"]},
                             {"VERSION_KNOWN", "VERSION_UNKNOWN", "SERVICE_ONLY_CANDIDATE"})
            self.assertTrue(all(row["scannable"] and row["inventory_eligible"]
                                for row in preview["targets"]))
            self.assertFalse(preview["version_verification_preview"]["enabled"])
            self.assertEqual(preview["version_verification_preview"]["network_requests"], 0)
            self.assertEqual(preview["version_verification_preview"]["database_writes"], 0)
            self.assertNotIn("candidate.other", {row["domain"] for row in preview["targets"]})
            self.assertNotIn("external.org.example", {row["domain"] for row in preview["targets"]})
            connection.close()
            connection = self.connect()
            limited = capd.preview_product_targets(connection, "apache", scan_id=19, limit=1)
            self.assertEqual(limited["populations"]["eligible_inventory_total"], 4)
            self.assertEqual(limited["populations"]["selected_inventory_total"], 1)
            self.assertTrue(limited["populations"]["truncated"])
            self.assertFalse(limited["populations"]["candidate_counts_complete"])
            self.assertEqual(limited["populations"]["candidate_counts_scope"], "SELECTED_INVENTORY")
            self.assertEqual(limited["populations"]["selected_candidate_counts"]["product_matched_candidates"], 1)
        finally:
            connection.close()

    def test_independent_apache_authorization_rechecks_completed_scan_membership(self):
        observed_url = "https://known.example/"
        connection = self.connect()
        with connection:
            with connection.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO domain_technology_observations(
                        scan_id,domain_id,technology,version,confidence,evidence_type,
                        sanitized_evidence,observed_url,detector_version
                    ) VALUES (19,701,'apache',NULL,'medium','server_header',
                              'marker=apache',%s,'fixture')
                """, (observed_url,))
        connection.close()

        from datetime import datetime, timezone
        now = datetime(2026, 11, 13, tzinfo=timezone.utc)
        context = create_authorization_context(APACHE_CHECK_ID, APACHE_CHECK_REVISION, 19, now=now)
        selected = {
            "domain_id": 701, "domain": "known.example", "asset_class": "KNOWN",
            "scannable": True, "inventory_eligible": True,
            "classification": "VERSION_UNKNOWN", "source_scan_id": 19,
            "evidence": [{
                "source": "domain_technology_observations", "technology": "apache",
                "evidence_type": "server_header", "observed_url": observed_url,
            }],
        }

        with mock.patch.dict("os.environ", {"ASIP_DEFAULT_SCAN_OPERATIONS": "CAPD_HTTP_HEADER_VERIFY"}):
            connection = self.connect()
            try:
                allowed = recheck_apache_target_from_inventory(
                    connection.cursor(), context, selected, now=now
                )
                self.assertTrue(allowed["inventory_policy_passed"])
                self.assertEqual(allowed["source_scan_id"], 19)
                self.assertEqual(allowed["operation"], "CAPD_HTTP_HEADER_VERIFY")
            finally:
                connection.close()

            connection = self.connect()
            with connection:
                with connection.cursor() as cursor:
                    cursor.execute("UPDATE domains SET scannable=FALSE WHERE id=701")
            connection.close()
            connection = self.connect()
            try:
                denied = recheck_apache_target_from_inventory(
                    connection.cursor(), context, selected, now=now
                )
                self.assertFalse(denied["inventory_policy_passed"])
                self.assertIn("TARGET_NOT_SCANNABLE", denied["reason_codes"])
            finally:
                connection.close()

            connection = self.connect()
            with connection:
                with connection.cursor() as cursor:
                    cursor.execute("UPDATE domains SET scannable=TRUE WHERE id=701")
                    cursor.execute(
                        "UPDATE domain_technology_observations SET observed_url=%s WHERE scan_id=19 AND domain_id=701 AND technology='apache'",
                        ("https://other.example/",),
                    )
            connection.close()
            connection = self.connect()
            try:
                stale = recheck_apache_target_from_inventory(
                    connection.cursor(), context, selected, now=now
                )
                self.assertFalse(stale["inventory_policy_passed"])
                self.assertIn("APACHE_SERVICE_EVIDENCE_MISSING_OR_STALE", stale["reason_codes"])
            finally:
                connection.close()

        with mock.patch.dict("os.environ", {}, clear=True):
            connection = self.connect()
            try:
                denied = recheck_apache_target_from_inventory(
                    connection.cursor(), context, selected, now=now
                )
                self.assertFalse(denied["inventory_policy_passed"])
                self.assertIn("CAPD_HTTP_HEADER_VERIFY_OPERATION_DISABLED", denied["reason_codes"])
            finally:
                connection.close()

    def test_unknown_ownership_is_not_counted_as_eligible(self):
        connection = self.connect()
        try:
            summary = capd._eligibility_summary(connection.cursor(), 19)
            self.assertEqual(summary["eligible_targets"], 4)
            self.assertEqual(summary["skipped_by_reason"]["OWNERSHIP_NOT_CONFIRMED"], 1)
            self.assertEqual(sum(summary["skipped_by_reason"].values()), summary["excluded_or_ineligible"])
        finally:
            connection.close()

    def test_dry_run_is_read_only_and_selection_is_revalidated_on_execution(self):
        connection = self.connect()
        try:
            preview = capd.execute_passive(connection, "CVE-2026-109618", scan_id=19, limit=100, dry_run=True)
            self.assertEqual(preview["selection"]["eligible_targets"], 4)
            self.assertEqual(preview["selection"]["selected_targets"], 4)
            self.assertEqual(preview["network_requests"], 0)
            self.assertEqual(self.fetchall("SELECT COUNT(*) FROM capd_runs"), [(0,)])
        finally:
            connection.close()
        connection = self.connect()
        with connection:
            with connection.cursor() as cursor:
                cursor.execute("UPDATE domains SET scannable=FALSE WHERE id=702")
        connection.close()
        connection = self.connect()
        try:
            result = capd.execute_passive(connection, "CVE-2026-109618", scan_id=19, limit=100)
            self.assertEqual(result["selection"]["selected_targets"], 3)
            self.assertEqual(result["selection"]["eligible_targets"], 3)
            self.assertEqual(result["network_requests"], 0)
        finally:
            connection.close()

    def test_passive_run_persists_statuses_without_candidate_or_external_leakage(self):
        connection = self.connect()
        try:
            result = capd.execute_passive(connection, "CVE-2026-109618", scan_id=19, limit=100)
            self.assertEqual(result["status"], "SUCCEEDED")
            self.assertEqual(result["selection"]["selected_targets"], 4)
            self.assertEqual(result["counts"]["POTENTIAL_MATCH"], 1)
            self.assertEqual(result["counts"]["NOT_APPLICABLE"], 1)
            self.assertEqual(result["counts"]["INSUFFICIENT_EVIDENCE"], 2)
            results = capd.list_results(connection, result["run_id"], limit=20)
            self.assertEqual(results["total"], 4)
            self.assertEqual({item["asset_class"] for item in results["results"]}, {"KNOWN", "SHADOW"})
            self.assertNotIn("candidate.other", {item["domain"] for item in results["results"]})
            self.assertNotIn("external.org.example", {item["domain"] for item in results["results"]})
            self.assertEqual(capd.get_run(connection, result["run_id"])["status"], "SUCCEEDED")
            self.assertEqual(capd.list_runs(connection, check_id="CVE-2026-109618")["total"], 1)
            filtered = capd.list_results(connection, result["run_id"], result_status="POTENTIAL_MATCH")
            self.assertEqual(filtered["total"], 1)
            stored = capd.get_run(connection, result["run_id"])
            self.assertEqual(stored["check"]["check_revision"], "1.0.0")
            self.assertEqual(stored["check"]["affected_ranges"][0]["fixed"], "8.2.35")
            second = capd.execute_passive(connection, "CVE-2026-109618", scan_id=19, limit=100)
            self.assertNotEqual(second["run_id"], result["run_id"])
            self.assertEqual(capd.list_runs(connection, check_id="CVE-2026-109618")["total"], 2)
            self.assertEqual(capd.list_results(connection, result["run_id"])["total"], 4)
            self.assertEqual(capd.list_results(connection, second["run_id"])["total"], 4)
        finally:
            connection.close()

    def test_forced_target_error_is_saved_with_valid_json_and_run_is_partial(self):
        original = capd._assess_asset

        def forced(target_check, target, records):
            if target["domain_id"] == 702:
                raise RuntimeError("secret-token-must-not-be-persisted")
            return original(target_check, target, records)

        connection = self.connect()
        try:
            with mock.patch.object(capd, "_assess_asset", side_effect=forced):
                run = capd.execute_passive(connection, "CVE-2026-109618", scan_id=19)
            self.assertEqual(run["status"], "PARTIAL")
            self.assertEqual(run["counts"]["ERROR"], 1)
            result = self.fetchall(
                "SELECT result_status,evidence,limitations,explanation FROM capd_results WHERE run_id=%s AND domain_id=702",
                (run["run_id"],),
            )[0]
            self.assertEqual(result[0], "ERROR")
            self.assertEqual(result[1], [])
            self.assertEqual(result[2], ["Target evidence evaluation failed."])
            self.assertNotIn("secret-token", result[3])
            self.assertEqual(self.fetchall("SELECT COUNT(*) FROM capd_results WHERE run_id=%s", (run["run_id"],)), [(4,)])
        finally:
            connection.close()

    def test_unrecoverable_evidence_load_failure_marks_run_failed(self):
        connection = self.connect()
        try:
            with mock.patch.object(capd, "_load_evidence", side_effect=RuntimeError("fixture failure")):
                with self.assertRaisesRegex(RuntimeError, "fixture failure"):
                    capd.execute_passive(connection, "CVE-2026-109618", scan_id=19)
            self.assertEqual(self.fetchall("SELECT status FROM capd_runs"), [("FAILED",)])
            self.assertEqual(self.fetchall("SELECT COUNT(*) FROM capd_results"), [(0,)])
        finally:
            connection.close()

    def test_failed_scan_and_invalid_run_ids_are_rejected(self):
        connection = self.connect()
        try:
            with self.assertRaises(capd.CapdError):
                capd.preview_targets(connection, "CVE-2026-109618", scan_id=20)
            with self.assertRaises(capd.CapdError):
                capd.get_run(connection, "not-a-uuid")
        finally:
            connection.close()

    def fetchall(self, query, params=()):
        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute(query, params)
                return cursor.fetchall()
        finally:
            connection.close()
