import importlib
import pathlib
import sys
import tempfile
import unittest
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(BACKEND / "tests"))

import optional_migrations  # noqa: E402
_fixture = importlib.import_module("test_remediation_package_2d1c")


class OptionalMigrationPostgreSQLTests(unittest.TestCase):
    """Ledger and optional DDL behavior against disposable PostgreSQL."""

    @classmethod
    def setUpClass(cls):
        _fixture.PostgreSQLIngestConvergenceTests.setUpClass.__func__(cls)
        connection = cls.connect()
        with connection:
            with connection.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO scans(id, status) VALUES (919, 'SUCCEEDED')
                    ON CONFLICT (id) DO NOTHING;
                    INSERT INTO domains(id, domain) VALUES (9919, 'migration-fixture.example')
                    ON CONFLICT (id) DO NOTHING
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS active_scan_scopes (
                        testing_level text
                    );
                    ALTER TABLE active_scan_scopes
                        DROP CONSTRAINT IF EXISTS active_scan_scopes_testing_level;
                    ALTER TABLE active_scan_scopes
                        ADD CONSTRAINT active_scan_scopes_testing_level
                        CHECK (testing_level IN (
                            'TECHNOLOGY_HTTP', 'PORT_SCAN', 'ADHOC_CHECK',
                            'HTTP_TLS_OBSERVATION', 'DNS_SECURITY', 'ASN_METADATA'
                        ))
                """)
        connection.close()

    @classmethod
    def tearDownClass(cls):
        _fixture.PostgreSQLIngestConvergenceTests.tearDownClass.__func__(cls)

    @classmethod
    def connect(cls):
        return cls.psycopg2.connect(**cls.connection_args)

    @staticmethod
    def _apply_015(connection):
        migration = optional_migrations.load_migration("015_add_capd_runs")
        return optional_migrations.apply(
            connection, "015_add_capd_runs", approval_checksum=migration.checksum
        )

    def setUp(self):
        connection = self.connect()
        with connection:
            with connection.cursor() as cursor:
                cursor.execute("""
                    DROP TABLE IF EXISTS public.capd_results,
                        public.capd_runs, public.capd_approval_consumptions,
                        public.brand_redirect_observations,
                        public.asip_optional_migration_ledger CASCADE
                """)
                cursor.execute("""
                    ALTER TABLE public.active_scan_scopes
                        DROP CONSTRAINT IF EXISTS active_scan_scopes_testing_level;
                    ALTER TABLE public.active_scan_scopes
                        DROP CONSTRAINT IF EXISTS active_scan_scopes_brand_campaign_policy;
                    ALTER TABLE public.active_scan_scopes
                        DROP COLUMN IF EXISTS monitoring_purpose,
                        DROP COLUMN IF EXISTS eligible_discovery_sources,
                        DROP COLUMN IF EXISTS max_requests_per_scan;
                    ALTER TABLE public.active_scan_scopes
                        ADD CONSTRAINT active_scan_scopes_testing_level
                        CHECK (testing_level IN (
                            'TECHNOLOGY_HTTP', 'PORT_SCAN', 'ADHOC_CHECK',
                            'HTTP_TLS_OBSERVATION', 'DNS_SECURITY', 'ASN_METADATA'
                        ))
                """)
        connection.close()

    def test_plan_is_read_only_and_reports_pending_checksum(self):
        connection = self.connect()
        result = optional_migrations.plan(connection, "015_add_capd_runs")
        self.assertEqual(result["state"], "PENDING")
        self.assertEqual(len(result["sha256"]), 64)
        self.assertFalse(result["ledger_present"])
        connection.rollback()
        with connection.cursor() as cursor:
            cursor.execute("SELECT to_regclass('public.asip_optional_migration_ledger')")
            self.assertIsNone(cursor.fetchone()[0])
        connection.close()

    def test_apply_015_without_014_is_atomic_and_preserves_existing_rows(self):
        connection = self.connect()
        with connection.cursor() as cursor:
            cursor.execute("SELECT count(*) FROM scans")
            scans_before = cursor.fetchone()[0]
            cursor.execute("SELECT count(*) FROM domains")
            domains_before = cursor.fetchone()[0]
        result = self._apply_015(connection)
        self.assertEqual(result["state"], "APPLIED")
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT to_regclass('public.capd_runs'),
                       to_regclass('public.capd_results'),
                       to_regclass('public.tracked_security_issues'),
                       to_regclass('public.tracked_security_issue_history')
            """)
            capd_runs, capd_results, lifecycle, lifecycle_history = cursor.fetchone()
            self.assertIsNotNone(capd_runs)
            self.assertIsNotNone(capd_results)
            self.assertIsNone(lifecycle)
            self.assertIsNone(lifecycle_history)
            cursor.execute("""
                SELECT migration_id, sha256, source_file, applied_at
                FROM public.asip_optional_migration_ledger
            """)
            rows = cursor.fetchall()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0][0], "015_add_capd_runs")
            self.assertEqual(rows[0][1], result["sha256"])
            self.assertEqual(rows[0][2], "015_add_capd_runs.sql")
            self.assertIsNotNone(rows[0][3])
            cursor.execute("SELECT count(*) FROM scans")
            self.assertEqual(cursor.fetchone()[0], scans_before)
            cursor.execute("SELECT count(*) FROM domains")
            self.assertEqual(cursor.fetchone()[0], domains_before)
        connection.close()

    def test_duplicate_application_and_changed_checksum_are_rejected(self):
        connection = self.connect()
        self._apply_015(connection)
        with self.assertRaisesRegex(optional_migrations.OptionalMigrationError,
                                   "already applied"):
            self._apply_015(connection)

        original = optional_migrations.OPTIONAL_MIGRATIONS
        with tempfile.TemporaryDirectory() as directory:
            changed_path = pathlib.Path(directory) / "015_add_capd_runs.sql"
            source = original["015_add_capd_runs"].read_text(encoding="utf-8")
            changed_path.write_text(source.replace("CREATE TABLE public.capd_runs", 
                                                   "-- changed checksum\nCREATE TABLE public.capd_runs", 1),
                                    encoding="utf-8")
            with mock.patch.dict(optional_migrations.OPTIONAL_MIGRATIONS,
                                 {"015_add_capd_runs": changed_path}):
                with self.assertRaisesRegex(optional_migrations.OptionalMigrationError,
                                            "Checksum mismatch"):
                    optional_migrations.plan(connection, "015_add_capd_runs")
        connection.close()

    def test_failed_sql_rolls_back_ddl_and_receipt(self):
        connection = self.connect()
        with tempfile.TemporaryDirectory() as directory:
            broken_path = pathlib.Path(directory) / "015_add_capd_runs.sql"
            broken_path.write_text(
                "BEGIN; CREATE TABLE public.capd_partial(id integer); "
                "SELECT definitely_not_valid_sql; COMMIT;",
                encoding="utf-8",
            )
            with mock.patch.dict(optional_migrations.OPTIONAL_MIGRATIONS,
                                 {"015_add_capd_runs": broken_path}):
                with self.assertRaises(self.psycopg2.Error):
                    optional_migrations.apply(
                        connection, "015_add_capd_runs",
                        approval_checksum=optional_migrations.load_migration(
                            "015_add_capd_runs"
                        ).checksum,
                    )
        with connection.cursor() as cursor:
            cursor.execute("SELECT to_regclass('public.capd_partial')")
            self.assertIsNone(cursor.fetchone()[0])
            cursor.execute("SELECT to_regclass('public.asip_optional_migration_ledger')")
            self.assertIsNone(cursor.fetchone()[0])
        connection.close()

    def test_approval_is_required_and_no_legacy_receipts_are_fabricated(self):
        connection = self.connect()
        with self.assertRaisesRegex(optional_migrations.OptionalMigrationError,
                                   "exact SHA-256"):
            optional_migrations.apply(
                connection, "015_add_capd_runs", approval_checksum="unreviewed"
            )
        self._apply_015(connection)
        with connection.cursor() as cursor:
            cursor.execute("SELECT migration_id FROM public.asip_optional_migration_ledger")
            self.assertEqual(cursor.fetchall(), [("015_add_capd_runs",)])
        connection.close()

    def test_016_is_read_only_pending_then_applies_without_014_or_015(self):
        connection = self.connect()
        migration = optional_migrations.load_migration(
            "016_add_capd_http_header_verify_operation"
        )
        planned = optional_migrations.plan(
            connection, migration.migration_id
        )
        self.assertEqual(planned["state"], "PENDING")
        self.assertEqual(planned["sha256"], migration.checksum)
        self.assertFalse(planned["expected_schema_present"])
        connection.rollback()

        result = optional_migrations.apply(
            connection, migration.migration_id,
            approval_checksum=migration.checksum,
        )
        self.assertEqual(result["state"], "APPLIED")
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT pg_get_constraintdef(oid) FROM pg_constraint
                 WHERE conrelid='public.active_scan_scopes'::regclass
                   AND conname='active_scan_scopes_testing_level'
            """)
            self.assertIn("CAPD_HTTP_HEADER_VERIFY", cursor.fetchone()[0])
            cursor.execute("""
                SELECT to_regclass('public.capd_runs'),
                       to_regclass('public.capd_results'),
                       to_regclass('public.tracked_security_issues'),
                       to_regclass('public.tracked_security_issue_history')
            """)
            self.assertEqual(cursor.fetchone(), (None, None, None, None))
            cursor.execute("""
                SELECT migration_id, sha256, source_file, applied_at
                  FROM public.asip_optional_migration_ledger
            """)
            rows = cursor.fetchall()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0][:3], (
                migration.migration_id, migration.checksum,
                "016_add_capd_http_header_verify_operation.sql",
            ))
            self.assertIsNotNone(rows[0][3])
        with self.assertRaisesRegex(
            optional_migrations.OptionalMigrationError, "already applied"
        ):
            optional_migrations.apply(
                connection, migration.migration_id,
                approval_checksum=migration.checksum,
            )
        connection.close()

    def test_016_rejects_untracked_constraint_state(self):
        connection = self.connect()
        migration = optional_migrations.load_migration(
            "016_add_capd_http_header_verify_operation"
        )
        connection.rollback()
        with connection:
            with connection.cursor() as cursor:
                cursor.execute(migration.body)
        with self.assertRaisesRegex(
            optional_migrations.OptionalMigrationError,
            "without an optional-migration receipt",
        ):
            optional_migrations.plan(connection, migration.migration_id)
        connection.rollback()
        connection.close()

    def test_016_failed_ddl_rolls_back_constraint_and_receipt(self):
        connection = self.connect()
        migration = optional_migrations.load_migration(
            "016_add_capd_http_header_verify_operation"
        )
        with tempfile.TemporaryDirectory() as directory:
            broken_path = pathlib.Path(directory) / migration.source_file
            source = optional_migrations.OPTIONAL_MIGRATIONS[
                migration.migration_id
            ].read_text(encoding="utf-8")
            broken_path.write_text(
                source.replace("COMMIT;", "SELECT definitely_not_valid_sql; COMMIT;"),
                encoding="utf-8",
            )
            with mock.patch.dict(optional_migrations.OPTIONAL_MIGRATIONS,
                                 {migration.migration_id: broken_path}):
                broken_migration = optional_migrations.load_migration(
                    migration.migration_id
                )
                with self.assertRaises(self.psycopg2.Error):
                    optional_migrations.apply(
                        connection, migration.migration_id,
                        approval_checksum=broken_migration.checksum,
                    )
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT pg_get_constraintdef(oid) FROM pg_constraint
                 WHERE conrelid='public.active_scan_scopes'::regclass
                   AND conname='active_scan_scopes_testing_level'
            """)
            self.assertNotIn("CAPD_HTTP_HEADER_VERIFY", cursor.fetchone()[0])
            cursor.execute("SELECT to_regclass('public.asip_optional_migration_ledger')")
            self.assertIsNone(cursor.fetchone()[0])
        connection.close()

    def test_017_consumption_receipt_migration_is_independent_of_014_015_and_016(self):
        connection = self.connect()
        migration = optional_migrations.load_migration(
            "017_add_capd_approval_consumptions"
        )
        result = optional_migrations.apply(
            connection, migration.migration_id,
            approval_checksum=migration.checksum,
        )
        self.assertEqual(result["state"], "APPLIED")
        self.assertEqual(result["sha256"], migration.checksum)
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT to_regclass('public.capd_approval_consumptions'),
                       to_regclass('public.capd_runs'),
                       to_regclass('public.capd_results'),
                       to_regclass('public.tracked_security_issues'),
                       to_regclass('public.tracked_security_issue_history')
            """)
            receipt, capd_runs, capd_results, lifecycle, lifecycle_history = cursor.fetchone()
            self.assertIsNotNone(receipt)
            self.assertIsNone(capd_runs)
            self.assertIsNone(capd_results)
            self.assertIsNone(lifecycle)
            self.assertIsNone(lifecycle_history)
            cursor.execute("""
                SELECT migration_id FROM public.asip_optional_migration_ledger
                 ORDER BY migration_id
            """)
            self.assertEqual(cursor.fetchall(), [("017_add_capd_approval_consumptions",)])
        connection.close()

    def test_017_failed_ddl_rolls_back_receipt_table_and_ledger(self):
        connection = self.connect()
        migration = optional_migrations.load_migration(
            "017_add_capd_approval_consumptions"
        )
        with tempfile.TemporaryDirectory() as directory:
            broken_path = pathlib.Path(directory) / "017_add_capd_approval_consumptions.sql"
            broken_path.write_text(
                "BEGIN; CREATE TABLE public.capd_receipt_partial(id integer); "
                "SELECT definitely_not_valid_sql; COMMIT;",
                encoding="utf-8",
            )
            with mock.patch.dict(optional_migrations.OPTIONAL_MIGRATIONS,
                                 {migration.migration_id: broken_path}):
                broken_migration = optional_migrations.load_migration(
                    migration.migration_id
                )
                with self.assertRaises(self.psycopg2.Error):
                    optional_migrations.apply(
                        connection, migration.migration_id,
                        approval_checksum=broken_migration.checksum,
                    )
        with connection.cursor() as cursor:
            cursor.execute("SELECT to_regclass('public.capd_receipt_partial')")
            self.assertIsNone(cursor.fetchone()[0])
            cursor.execute("SELECT to_regclass('public.asip_optional_migration_ledger')")
            self.assertIsNone(cursor.fetchone()[0])
        connection.close()

    def test_018_brand_redirect_migration_is_planable_and_additive(self):
        connection = self.connect()
        with connection.cursor() as cursor:
            cursor.execute("SELECT count(*) FROM scans")
            scans_before = cursor.fetchone()[0]
            cursor.execute("SELECT count(*) FROM domains")
            domains_before = cursor.fetchone()[0]

        migration = optional_migrations.load_migration(
            "018_add_brand_redirect_observations"
        )
        planned = optional_migrations.plan(connection, migration.migration_id)
        self.assertEqual(planned["state"], "PENDING")
        self.assertEqual(planned["sha256"], migration.checksum)
        connection.rollback()

        result = optional_migrations.apply(
            connection, migration.migration_id,
            approval_checksum=migration.checksum,
        )
        self.assertEqual(result["state"], "APPLIED")
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT column_name FROM information_schema.columns
                 WHERE table_schema='public'
                   AND table_name='brand_redirect_observations'
            """)
            columns = {row[0] for row in cursor.fetchall()}
            self.assertTrue({
                "scan_id", "domain_id", "operation_id", "observed_at",
                "evidence_source", "completeness", "evidence",
            }.issubset(columns))
            cursor.execute("SELECT count(*) FROM scans")
            self.assertEqual(cursor.fetchone()[0], scans_before)
            cursor.execute("SELECT count(*) FROM domains")
            self.assertEqual(cursor.fetchone()[0], domains_before)
        connection.close()

    def test_019_brand_redirect_scope_level_extends_existing_constraint(self):
        connection = self.connect()
        with connection:
            with connection.cursor() as cursor:
                cursor.execute("""
                    ALTER TABLE public.active_scan_scopes
                        DROP CONSTRAINT active_scan_scopes_testing_level;
                    ALTER TABLE public.active_scan_scopes
                        ADD CONSTRAINT active_scan_scopes_testing_level CHECK (
                            testing_level IN (
                                'TECHNOLOGY_HTTP', 'PORT_SCAN', 'ADHOC_CHECK',
                                'HTTP_TLS_OBSERVATION', 'DNS_SECURITY',
                                'ASN_METADATA', 'CAPD_HTTP_HEADER_VERIFY'
                            )
                        )
                """)
        migration = optional_migrations.load_migration(
            "019_add_brand_redirect_scope_level"
        )
        planned = optional_migrations.plan(connection, migration.migration_id)
        self.assertEqual(planned["state"], "PENDING")
        connection.rollback()
        result = optional_migrations.apply(
            connection, migration.migration_id,
            approval_checksum=migration.checksum,
        )
        self.assertEqual(result["state"], "APPLIED")
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT pg_get_constraintdef(oid)
                  FROM pg_constraint
                 WHERE conrelid='public.active_scan_scopes'::regclass
                   AND conname='active_scan_scopes_testing_level'
            """)
            definition = cursor.fetchone()[0]
        for value in (
            "TECHNOLOGY_HTTP", "PORT_SCAN", "HTTP_TLS_OBSERVATION",
            "DNS_SECURITY", "ASN_METADATA", "CAPD_HTTP_HEADER_VERIFY",
            "BRAND_REDIRECT_OBSERVATION",
        ):
            self.assertIn(value, definition)
        connection.close()

    def test_020_campaign_policy_is_additive_and_legacy_scopes_fail_closed(self):
        connection = self.connect()
        with connection:
            with connection.cursor() as cursor:
                cursor.execute("""
                    ALTER TABLE public.active_scan_scopes
                        ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'ACTIVE'
                """)
        for migration_id in (
            "018_add_brand_redirect_observations",
            "019_add_brand_redirect_scope_level",
        ):
            migration = optional_migrations.load_migration(migration_id)
            optional_migrations.apply(
                connection, migration_id, approval_checksum=migration.checksum,
            )
        migration = optional_migrations.load_migration(
            "020_add_brand_redirect_campaign_policy"
        )
        planned = optional_migrations.plan(connection, migration.migration_id)
        self.assertEqual(planned["state"], "PENDING")
        connection.rollback()
        optional_migrations.apply(
            connection, migration.migration_id,
            approval_checksum=migration.checksum,
        )
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT column_name FROM information_schema.columns
                 WHERE table_schema='public' AND table_name='active_scan_scopes'
            """)
            columns = {row[0] for row in cursor.fetchall()}
            self.assertTrue({
                "monitoring_purpose", "eligible_discovery_sources",
                "max_requests_per_scan",
            }.issubset(columns))
            cursor.execute("""
                SELECT pg_get_constraintdef(oid)
                  FROM pg_constraint
                 WHERE conrelid='public.brand_redirect_observations'::regclass
                   AND conname='brand_redirect_observations_completeness_check'
            """)
            self.assertIn("REQUEST_BUDGET_EXHAUSTED", cursor.fetchone()[0])
            cursor.execute("""
                SELECT convalidated FROM pg_constraint
                 WHERE conrelid='public.active_scan_scopes'::regclass
                   AND conname='active_scan_scopes_brand_campaign_policy'
            """)
            self.assertFalse(cursor.fetchone()[0])
        connection.close()


if __name__ == "__main__":
    unittest.main()
