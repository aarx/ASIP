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
                        public.asip_optional_migration_ledger CASCADE
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


if __name__ == "__main__":
    unittest.main()
