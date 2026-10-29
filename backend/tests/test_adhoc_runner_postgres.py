import pathlib
import sys
import threading
import unittest
from datetime import datetime, timezone
import importlib


BACKEND = pathlib.Path(__file__).resolve().parents[1]
REPOSITORY = BACKEND.parent
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(BACKEND / "tests"))

from adhoc_campaigns import create_campaign, get_campaign, get_campaign_results, transition_campaign  # noqa: E402
from adhoc_runner import AdhocCampaignRunner, RunnerPolicy, TransportResponse  # noqa: E402
_remediation_fixture = importlib.import_module("test_remediation_package_2d1c")


class _Resolver:
    def resolve(self, hostname):
        return ["8.8.8.8"]


class _Transport:
    def request(self, plan):
        return TransportResponse(
            http_status=200,
            connected_peer_ip=plan.pinned_resolution.addresses[0],
            redirect_status=None,
            redirect_location=None,
            fingerprint_headers={"Server": "PHP/8.2.34"},
            observed_at=datetime.now(timezone.utc),
        )


class _Fingerprinter:
    def __call__(self, headers):
        return [{
            "technology": "php",
            "version": "8.2.34",
            "confidence": "high",
            "evidence_type": "server_header",
            "sanitized_evidence": headers.get("Server", ""),
        }]


class _BlockingTransport(_Transport):
    def __init__(self):
        self.started = threading.Event()
        self.release = threading.Event()

    def request(self, plan):
        self.started.set()
        if not self.release.wait(10):
            raise TimeoutError("test transport was not released")
        return super().request(plan)


class AdhocRunnerPostgreSQLTests(unittest.TestCase):
    """Exercise migration 005 and runner SQL against disposable PostgreSQL."""

    @classmethod
    def setUpClass(cls):
        # Reuse the repository's disposable PostgreSQL fixture and base schema,
        # but never connect to the configured/live database.
        _remediation_fixture.PostgreSQLIngestConvergenceTests.setUpClass.__func__(cls)
        connection = cls.connect()
        try:
            with connection:
                with connection.cursor() as cursor:
                    cursor.execute("ALTER TABLE scans ADD COLUMN completed_at timestamptz")
                    cursor.execute(
                        (REPOSITORY / "backend/migrations/005_add_adhoc_campaigns.sql")
                        .read_text(encoding="utf-8")
                    )
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
                cursor.execute(
                    "TRUNCATE adhoc_campaign_results, adhoc_campaign_targets, "
                    "adhoc_campaigns RESTART IDENTITY"
                )
                cursor.execute("DELETE FROM scan_results")
                cursor.execute("DELETE FROM domains")
                cursor.execute("DELETE FROM scans")
                cursor.execute(
                    "INSERT INTO scans(id, status, completed_at) VALUES "
                    "(16, 'SUCCEEDED', CURRENT_TIMESTAMP)"
                )
                cursor.execute(
                    "INSERT INTO domains(id, domain, ownership_status, scannable, "
                    "validation_source) VALUES "
                    "(701, 'approved.example', 'CONFIRMED', TRUE, 'manual'), "
                    "(702, 'second.example', 'CONFIRMED', TRUE, 'manual'), "
                    "(703, 'unlisted.example', 'CONFIRMED', TRUE, 'manual')"
                )
                cursor.execute(
                    "INSERT INTO scan_results(scan_id, domain_id, seed) VALUES "
                    "(16, 701, 'fixture'), (16, 702, 'fixture')"
                )
        connection.close()

    def create_running_campaign(self, connection, *, target="approved.example", key="test-key"):
        created = create_campaign(
            connection,
            check_id="php-rce",
            source_scan_id=16,
            target_domains=[target],
            requested_by="test-operator",
            idempotency_key=key,
            assessment_date="2026-10-28",
            dataset_revision="2026-10-28",
            operator_authorizer=lambda identity: identity == "test-operator",
        )
        transition_campaign(connection, created["campaign_id"], "RUNNING")
        return created["campaign_id"]

    def runner(self, connection_factory, transport=None):
        return AdhocCampaignRunner(
            policy=RunnerPolicy(enabled=True),
            resolver=_Resolver(),
            transport=transport or _Transport(),
            fingerprinter=_Fingerprinter(),
            operator_authorizer=lambda identity: identity == "test-operator",
            conn_factory=connection_factory,
        )

    def test_real_sql_lifecycle_is_scan_bound_and_does_not_touch_canonical_tables(self):
        connection = self.connect()
        campaign_id = self.create_running_campaign(connection, key="success-key")
        connection.close()

        before = self.snapshot_canonical_counts()
        runner = self.runner(self.connect)
        result = runner.run_campaign(campaign_id, "test-operator")
        after = self.snapshot_canonical_counts()

        self.assertEqual(result["status"], "SUCCEEDED")
        self.assertEqual(result["completed"], 1)
        self.assertEqual(result["skipped"], 0)
        self.assertEqual(before, after)

        connection = self.connect()
        try:
            campaign = get_campaign(connection, campaign_id)
            results = get_campaign_results(connection, campaign_id)
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT target_status FROM adhoc_campaign_targets "
                    "WHERE campaign_id = %s", (campaign_id,)
                )
                target_status = cursor.fetchone()[0]
                cursor.execute(
                    "SELECT execution_status, evidence_status, evaluation_status, "
                    "dataset_revision, cve_intelligence->>'dataset_revision' "
                    "FROM adhoc_campaign_results WHERE campaign_id = %s",
                    (campaign_id,),
                )
                stored = cursor.fetchone()
        finally:
            connection.close()

        self.assertEqual(campaign["progress"]["completed"], 1)
        self.assertEqual(results["count"], 1)
        self.assertEqual(target_status, "COMPLETED")
        self.assertEqual(stored[:4], ("COMPLETED", "COLLECTED", "EVALUATED", "2026-10-28"))
        self.assertEqual(stored[4], "2026-10-28")

    def test_concurrent_cancellation_is_recorded_by_a_separate_connection(self):
        connection = self.connect()
        campaign_id = self.create_running_campaign(connection, key="cancel-key")
        connection.close()
        transport = _BlockingTransport()
        runner = self.runner(self.connect, transport)
        errors = []

        def execute():
            try:
                runner.run_campaign(campaign_id, "test-operator")
            except Exception as exc:  # pragma: no cover - assertion below reports it
                errors.append(exc)

        worker = threading.Thread(target=execute)
        worker.start()
        self.assertTrue(transport.started.wait(5), "runner did not reach transport")

        cancellation = self.connect()
        try:
            with cancellation:
                with cancellation.cursor() as cursor:
                    cursor.execute(
                        "UPDATE adhoc_campaigns SET status = 'CANCEL_REQUESTED', "
                        "cancel_requested_at = CURRENT_TIMESTAMP WHERE id = %s",
                        (campaign_id,),
                    )
        finally:
            cancellation.close()
        transport.release.set()
        worker.join(10)

        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        connection = self.connect()
        try:
            campaign = get_campaign(connection, campaign_id)
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT target_status FROM adhoc_campaign_targets "
                    "WHERE campaign_id = %s", (campaign_id,)
                )
                target_status = cursor.fetchone()[0]
                cursor.execute(
                    "SELECT execution_status, evidence_status, failure_code "
                    "FROM adhoc_campaign_results WHERE campaign_id = %s",
                    (campaign_id,),
                )
                result = cursor.fetchone()
        finally:
            connection.close()

        self.assertEqual(campaign["status"], "CANCELLED")
        self.assertEqual(campaign["progress"]["cancelled"], 1)
        self.assertEqual(target_status, "CANCELLED")
        self.assertEqual(result, ("CANCELLED", "BLOCKED", "campaign_cancelled"))

    def test_migration_foreign_keys_reject_cross_scan_target_rows(self):
        connection = self.connect()
        try:
            campaign_id = self.create_running_campaign(connection, key="fk-key")
            with self.assertRaises(self.psycopg2.errors.ForeignKeyViolation):
                with connection:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "INSERT INTO adhoc_campaign_targets "
                            "(campaign_id, source_scan_id, domain_id, domain_snapshot, "
                            "ownership_status_snapshot, scannable_snapshot, "
                            "validation_source_snapshot) VALUES "
                            "(%s, 16, 703, 'unlisted.example', 'CONFIRMED', TRUE, 'manual')",
                            (campaign_id,),
                        )
        finally:
            connection.close()

    def snapshot_canonical_counts(self):
        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                counts = {}
                for table in (
                    "scans", "scan_results", "domains", "domain_tech",
                    "domain_findings", "domain_risk",
                ):
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    counts[table] = cursor.fetchone()[0]
                return counts
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
