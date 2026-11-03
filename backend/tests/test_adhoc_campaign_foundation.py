import pathlib
import sys
import unittest
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from adhoc_campaigns import (  # noqa: E402
    CampaignError,
    CampaignSchemaUnavailable,
    CAMPAIGN_STATES,
    OPERATOR_AUTHENTICATION_AVAILABLE,
    campaign_request_fingerprint,
    create_campaign,
    get_campaign_results,
    runtime_authorization_query,
    transition_campaign,
    normalize_target_set,
    validate_campaign_transition,
    validate_explicit_target_selection,
)


class FakeConnection:
    def __init__(self, cursor):
        self.cursor_obj = cursor
        self.commits = 0
        self.rollbacks = 0

    def cursor(self):
        return self.cursor_obj

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


class QueueCursor:
    def __init__(self, fetchones=(), fetchalls=()):
        self.fetchones = iter(fetchones)
        self.fetchalls = iter(fetchalls)
        self.executions = []

    def execute(self, query, params=None):
        self.executions.append((query, params))

    def fetchone(self):
        return next(self.fetchones)

    def fetchall(self):
        return next(self.fetchalls)


class MissingCampaignTable(Exception):
    pgcode = "42P01"


class CampaignFoundationTests(unittest.TestCase):
    def test_state_machine_accepts_only_declared_transitions(self):
        self.assertEqual(len(CAMPAIGN_STATES), 7)
        self.assertTrue(validate_campaign_transition("QUEUED", "RUNNING"))
        self.assertTrue(validate_campaign_transition("RUNNING", "PARTIAL"))
        with self.assertRaises(CampaignError):
            validate_campaign_transition("SUCCEEDED", "RUNNING")
        with self.assertRaises(CampaignError):
            validate_campaign_transition("QUEUED", "SUCCEEDED")

    def test_explicit_targets_require_scan_membership_and_exact_authorization(self):
        members = [
            (1, "approved.example", "CONFIRMED", True, "manual"),
            (2, "candidate.example", "CANDIDATE", True, "manual"),
            (3, "external.example", "EXTERNAL", True, "manual"),
            (4, "unvalidated.example", "CONFIRMED", True, "discovery"),
            (5, "not-scannable.example", "CONFIRMED", False, "manual"),
        ]
        snapshots = validate_explicit_target_selection(["APPROVED.EXAMPLE."], members)
        self.assertEqual(snapshots[0]["domain_id"], 1)
        self.assertEqual(snapshots[0]["domain_snapshot"], "approved.example")
        for domain in (
            "candidate.example",
            "external.example",
            "not-scannable.example",
            "missing.example",
        ):
            with self.subTest(domain=domain):
                with self.assertRaises(CampaignError):
                    validate_explicit_target_selection([domain], members)

        shadow = validate_explicit_target_selection(["unvalidated.example"], members)
        self.assertEqual(shadow[0]["validation_source_snapshot"], "discovery")

    def test_zero_and_duplicate_target_requests_are_rejected(self):
        members = [(1, "approved.example", "CONFIRMED", True, "manual")]
        for targets in ([], ["approved.example", "approved.example"]):
            with self.subTest(targets=targets):
                with self.assertRaises(CampaignError):
                    validate_explicit_target_selection(targets, members)

    def test_runtime_recheck_uses_membership_and_central_predicate(self):
        from unittest.mock import patch

        with patch.dict("os.environ", {"ASIP_DEFAULT_SCAN_OPERATIONS": "ADHOC_CHECK"}):
            query, params = runtime_authorization_query(7, 16)
        self.assertEqual(params, (16, 7))
        self.assertIn("sr.scan_id = %s", query)
        self.assertIn("d.ownership_status = 'CONFIRMED'", query)
        self.assertIn("d.scannable IS TRUE", query)
        self.assertNotIn("d.validation_source = 'manual'", query)
        self.assertIn("d.scannable IS TRUE", query)
        self.assertIn("manually rejected", query)
        self.assertIn("FROM seed_domains seed_root", query)
        self.assertIn("FROM known_domains known_host", query)
        with patch.dict("os.environ", {"ASIP_DEFAULT_SCAN_OPERATIONS": "ADHOC_CHECK"}):
            enabled_query, _ = runtime_authorization_query(7, 16)
        with patch.dict("os.environ", {"ASIP_DEFAULT_SCAN_OPERATIONS": "PORT_SCAN"}):
            disabled_query, _ = runtime_authorization_query(7, 16)
        self.assertIn("AND TRUE", enabled_query)
        self.assertIn("AND FALSE", disabled_query)

    def test_creation_requires_operator_authorization_dependency(self):
        with self.assertRaises(PermissionError):
            create_campaign(
                FakeConnection(QueueCursor()),
                check_id="php-rce",
                source_scan_id=16,
                target_domains=["approved.example"],
                requested_by="analyst",
                idempotency_key="request-1",
                dataset_revision="2026-10-28",
            )
        self.assertFalse(OPERATOR_AUTHENTICATION_AVAILABLE)

    def test_creation_is_idempotent_for_same_authorized_request(self):
        fingerprint = campaign_request_fingerprint(
            check_id="php-rce",
            source_scan_id=16,
            requested_by="analyst",
            target_set=["approved.example"],
            assessment_date="2026-10-28",
            dataset_revision="2026-10-28",
        )
        cursor = QueueCursor(
            fetchones=[(
                91, "php-rce", 16, "analyst", ["approved.example"],
                fingerprint, "2026-10-28", "2026-10-28", "QUEUED",
            )]
        )
        conn = FakeConnection(cursor)
        result = create_campaign(
            conn,
            check_id="php-rce",
            source_scan_id=16,
            target_domains=["approved.example"],
            requested_by="analyst",
            idempotency_key="request-1",
            dataset_revision="2026-10-28",
            assessment_date="2026-10-28",
            operator_authorizer=lambda subject: subject == "analyst",
        )
        self.assertEqual(result, {"campaign_id": 91, "status": "QUEUED", "idempotent": True})
        self.assertEqual(conn.commits, 1)
        self.assertIn("pg_advisory_xact_lock", cursor.executions[0][0])
        self.assertTrue(all("INSERT INTO adhoc_campaigns" not in sql for sql, _ in cursor.executions))

    def test_same_key_conflicting_target_set_is_rejected(self):
        fingerprint = campaign_request_fingerprint(
            check_id="php-rce", source_scan_id=16, requested_by="analyst",
            target_set=["other.example"], assessment_date="2026-10-28",
            dataset_revision="2026-10-28",
        )
        cursor = QueueCursor(fetchones=[(
            91, "php-rce", 16, "analyst", ["other.example"], fingerprint,
            "2026-10-28", "2026-10-28", "QUEUED",
        )])
        with self.assertRaisesRegex(CampaignError, "Idempotency key conflicts"):
            create_campaign(
                FakeConnection(cursor), check_id="php-rce", source_scan_id=16,
                target_domains=["approved.example"], requested_by="analyst",
                idempotency_key="request-1", dataset_revision="2026-10-28",
                assessment_date="2026-10-28",
                operator_authorizer=lambda subject: subject == "analyst",
            )

    def test_same_key_conflicting_dataset_revision_is_rejected(self):
        fingerprint = campaign_request_fingerprint(
            check_id="php-rce", source_scan_id=16, requested_by="analyst",
            target_set=["approved.example"], assessment_date="2026-10-28",
            dataset_revision="old-revision",
        )
        cursor = QueueCursor(fetchones=[(
            91, "php-rce", 16, "analyst", ["approved.example"], fingerprint,
            "2026-10-28", "old-revision", "QUEUED",
        )])
        with self.assertRaisesRegex(CampaignError, "Idempotency key conflicts"):
            create_campaign(
                FakeConnection(cursor), check_id="php-rce", source_scan_id=16,
                target_domains=["approved.example"], requested_by="analyst",
                idempotency_key="request-1", dataset_revision="2026-10-28",
                assessment_date="2026-10-28",
                operator_authorizer=lambda subject: subject == "analyst",
            )

    def test_target_identity_is_order_independent_after_normalization(self):
        self.assertEqual(
            normalize_target_set(["B.example.", "a.example"]),
            ("a.example", "b.example"),
        )

    def test_request_fingerprint_covers_complete_request_identity(self):
        base = dict(
            check_id="php-rce", source_scan_id=16, requested_by="analyst",
            target_set=["approved.example"], assessment_date="2026-10-28",
            dataset_revision="2026-10-28",
        )
        for field, value in (
            ("check_id", "other-check"),
            ("source_scan_id", 17),
            ("requested_by", "different-operator"),
            ("assessment_date", "2026-10-29"),
            ("dataset_revision", "different-revision"),
            ("target_set", ["other.example"]),
        ):
            with self.subTest(field=field):
                variant = dict(base)
                variant[field] = value
                self.assertNotEqual(
                    campaign_request_fingerprint(**base),
                    campaign_request_fingerprint(**variant),
                )

    def test_missing_key_is_serialized_by_transaction_advisory_lock(self):
        cursor = QueueCursor(
            fetchones=[None, (16, "FAILED", None)]
        )
        with self.assertRaises(CampaignError):
            create_campaign(
                FakeConnection(cursor), check_id="php-rce", source_scan_id=16,
                target_domains=["approved.example"], requested_by="analyst",
                idempotency_key="concurrent-key", dataset_revision="2026-10-28",
                operator_authorizer=lambda subject: True,
            )
        self.assertIn("pg_advisory_xact_lock", cursor.executions[0][0])
        self.assertIsInstance(cursor.executions[0][1][0], int)

    def test_failed_creation_rolls_back_before_insert(self):
        cursor = QueueCursor(
            fetchones=[None, (16, "SUCCEEDED", "2026-10-04")],
            fetchalls=[[(7, "approved.example", "CANDIDATE", True, "manual")]],
        )
        conn = FakeConnection(cursor)
        with self.assertRaises(CampaignError):
            create_campaign(
                conn, check_id="php-rce", source_scan_id=16,
                target_domains=["approved.example"], requested_by="analyst",
                idempotency_key="rollback-key", dataset_revision="2026-10-28",
                operator_authorizer=lambda subject: True,
            )
        self.assertEqual(conn.commits, 0)
        self.assertEqual(conn.rollbacks, 1)
        self.assertTrue(all("INSERT INTO adhoc_campaigns" not in sql for sql, _ in cursor.executions))

    def test_creation_snapshots_authorized_target_in_one_transaction(self):
        cursor = QueueCursor(
            fetchones=[None, (16, "SUCCEEDED", "2026-10-04"), (101,)],
            fetchalls=[[(7, "approved.example", "CONFIRMED", True, "manual")]],
        )
        conn = FakeConnection(cursor)
        result = create_campaign(
            conn,
            check_id="php-rce",
            source_scan_id=16,
            target_domains=["approved.example"],
            requested_by="analyst",
            idempotency_key="request-create",
            dataset_revision="2026-10-28",
            operator_authorizer=lambda subject: True,
        )
        self.assertEqual(result["campaign_id"], 101)
        self.assertEqual(result["target_count"], 1)
        self.assertEqual(conn.commits, 1)
        self.assertEqual(conn.rollbacks, 0)
        self.assertTrue(all("domain_findings" not in sql for sql, _ in cursor.executions))
        self.assertTrue(all("domain_risk" not in sql for sql, _ in cursor.executions))

    def test_transition_service_locks_and_commits_valid_state_change(self):
        cursor = QueueCursor(fetchones=[("QUEUED",)])
        conn = FakeConnection(cursor)
        self.assertEqual(transition_campaign(conn, 101, "RUNNING"), "RUNNING")
        self.assertEqual(conn.commits, 1)
        self.assertIn("FOR UPDATE", cursor.executions[0][0])

    def test_failed_source_scan_is_rejected_before_target_snapshot(self):
        cursor = QueueCursor(fetchones=[None, (16, "FAILED", None)])
        with self.assertRaises(CampaignError):
            create_campaign(
                FakeConnection(cursor),
                check_id="php-rce",
                source_scan_id=16,
                target_domains=["approved.example"],
                requested_by="analyst",
                idempotency_key="request-failed-scan",
                dataset_revision="2026-10-28",
                operator_authorizer=lambda subject: True,
            )
        self.assertEqual(len(cursor.executions), 3)

    def test_read_api_filters_before_pagination_and_hides_internal_ids(self):
        cursor = QueueCursor(
            fetchones=[(1,)],
            fetchalls=[[
                (
                    10, 7, "approved.example", 16, "COMPLETED", None,
                    None, None, None, "COMPLETED", "COLLECTED", "EVALUATED",
                    "no_php_observation", None, None, [], None, None,
                    None, None, "2026-10-28",
                )
            ]],
        )
        result = get_campaign_results(
            FakeConnection(cursor),
            91,
            page=2,
            limit=1,
            target_status="COMPLETED",
            evaluation_status="EVALUATED",
            classification="no_php_observation",
        )
        self.assertEqual(result["page"], 2)
        self.assertNotIn("target_id", result["results"][0])
        self.assertNotIn("domain_id", result["results"][0])
        self.assertEqual(cursor.executions[0][1], (91, "COMPLETED", "EVALUATED", "no_php_observation"))
        self.assertEqual(cursor.executions[1][1][-2:], (1, 1))

    def test_missing_schema_is_distinguished_from_empty_results(self):
        cursor = mock.Mock()
        cursor.execute.side_effect = MissingCampaignTable()
        conn = FakeConnection(cursor)
        with self.assertRaises(CampaignSchemaUnavailable):
            get_campaign_results(conn, 1)

    def test_migration_is_additive_and_contains_required_constraints(self):
        migration = (BACKEND / "migrations/005_add_adhoc_campaigns.sql").read_text()
        normalized = " ".join(migration.split()).upper()
        self.assertIn("BEGIN;", normalized)
        self.assertIn("COMMIT;", normalized)
        for table in (
            "CREATE TABLE PUBLIC.ADHOC_CAMPAIGNS",
            "CREATE TABLE PUBLIC.ADHOC_CAMPAIGN_TARGETS",
            "CREATE TABLE PUBLIC.ADHOC_CAMPAIGN_RESULTS",
        ):
            self.assertIn(table, normalized)
        for token in (
            "IDEMPOTENCY_KEY",
            "SOURCE_SCAN_ID",
            "DOMAIN_SNAPSHOT",
            "OBSERVATIONS JSONB",
            "FOREIGN KEY (SOURCE_SCAN_ID, DOMAIN_ID)",
            "FOREIGN KEY (CAMPAIGN_ID, SOURCE_SCAN_ID)",
            "UNIQUE (CAMPAIGN_ID, DOMAIN_ID)",
            "UNIQUE (CAMPAIGN_ID, ID)",
            "UNIQUE (CAMPAIGN_ID, TARGET_ID, ATTEMPT_NUMBER)",
            "TARGET_SET JSONB",
            "REQUEST_FINGERPRINT TEXT",
        ):
            self.assertIn(token, normalized)
        self.assertNotIn("ALTER TABLE PUBLIC.SCANS", normalized)
        self.assertNotIn("ALTER TABLE PUBLIC.DOMAINS", normalized)
        self.assertNotIn("DROP TABLE", normalized)

    def test_creation_route_is_not_exposed_without_operator_authentication(self):
        main_source = (BACKEND / "main.py").read_text()
        self.assertNotIn('@app.post("/v2/adhoc/campaigns")', main_source)
        self.assertIn('@app.get("/v2/adhoc/campaigns")', main_source)
        self.assertNotIn("import requests", (BACKEND / "adhoc_campaigns.py").read_text())


if __name__ == "__main__":
    unittest.main()
