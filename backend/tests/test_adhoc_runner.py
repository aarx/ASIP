import pathlib
import sys
import unittest
from datetime import datetime, timezone
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from adhoc_runner import (  # noqa: E402
    ASIP_ORCHESTRATION_LOCK_ID,
    AdhocCampaignRunner,
    AuthorizationRevoked,
    CampaignCancelled,
    CampaignDeadlineExceeded,
    DNSRebindingDetected,
    ExecutionContext,
    LockUnavailable,
    RedirectRejected,
    RunnerDisabled,
    RunnerExecutionUnavailable,
    RunnerPolicy,
    TargetNotFound,
    UnsafeAddress,
    UnsafeHostname,
    UnsupportedRequest,
    acquire_runner_lock,
    build_request_plan,
    campaign_deadline,
    evaluate_php_observation,
    load_execution_context,
    reject_redirect,
    release_runner_lock,
    sanitize_evidence,
    validate_dns_answers,
    validate_execution_context,
    validate_hostname,
    validate_pinned_address,
)


class Cursor:
    def __init__(self, row=None):
        self.row = row
        self.executions = []

    def execute(self, query, params=None):
        self.executions.append((query, params))

    def fetchone(self):
        return self.row


class Connection:
    def __init__(self, cursor):
        self._cursor = cursor
        self.commits = 0
        self.rollbacks = 0
        self.closed = False

    def cursor(self):
        return self._cursor

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True


def context(**overrides):
    values = dict(
        campaign_id=10,
        target_id=20,
        source_scan_id=16,
        domain_id=30,
        domain="approved.example",
        campaign_status="RUNNING",
        target_status="PENDING",
        source_scan_status="SUCCEEDED",
        created_at=datetime(2026, 10, 29, 12, 0, tzinfo=timezone.utc),
        ownership_status="CONFIRMED",
        scannable=True,
        validation_source="manual",
    )
    values.update(overrides)
    return ExecutionContext(**values)


class RunnerGuardTests(unittest.TestCase):
    def test_runner_is_disabled_by_default_and_never_executes_transport(self):
        transport = mock.Mock()
        runner = AdhocCampaignRunner(transport=transport)
        conn = Connection(Cursor())
        with self.assertRaises(RunnerDisabled):
            runner.prepare_target(conn, 10, 20, "operator")
        transport.request.assert_not_called()

    def test_operator_authorization_is_required_before_target_access(self):
        runner = AdhocCampaignRunner(
            policy=RunnerPolicy(enabled=True),
            operator_authorizer=lambda identity: False,
        )
        cursor = Cursor()
        with self.assertRaises(PermissionError):
            runner.prepare_target(Connection(cursor), 10, 20, "operator")
        self.assertEqual(cursor.executions, [])

    def test_enabled_preparation_rechecks_live_authorization_without_transport(self):
        row = (
            10, "RUNNING", 16, context().created_at,
            20, "PENDING", 16, 30, "SUCCEEDED", "approved.example",
            "CONFIRMED", True, "manual", "2026-10-28", "2026-10-28",
        )
        cursor = Cursor(row)
        transport = mock.Mock()
        runner = AdhocCampaignRunner(
            policy=RunnerPolicy(enabled=True),
            transport=transport,
            operator_authorizer=lambda identity: identity == "operator",
        )
        prepared = runner.prepare_target(
            Connection(cursor), 10, 20, "operator",
            now=datetime(2026, 10, 29, 12, 1, tzinfo=timezone.utc),
        )
        self.assertEqual(prepared.domain, "approved.example")
        self.assertIn("d.ownership_status = 'CONFIRMED'", cursor.executions[-1][0])
        transport.request.assert_not_called()

    def test_missing_target_is_rejected_by_scan_bound_query(self):
        cursor = Cursor()
        with self.assertRaises(TargetNotFound):
            load_execution_context(cursor, 10, 20)
        query, params = cursor.executions[0]
        self.assertIn("JOIN SCAN_RESULTS", query.upper())
        self.assertEqual(params, (10, 20))

    def test_non_running_campaign_and_revoked_authorization_are_rejected(self):
        with self.assertRaisesRegex(Exception, "RUNNING"):
            validate_execution_context(context(campaign_status="QUEUED"))
        with self.assertRaises(AuthorizationRevoked):
            validate_execution_context(context(ownership_status="CANDIDATE"))
        with self.assertRaises(AuthorizationRevoked):
            validate_execution_context(context(scannable=False))
        with self.assertRaises(AuthorizationRevoked):
            validate_execution_context(context(validation_source="discovery"))

    def test_cancellation_and_deadline_guards_are_cooperative(self):
        with self.assertRaises(CampaignCancelled):
            validate_execution_context(context(), cancellation_requested=True)
        now = datetime(2026, 10, 29, 12, 16, tzinfo=timezone.utc)
        self.assertEqual(
            campaign_deadline(context().created_at),
            datetime(2026, 10, 29, 12, 15, tzinfo=timezone.utc),
        )
        with self.assertRaises(CampaignDeadlineExceeded):
            validate_execution_context(context(), now=now)

    def test_source_scan_and_target_state_are_execution_guards(self):
        with self.assertRaisesRegex(Exception, "successful"):
            validate_execution_context(context(source_scan_status="FAILED"))
        with self.assertRaisesRegex(Exception, "not runnable"):
            validate_execution_context(context(target_status="CANCELLED"))
        with self.assertRaises(CampaignCancelled):
            validate_execution_context(context(campaign_status="CANCEL_REQUESTED"))

    def test_full_scan_lock_contention_blocks_runner(self):
        cursor = Cursor((False,))
        conn = Connection(cursor)
        with self.assertRaises(LockUnavailable):
            acquire_runner_lock(lambda: conn)
        self.assertTrue(conn.closed)
        self.assertEqual(cursor.executions[0][1], (ASIP_ORCHESTRATION_LOCK_ID,))

    def test_lock_success_and_release_use_existing_lock_id(self):
        cursor = Cursor((True,))
        conn = Connection(cursor)
        acquired = acquire_runner_lock(lambda: conn)
        self.assertIs(acquired, conn)
        self.assertEqual(conn.commits, 1)
        cursor.row = (True,)
        release_runner_lock(conn)
        self.assertTrue(conn.closed)
        self.assertEqual(cursor.executions[-1][1], (ASIP_ORCHESTRATION_LOCK_ID,))


class NetworkSafetyTests(unittest.TestCase):
    def test_hostname_validation_rejects_literals_and_malformed_names(self):
        self.assertEqual(validate_hostname("Example.COM."), "example.com")
        for value in ("127.0.0.1", "[::1]", "bad..example", "-bad.example"):
            with self.subTest(value=value):
                with self.assertRaises(UnsafeHostname):
                    validate_hostname(value)

    def test_public_ipv4_and_ipv6_answers_are_pinned(self):
        resolution = validate_dns_answers(
            "example.com", ["8.8.8.8", "2001:4860:4860::8888"]
        )
        self.assertEqual(len(resolution.addresses), 2)
        self.assertEqual(validate_pinned_address(resolution, "8.8.8.8"), "8.8.8.8")
        with self.assertRaises(DNSRebindingDetected):
            validate_pinned_address(resolution, "1.1.1.1")

    def test_private_reserved_and_malformed_dns_answers_are_rejected(self):
        for answer in ("127.0.0.1", "10.0.0.1", "::1", "not-an-ip"):
            with self.subTest(answer=answer):
                with self.assertRaises(UnsafeAddress):
                    validate_dns_answers("example.com", [answer])

    def test_scheme_ports_timeout_and_redirects_are_bounded(self):
        resolution = validate_dns_answers("example.com", ["8.8.8.8"])
        plan = build_request_plan("example.com", resolution, scheme="https")
        self.assertEqual(plan.port, 443)
        self.assertEqual(plan.url, "https://example.com")
        with self.assertRaises(UnsupportedRequest):
            build_request_plan("example.com", resolution, port=8443)
        with self.assertRaises(UnsupportedRequest):
            build_request_plan("example.com", resolution, scheme="ftp")
        with self.assertRaises(UnsupportedRequest):
            build_request_plan("example.com", resolution, timeout_seconds=31)
        with self.assertRaises(RedirectRejected):
            reject_redirect("https://other.example/")

    def test_evidence_sanitization_redacts_secrets_and_bounds_output(self):
        evidence = sanitize_evidence({
            "server": "Apache",
            "authorization": "Bearer very-secret-token",
            "set-cookie": "session=secret",
            "banner": "token=abc123\n",
        })
        self.assertNotIn("very-secret-token", evidence)
        self.assertNotIn("session=secret", evidence)
        self.assertNotIn("token=abc123", evidence)
        self.assertNotIn("\n", evidence)
        self.assertLessEqual(len(evidence), 2048)


class OfflineEvaluationTests(unittest.TestCase):
    def test_runner_is_not_registered_in_startup_or_public_api(self):
        main_source = (BACKEND / "main.py").read_text(encoding="utf-8")
        self.assertNotIn("adhoc_runner", main_source)
        self.assertNotIn('@app.post("/v2/adhoc/campaigns")', main_source)
        self.assertNotIn('@app.post("/v2/adhoc/campaigns/{campaign_id}/cancel")', main_source)

    def test_php_evaluators_are_reused_without_database_or_network(self):
        result = evaluate_php_observation(
            {"technology": "PHP", "version": "8.2.34"}, "2026-10-28"
        )
        self.assertEqual(result["lifecycle"]["status"], "security_support")
        self.assertEqual(
            result["cve_intelligence"]["candidates"][0]["applicability_status"],
            "potentially_affected",
        )

    def test_runner_execution_path_is_not_implemented_or_networked(self):
        runner = AdhocCampaignRunner(
            policy=RunnerPolicy(enabled=True),
            transport=mock.Mock(),
        )
        with self.assertRaises(RunnerExecutionUnavailable):
            runner.execute_prepared(context())
        runner.transport.request.assert_not_called()

    def test_context_query_contains_no_canonical_writes(self):
        cursor = Cursor()
        with self.assertRaises(TargetNotFound):
            load_execution_context(cursor, 10, 20)
        for query, _ in cursor.executions:
            self.assertTrue(query.lstrip().upper().startswith("SELECT"))
            read_sql = query.upper().replace("FOR UPDATE", "")
            self.assertNotRegex(read_sql, r"\b(INSERT|UPDATE|DELETE|TRUNCATE)\b")


if __name__ == "__main__":
    unittest.main()
