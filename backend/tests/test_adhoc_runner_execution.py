import pathlib
import sys
import unittest
from datetime import date, datetime, timezone
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from adhoc_runner import (  # noqa: E402
    AdhocCampaignRunner,
    LockUnavailable,
    RunnerPolicy,
    TransportResponse,
)


NOW = datetime(2026, 10, 29, 12, 1, tzinfo=timezone.utc)


class FakeRunnerCursor:
    def __init__(self, database):
        self.database = database
        self.rows = None
        self.rowcount = 0
        self.executions = database.executions

    def execute(self, query, params=None):
        sql = " ".join(query.split()).upper()
        self.executions.append((query, params))
        self.rows = None
        self.rowcount = 0

        if "PG_TRY_ADVISORY_LOCK" in sql:
            self.rows = [(self.database.lock_available,)]
        elif "PG_ADVISORY_UNLOCK" in sql:
            self.rows = [(True,)]
        elif sql.startswith("SELECT ID, STATUS, SOURCE_SCAN_ID, CREATED_AT"):
            campaign = self.database.campaign
            self.rows = [(
                campaign["id"], campaign["status"], campaign["source_scan_id"],
                campaign["created_at"], campaign["assessment_date"],
                campaign["dataset_revision"],
            )]
        elif sql.startswith("SELECT T.ID, T.TARGET_STATUS"):
            self.rows = [
                (target["id"], target["status"], target["id"] in self.database.results)
                for target in self.database.targets
            ]
        elif "FROM ADHOC_CAMPAIGN_TARGETS T" in sql and "C.ASSESSMENT_DATE" in sql:
            self.rows = [
                (
                    target["id"], target["source_scan_id"], target["domain_id"],
                    target["domain"], target["status"], self.database.campaign["created_at"],
                    self.database.campaign["assessment_date"],
                    self.database.campaign["dataset_revision"],
                )
                for target in self.database.targets if target["status"] == "PENDING"
            ]
        elif "FROM ADHOC_CAMPAIGNS C" in sql and "T.ID = %S" in sql:
            target_id = params[-1]
            target = next((item for item in self.database.targets if item["id"] == target_id), None)
            if target is None:
                self.rows = []
            else:
                campaign = self.database.campaign
                self.rows = [(
                    campaign["id"], campaign["status"], campaign["source_scan_id"],
                    campaign["created_at"], target["id"], target["status"],
                    target["source_scan_id"], target["domain_id"], "SUCCEEDED",
                    target["domain"], target["ownership_status"], target["scannable"],
                    target["validation_source"], campaign["assessment_date"],
                    campaign["dataset_revision"],
                )]
        elif sql.startswith("SELECT D.ID, D.DOMAIN"):
            target = self.database.target_for_domain(params[1])
            if target and target["source_scan_id"] == params[0] and target["authorized"]:
                self.rows = [(
                    target["domain_id"], target["domain"], "CONFIRMED", True, "manual"
                )]
            else:
                self.rows = []
        elif sql.startswith("UPDATE ADHOC_CAMPAIGN_TARGETS SET TARGET_STATUS = 'RUNNING'"):
            target_id = params[0]
            target = self.database.target(target_id)
            if target["status"] == "PENDING":
                target["status"] = "RUNNING"
                self.rowcount = 1
        elif sql.startswith("INSERT INTO ADHOC_CAMPAIGN_RESULTS"):
            self.database.results[params[1]] = {
                "campaign_id": params[0], "target_id": params[1],
                "execution_status": params[2], "evidence_status": params[3],
                "evaluation_status": params[4], "classification": params[5],
                "failure_code": params[6], "skip_reason_code": params[7],
                "observations": params[8], "lifecycle": params[9],
                "cve_intelligence": params[10], "observed_at": params[11],
                "dataset_revision": params[12],
            }
            self.rowcount = 1
        elif sql.startswith("UPDATE ADHOC_CAMPAIGN_TARGETS SET TARGET_STATUS = 'COMPLETED'"):
            target = self.database.target(params[0])
            target["status"] = "COMPLETED"
            self.rowcount = 1
        elif sql.startswith("UPDATE ADHOC_CAMPAIGN_TARGETS SET TARGET_STATUS = %S"):
            target = self.database.target(params[2])
            target["status"] = params[0]
            self.rowcount = 1
        elif sql.startswith("SELECT STATUS FROM ADHOC_CAMPAIGNS"):
            self.rows = [(self.database.campaign["status"],)]
        elif sql.startswith("UPDATE ADHOC_CAMPAIGNS SET STATUS"):
            self.database.campaign["status"] = params[0]
            if len(params) > 1:
                self.database.campaign["failure_code"] = params[1]
            self.rowcount = 1
        elif sql.startswith("SELECT COUNT(*), COUNT(*) FILTER"):
            statuses = [target["status"] for target in self.database.targets]
            self.rows = [(
                len(statuses), statuses.count("COMPLETED"), statuses.count("FAILED"),
                statuses.count("CANCELLED"), sum(status in {"PENDING", "RUNNING"} for status in statuses),
            )]

    def fetchone(self):
        if self.rows is None:
            return None
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows or []


class FakeRunnerConnection:
    def __init__(self, database):
        self.database = database
        self.closed = False
        self.commits = 0
        self.rollbacks = 0

    def cursor(self):
        return FakeRunnerCursor(self.database)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True


class FakeRunnerDatabase:
    def __init__(self, domains=None, lock_available=True):
        self.lock_available = lock_available
        self.executions = []
        self.campaign = {
            "id": 91, "status": "RUNNING", "source_scan_id": 16,
            "created_at": datetime(2026, 10, 29, 12, 0, tzinfo=timezone.utc),
            "assessment_date": date(2026, 10, 28),
            "dataset_revision": "2026-10-28", "failure_code": None,
        }
        self.targets = []
        for index, item in enumerate(domains or [(7, "approved.example")], start=1):
            domain_id, domain = item
            self.targets.append({
                "id": index, "domain_id": domain_id, "domain": domain,
                "source_scan_id": 16, "status": "PENDING",
                "ownership_status": "CONFIRMED", "scannable": True,
                "validation_source": "manual", "authorized": True,
            })
        self.results = {}
        self.connection = FakeRunnerConnection(self)

    def target(self, target_id):
        return next(target for target in self.targets if target["id"] == target_id)

    def target_for_domain(self, domain_id):
        return next((target for target in self.targets if target["domain_id"] == domain_id), None)


class FakeResolver:
    def __init__(self, answers=None, error=None):
        self.answers = answers or ["8.8.8.8"]
        self.error = error
        self.calls = []

    def resolve(self, hostname):
        self.calls.append(hostname)
        if self.error:
            raise self.error
        return self.answers


class FakeTransport:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.plans = []

    def request(self, plan):
        self.plans.append(plan)
        if self.error:
            raise self.error
        return self.response


def response(*, headers=None, peer="8.8.8.8", status=200, redirect_status=None,
             redirect_location=None, failure_code=None):
    return TransportResponse(
        http_status=status,
        connected_peer_ip=peer,
        redirect_status=redirect_status,
        redirect_location=redirect_location,
        fingerprint_headers=headers or {},
        observed_at=NOW,
        failure_code=failure_code,
    )


def service(database, resolver, transport, fingerprinter, *, clock=lambda: NOW,
            cancel_check=None):
    return AdhocCampaignRunner(
        policy=RunnerPolicy(enabled=True), resolver=resolver, transport=transport,
        fingerprinter=fingerprinter, operator_authorizer=lambda identity: identity == "operator",
        conn_factory=lambda: database.connection, clock=clock,
    ), cancel_check


class CampaignExecutionTests(unittest.TestCase):
    def test_successful_php_campaign_persists_candidate_without_canonical_writes(self):
        database = FakeRunnerDatabase()
        resolver = FakeResolver()
        transport = FakeTransport(response(headers={"Server": "PHP/8.2.34"}))
        fingerprinter = lambda headers: [{
            "technology": "php", "version": "8.2.34", "confidence": "high",
            "evidence_type": "server_header", "sanitized_evidence": headers["Server"],
        }]
        runner, cancel = service(database, resolver, transport, fingerprinter)
        result = runner.run_campaign(91, "operator", cancel_check=cancel)
        stored = database.results[1]
        self.assertEqual(result["status"], "SUCCEEDED")
        self.assertEqual(stored["classification"], "potential_cve")
        self.assertEqual(stored["evaluation_status"], "EVALUATED")
        self.assertTrue(stored["cve_intelligence"])
        self.assertEqual(database.targets[0]["status"], "COMPLETED")
        self.assertTrue(database.connection.closed)
        for query, _ in database.executions:
            upper = query.upper()
            if upper.lstrip().startswith(("INSERT", "UPDATE", "DELETE", "TRUNCATE")):
                self.assertRegex(upper, r"ADHOC_CAMPAIGN(S|_TARGETS|_RESULTS)")

    def test_no_php_fingerprint_is_evaluated_as_no_php_observation(self):
        database = FakeRunnerDatabase()
        runner, _ = service(
            database, FakeResolver(),
            FakeTransport(response(headers={"Server": "nginx/1.25.0"})),
            lambda headers: [{"technology": "nginx", "version": "1.25.0"}],
        )
        runner.run_campaign(91, "operator")
        self.assertEqual(database.results[1]["classification"], "no_php_observation")
        self.assertEqual(database.results[1]["evaluation_status"], "NOT_EVALUATED")

    def test_unknown_php_version_is_insufficient_evidence(self):
        database = FakeRunnerDatabase()
        runner, _ = service(
            database, FakeResolver(),
            FakeTransport(response(headers={"Server": "PHP"})),
            lambda headers: [{"technology": "php", "version": None}],
        )
        runner.run_campaign(91, "operator")
        self.assertEqual(database.results[1]["classification"], "insufficient_evidence")

    def test_revoked_authorization_is_persisted_without_transport(self):
        database = FakeRunnerDatabase()
        database.targets[0]["authorized"] = False
        transport = FakeTransport(response(headers={"Server": "PHP/8.2.34"}))
        runner, _ = service(
            database, FakeResolver(), transport,
            lambda headers: [{"technology": "php", "version": "8.2.34"}],
        )
        result = runner.run_campaign(91, "operator")
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(database.results[1]["failure_code"], "authorization_revoked")
        self.assertEqual(transport.plans, [])

    def test_unsafe_dns_peer_mismatch_redirect_and_timeout_are_failures(self):
        cases = (
            (FakeResolver(answers=["10.0.0.1"]), FakeTransport(response()), "unsafe_dns"),
            (FakeResolver(), FakeTransport(response(peer="1.1.1.1")), "peer_ip_mismatch"),
            (FakeResolver(), FakeTransport(response(redirect_status=302, redirect_location="https://other.example")), "redirect_rejected"),
            (FakeResolver(), FakeTransport(response(failure_code="transport_timeout")), "transport_timeout"),
        )
        for resolver, transport, expected in cases:
            with self.subTest(expected=expected):
                database = FakeRunnerDatabase()
                runner, _ = service(
                    database, resolver, transport,
                    lambda headers: [{"technology": "php", "version": "8.2.34"}],
                )
                runner.run_campaign(91, "operator")
                self.assertEqual(database.results[1]["failure_code"], expected)
                self.assertEqual(database.results[1]["observations"], "[]")

    def test_partial_failure_continues_serially_and_completes_partial(self):
        database = FakeRunnerDatabase(domains=[(7, "good.example"), (8, "bad.example")])
        resolver = FakeResolver()
        def resolve(hostname):
            resolver.calls.append(hostname)
            if hostname == "bad.example":
                raise RuntimeError("mock DNS failure")
            return ["8.8.8.8"]

        resolver.resolve = resolve
        runner, _ = service(
            database, resolver,
            FakeTransport(response(headers={"Server": "PHP/8.2.34"})),
            lambda headers: [{"technology": "php", "version": "8.2.34"}],
        )
        result = runner.run_campaign(91, "operator")
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(database.results[2]["failure_code"], "dns_resolution_failed")
        self.assertEqual(len(resolver.calls), 2)

    def test_cancellation_and_deadline_do_not_start_transport(self):
        for clock, cancel_check, expected_status in (
            (lambda: NOW, lambda: True, "CANCELLED"),
            (lambda: datetime(2026, 10, 29, 12, 20, tzinfo=timezone.utc), None, "FAILED"),
        ):
            with self.subTest(expected_status=expected_status):
                database = FakeRunnerDatabase()
                transport = FakeTransport(response())
                runner, _ = service(
                    database, FakeResolver(), transport,
                    lambda headers: [{"technology": "php", "version": "8.2.34"}],
                    clock=clock,
                )
                runner.run_campaign(91, "operator", cancel_check=cancel_check)
                self.assertEqual(database.campaign["status"], expected_status)
                self.assertEqual(transport.plans, [])

    def test_lock_contention_and_exception_release_lock(self):
        database = FakeRunnerDatabase(lock_available=False)
        runner, _ = service(
            database, FakeResolver(), FakeTransport(response()), lambda headers: [],
        )
        with self.assertRaises(LockUnavailable):
            runner.run_campaign(91, "operator")
        self.assertTrue(database.connection.closed)

        database = FakeRunnerDatabase()
        database.campaign["status"] = "QUEUED"
        runner, _ = service(
            database, FakeResolver(), FakeTransport(response()), lambda headers: [],
        )
        with self.assertRaises(Exception):
            runner.run_campaign(91, "operator")
        self.assertTrue(database.connection.closed)

    def test_duplicate_execution_is_rejected(self):
        database = FakeRunnerDatabase()
        runner, _ = service(
            database, FakeResolver(), FakeTransport(response()), lambda headers: [],
        )
        runner.run_campaign(91, "operator")
        with self.assertRaises(Exception):
            runner.run_campaign(91, "operator")


if __name__ == "__main__":
    unittest.main()
