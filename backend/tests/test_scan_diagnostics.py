import importlib
import importlib.util
import json
import logging
import pathlib
import sys
import threading
import types
import unittest
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
REPOSITORY = BACKEND.parent
sys.path.insert(0, str(BACKEND))

import scan_diagnostics  # noqa: E402
_pg_fixture = importlib.import_module("test_remediation_package_2d1c")


def _load_orchestration():
    fake_db = types.ModuleType("db")
    fake_db.get_conn = mock.Mock()
    fake_db.require_running_scan = mock.Mock()
    name = f"scan_diag_orchestration_{id(fake_db)}"
    spec = importlib.util.spec_from_file_location(name, BACKEND / "orchestration.py")
    module = importlib.util.module_from_spec(spec)
    prior = sys.modules.get("db")
    try:
        sys.modules["db"] = fake_db
        spec.loader.exec_module(module)
    finally:
        if prior is None:
            sys.modules.pop("db", None)
        else:
            sys.modules["db"] = prior
    return module


class _FakeProcess:
    pid = 99999999
    stdout = None

    def __init__(self, returncode=0, output=""):
        self.returncode = returncode
        self.output = output

    def communicate(self, timeout=None):
        return self.output, None


class _InterruptProcess(_FakeProcess):
    def communicate(self, timeout=None):
        raise KeyboardInterrupt()


class _ApiCursor:
    def __init__(self, one=None, many=None):
        self.one = one
        self.many = many or []
        self.query = None

    def execute(self, query, params=None):
        self.query = query

    def fetchone(self):
        return self.one

    def fetchall(self):
        return self.many


class _ApiConnection:
    def __init__(self, cursor):
        self._cursor = cursor
        self.closed = False

    def cursor(self):
        return self._cursor

    def close(self):
        self.closed = True


class ScanDiagnosticsApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with mock.patch("logging.FileHandler", return_value=logging.NullHandler()):
            cls.main = importlib.import_module("main")

    def test_detail_response_is_bounded_and_excludes_raw_values(self):
        doc = scan_diagnostics.empty_diagnostics()
        doc["attempts"] = [{
            "stage": "SAN Expansion", "order": 3, "attempt": 1,
            "status": "SUCCEEDED", "started_at": "2026-11-01T00:00:00+00:00",
            "completed_at": "2026-11-01T00:00:02+00:00",
            "duration_seconds": 2.0, "error_category": None,
            "worker_summary": {
                "selected_parent_targets": 5,
                "raw_logs": "secret-looking log text",
                "api_key": "do-not-return",
            },
        }]
        cursor = _ApiCursor(one=(17, "SUCCEEDED", "scan-time", "start", "end",
                                "seed.example", 12, 2.0, doc))
        conn = _ApiConnection(cursor)
        with mock.patch.object(self.main, "get_conn", return_value=conn):
            result = self.main.frontend_v2_scan_detail(17)
        self.assertTrue(conn.closed)
        self.assertEqual(result["status"], "SUCCEEDED")
        self.assertTrue(result["diagnostics_available"])
        self.assertEqual(result["stage_attempts"][0]["worker_summary"],
                         {"selected_parent_targets": 5})
        self.assertNotIn("raw_logs", json.dumps(result))
        self.assertNotIn("do-not-return", json.dumps(result))
        self.assertIn("stage_diagnostics", cursor.query)

    def test_historical_null_diagnostics_remain_unknown(self):
        cursor = _ApiCursor(one=(16, "SUCCEEDED", "scan-time", "start", "end",
                                "seed.example", 10, 30.0, None))
        with mock.patch.object(self.main, "get_conn", return_value=_ApiConnection(cursor)):
            result = self.main.frontend_v2_scan_detail(16)
        self.assertFalse(result["diagnostics_available"])
        self.assertIsNone(result["stage_attempts"])
        self.assertIsNone(result["current_stage"])
        self.assertIsNone(result["failure_category"])

    def test_running_response_only_exposes_current_stage_for_running_scan(self):
        doc = scan_diagnostics.empty_diagnostics()
        doc["current_stage"] = {
            "stage": "DNS Resolution", "order": 6, "attempt": 1,
            "started_at": "start",
        }
        cursor = _ApiCursor(one=(18, "RUNNING", "scan-time", "start", None,
                                "seed.example", 3, 4.0, doc))
        with mock.patch.object(self.main, "get_conn", return_value=_ApiConnection(cursor)):
            result = self.main.frontend_v2_scan_detail(18)
        self.assertEqual(result["current_stage"]["stage"], "DNS Resolution")
        self.assertIsNone(result["completed_at"])
        self.assertEqual(result["duration_seconds"], 4.0)

    def test_scan_list_contract_is_unchanged(self):
        row = (17, "SUCCEEDED", "time", "start", "end", "seed.example", 12, 2.0)
        cursor = _ApiCursor(many=[row])
        with mock.patch.object(self.main, "get_conn", return_value=_ApiConnection(cursor)), \
                mock.patch.object(self.main, "get_latest_authoritative_scan_id", return_value=17), \
                mock.patch.object(self.main, "get_previous_authoritative_scan_id", return_value=16):
            result = self.main.frontend_v2_scans()
        self.assertEqual(set(result), {
            "current_authoritative_scan_id", "previous_authoritative_scan_id", "scans"
        })
        self.assertEqual(set(result["scans"][0]), {
            "scan_id", "status", "scan_time", "started_at", "completed_at",
            "seed", "asset_count", "duration_seconds", "is_current_authoritative",
            "is_previous_authoritative",
        })

    def test_mismatched_scan_outcome_is_not_reported_as_success(self):
        doc = scan_diagnostics.empty_diagnostics()
        doc["scan_outcome"] = {"status": "SUCCEEDED", "completed_at": "later"}
        projected = scan_diagnostics.api_diagnostics(doc, "RUNNING")
        self.assertIsNone(projected["scan_outcome"])

    def test_scan_failure_category_is_available_without_stage_attempt(self):
        doc = scan_diagnostics.empty_diagnostics()
        doc["scan_outcome"] = {
            "status": "FAILED", "completed_at": "later",
            "error_category": "SCAN_FAILED",
        }
        projected = scan_diagnostics.api_diagnostics(doc, "FAILED")
        self.assertEqual(projected["scan_outcome"]["error_category"], "SCAN_FAILED")


class ScanDiagnosticsPostgreSQLTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _pg_fixture.PostgreSQLIngestConvergenceTests.setUpClass.__func__(cls)
        conn = cls.connect()
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        ALTER TABLE scans
                            ADD COLUMN started_at timestamptz,
                            ADD COLUMN completed_at timestamptz,
                            ADD COLUMN runner_token text,
                            ADD COLUMN heartbeat_at timestamptz,
                            ADD COLUMN failure_reason text;
                        CREATE SEQUENCE scan_diagnostics_scans_id_seq;
                        ALTER TABLE scans ALTER COLUMN id
                            SET DEFAULT nextval('scan_diagnostics_scans_id_seq');
                    """)
                    cur.execute((REPOSITORY / "backend/migrations/010_add_scan_stage_diagnostics.sql")
                                .read_text(encoding="utf-8"))
        except Exception:
            _pg_fixture.PostgreSQLIngestConvergenceTests.tearDownClass.__func__(cls)
            raise
        finally:
            conn.close()
        cls.orchestration = _load_orchestration()
        cls.orchestration.get_conn = cls.connect

    @classmethod
    def tearDownClass(cls):
        _pg_fixture.PostgreSQLIngestConvergenceTests.tearDownClass.__func__(cls)

    @classmethod
    def connect(cls):
        return cls.psycopg2.connect(**cls.connection_args)

    def setUp(self):
        conn = self.connect()
        with conn:
            with conn.cursor() as cur:
                cur.execute("TRUNCATE scans")
        conn.close()
        identity = {}
        self.scan_id = self.orchestration.create_scan(identity)
        self.token = identity["runner_token"]

    def _read_scan(self, scan_id=None):
        conn = self.connect()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT status, runner_token, stage_diagnostics FROM scans WHERE id=%s",
                    (scan_id or self.scan_id,),
                )
                return cur.fetchone()
        finally:
            conn.close()

    def _start(self, name="DNS Resolution", order=6, attempt=1,
               scan_id=None, token=None):
        conn = self.connect()
        try:
            return scan_diagnostics.start_stage_attempt(
                conn, scan_id or self.scan_id, token or self.token,
                name, order, attempt,
            )
        finally:
            conn.close()

    def _finish(self, status="SUCCEEDED", name="DNS Resolution", order=6,
                attempt=1, error=None, summary=None):
        conn = self.connect()
        try:
            return scan_diagnostics.finish_stage_attempt(
                conn, self.scan_id, self.token, name, order, attempt,
                status, 1.25, error, summary,
            )
        finally:
            conn.close()

    def test_new_scan_has_empty_versioned_diagnostics(self):
        status, token, diagnostics = self._read_scan()
        self.assertEqual(status, "RUNNING")
        self.assertEqual(token, self.token)
        self.assertEqual(diagnostics, scan_diagnostics.empty_diagnostics() | {
            "last_updated_at": diagnostics["last_updated_at"]
        })
        self.assertEqual(diagnostics["attempts"], [])

    def test_start_success_and_sanitized_worker_summary_persist(self):
        self.assertTrue(self._start())
        summary = scan_diagnostics.extract_worker_summary(
            '2026 INFO http_stage_summary {"selected":4,"completed_observations":3,'
            '"worker_errors":0,"headers":"secret","raw_logs":"dont store"}'
        )
        self.assertEqual(summary, {
            "selected": 4, "completed_observations": 3, "worker_errors": 0
        })
        self.assertTrue(self._finish(summary=summary))
        attempt = self._read_scan()[2]["attempts"][0]
        self.assertEqual(attempt["status"], "SUCCEEDED")
        self.assertEqual(attempt["duration_seconds"], 1.25)
        self.assertEqual(attempt["worker_summary"], summary)

    def test_port_scan_destination_observations_are_bounded_and_sanitized(self):
        raw = {
            "selected": 2,
            "completed": 2,
            "no_sensitive_ports": 1,
            "nmap_destination_observations": [
                {"domain_id": 9, "status": "complete", "destination_ip": "8.8.8.8"},
                {"domain_id": 10, "status": "skipped", "destination_ip": None},
                {"domain_id": 11, "status": "complete", "destination_ip": "not-an-ip"},
                {"domain_id": 12, "status": "complete", "destination_ip": "8.8.4.4", "domain": "secret.example"},
            ],
            "raw_logs": "do not persist",
        }
        summary = scan_diagnostics.extract_worker_summary(
            "ASIP_WORKER_SUMMARY " + json.dumps(raw)
        )
        self.assertEqual(summary["nmap_destination_observations"], [
            {"domain_id": 9, "status": "complete", "destination_ip": "8.8.8.8"},
            {"domain_id": 10, "status": "skipped"},
            {"domain_id": 12, "status": "complete", "destination_ip": "8.8.4.4"},
        ])
        self.assertNotIn("raw_logs", summary)
        self.assertNotIn("secret.example", json.dumps(summary))
        too_many = {
            "selected": 20,
            "nmap_destination_observations": [
                {"domain_id": i, "status": "complete", "destination_ip": "8.8.8.8"}
                for i in range(1, 25)
            ],
        }
        bounded = scan_diagnostics.sanitize_worker_summary(too_many)
        self.assertEqual(len(bounded["nmap_destination_observations"]),
                         scan_diagnostics.MAX_DESTINATION_OBSERVATIONS)
        long_addresses = {
            "selected": 16,
            "nmap_destination_observations": [
                {"domain_id": i, "status": "complete", "destination_ip": "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"}
                for i in range(1, 17)
            ],
        }
        bounded_ipv6 = scan_diagnostics.sanitize_worker_summary(long_addresses)
        self.assertIsNotNone(bounded_ipv6)
        self.assertLessEqual(
            len(json.dumps(bounded_ipv6, separators=(",", ":"))),
            scan_diagnostics.MAX_SUMMARY_JSON_BYTES,
        )

    def test_retry_keeps_failed_attempt_then_success(self):
        self.assertTrue(self._start("Recon", 0, 1))
        self.assertTrue(self._finish("FAILED", "Recon", 0, 1, "RETRYABLE_INCOMPLETE"))
        self.assertTrue(self._start("Recon", 0, 2))
        self.assertTrue(self._finish("SUCCEEDED", "Recon", 0, 2))
        attempts = self._read_scan()[2]["attempts"]
        self.assertEqual([item["status"] for item in attempts], ["FAILED", "SUCCEEDED"])
        self.assertEqual([item["attempt"] for item in attempts], [1, 2])
        self.assertEqual(attempts[0]["error_category"], "RETRYABLE_INCOMPLETE")

    def test_timeout_and_cancellation_outcomes_are_distinct(self):
        self.assertTrue(self._start("HTTP", 7, 1))
        self.assertTrue(self._finish("TIMED_OUT", "HTTP", 7, 1, "STAGE_TIMEOUT"))
        self.assertTrue(self._start("Port Scan", 9, 1))
        self.assertTrue(self._finish("CANCELLED", "Port Scan", 9, 1, "INTERRUPTED"))
        attempts = self._read_scan()[2]["attempts"]
        self.assertEqual([item["status"] for item in attempts], ["TIMED_OUT", "CANCELLED"])

    def test_stale_token_stopped_scan_and_other_scan_are_rejected(self):
        before = self._read_scan()[2]
        self.assertFalse(self._start(token="stale-runner"))
        self.assertFalse(self._start(scan_id=self.scan_id + 999))
        conn = self.connect()
        with conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE scans SET status='SUCCEEDED' WHERE id=%s", (self.scan_id,))
        conn.close()
        self.assertFalse(self._start())
        self.assertEqual(self._read_scan()[2], before)

    def test_concurrent_stage_updates_do_not_lose_attempts(self):
        barrier = threading.Barrier(3)
        outcomes = []

        def start(name, order):
            barrier.wait()
            outcomes.append(self._start(name, order, 1))

        threads = [
            threading.Thread(target=start, args=("Stage A", 1)),
            threading.Thread(target=start, args=("Stage B", 2)),
        ]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=5)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(outcomes, [True, True])
        self.assertEqual(len(self._read_scan()[2]["attempts"]), 2)

    def test_attempt_limit_is_bounded(self):
        conn = self.connect()
        try:
            with conn:
                with conn.cursor() as cur:
                    doc = scan_diagnostics.empty_diagnostics()
                    doc["attempts"] = [{"stage": "x", "order": i, "attempt": 1,
                                        "status": "FAILED"}
                                       for i in range(scan_diagnostics.MAX_STAGE_ATTEMPTS)]
                    cur.execute("UPDATE scans SET stage_diagnostics=%s::jsonb WHERE id=%s",
                                (json.dumps(doc), self.scan_id))
            with self.assertRaisesRegex(ValueError, "attempt limit"):
                scan_diagnostics.start_stage_attempt(
                    conn, self.scan_id, self.token, "Overflow", 33, 1
                )
        finally:
            conn.close()

    def test_orchestrator_success_failure_and_cancel(self):
        module = self.orchestration
        original_get_conn = module.get_conn
        module.get_conn = self.connect
        self.addCleanup(setattr, module, "get_conn", original_get_conn)

        with mock.patch.object(module.subprocess, "Popen",
                               return_value=_FakeProcess(0, 'http_stage_summary {"selected":1}')):
            self.assertEqual(module.run_step("HTTP", "mock", 1, 2,
                                             scan_id=self.scan_id,
                                             runner_token=self.token,
                                             stage_order=1), 0)
        attempt = self._read_scan()[2]["attempts"][-1]
        self.assertEqual(attempt["status"], "SUCCEEDED")
        self.assertEqual(attempt["worker_summary"], {"selected": 1})

        with mock.patch.object(module.subprocess, "Popen",
                               return_value=_FakeProcess(9)), \
                mock.patch.object(module, "stop_active_child"):
            self.assertEqual(module.run_step("Failure", "mock", 1, 2,
                                             scan_id=self.scan_id,
                                             runner_token=self.token,
                                             stage_order=2), 9)
        self.assertEqual(self._read_scan()[2]["attempts"][-1]["error_category"],
                         "NONZERO_EXIT")

        with mock.patch.object(module.subprocess, "Popen", return_value=_InterruptProcess()), \
                mock.patch.object(module, "stop_active_child"):
            with self.assertRaises(KeyboardInterrupt):
                module.run_step("Cancelled", "mock", 1, 2,
                                scan_id=self.scan_id,
                                runner_token=self.token,
                                stage_order=3)
        self.assertEqual(self._read_scan()[2]["attempts"][-1]["status"], "CANCELLED")

    def test_stale_runner_does_not_launch_stage(self):
        module = self.orchestration
        with mock.patch.object(module, "get_conn", self.connect), \
                mock.patch.object(module.subprocess, "Popen") as popen:
            with self.assertRaises(module.RunnerLeaseError):
                module.run_step("Must not start", "mock", 1, 1,
                                scan_id=self.scan_id,
                                runner_token="stale-token",
                                stage_order=0)
        popen.assert_not_called()

    def test_terminal_scan_outcome_is_atomic_and_not_false_success(self):
        self.orchestration.mark_scan_terminal(
            self.scan_id, "FAILED", failure_reason="INTERRUPTED",
            runner_token=self.token,
        )
        status, _token, diagnostics = self._read_scan()
        self.assertEqual(status, "FAILED")
        self.assertEqual(diagnostics["scan_outcome"]["status"], "FAILED")
        self.assertEqual(diagnostics["scan_outcome"]["error_category"], "INTERRUPTED")
        self.assertIsNone(diagnostics["current_stage"])


if __name__ == "__main__":
    unittest.main()
