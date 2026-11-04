import importlib.util
import json
import pathlib
import os
import sys
import threading
import time
import types
import unittest
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))


def load_worker():
    name = f"http_observation_concurrency_{len(sys.modules)}"
    spec = importlib.util.spec_from_file_location(
        name, BACKEND / "http_observation_worker.py"
    )
    module = importlib.util.module_from_spec(spec)
    previous_argv = sys.argv[:]
    try:
        sys.argv = ["http_observation_worker.py", "17"]
        spec.loader.exec_module(module)
    finally:
        sys.argv = previous_argv
    return module


class FakeCursor:
    def __init__(self):
        self.rowcount = 1
        self.executions = []

    def execute(self, sql, params=None):
        self.executions.append((sql, params))
        self.rowcount = 1


class FakeConnection:
    def __init__(self, identity):
        self.identity = identity
        self._cursor = FakeCursor()
        self.closed = False
        self.commits = 0

    def cursor(self):
        return self._cursor

    def commit(self):
        self.commits += 1

    def close(self):
        self.closed = True


def response(status="RESPONDED", *, stop_reason=None, redirects=0):
    return {
        "http_observation_status": status,
        "http_status": 200 if status == "RESPONDED" else 0,
        "http_reason": "OK" if status == "RESPONDED" else "",
        "final_url": "https://asset.example/" if status == "RESPONDED" else None,
        "final_status": 200 if status == "RESPONDED" else None,
        "redirect_count": redirects,
        "redirect_evidence": {
            "observed_hops": [{}] * redirects,
            "stop_reason": stop_reason,
        },
        "title": "example",
    }


class HttpObservationConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.worker = load_worker()
        self.connections = []
        self.connection_lock = threading.Lock()

        def new_connection():
            with self.connection_lock:
                connection = FakeConnection(len(self.connections) + 1)
                self.connections.append(connection)
                return connection

        self.worker.get_conn = new_connection
        self.worker.require_running_scan = mock.Mock()
        self.worker.recheck_active_authorization = mock.Mock(
            return_value=(True, "authorized")
        )

    @staticmethod
    def rows(count):
        return [(i, f"asset-{i}.example", f"198.51.100.{i}")
                for i in range(1, count + 1)]

    def test_worker_configuration_defaults_and_clamps_to_two(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(self.worker.configured_http_workers(None), 2)
        with mock.patch.dict(os.environ, {"ASIP_HTTP_WORKERS": "1"}):
            self.assertEqual(self.worker.configured_http_workers(None), 1)
        for value in (0, -1, "invalid"):
            with self.subTest(value=value):
                self.assertEqual(self.worker.configured_http_workers(value), 1 if value in (0, -1) else 2)
        for value in (2, 4, 99):
            with self.subTest(value=value):
                self.assertEqual(self.worker.configured_http_workers(value), 2)

    def test_two_workers_are_the_default_maximum_and_connections_are_independent(self):
        active = 0
        maximum = 0
        lock = threading.Lock()

        def probe(_domain, *, before_request, **_kwargs):
            nonlocal active, maximum
            self.assertTrue(before_request())
            with lock:
                active += 1
                maximum = max(maximum, active)
            time.sleep(0.025)
            with lock:
                active -= 1
            return response()

        self.worker.http_probe = probe
        summary = self.worker.run_observations(self.rows(6), 17)
        self.assertEqual(maximum, 2)
        self.assertEqual(summary["maximum_observed_concurrency"], 2)
        self.assertEqual(summary["configured_workers"], 2)
        self.assertEqual(summary["completed_observations"], 6)
        self.assertEqual(len(self.connections), 6)
        self.assertEqual(len({conn.identity for conn in self.connections}), 6)
        self.assertTrue(all(conn.closed for conn in self.connections))

    def test_one_worker_is_sequential(self):
        active = 0
        maximum = 0
        lock = threading.Lock()

        def probe(_domain, *, before_request, **_kwargs):
            nonlocal active, maximum
            self.assertTrue(before_request())
            with lock:
                active += 1
                maximum = max(maximum, active)
            time.sleep(0.01)
            with lock:
                active -= 1
            return response()

        self.worker.http_probe = probe
        summary = self.worker.run_observations(self.rows(3), 17, workers=1)
        self.assertEqual(maximum, 1)
        self.assertEqual(summary["maximum_observed_concurrency"], 1)

    def test_deduplicates_by_domain_id_and_preserves_target_rows(self):
        calls = []

        def probe(domain, *, before_request, expected_ip):
            self.assertTrue(before_request())
            calls.append((domain, expected_ip))
            return response()

        self.worker.http_probe = probe
        rows = [self.rows(1)[0], (1, "duplicate.example", "198.51.100.9"), self.rows(2)[1]]
        summary = self.worker.run_observations(rows, 17, workers=1)
        self.assertEqual(summary["selected"], 2)
        self.assertEqual(calls, [
            ("asset-1.example", "198.51.100.1"),
            ("asset-2.example", "198.51.100.2"),
        ])
        writes = [entry for conn in self.connections for entry in conn._cursor.executions]
        self.assertEqual(len(writes), 2)
        self.assertEqual({params[-2:] for _sql, params in writes}, {(1, 17), (2, 17)})

    def test_authorization_denial_skips_probe_and_closes_connection(self):
        self.worker.recheck_active_authorization.return_value = (
            False, "authorization no longer valid"
        )
        self.worker.http_probe = mock.Mock()
        summary = self.worker.run_observations(self.rows(1), 17)
        self.assertEqual(summary["authorization_skips"], 1)
        self.worker.http_probe.assert_not_called()
        self.assertTrue(self.connections[0].closed)

    def test_authorization_failure_fails_stage_instead_of_silent_success(self):
        self.worker.recheck_active_authorization.return_value = (
            False, "authorization check failed"
        )
        self.worker.http_probe = mock.Mock()
        with self.assertRaises(self.worker.ObservationStageError):
            self.worker.run_observations(self.rows(1), 17)
        self.worker.http_probe.assert_not_called()

    def test_probe_rechecks_authorization_and_revocation_prevents_contact(self):
        self.worker.recheck_active_authorization.side_effect = [
            (True, "authorized"),
            (False, "authorization no longer valid"),
        ]
        contacted = []

        def probe(_domain, *, before_request, **_kwargs):
            if before_request():
                contacted.append(True)
            return response("UNKNOWN")

        self.worker.http_probe = probe
        summary = self.worker.run_observations(self.rows(1), 17)
        self.assertEqual(contacted, [])
        self.assertEqual(summary["failed_incomplete"], 1)

    def test_no_response_is_reported_separately_from_worker_errors(self):
        self.worker.http_probe = lambda *_args, **_kwargs: response("NO_RESPONSE")
        summary = self.worker.run_observations(self.rows(1), 17)
        self.assertEqual(summary["http_no_response"], 1)
        self.assertEqual(summary["worker_errors"], 0)

    def test_worker_exception_fails_stage_and_does_not_dispatch_remaining_targets(self):
        calls = []

        def probe(domain, *, before_request, **_kwargs):
            calls.append(domain)
            if domain == "asset-1.example":
                raise OSError("mocked database or worker failure")
            time.sleep(0.04)
            return response()

        self.worker.http_probe = probe
        with self.assertRaises(self.worker.ObservationStageError):
            self.worker.run_observations(self.rows(4), 17, workers=2)
        self.assertLessEqual(len(calls), 2)

    def test_pre_cancelled_stage_starts_no_targets(self):
        event = threading.Event()
        event.set()
        self.worker.http_probe = mock.Mock()
        with self.assertRaises(self.worker.ObservationInterrupted):
            self.worker.run_observations(self.rows(3), 17, cancel_event=event)
        self.worker.http_probe.assert_not_called()
        self.assertEqual(self.connections, [])

    def test_cancellation_stops_dispatching_targets_and_fails_stage(self):
        event = threading.Event()
        calls = []

        def probe(domain, *, before_request, **_kwargs):
            self.assertTrue(before_request())
            calls.append(domain)
            event.set()
            return response()

        self.worker.http_probe = probe
        with self.assertRaises(self.worker.ObservationInterrupted):
            self.worker.run_observations(
                self.rows(4), 17, workers=1, cancel_event=event
            )
        self.assertEqual(calls, ["asset-1.example"])

    def test_stage_and_target_metrics_are_structured_and_accurate(self):
        self.worker.http_probe = lambda *_args, **_kwargs: response(redirects=2)
        with self.assertLogs(self.worker.logger, level="INFO") as captured:
            summary = self.worker.run_observations(self.rows(1), 17, workers=1)
        target = json.loads(next(line.split("http_target ", 1)[1]
                                 for line in captured.output if "http_target " in line))
        stage = json.loads(next(line.split("http_stage_summary ", 1)[1]
                                for line in captured.output if "http_stage_summary " in line))
        self.assertEqual(target["scan_id"], 17)
        self.assertEqual(target["domain_id"], 1)
        self.assertEqual(target["redirect_count"], 2)
        self.assertFalse(target["timeout_or_error"])
        self.assertEqual(stage["selected"], 1)
        self.assertEqual(stage["completed_observations"], 1)
        self.assertEqual(stage["maximum_observed_concurrency"], 1)
        self.assertGreaterEqual(summary["elapsed_seconds"], 0)

    def test_http_result_fields_and_redirect_evidence_are_passed_unchanged(self):
        expected = response(redirects=1)
        self.worker.http_probe = lambda *_args, **_kwargs: expected
        self.worker.run_observations(self.rows(1), 17, workers=1)
        sql, params = self.connections[0]._cursor.executions[0]
        self.assertIn("http_status", sql)
        self.assertIn("final_url", sql)
        self.assertIn("final_status", sql)
        self.assertIn("http_redirect_evidence", sql)
        self.assertIn('"observed_hops"', params[5])
        self.assertEqual(params[-2:], (1, 17))


if __name__ == "__main__":
    unittest.main()
