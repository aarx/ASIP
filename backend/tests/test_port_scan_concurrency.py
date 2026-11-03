import importlib.util
import logging
import pathlib
import subprocess
import sys
import threading
import time
import types
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]


def load_worker():
    fake_db = types.ModuleType("db")
    fake_db.get_conn = mock.Mock()
    fake_db.require_running_scan = mock.Mock()
    auth = types.ModuleType("authorization_policy")
    auth.active_scan_authorization_sql = mock.Mock(return_value="TRUE")
    auth.recheck_active_authorization = mock.Mock(return_value=(True, "authorized"))
    spec = importlib.util.spec_from_file_location(
        f"port_scan_worker_test_{id(fake_db)}", BACKEND / "port_scan_worker.py"
    )
    module = importlib.util.module_from_spec(spec)
    prior = {key: sys.modules.get(key) for key in ("db", "authorization_policy")}
    argv = sys.argv[:]
    try:
        sys.modules["db"] = fake_db
        sys.modules["authorization_policy"] = auth
        sys.argv = ["port_scan_worker.py", "42"]
        with mock.patch("logging.FileHandler", return_value=logging.NullHandler()):
            spec.loader.exec_module(module)
    finally:
        sys.argv = argv
        for key, value in prior.items():
            if value is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = value
    module._test_db = fake_db
    module._test_auth = auth
    return module


class Cursor:
    def __init__(self, rows=()):
        self.rows = list(rows)
        self.executions = []

    def execute(self, sql, params=None):
        self.executions.append((sql, params))

    def fetchall(self):
        return list(self.rows)

    def fetchone(self):
        return (1,)


class Connection:
    def __init__(self, cursor=None):
        self._cursor = cursor or Cursor()
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


class PortScanConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.worker = load_worker()

    def test_worker_count_defaults_and_is_clamped(self):
        self.assertEqual(self.worker.configured_worker_count(None), 2)
        self.assertEqual(self.worker.configured_worker_count("1"), 1)
        self.assertEqual(self.worker.configured_worker_count("4"), 4)
        self.assertEqual(self.worker.configured_worker_count("40"), 4)
        self.assertEqual(self.worker.configured_worker_count("invalid"), 2)
        self.assertEqual(self.worker.configured_worker_count("0"), 1)

    def _measure_pool(self, worker_count, inputs):
        lock = threading.Lock()
        active = 0
        peak = 0
        seen = []

        def target(_scan_id, domain_id, domain, _cancel_event):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
                seen.append((domain_id, domain))
            time.sleep(0.015)
            with lock:
                active -= 1
            return {"status": "complete", "domain": domain}

        result = self.worker.run_port_scan_pool(
            42, inputs, worker_count=worker_count, target_worker=target
        )
        return peak, seen, result

    def test_default_pool_never_exceeds_two_and_deduplicates_targets(self):
        targets = [(i, f"host{i}.example") for i in range(8)]
        peak, seen, outcomes = self._measure_pool(2, targets + [targets[0]])
        self.assertEqual(peak, 2)
        self.assertEqual(len(seen), 8)
        self.assertEqual({item[0] for item in seen}, set(range(8)))
        self.assertEqual(len(outcomes), 8)

    def test_configured_pool_clamps_at_four_and_one_is_serial(self):
        targets = [(i, f"host{i}.example") for i in range(10)]
        peak, seen, _ = self._measure_pool(99, targets)
        self.assertEqual(peak, 4)
        self.assertEqual(len(seen), len(targets))
        peak, seen, outcomes = self._measure_pool(1, targets)
        self.assertEqual(peak, 1)
        self.assertEqual(seen, targets)
        self.assertEqual(len(outcomes), len(targets))

    def test_target_selection_preserves_membership_and_authorization_predicates(self):
        cursor = Cursor([(9, "member.example")])
        rows = self.worker.get_resolving_domains(cursor, 42)
        sql, params = cursor.executions[0]
        self.assertEqual(rows, [(9, "member.example")])
        self.assertIn("DISTINCT ON (d.id)", sql)
        self.assertIn("scan_results", sql)
        self.assertIn("s.has_ip = TRUE", sql)
        self.assertIn("active_scan_authorization_sql", self.worker.get_resolving_domains.__code__.co_names)
        self.assertEqual(params, (42, 42))

    def test_denied_or_revoked_target_never_starts_nmap(self):
        conn = Connection()
        self.worker._test_db.get_conn.return_value = conn
        self.worker._test_auth.recheck_active_authorization.return_value = (
            False, "scope revoked"
        )
        nmap = mock.Mock()
        self.worker.scan_ports = nmap
        result = self.worker.scan_target(42, 9, "outside.example", threading.Event())
        self.assertEqual(result["status"], "skipped")
        nmap.assert_not_called()
        self.assertFalse(any("INSERT INTO domain_ports" in sql for sql, _ in conn._cursor.executions))
        self.assertTrue(conn.closed)

    def test_authorization_database_failure_fails_stage_without_nmap(self):
        conn = Connection()
        self.worker._test_db.get_conn.return_value = conn
        self.worker._test_auth.recheck_active_authorization.return_value = (
            False, "authorization check failed"
        )
        nmap = mock.Mock()
        self.worker.scan_ports = nmap
        result = self.worker.scan_target(42, 9, "member.example", threading.Event())
        self.assertEqual(result["status"], "failed")
        nmap.assert_not_called()
        with self.assertRaises(self.worker.PortScanStageError):
            self.worker.run_port_scan_pool(
                42,
                [(9, "member.example")],
                target_worker=lambda *_args: result,
            )

    def test_authorization_revoked_after_nmap_prevents_result_write(self):
        conn = Connection()
        self.worker._test_db.get_conn.return_value = conn
        self.worker._test_auth.recheck_active_authorization.side_effect = [
            (True, "authorized"), (False, "scope revoked")
        ]
        nmap = mock.Mock(return_value=[(443, "https")])
        self.worker.scan_ports = nmap
        result = self.worker.scan_target(42, 9, "member.example", threading.Event())
        self.assertEqual(result["status"], "failed")
        nmap.assert_called_once()
        self.assertFalse(any("INSERT INTO domain_ports" in sql for sql, _ in conn._cursor.executions))
        self.assertEqual(conn.rollbacks, 1)

    def test_successful_target_uses_membership_conditional_deduplicated_write(self):
        conn = Connection()
        self.worker._test_db.get_conn.return_value = conn
        self.worker._test_auth.recheck_active_authorization.return_value = (
            True, "authorized"
        )
        self.worker.scan_ports = mock.Mock(return_value=[(443, "https"), (8443, "https-alt")])
        result = self.worker.scan_target(42, 9, "member.example", threading.Event())
        self.assertEqual(result, {"status": "complete", "domain": "member.example", "ports": 2})
        writes = [(sql, params) for sql, params in conn._cursor.executions if "INSERT INTO domain_ports" in sql]
        self.assertEqual(len(writes), 2)
        self.assertTrue(all("scan_results" in sql and "ON CONFLICT" in sql for sql, _ in writes))
        self.assertEqual(writes[0][1], (9, 42, 443, "https", 42, 9))
        self.assertEqual(conn.commits, 2)

    def test_nmap_profile_is_unchanged_and_open_ports_are_parsed(self):
        proc = mock.Mock()
        proc.communicate.return_value = ("443/tcp open https\n", "")
        proc.returncode = 0
        with mock.patch.object(self.worker.subprocess, "Popen", return_value=proc) as popen:
            result = self.worker.scan_ports("member.example")
        self.assertEqual(result, [(443, "https")])
        args, kwargs = popen.call_args
        self.assertEqual(args[0][:4], ["nmap", "-Pn", "-T3", "--open"])
        self.assertEqual(args[0][-1], "member.example")
        self.assertEqual(kwargs, {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "text": True})
        self.assertEqual(popen.call_count, 1)

    def test_timeout_and_cancellation_terminate_without_retry_or_partial_write(self):
        proc = mock.Mock()
        proc.poll.side_effect = [None, -15]
        proc.communicate.return_value = ("443/tcp open https\n", "")
        proc.returncode = -15
        with mock.patch.object(self.worker, "PORT_SCAN_TIMEOUT_SECONDS", 0), mock.patch.object(
            self.worker.subprocess, "Popen", return_value=proc
        ) as popen, self.assertRaises(self.worker.PortScanTimeout):
            self.worker.scan_ports("member.example")
        self.assertEqual(popen.call_count, 1)
        proc.terminate.assert_called_once()

        event = threading.Event()
        proc = mock.Mock()
        proc.poll.side_effect = [None, -15]

        communicate_calls = 0

        def in_flight(*_args, **_kwargs):
            nonlocal communicate_calls
            communicate_calls += 1
            if communicate_calls == 1:
                event.set()
                raise subprocess.TimeoutExpired("nmap", 0.25)
            return "443/tcp open https\n", ""

        proc.communicate.side_effect = in_flight
        with mock.patch.object(
            self.worker.subprocess, "Popen", return_value=proc
        ) as popen, self.assertRaises(self.worker.PortScanCancelled):
            self.worker.scan_ports("member.example", event)
        self.assertEqual(popen.call_count, 1)
        proc.terminate.assert_called_once()

    def test_worker_exception_isolated_but_marks_stage_incomplete(self):
        completed = threading.Event()

        def target(_scan_id, _domain_id, domain, _cancel):
            if domain == "bad.example":
                raise RuntimeError("mocked worker failure")
            completed.set()
            return {"status": "complete", "domain": domain}

        with self.assertRaisesRegex(self.worker.PortScanStageError, "incomplete"):
            self.worker.run_port_scan_pool(
                42,
                [(1, "bad.example"), (2, "good.example")],
                worker_count=2,
                target_worker=target,
            )
        self.assertTrue(completed.is_set())


if __name__ == "__main__":
    unittest.main()
