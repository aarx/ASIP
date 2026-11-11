import importlib.util
import io
import logging
import pathlib
import subprocess
import sys
import threading
import time
import types
import unittest
from contextlib import redirect_stdout
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

import scan_diagnostics


BACKEND = pathlib.Path(__file__).resolve().parents[1]


def load_worker():
    fake_db = types.ModuleType("db")
    fake_db.get_conn = mock.Mock()
    fake_db.require_running_scan = mock.Mock()
    auth = types.ModuleType("authorization_policy")
    auth.active_scan_authorization_sql = mock.Mock(return_value="TRUE")
    auth.recheck_active_authorization = mock.Mock(return_value=(True, "authorized"))
    ownership = types.ModuleType("ownership")
    ownership.reporting_asset_class_sql = mock.Mock(return_value="'KNOWN'")
    spec = importlib.util.spec_from_file_location(
        f"port_scan_worker_test_{id(fake_db)}", BACKEND / "port_scan_worker.py"
    )
    module = importlib.util.module_from_spec(spec)
    names = ("db", "authorization_policy", "ownership")
    prior = {key: sys.modules.get(key) for key in names}
    argv = sys.argv[:]
    try:
        sys.modules.update({"db": fake_db, "authorization_policy": auth, "ownership": ownership})
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
    def __init__(self, rows=(), row=("member.example", "KNOWN", "8.8.8.8")):
        self.rows = list(rows)
        self.row = row
        self.executions = []

    def execute(self, sql, params=None):
        self.executions.append((sql, params))

    def fetchall(self):
        return list(self.rows)

    def fetchone(self):
        return self.row


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

    def test_target_selection_is_current_scan_hostname_based_and_authorized(self):
        cursor = Cursor([(9, "member.example", None)])
        rows = self.worker.get_resolving_domains(cursor, 42)
        sql, params = cursor.executions[0]
        self.assertEqual(rows, [(9, "member.example", None)])
        self.assertIn("DISTINCT ON (d.id)", sql)
        self.assertIn("scan_results", sql)
        self.assertIn("IN ('KNOWN', 'SHADOW')", sql)
        self.assertIn("active_scan_authorization_sql", self.worker.get_resolving_domains.__code__.co_names)
        self.assertNotIn("s.has_ip", sql)
        self.assertNotIn("shared_state.ip", sql)
        self.assertEqual(params, (42,))

    def test_candidate_or_nonmember_is_skipped_before_authorization_or_nmap(self):
        for row in (("candidate.example", "CANDIDATE", "8.8.8.8"), None):
            conn = Connection(Cursor(row=row))
            self.worker._test_db.get_conn.return_value = conn
            nmap = mock.Mock()
            self.worker.scan_ports = nmap
            result = self.worker.scan_target(42, 9, "candidate.example", threading.Event())
            self.assertEqual(result["status"], "skipped")
            nmap.assert_not_called()
            self.worker._test_auth.recheck_active_authorization.assert_not_called()

    def test_known_and_shadow_are_supported_and_observed_ip_is_never_target(self):
        for asset_class in ("KNOWN", "SHADOW"):
            conn = Connection(Cursor(row=("member.example", asset_class, "8.8.8.9")))
            self.worker._test_db.get_conn.return_value = conn
            self.worker._test_auth.recheck_active_authorization.return_value = (True, "authorized")
            nmap_result = self.worker.PortScanResult([], "8.8.8.10")
            self.worker.scan_ports = mock.Mock(return_value=nmap_result)
            result = self.worker.scan_target(42, 9, "member.example", threading.Event())
            self.assertEqual(result["status"], "no_sensitive_ports")
            self.assertEqual(result["destination_ip"], "8.8.8.10")
            self.assertEqual(self.worker.scan_ports.call_args.args[0], "member.example")

    def test_explicit_nonpublic_or_special_use_observation_is_skipped(self):
        for observed in ("127.0.0.1", "192.0.2.1", "10.0.0.8", "::1", "169.254.1.1"):
            conn = Connection(Cursor(row=("member.example", "KNOWN", observed)))
            self.worker._test_db.get_conn.return_value = conn
            nmap = mock.Mock()
            self.worker.scan_ports = nmap
            result = self.worker.scan_target(42, 9, "member.example", threading.Event())
            self.assertEqual(result["status"], "skipped")
            nmap.assert_not_called()

    def test_denied_or_revoked_target_never_starts_nmap(self):
        conn = Connection()
        self.worker._test_db.get_conn.return_value = conn
        self.worker._test_auth.recheck_active_authorization.return_value = (False, "scope revoked")
        nmap = mock.Mock()
        self.worker.scan_ports = nmap
        result = self.worker.scan_target(42, 9, "member.example", threading.Event())
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
            self.worker.run_port_scan_pool(42, [(9, "member.example")], target_worker=lambda *_args: result)

    def test_authorization_revoked_after_nmap_prevents_result_write(self):
        conn = Connection()
        self.worker._test_db.get_conn.return_value = conn
        self.worker._test_auth.recheck_active_authorization.side_effect = [
            (True, "authorized"), (False, "scope revoked")
        ]
        self.worker.scan_ports = mock.Mock(return_value=[])
        result = self.worker.scan_target(42, 9, "member.example", threading.Event())
        self.assertEqual(result["status"], "failed")
        self.worker.scan_ports.assert_called_once_with("member.example", cancel_event=mock.ANY)
        self.assertFalse(any("INSERT INTO domain_ports" in sql for sql, _ in conn._cursor.executions))
        self.assertEqual(conn.rollbacks, 1)

    def test_successful_target_persists_ports_under_domain_identity(self):
        conn = Connection()
        self.worker._test_db.get_conn.return_value = conn
        self.worker._test_auth.recheck_active_authorization.return_value = (True, "authorized")
        self.worker.scan_ports = mock.Mock(return_value=self.worker.PortScanResult(
            [(443, "https"), (8443, "https-alt")], "8.8.8.8"
        ))
        result = self.worker.scan_target(42, 9, "member.example", threading.Event())
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["domain_id"], 9)
        self.assertEqual(result["domain"], "member.example")
        self.assertEqual(result["ports"], 2)
        writes = [(sql, params) for sql, params in conn._cursor.executions if "INSERT INTO domain_ports" in sql]
        self.assertEqual(len(writes), 2)
        self.assertTrue(all("scan_results" in sql and "ON CONFLICT" in sql for sql, _ in writes))
        self.assertEqual(writes[0][1], (9, 42, 443, "https", 42, 9))
        self.assertEqual(conn.commits, 2)

    def test_nmap_uses_hostname_and_preserves_sensitive_tcp_profile(self):
        proc = mock.Mock()
        proc.communicate.return_value = (
            "Nmap scan report for api.member.example (8.8.8.8)\n443/tcp open https\n", ""
        )
        proc.returncode = 0
        with mock.patch.object(self.worker.subprocess, "Popen", return_value=proc) as popen:
            result = self.worker.scan_ports("API.Member.Example.")
        self.assertEqual(result, [(443, "https")])
        self.assertEqual(result.destination_ip, "8.8.8.8")
        args, kwargs = popen.call_args
        command = args[0]
        self.assertEqual(command[0:4], ["nmap", "-Pn", "-T3", "--open"])
        self.assertEqual(command[-1], "api.member.example")
        self.assertNotIn("-n", command)
        self.assertNotIn("--resolve-all", command)
        self.assertIn("-p", command)
        self.assertIn("27017,11211", command[command.index("-p") + 1])
        self.assertEqual(kwargs, {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE, "text": True})
        self.assertEqual(popen.call_count, 1)

    def test_worker_emits_one_capturable_summary_with_nmap_destination(self):
        output = io.StringIO()
        outcomes = [{
            "status": "complete", "domain_id": 9, "domain": "member.example",
            "ports": 1, "destination_ip": "8.8.8.8",
        }]
        with redirect_stdout(output):
            self.worker._emit_worker_summary([(9, "member.example")], outcomes, 0.25)
        self.assertEqual(output.getvalue().count("ASIP_WORKER_SUMMARY "), 1)
        summary = scan_diagnostics.extract_worker_summary(output.getvalue())
        self.assertEqual(summary["selected"], 1)
        self.assertEqual(summary["open_port_targets"], 1)
        self.assertEqual(summary["nmap_destination_observations"], [{
            "domain_id": 9, "status": "complete", "destination_ip": "8.8.8.8",
        }])

    def test_hostname_validation_blocks_injection_and_nmap_options(self):
        with mock.patch.object(self.worker.subprocess, "Popen") as popen:
            for value in ("", "bad host.example", "host.example;id", "-Pn", "bad..example", "192.0.2.1"):
                with self.subTest(value=value), self.assertRaises(self.worker.PortScanError):
                    self.worker.scan_ports(value)
            popen.assert_not_called()

    def test_unresolved_host_is_not_reported_as_zero_ports(self):
        proc = mock.Mock()
        proc.communicate.return_value = ('Failed to resolve "member.example".\n', "")
        proc.returncode = 2
        with mock.patch.object(self.worker.subprocess, "Popen", return_value=proc):
            with self.assertRaises(self.worker.PortScanHostUnavailable):
                self.worker.scan_ports("member.example")

    def test_nonzero_exit_and_timeout_do_not_become_zero_port_results(self):
        proc = mock.Mock()
        proc.communicate.return_value = ("", "scan failed")
        proc.returncode = 2
        with mock.patch.object(self.worker.subprocess, "Popen", return_value=proc):
            with self.assertRaises(self.worker.PortScanError):
                self.worker.scan_ports("member.example")

        proc = mock.Mock()
        proc.poll.return_value = None
        proc.communicate.return_value = ("443/tcp open https\n", "")
        with mock.patch.object(self.worker, "PORT_SCAN_TIMEOUT_SECONDS", 0), mock.patch.object(
            self.worker.subprocess, "Popen", return_value=proc
        ), self.assertRaises(self.worker.PortScanTimeout):
            self.worker.scan_ports("member.example")
        proc.terminate.assert_called_once()

    def test_worker_exception_marks_stage_incomplete_after_other_target_finishes(self):
        completed = threading.Event()

        def target(_scan_id, _domain_id, domain, _cancel):
            if domain == "bad.example":
                raise RuntimeError("mocked worker failure")
            completed.set()
            return {"status": "no_sensitive_ports", "domain": domain}

        with self.assertRaisesRegex(self.worker.PortScanStageError, "incomplete") as raised:
            self.worker.run_port_scan_pool(
                42,
                [(1, "bad.example"), (2, "good.example")],
                worker_count=2,
                target_worker=target,
            )
        self.assertTrue(completed.is_set())
        self.assertEqual(len(raised.exception.outcomes), 2)


if __name__ == "__main__":
    unittest.main()
