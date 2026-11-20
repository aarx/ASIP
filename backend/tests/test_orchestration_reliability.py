import importlib.util
import json
import os
import pathlib
import shlex
import signal
import subprocess
import sys
import threading
import types
import time
import unittest
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]


def load_backend_module(filename):
    module_name = f"reliability_{filename.stem}_{id(filename)}"
    spec = importlib.util.spec_from_file_location(module_name, filename)
    module = importlib.util.module_from_spec(spec)
    fake_db = types.ModuleType("db")
    fake_db.get_conn = mock.Mock()
    fake_db.require_running_scan = mock.Mock()
    replacements = {"db": fake_db}
    old_modules = {name: sys.modules.get(name) for name in replacements}
    old_path = sys.path[:]
    try:
        sys.modules.update(replacements)
        sys.path.insert(0, str(BACKEND))
        spec.loader.exec_module(module)
    finally:
        sys.path[:] = old_path
        for name, previous in old_modules.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous
    return module


class OrchestrationStageExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_backend_module(BACKEND / "orchestration.py")

    def test_stage_can_exceed_legacy_timeout_configuration_and_finish(self):
        command = (
            f"{shlex.quote(sys.executable)} -c "
            + shlex.quote("import time; time.sleep(0.2); print('stage-complete', flush=True)")
        )
        for stage_name in ("SAN Expansion", "DNS Resolution"):
            with self.subTest(stage=stage_name):
                started = time.monotonic()
                with mock.patch.dict(os.environ, {
                    "ASIP_STAGE_TIMEOUT_SECONDS": "0.01",
                    "ASIP_SAN_STAGE_TIMEOUT_SECONDS": "0.01",
                }, clear=True):
                    result = self.module.run_step(stage_name, command, 1, 1)
                elapsed = time.monotonic() - started
                self.assertEqual(result, 0)
                self.assertGreaterEqual(elapsed, 0.2)

    def test_stage_diagnostics_report_success_after_longer_execution(self):
        command = (
            f"{shlex.quote(sys.executable)} -c "
            + shlex.quote("import time; time.sleep(0.15)")
        )
        with mock.patch.object(self.module, "_diagnostics_finish") as finish:
            result = self.module.run_step(
                "DNS Resolution", command, 1, 1,
                scan_id=32, runner_token="token", stage_order=4,
            )
        self.assertEqual(result, 0)
        self.assertEqual(finish.call_args.args[5], "SUCCEEDED")
        self.assertGreaterEqual(finish.call_args.args[6], 0.15)

    def test_retryable_attempts_reinvoke_stage_and_failures_still_propagate(self):
        with mock.patch.object(
            self.module, "run_step",
            side_effect=[self.module.RETRYABLE_INCOMPLETE_EXIT_CODE, 0],
        ) as run_step:
            self.module.run_required_stage("DNS Resolution", "same-command")
        self.assertEqual(run_step.call_count, 2)
        self.assertEqual(run_step.call_args_list[0].args[:2], ("DNS Resolution", "same-command"))
        self.assertEqual(run_step.call_args_list[1].args[:2], ("DNS Resolution", "same-command"))

        with mock.patch.object(self.module, "run_step", return_value=7):
            with self.assertRaisesRegex(
                self.module.StageExecutionError, "failed with exit code 7"
            ):
                self.module.run_required_stage("DNS Resolution", "failing-command")

    def test_streams_merged_stdout_and_stderr_before_stage_exits(self):
        command = (
            f"{shlex.quote(sys.executable)} -c "
            + shlex.quote(
                "import sys,time; "
                "print('stdout-first',flush=True); "
                "print('stderr-second',file=sys.stderr,flush=True); "
                "print('stdout-third',flush=True); time.sleep(0.5)"
            )
        )
        output_seen = threading.Event()
        done = threading.Event()
        records = []
        results = []

        def record_log(*args, **_kwargs):
            message = " ".join(str(value) for value in args)
            records.append(message)
            if "stdout-first" in message:
                output_seen.set()

        def run_stage():
            results.append(self.module.run_step(
                "Live Stage", command, 1, 1
            ))
            done.set()

        with mock.patch.object(self.module.logging, "info", side_effect=record_log):
            worker = threading.Thread(target=run_stage)
            worker.start()
            self.assertTrue(output_seen.wait(2), "child output was not forwarded live")
            self.assertFalse(done.is_set(), "stage exited before live output was observed")
            worker.join(3)

        self.assertFalse(worker.is_alive())
        self.assertEqual(results, [0])
        forwarded = [item for item in records if "[Live Stage]" in item]
        self.assertEqual(len(forwarded), 3)
        sequence = [
            next(index for index, item in enumerate(forwarded) if marker in item)
            for marker in ("stdout-first", "stderr-second", "stdout-third")
        ]
        self.assertEqual(sequence, sorted(sequence))

    def test_quiet_success_and_nonzero_exit_keep_stage_outcomes(self):
        quiet = self.module.run_step(
            "Quiet Stage",
            f"{shlex.quote(sys.executable)} -c 'import time; time.sleep(0.05)'",
            1, 1,
        )
        nonzero = self.module.run_step(
            "Nonzero Stage",
            f"{shlex.quote(sys.executable)} -c 'raise SystemExit(7)'",
            1, 1,
        )
        self.assertEqual(quiet, 0)
        self.assertEqual(nonzero, 7)

    def test_stage_capture_is_bounded_for_large_unterminated_output(self):
        command = (
            f"{shlex.quote(sys.executable)} -c "
            + shlex.quote("import sys; sys.stdout.write('x' * 200000); sys.stdout.flush()")
        )
        process = subprocess.Popen(
            command, shell=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        try:
            with mock.patch.object(self.module.logging, "info"):
                output = self.module._stream_stage_output(process, "Large Stage")
        finally:
            process.stdout.close()
        self.assertEqual(process.returncode, 0)
        self.assertLessEqual(len(output), self.module.MAX_STAGE_OUTPUT_CAPTURE_BYTES)

    def test_handled_sigterm_cleans_stage_grandchild(self):
        from pathlib import Path
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ready = root / "stage-ready"
            marker = root / "grandchild-survived"
            child_pid = root / "stage-pid"
            grandchild_code = (
                "import signal,time,pathlib; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "time.sleep(2); pathlib.Path(" + repr(str(marker)) + ").touch()"
            )
            stage_code = (
                "import pathlib,subprocess,sys,time; "
                "subprocess.Popen([sys.executable,'-c'," + repr(grandchild_code) + "]); "
                "pathlib.Path(" + repr(str(ready)) + ").touch(); time.sleep(30)"
            )
            stage_command = (
                f"{shlex.quote(sys.executable)} -c {shlex.quote(stage_code)}"
            )
            helper_code = (
                "import pathlib,signal,subprocess,sys,types\n"
                f"sys.path.insert(0,{str(BACKEND)!r})\n"
                "fake=types.ModuleType('db'); fake.get_conn=lambda:None\n"
                "sys.modules['db']=fake; import orchestration\n"
                "real=orchestration.subprocess.Popen\n"
                "def tracked(*a, **k):\n"
                "    p=real(*a, **k)\n"
                f"    pathlib.Path({str(child_pid)!r}).write_text(str(p.pid))\n"
                "    return p\n"
                "orchestration.subprocess.Popen=tracked\n"
                "orchestration.CHILD_TERMINATE_GRACE_SECONDS=0.2\n"
                "signal.signal(signal.SIGTERM,orchestration._handle_shutdown_signal)\n"
                "try:\n"
                f"    orchestration.run_step('signal-test',{stage_command!r},1,1)\n"
                "except KeyboardInterrupt:\n"
                "    raise SystemExit(37)\n"
            )
            parent = subprocess.Popen(
                [sys.executable, "-c", helper_code],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not ready.exists():
                if parent.poll() is not None:
                    self.fail("orchestration helper exited before stage became ready")
                time.sleep(0.02)
            self.assertTrue(ready.exists(), "stage did not reach its ready point")
            parent.terminate()
            self.assertEqual(parent.wait(timeout=4), 37)
            time.sleep(2.1)
            self.assertFalse(marker.exists())

    def test_sigkill_leaves_stage_descendant_but_recovery_fails_closed(self):
        """A dead launcher cannot infer process-tree death from its lost lock."""
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / "child-ready"
            marker = Path(directory) / "child-survived"
            child_code = (
                "import pathlib,time; pathlib.Path(" + repr(str(ready)) +").touch(); "
                "time.sleep(2); pathlib.Path(" + repr(str(marker)) + ").touch()"
            )
            launcher_code = (
                "import subprocess,sys,time; "
                "subprocess.Popen([sys.executable,'-c'," + repr(child_code) + "]); "
                "time.sleep(30)"
            )
            launcher = subprocess.Popen(
                [sys.executable, "-c", launcher_code], start_new_session=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            try:
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline and not ready.exists():
                    if launcher.poll() is not None:
                        self.fail("launcher exited before child became ready")
                    time.sleep(0.01)
                self.assertTrue(ready.exists())
                launcher.send_signal(signal.SIGKILL)
                launcher.wait(timeout=2)
                class Cursor:
                    def __init__(self):
                        self.statements = []

                    def execute(self, query, params=None):
                        self.statements.append(query)

                    def fetchall(self):
                        return [(42, "runner-token", "expired-heartbeat")]

                class Connection:
                    def __init__(self):
                        self.cursor_instance = Cursor()
                        self.commits = 0

                    def cursor(self):
                        return self.cursor_instance

                    def commit(self):
                        self.commits += 1

                connection = Connection()
                with self.assertRaisesRegex(
                    RuntimeError, "cannot prove its worker process tree"
                ):
                    self.module.recover_orphaned_scans(connection)
                self.assertEqual(connection.commits, 1)
                self.assertEqual(len(connection.cursor_instance.statements), 1)
                time.sleep(2.1)
                self.assertTrue(
                    marker.exists(),
                    "the descendant should demonstrate survival of launcher SIGKILL",
                )
            finally:
                # This process group was created exclusively by this test.
                try:
                    os.killpg(launcher.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_shutdown_signals_raise_into_pipeline_cleanup(self):
        for signum in (self.module.signal.SIGTERM, self.module.signal.SIGINT):
            with self.subTest(signum=signum), self.assertRaises(KeyboardInterrupt):
                self.module._handle_shutdown_signal(signum, None)

    def test_main_installs_handled_termination_signals(self):
        self.module.acquire_orchestration_lock = mock.Mock(return_value=None)
        with mock.patch.object(self.module.signal, "signal", wraps=signal.signal) as install:
            with self.assertRaises(SystemExit):
                self.module.main()

        installed = [call.args[:2] for call in install.call_args_list]
        self.assertIn(
            (self.module.signal.SIGTERM, self.module._handle_shutdown_signal),
            installed,
        )
        self.assertIn(
            (self.module.signal.SIGINT, self.module._handle_shutdown_signal),
            installed,
        )

    def test_designated_retryable_exit_code_remains_bounded(self):
        with mock.patch.object(
            self.module,
            "run_step",
            side_effect=[self.module.RETRYABLE_INCOMPLETE_EXIT_CODE, 0],
        ) as run_step:
            self.module.run_required_stage("Retryable Stage", "ignored")
        self.assertEqual(run_step.call_count, 2)

    def _heartbeat_connection(self, rowcount=1):
        connection = mock.Mock()
        connection.cursor.return_value.rowcount = rowcount
        return connection

    def _run_heartbeat_attempt(self, outcomes, *, rowcount=1, recovery_seconds=60):
        heartbeat = self.module.RunnerHeartbeat(
            scan_id=42,
            runner_token="runner-42",
            interval_seconds=0.01,
        )
        connections = [self._heartbeat_connection(rowcount) for _ in outcomes]
        results = iter(outcomes)

        def get_conn():
            result = next(results)
            if isinstance(result, BaseException):
                raise result
            return result

        with mock.patch.object(self.module, "get_conn", side_effect=get_conn) as get:
            with mock.patch.object(
                self.module, "RUNNER_HEARTBEAT_RECOVERY_SECONDS", recovery_seconds
            ), mock.patch.object(
                self.module, "RUNNER_HEARTBEAT_RETRY_INITIAL_SECONDS", 0
            ):
                heartbeat.start()
                deadline = time.monotonic() + 2
                while get.call_count < len(outcomes) and time.monotonic() < deadline:
                    time.sleep(0.001)
                heartbeat.stop()
        return heartbeat, get, connections

    def test_heartbeat_recovers_from_transient_dns_failure(self):
        recovered = self._heartbeat_connection()
        heartbeat, get, _ = self._run_heartbeat_attempt([
            self.module_exception(
                'could not translate host name "db" to address: '
                "Temporary failure in name resolution"
            ),
            recovered,
        ])
        heartbeat.ensure_healthy()
        self.assertEqual(get.call_count, 2)
        self.assertTrue(recovered.commit.called)

    def test_heartbeat_recovers_from_connection_refusal(self):
        recovered = self._heartbeat_connection()
        heartbeat, get, _ = self._run_heartbeat_attempt([
            ConnectionRefusedError("connection refused"), recovered,
        ])
        heartbeat.ensure_healthy()
        self.assertEqual(get.call_count, 2)

    def test_heartbeat_lease_mismatch_fails_immediately(self):
        heartbeat, get, connections = self._run_heartbeat_attempt(
            [self._heartbeat_connection(rowcount=0)]
        )
        with self.assertRaisesRegex(
            self.module.RunnerLeaseError, "no longer owned"
        ):
            heartbeat.ensure_healthy()
        self.assertEqual(get.call_count, 1)
        self.assertFalse(connections[0].commit.called)

    def test_heartbeat_status_change_fails_immediately(self):
        self.test_heartbeat_lease_mismatch_fails_immediately()

    def test_explicit_cancellation_status_change_fails_immediately(self):
        self.test_heartbeat_lease_mismatch_fails_immediately()

    def test_heartbeat_outage_has_bounded_diagnosed_failure(self):
        heartbeat = self.module.RunnerHeartbeat(42, "runner-42", interval_seconds=0.01)
        with mock.patch.object(
            self.module, "get_conn",
            side_effect=ConnectionRefusedError("connection refused"),
        ) as get, mock.patch.object(
            self.module, "RUNNER_HEARTBEAT_RECOVERY_SECONDS", 0
        ):
            heartbeat.start()
            heartbeat._thread.join(timeout=1)
        with self.assertRaisesRegex(
            self.module.RunnerLeaseError, "after .* transient database outage"
        ):
            heartbeat.ensure_healthy()
        self.assertEqual(get.call_count, 1)

    def module_exception(self, message):
        return type("OperationalError", (Exception,), {})(message)

    def test_recovered_heartbeat_keeps_successful_stage_evidence(self):
        heartbeat, _, _ = self._run_heartbeat_attempt([
            ConnectionRefusedError("connection refused"),
            self._heartbeat_connection(),
        ])
        heartbeat.ensure_healthy()
        with mock.patch.object(self.module, "_diagnostics_start"), mock.patch.object(
            self.module, "_diagnostics_finish"
        ) as finish:
            self.module.run_step(
                "DNS Security",
                f"{shlex.quote(sys.executable)} -c 'pass'",
                1, 1, scan_id=42, runner_token="runner-42", stage_order=3,
            )
        self.assertEqual(finish.call_args.args[5], "SUCCEEDED")

    def test_one_heartbeat_thread_is_created_for_runner(self):
        heartbeat = self.module.RunnerHeartbeat(42, "runner-42", interval_seconds=10)
        heartbeat.start()
        try:
            self.assertTrue(heartbeat._thread.is_alive())
            self.assertEqual(heartbeat._thread.name, "asip-scan-heartbeat-42")
            self.assertEqual(
                sum(t.name == "asip-scan-heartbeat-42" for t in threading.enumerate()), 1
            )
        finally:
            heartbeat.stop()

    def test_stage_stream_parses_worker_progress_and_emits_elapsed_ticks(self):
        marker = {
            "scan_id": 42, "stage": "DNS Security", "status": "RUNNING",
            "selected": 3, "total": 3, "processed": 1,
            "elapsed_seconds": 30,
        }
        code = (
            "import json,time; print('ASIP_STAGE_PROGRESS '+json.dumps("
            + repr(marker) + ")); time.sleep(0.06)"
        )
        process = subprocess.Popen(
            [sys.executable, "-c", code], stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        progress = []
        with mock.patch.object(self.module.logging, "info"):
            self.module._stream_stage_output(
                process, "DNS Security", progress.append, progress_interval=0.02
            )
        self.assertEqual(process.returncode, 0)
        self.assertTrue(any(item.get("processed") == 1 for item in progress))
        self.assertTrue(any(
            item.get("status") == "RUNNING" and "processed" not in item
            for item in progress
        ))

    def test_progress_database_failure_does_not_fail_stage_execution(self):
        with mock.patch.object(
            self.module, "get_conn", side_effect=RuntimeError("offline")
        ), mock.patch.object(self.module.logging, "warning") as warning:
            self.module._diagnostics_progress(
                42, "runner-42", "DNS Security", 7, 1,
                {"status": "RUNNING", "processed": 1},
            )
        warning.assert_called_once()


class ReconToolExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_backend_module(BACKEND / "recon.py")

    def test_recon_tool_can_exceed_legacy_timeout_setting(self):
        command = [
            sys.executable,
            "-c",
            "import time; time.sleep(0.2); print('tool-complete')",
        ]
        started = time.monotonic()
        with mock.patch.dict(os.environ, {"ASIP_RECON_TOOL_TIMEOUT_SECONDS": "0.01"}):
            completed, results, error = self.module.run_tool(command)
        self.assertTrue(completed)
        self.assertEqual(results, ["tool-complete"])
        self.assertIsNone(error)
        self.assertGreaterEqual(time.monotonic() - started, 0.2)

    def test_recon_tool_inherits_stage_process_group_for_cancellation(self):
        with mock.patch.object(self.module.subprocess, "Popen") as popen:
            process = popen.return_value
            process.returncode = 0
            process.communicate.return_value = ("done\n", "")
            self.module.run_tool(["recon-tool"])
        self.assertNotIn("start_new_session", popen.call_args.kwargs)
        process.communicate.assert_called_once_with()


class AuthorizationBoundaryRegressionTests(unittest.TestCase):
    def test_existing_explicit_active_workers_keep_runtime_rechecks(self):
        for filename in ("tech_worker.py", "port_scan_worker.py"):
            source = (BACKEND / filename).read_text(encoding="utf-8")
            with self.subTest(filename=filename):
                self.assertIn("recheck_active_authorization", source)
                self.assertIn("active_scan_authorization_sql", source)

    def test_ambiguous_target_contact_stages_are_not_silently_remapped(self):
        source = (BACKEND / "authorization_policy.py").read_text(encoding="utf-8")
        self.assertIn('"TECHNOLOGY_HTTP"', source)
        self.assertIn('"PORT_SCAN"', source)
        self.assertIn('"ADHOC_CHECK"', source)
        self.assertNotIn('"TAKEOVER_HTTP"', source)
        self.assertNotIn('"CERTIFICATE_COLLECTION"', source)


if __name__ == "__main__":
    unittest.main()
