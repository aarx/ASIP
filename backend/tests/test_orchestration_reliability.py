import importlib.util
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


class OrchestrationTimeoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_backend_module(BACKEND / "orchestration.py")

    def test_hung_stage_is_bounded_and_process_group_is_cleaned(self):
        command = (
            f"{shlex.quote(sys.executable)} -c "
            "'import time; time.sleep(30)'"
        )
        result = self.module.run_step(
            "Hung Stage", command, 1, 2, timeout_seconds=0.1
        )
        self.assertEqual(result, self.module.STAGE_TIMEOUT_EXIT_CODE)

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
                "Live Stage", command, 1, 1, timeout_seconds=3
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
            1, 1, timeout_seconds=2,
        )
        nonzero = self.module.run_step(
            "Nonzero Stage",
            f"{shlex.quote(sys.executable)} -c 'raise SystemExit(7)'",
            1, 1, timeout_seconds=2,
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
                output = self.module._stream_stage_output(process, "Large Stage", 3)
        finally:
            process.stdout.close()
        self.assertEqual(process.returncode, 0)
        self.assertLessEqual(len(output), self.module.MAX_STAGE_OUTPUT_CAPTURE_BYTES)

    def test_timeout_kills_grandchild_that_ignores_sigterm(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "survived"
            grandchild_code = (
                "import signal,time,pathlib; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "time.sleep(1.2); pathlib.Path(" + repr(str(marker)) + ").touch()"
            )
            parent_code = (
                "import subprocess,sys,time; "
                "subprocess.Popen([sys.executable,'-c'," + repr(grandchild_code) + "]); "
                "time.sleep(30)"
            )
            command = f"{shlex.quote(sys.executable)} -c {shlex.quote(parent_code)}"
            with mock.patch.object(
                self.module, "CHILD_TERMINATE_GRACE_SECONDS", 0.15
            ):
                result = self.module.run_step(
                    "Grandchild Stage", command, 1, 1, timeout_seconds=0.4
                )
            self.assertEqual(result, self.module.STAGE_TIMEOUT_EXIT_CODE)
            time.sleep(1.3)
            self.assertFalse(marker.exists())

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
                f"    orchestration.run_step('signal-test',{stage_command!r},1,1,20)\n"
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
                self.assertEqual(connection.commits, 0)
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

    def test_timeout_is_a_terminal_stage_failure_not_an_infinite_retry(self):
        with mock.patch.object(
            self.module,
            "run_step",
            return_value=self.module.STAGE_TIMEOUT_EXIT_CODE,
        ) as run_step:
            with self.assertRaisesRegex(
                self.module.StageExecutionError, "timed out"
            ):
                self.module.run_required_stage("Hung Stage", "ignored")
        run_step.assert_called_once()

    def test_designated_retryable_exit_code_remains_bounded(self):
        with mock.patch.object(
            self.module,
            "run_step",
            side_effect=[self.module.RETRYABLE_INCOMPLETE_EXIT_CODE, 0],
        ) as run_step:
            self.module.run_required_stage("Retryable Stage", "ignored")
        self.assertEqual(run_step.call_count, 2)

    def test_heartbeat_database_error_fails_closed(self):
        heartbeat = self.module.RunnerHeartbeat(
            scan_id=42,
            runner_token="runner-42",
            interval_seconds=0.01,
        )
        with mock.patch.object(
            self.module, "get_conn", side_effect=RuntimeError("database unavailable")
        ):
            heartbeat.start()
            heartbeat._thread.join(timeout=1)
        heartbeat.stop()
        with self.assertRaisesRegex(
            self.module.RunnerLeaseError, "heartbeat failed"
        ):
            heartbeat.ensure_healthy()


class ReconToolTimeoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_backend_module(BACKEND / "recon.py")

    def test_hung_recon_tool_is_terminated_without_network(self):
        command = [sys.executable, "-c", "import time; time.sleep(30)"]
        previous = os.environ.get("ASIP_RECON_TOOL_TIMEOUT_SECONDS")
        os.environ["ASIP_RECON_TOOL_TIMEOUT_SECONDS"] = "1"
        try:
            completed, results, error = self.module.run_tool(command)
        finally:
            if previous is None:
                os.environ.pop("ASIP_RECON_TOOL_TIMEOUT_SECONDS", None)
            else:
                os.environ["ASIP_RECON_TOOL_TIMEOUT_SECONDS"] = previous
        self.assertFalse(completed)
        self.assertEqual(results, [])
        self.assertIn("timeout after 1s", error)


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
