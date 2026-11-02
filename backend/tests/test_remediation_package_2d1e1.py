import importlib.util
import io
import json
import logging
import os
import pathlib
import signal
import sys
import tempfile
import types
import unittest
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]


def group_gone_after_term(_pid, sig):
    if sig == 0:
        raise ProcessLookupError()


def load_orchestration():
    module_name = f"pkg2d1e1_orchestration_{len(sys.modules)}"
    spec = importlib.util.spec_from_file_location(
        module_name, BACKEND / "orchestration.py"
    )
    module = importlib.util.module_from_spec(spec)
    fake_db = types.ModuleType("db")
    fake_db.get_conn = lambda: None
    old_db = sys.modules.get("db")
    old_path = sys.path[:]
    with tempfile.TemporaryDirectory() as temp_dir:
        pathlib.Path(temp_dir, "logs").mkdir()
        try:
            sys.modules["db"] = fake_db
            sys.path.insert(0, str(BACKEND))
            with mock.patch("logging.FileHandler", return_value=logging.NullHandler()):
                spec.loader.exec_module(module)
        finally:
            sys.path[:] = old_path
            if old_db is None:
                sys.modules.pop("db", None)
            else:
                sys.modules["db"] = old_db
    return module


class FakeStream:
    def __init__(self, lines=(), interrupt=False, close_error=None):
        self.lines = list(lines)
        self.interrupt = interrupt
        self.close_error = close_error
        self.closed = False

    def __iter__(self):
        if self.interrupt:
            raise KeyboardInterrupt()
        return iter(self.lines)

    def close(self):
        self.closed = True
        if self.close_error is not None:
            raise self.close_error


class FakeProcess:
    _next_pid = 1000

    def __init__(self, returncode=0, interrupt=False, timeout_once=False):
        self.stdout = FakeStream(interrupt=interrupt)
        self.returncode = None if interrupt else returncode
        self.final_returncode = returncode
        self.timeout_once = timeout_once
        self.wait_calls = []
        self.terminate = mock.Mock()
        self.kill = mock.Mock()
        self.pid = FakeProcess._next_pid
        FakeProcess._next_pid += 1

    def poll(self):
        return self.returncode

    def communicate(self, timeout=None):
        if self.stdout.interrupt:
            raise KeyboardInterrupt()
        if timeout is not None and self.timeout_once:
            self.timeout_once = False
            raise __import__("subprocess").TimeoutExpired("worker", timeout)
        self.returncode = self.final_returncode
        return "", None

    def wait(self, timeout=None):
        self.wait_calls.append(timeout)
        if timeout is not None and self.timeout_once:
            self.timeout_once = False
            raise __import__("subprocess").TimeoutExpired("worker", timeout)
        self.returncode = self.final_returncode
        return self.returncode


class WorkerOutcomeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(BACKEND))
        import worker_outcome
        cls.outcome = worker_outcome

    @classmethod
    def tearDownClass(cls):
        sys.path.remove(str(BACKEND))

    def test_retryable_code_uses_standard_with_documented_fallback(self):
        expected = getattr(os, "EX_TEMPFAIL", 75)
        self.assertEqual(self.outcome.RETRYABLE_INCOMPLETE_EXIT_CODE, expected)
        self.assertEqual(
            self.outcome._resolve_retryable_exit_code(types.SimpleNamespace()), 75
        )

    def test_structured_summary_is_single_line_json_with_optional_details(self):
        summary = self.outcome.WorkerSummary(
            stage="example",
            outcome=self.outcome.WorkerOutcome.RETRYABLE_INCOMPLETE,
            candidates=None,
            attempted=2,
            operational_errors=2,
            details={"source": "test"},
        )
        stream = io.StringIO()

        self.outcome.emit_worker_summary(summary, stream)

        line = stream.getvalue()
        self.assertEqual(line.count("\n"), 1)
        self.assertTrue(line.startswith(self.outcome.SUMMARY_PREFIX))
        payload = json.loads(line[len(self.outcome.SUMMARY_PREFIX):])
        self.assertEqual(payload["version"], 1)
        self.assertEqual(payload["outcome"], "retryable_incomplete")
        self.assertIsNone(payload["candidates"])
        self.assertEqual(payload["operational_errors"], 2)
        self.assertEqual(payload["details"], {"source": "test"})

    def test_summary_rejects_negative_counters(self):
        with self.assertRaisesRegex(ValueError, "committed"):
            self.outcome.WorkerSummary(
                stage="example",
                outcome=self.outcome.WorkerOutcome.SUCCESS,
                candidates=1,
                committed=-1,
            )


class RequiredStageRetryTests(unittest.TestCase):
    def setUp(self):
        self.module = load_orchestration()

    def test_success_on_first_attempt_has_no_retry(self):
        self.module.run_step = mock.Mock(return_value=0)

        self.module.run_required_stage("Stage", "command")

        self.module.run_step.assert_called_once_with("Stage", "command", 1, 2)

    def test_retryable_then_success_uses_exactly_two_attempts(self):
        code = self.module.RETRYABLE_INCOMPLETE_EXIT_CODE
        self.module.run_step = mock.Mock(side_effect=[code, 0])

        self.module.run_required_stage("Stage", "command")

        self.assertEqual(self.module.run_step.call_count, 2)
        self.assertEqual(
            self.module.run_step.call_args_list,
            [mock.call("Stage", "command", 1, 2),
             mock.call("Stage", "command", 2, 2)],
        )

    def test_retryable_twice_fails_without_third_attempt(self):
        code = self.module.RETRYABLE_INCOMPLETE_EXIT_CODE
        self.module.run_step = mock.Mock(side_effect=[code, code])

        with self.assertRaisesRegex(RuntimeError, f"exit code {code}"):
            self.module.run_required_stage("Stage", "command")

        self.assertEqual(self.module.run_step.call_count, 2)

    def test_retryable_then_fatal_fails_after_two_attempts(self):
        code = self.module.RETRYABLE_INCOMPLETE_EXIT_CODE
        self.module.run_step = mock.Mock(side_effect=[code, 9])

        with self.assertRaisesRegex(RuntimeError, "exit code 9"):
            self.module.run_required_stage("Stage", "command")

        self.assertEqual(self.module.run_step.call_count, 2)

    def test_arbitrary_fatal_nonzero_is_not_retried(self):
        for returncode in (1, 2, 9, 127):
            with self.subTest(returncode=returncode):
                self.module.run_step = mock.Mock(return_value=returncode)
                with self.assertRaisesRegex(RuntimeError, f"exit code {returncode}"):
                    self.module.run_required_stage("Stage", "command")
                self.module.run_step.assert_called_once_with(
                    "Stage", "command", 1, 2
                )

    def test_process_start_failure_is_fatal_and_not_retried(self):
        with mock.patch.object(
            self.module.subprocess, "Popen", side_effect=OSError("cannot start")
        ) as popen:
            with self.assertRaisesRegex(OSError, "cannot start"):
                self.module.run_required_stage("Stage", "command")

        popen.assert_called_once()

    def test_attempt_logging_identifies_both_attempts(self):
        code = self.module.RETRYABLE_INCOMPLETE_EXIT_CODE
        processes = [FakeProcess(code), FakeProcess(0)]
        with mock.patch.object(
            self.module.subprocess, "Popen", side_effect=processes
        ), mock.patch.object(self.module.logging, "info") as info, \
                mock.patch.object(self.module.logging, "warning") as warning:
            self.module.run_required_stage("Stage", "command")

        info_text = "\n".join(str(call) for call in info.call_args_list)
        warning_text = "\n".join(str(call) for call in warning.call_args_list)
        self.assertIn("STARTING: Stage attempt 1/2", info_text)
        self.assertIn("STARTING: Stage attempt 2/2", info_text)
        self.assertIn("COMPLETED: Stage attempt 2/2", info_text)
        self.assertIn("RETRYABLE INCOMPLETE: Stage attempt 1/2", warning_text)

    def test_interrupt_cleanup_escalates_and_reaps(self):
        process = FakeProcess(returncode=-9, interrupt=True, timeout_once=True)
        with mock.patch.object(
            self.module.os, "killpg", side_effect=group_gone_after_term
        ) as killpg:
            self.module.stop_active_child(process)

        self.assertEqual(
            killpg.call_args_list,
            [mock.call(process.pid, signal.SIGTERM),
             mock.call(process.pid, 0),
             mock.call(process.pid, signal.SIGKILL)],
        )
        self.assertEqual(
            process.wait_calls,
            [self.module.CHILD_TERMINATE_GRACE_SECONDS,
             self.module.CHILD_TERMINATE_GRACE_SECONDS],
        )

    def test_cleanup_signal_failures_do_not_mask_keyboard_interrupt(self):
        process = FakeProcess(returncode=-15, interrupt=True)
        process.terminate.side_effect = PermissionError("terminate denied")
        with mock.patch.object(
            self.module.subprocess, "Popen", return_value=process
        ), mock.patch.object(
            self.module.os, "killpg", side_effect=OSError("killpg failed")
        ):
            with self.assertRaises(KeyboardInterrupt):
                self.module.run_step("Stage", "command", 1, 2)

    def test_cleanup_wait_failures_do_not_mask_keyboard_interrupt(self):
        process = FakeProcess(returncode=-15, interrupt=True)
        process.wait = mock.Mock(side_effect=OSError("wait failed"))
        with mock.patch.object(
            self.module.subprocess, "Popen", return_value=process
        ), mock.patch.object(
            self.module.os, "killpg", side_effect=group_gone_after_term
        ):
            with self.assertRaises(KeyboardInterrupt):
                self.module.run_step("Stage", "command", 1, 2)

        self.assertEqual(process.wait.call_count, 1)

    def test_cleanup_kill_failures_do_not_mask_keyboard_interrupt(self):
        process = FakeProcess(returncode=-15, interrupt=True, timeout_once=True)
        process.kill.side_effect = PermissionError("kill denied")
        with mock.patch.object(
            self.module.subprocess, "Popen", return_value=process
        ), mock.patch.object(
            self.module.os, "killpg",
            side_effect=[None, ProcessLookupError(), OSError("group kill failed")],
        ):
            with self.assertRaises(KeyboardInterrupt):
                self.module.run_step("Stage", "command", 1, 2)

    def test_stdout_close_failure_does_not_mask_keyboard_interrupt(self):
        process = FakeProcess(returncode=-15, interrupt=True)
        process.stdout.close_error = OSError("close failed")
        with mock.patch.object(
            self.module.subprocess, "Popen", return_value=process
        ), mock.patch.object(
            self.module.os, "killpg", side_effect=group_gone_after_term
        ):
            with self.assertRaises(KeyboardInterrupt):
                self.module.run_step("Stage", "command", 1, 2)

        self.assertTrue(process.stdout.closed)


class PipelineOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.module = load_orchestration()
        self.real_create_scan = self.module.create_scan
        self.transitions = []
        self.lock_connection = object()
        self.module.create_scan = mock.Mock(return_value=42)
        self.module.setup_logging = mock.Mock()
        self.module.mark_scan_terminal = mock.Mock(
            side_effect=lambda scan_id, status: self.transitions.append(
                (scan_id, status)
            )
        )
        self.module.acquire_orchestration_lock = mock.Mock(
            return_value=self.lock_connection
        )
        self.module.recover_orphaned_scans = mock.Mock(return_value=[])
        self.module.release_orchestration_lock = mock.Mock()

    def test_retry_keeps_running_then_allows_later_stage_and_success(self):
        code = self.module.RETRYABLE_INCOMPLETE_EXIT_CODE
        calls = []

        def run_step(name, cmd, attempt, max_attempts):
            calls.append((name, attempt))
            self.assertEqual(self.transitions, [])
            if name == "Recon" and attempt == 1:
                return code
            return 0

        self.module.run_step = run_step

        self.module.main()

        self.assertEqual(calls[:3], [("Recon", 1), ("Recon", 2), ("Ingest", 1)])
        self.assertEqual(self.transitions, [(42, "SUCCEEDED")])
        self.module.release_orchestration_lock.assert_called_once_with(
            self.lock_connection
        )

    def test_retry_exhaustion_marks_failed_and_stops_later_stages(self):
        code = self.module.RETRYABLE_INCOMPLETE_EXIT_CODE
        self.module.run_step = mock.Mock(side_effect=[code, code])

        with self.assertRaisesRegex(SystemExit, "1"):
            self.module.main()

        self.assertEqual(self.module.run_step.call_count, 2)
        self.assertEqual(self.transitions, [(42, "FAILED")])
        self.assertTrue(all(
            call.args[0] == "Recon" for call in self.module.run_step.call_args_list
        ))
        self.module.release_orchestration_lock.assert_called_once_with(
            self.lock_connection
        )

    def test_retry_then_fatal_marks_failed(self):
        code = self.module.RETRYABLE_INCOMPLETE_EXIT_CODE
        self.module.run_step = mock.Mock(side_effect=[code, 3])

        with self.assertRaisesRegex(SystemExit, "1"):
            self.module.main()

        self.assertEqual(self.module.run_step.call_count, 2)
        self.assertEqual(self.transitions, [(42, "FAILED")])

    def test_fatal_first_attempt_has_no_retry_or_later_stage(self):
        self.module.run_step = mock.Mock(return_value=4)

        with self.assertRaisesRegex(SystemExit, "1"):
            self.module.main()

        self.module.run_step.assert_called_once()
        self.assertEqual(self.transitions, [(42, "FAILED")])

    def test_success_requires_every_stage(self):
        names = []
        self.module.run_step = mock.Mock(
            side_effect=lambda name, cmd, attempt, maximum: names.append(name) or 0
        )

        self.module.main()

        self.assertEqual(len(names), 16)
        self.assertEqual(names[0], "Recon")
        self.assertEqual(names[-1], "Risk Scoring")
        self.assertEqual(self.transitions, [(42, "SUCCEEDED")])

    def test_keyboard_interrupt_first_attempt_cleans_child_and_marks_failed(self):
        process = FakeProcess(returncode=-15, interrupt=True)
        with mock.patch.object(
            self.module.subprocess, "Popen", return_value=process
        ) as popen, mock.patch.object(
            self.module.os, "killpg", side_effect=group_gone_after_term
        ) as killpg:
            with self.assertRaises(KeyboardInterrupt):
                self.module.main()

        popen.assert_called_once()
        self.assertEqual(
            killpg.call_args_list,
            [mock.call(process.pid, signal.SIGTERM),
             mock.call(process.pid, 0),
             mock.call(process.pid, signal.SIGKILL)],
        )
        self.assertEqual(self.transitions, [(42, "FAILED")])
        self.module.release_orchestration_lock.assert_called_once_with(
            self.lock_connection
        )

    def test_keyboard_interrupt_on_retry_has_no_third_attempt(self):
        code = self.module.RETRYABLE_INCOMPLETE_EXIT_CODE
        first = FakeProcess(returncode=code)
        second = FakeProcess(returncode=-15, interrupt=True)
        with mock.patch.object(
            self.module.subprocess, "Popen", side_effect=[first, second]
        ) as popen, mock.patch.object(
            self.module.os, "killpg", side_effect=group_gone_after_term
        ):
            with self.assertRaises(KeyboardInterrupt):
                self.module.main()

        self.assertEqual(popen.call_count, 2)
        self.assertEqual(self.transitions, [(42, "FAILED")])
        self.module.release_orchestration_lock.assert_called_once_with(
            self.lock_connection
        )

    def test_keyboard_interrupt_during_succeeded_marks_failed_and_releases_lock(self):
        self.module.run_step = mock.Mock(return_value=0)
        self.module.mark_scan_terminal = mock.Mock(
            side_effect=[KeyboardInterrupt(), None]
        )

        with self.assertRaises(KeyboardInterrupt):
            self.module.main()

        self.assertEqual(self.module.run_step.call_count, 16)
        self.assertEqual(
            self.module.mark_scan_terminal.call_args_list,
            [mock.call(42, "SUCCEEDED"), mock.call(42, "FAILED")],
        )
        self.module.release_orchestration_lock.assert_called_once_with(
            self.lock_connection
        )

    def test_ambiguous_succeeded_commit_is_not_overwritten_by_failed(self):
        state = {"status": "RUNNING"}
        calls = []

        def transition(scan_id, status):
            calls.append((scan_id, status))
            if status == "SUCCEEDED":
                state["status"] = "SUCCEEDED"
                raise KeyboardInterrupt()
            if state["status"] != "RUNNING":
                raise RuntimeError("guard rejected terminal scan")
            state["status"] = status

        self.module.run_step = mock.Mock(return_value=0)
        self.module.mark_scan_terminal = transition

        with self.assertRaises(KeyboardInterrupt):
            self.module.main()

        self.assertEqual(calls, [(42, "SUCCEEDED"), (42, "FAILED")])
        self.assertEqual(state["status"], "SUCCEEDED")
        self.module.release_orchestration_lock.assert_called_once_with(
            self.lock_connection
        )

    def test_commit_interrupt_during_create_uses_exact_retained_scan_id(self):
        cursor = mock.Mock()
        cursor.fetchone.return_value = (42,)
        connection = mock.Mock()
        connection.cursor.return_value = cursor

        def committed_then_interrupted():
            raise KeyboardInterrupt()

        connection.commit.side_effect = committed_then_interrupted
        self.module.create_scan = self.real_create_scan
        self.module.get_conn = mock.Mock(return_value=connection)
        self.module.run_step = mock.Mock()

        with self.assertRaises(KeyboardInterrupt):
            self.module.main()

        self.module.mark_scan_terminal.assert_called_once_with(42, "FAILED")
        self.module.run_step.assert_not_called()
        connection.close.assert_called_once_with()
        self.module.release_orchestration_lock.assert_called_once_with(
            self.lock_connection
        )

    def test_system_exit_is_not_swallowed_or_reclassified(self):
        self.module.run_step = mock.Mock(side_effect=SystemExit(9))

        with self.assertRaisesRegex(SystemExit, "9"):
            self.module.main()

        self.module.mark_scan_terminal.assert_not_called()
        self.module.release_orchestration_lock.assert_called_once_with(
            self.lock_connection
        )


if __name__ == "__main__":
    unittest.main()
