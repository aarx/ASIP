import importlib.util
import os
import pathlib
import shlex
import sys
import types
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
