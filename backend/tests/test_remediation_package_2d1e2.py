import contextlib
import importlib.util
import io
import os
import pathlib
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]


class FakeConnection:
    def __init__(self):
        self._cursor = mock.Mock()
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


class FakeResponse:
    def __init__(self, status_code=200, payload=None, json_error=None):
        self.status_code = status_code
        self.payload = payload
        self.json_error = json_error

    def json(self):
        if self.json_error is not None:
            raise self.json_error
        return self.payload


def load_recon(api_key=None):
    module_name = f"pkg2d1e2_recon_{len(sys.modules)}"
    spec = importlib.util.spec_from_file_location(module_name, BACKEND / "recon.py")
    module = importlib.util.module_from_spec(spec)

    fake_db = types.ModuleType("db")
    fake_db.get_conn = mock.Mock()
    fake_db.require_running_scan = mock.Mock()
    fake_config = types.ModuleType("config")
    fake_config.CERTSPOTTER_API_KEY = api_key
    fake_probe = types.ModuleType("http_probe")
    fake_probe.http_probe = mock.Mock(return_value=None)
    fake_artifact = types.ModuleType("recon_artifact")
    fake_artifact.publish_recon_artifact = mock.Mock()
    fake_artifact.scan_recon_artifact_path = lambda data, scan_id: (
        pathlib.Path(data).resolve()
        / "scans"
        / f"scan_{scan_id}"
        / "final_output.csv"
    )

    replacements = {
        "db": fake_db,
        "config": fake_config,
        "http_probe": fake_probe,
        "recon_artifact": fake_artifact,
    }
    previous = {name: sys.modules.get(name) for name in replacements}
    old_path = sys.path[:]
    try:
        sys.modules.update(replacements)
        sys.path.insert(0, str(BACKEND))
        spec.loader.exec_module(module)
    finally:
        sys.path[:] = old_path
        for name, old_module in previous.items():
            if old_module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = old_module

    return module


class CliSourceOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.recon = load_recon()
        self.recon.domain_registry.clear()
        self.recon.source_stats.clear()
        self.recon.source_outcomes.clear()
        self.recon.FAST_TOOLS = [("subfinder", ["subfinder", "-silent", "-d"])]

    @staticmethod
    def completed(returncode=0, stdout="", stderr=""):
        process = mock.Mock()
        process.returncode = returncode
        process.stdout = io.StringIO(stdout)
        process.stderr = io.StringIO(stderr)
        process.communicate.return_value = (stdout, stderr)
        return process

    def test_cli_zero_exit_with_usable_results_is_ok(self):
        with mock.patch.object(
            self.recon.subprocess, "Popen",
            return_value=self.completed(stdout="a.example.com\n"),
        ):
            self.recon.run_subdomain_enum("example.com", deep=False)

        self.assertEqual(self.recon.source_outcomes["subfinder"]["status"], "OK")
        self.assertEqual(self.recon.source_outcomes["subfinder"]["results"], 1)
        self.assertIn("a.example.com", self.recon.domain_registry)

    def test_cli_zero_exit_without_usable_results_is_zero(self):
        with mock.patch.object(
            self.recon.subprocess, "Popen", return_value=self.completed(stdout="\n")
        ):
            self.recon.run_subdomain_enum("example.com", deep=False)

        self.assertEqual(
            self.recon.source_outcomes["subfinder"]["status"], "ZERO"
        )
        self.assertEqual(self.recon.source_outcomes["subfinder"]["results"], 0)

    def test_cli_nonzero_is_failed_and_stdout_is_rejected(self):
        with mock.patch.object(
            self.recon.subprocess, "Popen",
            return_value=self.completed(returncode=3, stdout="a.example.com\n"),
        ):
            self.recon.run_subdomain_enum("example.com", deep=False)

        self.assertEqual(
            self.recon.source_outcomes["subfinder"]["status"], "FAILED"
        )
        self.assertNotIn("a.example.com", self.recon.domain_registry)

    def test_cli_launch_failure_is_failed_and_does_not_escape(self):
        with mock.patch.object(
            self.recon.subprocess, "Popen", side_effect=FileNotFoundError("missing")
        ):
            self.recon.run_subdomain_enum("example.com", deep=False)

        self.assertEqual(
            self.recon.source_outcomes["subfinder"]["status"], "FAILED"
        )

    def test_mixed_cli_outcomes_continue_independently(self):
        self.recon.FAST_TOOLS = [
            ("subfinder", ["subfinder", "-d"]),
            ("assetfinder", ["assetfinder"]),
            ("findomain", ["findomain", "-t"]),
        ]
        results = [
            self.completed(stdout="a.example.com\n"),
            self.completed(stdout=""),
            self.completed(returncode=2, stdout="ignored.example.com\n"),
        ]
        with mock.patch.object(self.recon.subprocess, "Popen", side_effect=results):
            self.recon.run_subdomain_enum("example.com", deep=False)

        self.assertEqual(
            {name: entry["status"] for name, entry in self.recon.source_outcomes.items()},
            {"subfinder": "OK", "assetfinder": "ZERO", "findomain": "FAILED"},
        )
        self.assertNotIn("ignored.example.com", self.recon.domain_registry)

    def test_amass_is_observed_only_when_deep_mode_is_enabled(self):
        self.recon.FAST_TOOLS = []
        self.recon.DEEP_TOOLS = [
            ("amass", ["amass", "enum", "-passive", "-norecursive", "-d"])
        ]
        with mock.patch.object(
            self.recon.subprocess, "Popen", return_value=self.completed(stdout="")
        ) as run:
            self.recon.run_subdomain_enum("example.com", deep=False)
            run.assert_not_called()
            self.recon.run_subdomain_enum("example.com", deep=True)

        run.assert_called_once()
        self.assertEqual(self.recon.source_outcomes["amass"]["status"], "ZERO")


class CertificateSourceOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.recon = load_recon(api_key="test-secret-key")
        self.recon.domain_registry.clear()
        self.recon.source_stats.clear()
        self.recon.source_outcomes.clear()

    def test_crtsh_runs_without_certspotter_key_and_certspotter_is_skipped(self):
        recon = load_recon(api_key=None)
        response = FakeResponse(200, [{"name_value": "a.example.com"}])
        with mock.patch.object(recon.requests, "get", return_value=response) as get:
            recon.certificate_expand("example.com")

        self.assertEqual(get.call_count, 1)
        self.assertIn("crt.sh", get.call_args.args[0])
        self.assertEqual(recon.source_outcomes["crt.sh"]["status"], "OK")
        self.assertEqual(
            recon.source_outcomes["certspotter"]["status"], "SKIPPED"
        )

    def test_crtsh_and_certspotter_outcomes_are_independent(self):
        responses = [
            FakeResponse(503, []),
            FakeResponse(200, [{"dns_names": ["a.example.com"]}]),
        ]
        with mock.patch.object(self.recon.requests, "get", side_effect=responses):
            self.recon.certificate_expand("example.com")

        self.assertEqual(self.recon.source_outcomes["crt.sh"]["status"], "FAILED")
        self.assertEqual(
            self.recon.source_outcomes["certspotter"]["status"], "OK"
        )

    def test_valid_empty_api_results_are_zero(self):
        with mock.patch.object(
            self.recon.requests, "get",
            side_effect=[FakeResponse(200, []), FakeResponse(200, [])],
        ):
            self.recon.certificate_expand("example.com")

        self.assertEqual(self.recon.source_outcomes["crt.sh"]["status"], "ZERO")
        self.assertEqual(
            self.recon.source_outcomes["certspotter"]["status"], "ZERO"
        )

    def test_api_transport_http_and_malformed_responses_are_failed(self):
        cases = (
            ("crtsh_transport", "crt.sh", lambda: self.recon.crtsh_expand("example.com"),
             OSError("timeout")),
            ("crtsh_http", "crt.sh", lambda: self.recon.crtsh_expand("example.com"),
             FakeResponse(500, [])),
            ("crtsh_malformed", "crt.sh", lambda: self.recon.crtsh_expand("example.com"),
             FakeResponse(200, {"wrong": "shape"})),
            ("certspotter_transport", "certspotter",
             lambda: self.recon.certspotter_expand("example.com"), OSError("timeout")),
            ("certspotter_http", "certspotter",
             lambda: self.recon.certspotter_expand("example.com"), FakeResponse(429, [])),
            ("certspotter_malformed", "certspotter",
             lambda: self.recon.certspotter_expand("example.com"),
             FakeResponse(200, [{"dns_names": "not-a-list"}])),
        )

        for label, source, operation, result in cases:
            with self.subTest(case=label):
                self.recon.source_outcomes.clear()
                if isinstance(result, BaseException):
                    patcher = mock.patch.object(
                        self.recon.requests, "get", side_effect=result
                    )
                else:
                    patcher = mock.patch.object(
                        self.recon.requests, "get", return_value=result
                    )
                with patcher:
                    operation()
                self.assertEqual(
                    self.recon.source_outcomes[source]["status"], "FAILED"
                )

    def test_certspotter_key_never_appears_in_output_or_summary(self):
        secret = "never-print-this-secret"
        recon = load_recon(api_key=secret)
        output = io.StringIO()
        with mock.patch.object(
            recon.requests, "get", side_effect=OSError(secret)
        ), contextlib.redirect_stdout(output):
            recon.certspotter_expand("example.com")
            recon.print_source_summary()

        self.assertNotIn(secret, output.getvalue())


class SummaryAndWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.recon = load_recon(api_key="test-key")
        self.recon.domain_registry.clear()
        self.recon.source_stats.clear()
        self.recon.source_outcomes.clear()

    def test_summary_distinguishes_statuses_counts_and_warnings(self):
        self.recon.record_source_attempt("subfinder", "OK", result_count=3)
        self.recon.record_source_attempt("assetfinder", "ZERO")
        self.recon.record_source_attempt(
            "findomain", "FAILED", error="exit 2"
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.recon.print_source_summary()

        summary = output.getvalue()
        self.assertIn("Subfinder", summary)
        self.assertRegex(summary, r"Subfinder\s+OK\s+3 results")
        self.assertRegex(summary, r"Assetfinder\s+ZERO\s+0 results")
        self.assertRegex(summary, r"Findomain\s+FAILED\s+exit 2")
        self.assertIn("Warnings: 2", summary)

    def test_all_external_failures_still_publish_after_running_guard(self):
        connection = FakeConnection()
        events = []
        self.recon.get_conn = mock.Mock(return_value=connection)
        self.recon.require_running_scan = mock.Mock(
            side_effect=lambda cursor, scan_id: events.append("guard")
        )
        self.recon.publish_recon_artifact = mock.Mock(
            side_effect=lambda *args, **kwargs: events.append("publish")
        )
        self.recon.resolve_ip = mock.Mock(return_value="")
        self.recon.FAST_TOOLS = [
            ("subfinder", ["subfinder", "-d"]),
            ("assetfinder", ["assetfinder"]),
            ("findomain", ["findomain", "-t"]),
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            (root / "data").mkdir()
            seeds = root / "seeds.txt"
            seeds.write_text("example.com\n", encoding="utf-8")
            old_cwd = os.getcwd()
            try:
                os.chdir(root)
                with mock.patch.object(
                    self.recon.subprocess, "Popen",
                    return_value=CliSourceOutcomeTests.completed(
                        returncode=1, stdout="", stderr="failed"
                    ),
                ), mock.patch.object(
                    self.recon.requests, "get", side_effect=OSError("offline")
                ), mock.patch("builtins.print"):
                    result = self.recon.main(
                        str(seeds), deep=False, expand=True, scan_id=42
                    )
            finally:
                os.chdir(old_cwd)

        self.assertIsNone(result)
        self.assertEqual(events, ["guard", "publish"])
        self.assertEqual(connection.commits, 1)
        self.assertEqual(connection.rollbacks, 0)
        self.assertTrue(connection.closed)
        self.assertEqual(
            {name: entry["status"] for name, entry in self.recon.source_outcomes.items()},
            {
                "subfinder": "FAILED",
                "assetfinder": "FAILED",
                "findomain": "FAILED",
                "crt.sh": "FAILED",
                "certspotter": "FAILED",
            },
        )


if __name__ == "__main__":
    unittest.main()
