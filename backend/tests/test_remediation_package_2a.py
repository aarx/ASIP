import importlib.util
import logging
import pathlib
import sys
import tempfile
import types
import unittest
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
MIGRATION = BACKEND / "migrations" / "001_add_scan_lifecycle.sql"
SCHEMA = BACKEND / "asm_schema_post_guardrails-schema-only.sql"


def load_backend_module(filename, extra_modules=None):
    module_name = f"pkg2a_{filename.stem}_{id(filename)}_{len(sys.modules)}"
    spec = importlib.util.spec_from_file_location(module_name, filename)
    module = importlib.util.module_from_spec(spec)
    fake_db = types.ModuleType("db")
    fake_db.get_conn = lambda: None
    fake_db.require_running_scan = lambda cursor, scan_id: None
    fake_db.get_latest_authoritative_scan_id = lambda cursor: None
    fake_db.get_previous_authoritative_scan_id = lambda cursor, current_scan_id=None: None
    replacements = {"db": fake_db}
    replacements.update(extra_modules or {})

    old_modules = {name: sys.modules.get(name) for name in replacements}
    old_path = sys.path[:]
    with tempfile.TemporaryDirectory() as temp_dir:
        pathlib.Path(temp_dir, "logs").mkdir()
        try:
            sys.modules.update(replacements)
            sys.path.insert(0, str(BACKEND))
            with mock.patch("logging.FileHandler", return_value=logging.NullHandler()):
                spec.loader.exec_module(module)
        finally:
            sys.path[:] = old_path
            for name, previous in old_modules.items():
                if previous is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = previous
    return module


class RecordingCursor:
    def __init__(self, fetchones=None, fetchalls=None):
        self.fetchones = list(fetchones or [])
        self.fetchalls = list(fetchalls or [])
        self.executions = []

    def execute(self, query, params=None):
        self.executions.append((query, params))

    def fetchone(self):
        return self.fetchones.pop(0) if self.fetchones else None

    def fetchall(self):
        return self.fetchalls.pop(0) if self.fetchalls else []


class FakeConnection:
    def __init__(self, cursor):
        self._cursor = cursor
        self.committed = False
        self.rolled_back = False
        self.closed = False

    def cursor(self):
        return self._cursor

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


class ScanLifecycleUnitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.orchestration = load_backend_module(BACKEND / "orchestration.py")
        cls.db = load_backend_module(BACKEND / "db.py", {
            "config": types.SimpleNamespace(
                DB_HOST="unused", DB_NAME="unused",
                DB_USER="unused", DB_PASSWORD="unused"
            )
        })
        cls.original_create_scan = staticmethod(cls.orchestration.create_scan)
        cls.original_setup_logging = staticmethod(cls.orchestration.setup_logging)
        cls.original_run_step = staticmethod(cls.orchestration.run_step)
        cls.original_mark_scan_terminal = staticmethod(
            cls.orchestration.mark_scan_terminal
        )

    def setUp(self):
        module = self.orchestration
        module.create_scan = self.original_create_scan
        module.setup_logging = self.original_setup_logging
        module.run_step = self.original_run_step
        module.mark_scan_terminal = self.original_mark_scan_terminal
        module.acquire_orchestration_lock = lambda: object()
        module.release_orchestration_lock = lambda connection: None

    def test_new_scan_starts_running_with_no_completed_at(self):
        cursor = RecordingCursor(fetchones=[(42,)])
        connection = FakeConnection(cursor)
        self.orchestration.get_conn = lambda: connection

        self.assertEqual(self.orchestration.create_scan(), 42)
        sql, params = cursor.executions[0]
        self.assertIn("status", sql)
        self.assertIn("'RUNNING'", sql)
        self.assertIn("NULL", sql)
        self.assertIsNone(params)
        self.assertTrue(connection.committed)
        self.assertFalse(connection.rolled_back)
        self.assertTrue(connection.closed)

    def test_terminal_transition_is_guarded_and_atomic(self):
        cursor = RecordingCursor(fetchones=[(42,)])
        connection = FakeConnection(cursor)
        self.orchestration.get_conn = lambda: connection

        self.orchestration.mark_scan_terminal(42, "FAILED")

        sql, params = cursor.executions[0]
        self.assertIn("status = %s", sql)
        self.assertIn("completed_at = NOW()", sql)
        self.assertIn("status = 'RUNNING'", sql)
        self.assertEqual(params, ("FAILED", 42))
        self.assertTrue(connection.committed)

    def test_terminal_transition_refuses_non_running_scan(self):
        cursor = RecordingCursor(fetchones=[None])
        connection = FakeConnection(cursor)
        self.orchestration.get_conn = lambda: connection

        with self.assertRaisesRegex(RuntimeError, "did not transition"):
            self.orchestration.mark_scan_terminal(42, "SUCCEEDED")

        self.assertTrue(connection.rolled_back)
        self.assertFalse(connection.committed)

    def test_invalid_terminal_status_is_rejected_before_database_access(self):
        self.orchestration.get_conn = mock.Mock()
        with self.assertRaises(ValueError):
            self.orchestration.mark_scan_terminal(42, "UNKNOWN")
        self.orchestration.get_conn.assert_not_called()

    def test_successful_pipeline_transitions_only_to_succeeded(self):
        module = self.orchestration
        transitions = []
        module.create_scan = lambda identity=None: 42
        module.setup_logging = lambda path: None
        module.run_step = lambda name, cmd, attempt, maximum: 0
        module.mark_scan_terminal = lambda scan_id, status: transitions.append((scan_id, status))

        module.main()

        self.assertEqual(transitions, [(42, "SUCCEEDED")])

    def test_stage_failure_attempts_failed_and_exits_nonzero(self):
        module = self.orchestration
        transitions = []
        module.create_scan = lambda identity=None: 42
        module.setup_logging = lambda path: None
        module.run_step = mock.Mock(side_effect=RuntimeError("stage failed"))
        module.mark_scan_terminal = lambda scan_id, status: transitions.append((scan_id, status))

        with self.assertRaisesRegex(SystemExit, "1"):
            module.main()

        self.assertEqual(transitions, [(42, "FAILED")])

    def test_failed_transition_failure_still_exits_without_success(self):
        module = self.orchestration
        module.create_scan = lambda identity=None: 42
        module.setup_logging = lambda path: None
        module.run_step = mock.Mock(side_effect=RuntimeError("stage failed"))
        module.mark_scan_terminal = mock.Mock(side_effect=RuntimeError("db failed"))

        with self.assertRaisesRegex(SystemExit, "1"):
            module.main()

        module.mark_scan_terminal.assert_called_once_with(42, "FAILED")

    def test_succeeded_transition_failure_does_not_attempt_failed(self):
        module = self.orchestration
        module.create_scan = lambda identity=None: 42
        module.setup_logging = lambda path: None
        module.run_step = lambda name, cmd, attempt, maximum: 0
        module.mark_scan_terminal = mock.Mock(side_effect=RuntimeError("ambiguous commit"))

        with mock.patch.object(module.logging, "info") as info, \
                self.assertRaisesRegex(SystemExit, "1"):
            module.main()

        module.mark_scan_terminal.assert_called_once_with(42, "SUCCEEDED")
        self.assertFalse(any(
            "Completed Successfully" in str(call)
            for call in info.call_args_list
        ))

    def test_keyboard_interrupt_assigns_failed_after_scan_creation(self):
        module = self.orchestration
        module.create_scan = lambda identity=None: 42
        module.setup_logging = lambda path: None
        module.run_step = mock.Mock(side_effect=KeyboardInterrupt())
        module.mark_scan_terminal = mock.Mock()

        with self.assertRaises(KeyboardInterrupt):
            module.main()

        module.mark_scan_terminal.assert_called_once_with(42, "FAILED")

    def test_system_exit_does_not_assign_failed(self):
        module = self.orchestration
        module.create_scan = lambda identity=None: 42
        module.setup_logging = lambda path: None
        module.run_step = mock.Mock(side_effect=SystemExit(9))
        module.mark_scan_terminal = mock.Mock()

        with self.assertRaisesRegex(SystemExit, "9"):
            module.main()

        module.mark_scan_terminal.assert_not_called()

    def test_latest_authoritative_helper_uses_only_succeeded(self):
        cursor = RecordingCursor(fetchones=[(17,)])
        result = self.db.get_latest_authoritative_scan_id(cursor)

        self.assertEqual(result, 17)
        sql, params = cursor.executions[0]
        self.assertIn("status = 'SUCCEEDED'", sql)
        self.assertIn("ORDER BY id DESC", sql)
        self.assertIn("LIMIT 1", sql)
        self.assertNotIn("MAX(", sql)
        self.assertIsNone(params)

    def test_latest_authoritative_helper_returns_none(self):
        cursor = RecordingCursor(fetchones=[None])
        self.assertIsNone(self.db.get_latest_authoritative_scan_id(cursor))


class ApiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fake_llm = types.ModuleType("llm_service")
        fake_llm.ask_llm = mock.Mock(return_value="unexpected")
        cls.fake_llm = fake_llm
        cls.main = load_backend_module(
            BACKEND / "main.py", {"llm_service": fake_llm}
        )
        cls.mcp = load_backend_module(BACKEND / "mcp_server.py")

    def setUp(self):
        self.main.get_latest_authoritative_scan_id = lambda cursor: None
        self.mcp.get_latest_authoritative_scan_id = lambda cursor: None
        self.fake_llm.ask_llm.reset_mock()

    def test_zero_authoritative_new_domains_shape(self):
        connection = FakeConnection(RecordingCursor())
        self.main.get_conn = lambda: connection
        self.assertEqual(self.main.new_domains(), {
            "latest_scan": None,
            "new_domains": []
        })

    def test_zero_authoritative_summary_has_zero_current_asset_count(self):
        cursor = RecordingCursor(fetchones=[
            (0,), (0,), (0,), (0,), (0,), (0,), (0,), (3,)
        ])
        self.main.get_conn = lambda: FakeConnection(cursor)

        self.assertEqual(self.main.summary(), {
            "total_domains": 0,
            "live_domains": 0,
            "known_domains": 0,
            "new_domains": 0,
            "findings": 0,
            "shadow_assets": 0,
            "non_web_assets": 0,
            "unverified_domains": 3,
            "candidate_domains": 0,
            "external_domains": 0,
        })

    def test_zero_authoritative_exposure_summary_shape(self):
        cursor = RecordingCursor(fetchones=[(0,), (0,), (0,)])
        self.main.get_conn = lambda: FakeConnection(cursor)
        self.assertEqual(self.main.exposure_summary(), {
            "scan_id": None,
            "total_domains": 0,
            "resolving_domains": 0,
            "http_responding_domains": 0
        })

    def test_zero_authoritative_domain_detail_and_analysis_skip_llm(self):
        self.main.get_conn = lambda: FakeConnection(RecordingCursor())
        expected = {"error": "no authoritative scan yet"}
        self.assertEqual(self.main.domain_detail("asset.example.test"), expected)
        self.assertEqual(self.main.domain_analysis("asset.example.test"), expected)
        self.fake_llm.ask_llm.assert_not_called()

    def test_zero_authoritative_targets_shape(self):
        self.main.get_conn = lambda: FakeConnection(RecordingCursor())
        self.assertEqual(self.main.export_targets(), [])

    def test_zero_authoritative_investigation_shape(self):
        self.main.get_conn = lambda: FakeConnection(RecordingCursor())
        self.assertEqual(self.main.investigation_assets(page=2, limit=5), {
            "page": 2, "limit": 5, "count": 0, "assets": []
        })

    def test_zero_authoritative_export_has_headers_and_no_rows(self):
        self.main.get_conn = lambda: FakeConnection(RecordingCursor())
        class CapturedStreamingResponse:
            def __init__(self, content, media_type):
                self.content = list(content)
                self.media_type = media_type
                self.headers = {}

        with mock.patch(
            "fastapi.responses.StreamingResponse", CapturedStreamingResponse
        ):
            response = self.main.export_enriched_csv()

        body = "".join(response.content)
        self.assertTrue(body.startswith("Domain,Is Known,Ownership Status,First Seen"))
        self.assertEqual(len(body.splitlines()), 1)
        self.assertEqual(response.media_type, "text/csv")

    def test_zero_authoritative_mcp_summary_shape(self):
        cursor = RecordingCursor(fetchones=[(0,), (0,)])
        self.mcp.get_conn = lambda: FakeConnection(cursor)
        self.assertEqual(self.mcp.get_summary(), {
            "scan_id": None,
            "live_domains": 0,
            "shadow_assets": 0
        })

    def test_zero_authoritative_mcp_lists_are_empty(self):
        self.mcp.get_conn = lambda: FakeConnection(
            RecordingCursor(fetchalls=[[]])
        )
        self.assertEqual(self.mcp.get_shadow_assets(), [])

        self.mcp.get_conn = lambda: FakeConnection(
            RecordingCursor(fetchalls=[[]])
        )
        self.assertEqual(self.mcp.get_findings(), [])

    def test_category_a_callers_use_shared_helper(self):
        source = (BACKEND / "main.py").read_text()
        required_functions = [
            "summary", "http_status", "sources", "seeds", "assets",
            "new_domains", "exposure_summary", "risky_domains",
            "sensitive_exposure", "hygiene_score", "provider_clusters",
            "shadow_assets", "risk_leaderboard", "domain_detail",
            "export_targets", "export_enriched_csv", "investigation_assets",
            "findings", "cert_expiry", "shadow_summary",
            "shadow_by_provider", "non_web_summary", "unknown_high_risk"
        ]
        for index, name in enumerate(required_functions):
            start = source.index(f"def {name}(")
            end = source.find("\n@app.get", start)
            if end == -1:
                end = len(source)
            self.assertIn(
                "get_latest_authoritative_scan_id(cur)",
                source[start:end],
                name
            )

class SchemaArtifactTests(unittest.TestCase):
    def test_migration_is_transactional_and_preserves_legacy_values(self):
        sql = MIGRATION.read_text()
        self.assertTrue(sql.lstrip().startswith("BEGIN;"))
        self.assertTrue(sql.rstrip().endswith("COMMIT;"))
        self.assertIn("DEFAULT 'UNKNOWN'", sql)
        self.assertNotIn("UPDATE public.scans", sql)
        self.assertNotIn("UPDATE scans", sql)
        self.assertIn("idx_scans_succeeded_id_desc", sql)

    def test_fresh_schema_has_equivalent_lifecycle_metadata(self):
        migration = MIGRATION.read_text()
        schema = SCHEMA.read_text()
        for token in [
            "status", "UNKNOWN", "RUNNING", "SUCCEEDED", "FAILED",
            "scans_status_check", "scans_status_completed_at_check",
            "idx_scans_succeeded_id_desc"
        ]:
            self.assertIn(token, migration)
            self.assertIn(token, schema)


if __name__ == "__main__":
    unittest.main()
