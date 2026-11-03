import ast
import importlib.util
import pathlib
import sys
import types
import unittest
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]


def source(filename):
    return (BACKEND / filename).read_text(encoding="utf-8")


def normalized(text):
    return " ".join(text.split()).upper()


def load_module(filename, replacements=None, argv=None):
    module_name = f"pkg3a_{filename}_{len(sys.modules)}"
    spec = importlib.util.spec_from_file_location(module_name, BACKEND / filename)
    module = importlib.util.module_from_spec(spec)
    replacements = replacements or {}
    previous_modules = {name: sys.modules.get(name) for name in replacements}
    previous_argv = sys.argv[:]
    previous_path = sys.path[:]
    try:
        sys.modules.update(replacements)
        sys.path.insert(0, str(BACKEND))
        if argv is not None:
            sys.argv = list(argv)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.argv = previous_argv
        sys.path[:] = previous_path
        for name, previous in previous_modules.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous


class HttpProbeOutcomeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(BACKEND))
        import http_probe
        cls.http_probe = http_probe

    def test_observation_requires_current_authorization(self):
        with mock.patch.object(self.http_probe, "_observe_once") as observe:
            result = self.http_probe.http_probe("example.test")
        self.assertEqual(result["http_observation_status"], "UNKNOWN")
        observe.assert_not_called()

    def test_no_response_after_authorized_attempts(self):
        allowed = mock.Mock(return_value=True)
        with mock.patch.object(self.http_probe, "_observe_once", side_effect=OSError("offline")):
            result = self.http_probe.http_probe("example.test", before_request=allowed)
        self.assertEqual(result["http_observation_status"], "NO_RESPONSE")
        self.assertEqual(allowed.call_count, 2)


class SchemaAndIngestOutcomeTests(unittest.TestCase):
    def test_migration_defaults_existing_rows_to_unknown_and_restricts_values(self):
        migration = source("migrations/002_add_http_observation_status.sql")
        norm = normalized(migration)

        self.assertIn("ADD COLUMN HTTP_OBSERVATION_STATUS TEXT NOT NULL DEFAULT 'UNKNOWN'", norm)
        for status in ("RESPONDED", "NO_RESPONSE", "FAILED", "UNKNOWN"):
            self.assertIn(status, norm)

    def test_schema_snapshots_include_unknown_default(self):
        for filename in (
            "asm_schema.sql",
            "asm_schema_post_guardrails.sql",
            "asm_schema_post_guardrails-schema-only.sql",
        ):
            with self.subTest(filename=filename):
                norm = normalized(source(filename))
                self.assertIn("HTTP_OBSERVATION_STATUS TEXT DEFAULT 'UNKNOWN'::TEXT NOT NULL", norm)
                self.assertIn("DOMAIN_STATES_HTTP_OBSERVATION_STATUS_CHECK", norm)

    def test_ingest_persists_explicit_status_and_legacy_missing_is_unknown(self):
        text = source("ingest.py")
        tree = ast.parse(text)
        normalize_status = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "normalize_http_observation_status"
        )
        normalize_text = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "normalize_artifact_text"
        )
        statuses = next(
            node for node in tree.body
            if isinstance(node, ast.Assign)
            and any(getattr(target, "id", None) == "HTTP_OBSERVATION_STATUSES" for target in node.targets)
        )
        namespace = {"pd": types.SimpleNamespace(isna=lambda value: value is None)}
        exec(compile(ast.Module([normalize_text, statuses, normalize_status], []), "<ingest-subset>", "exec"), namespace)

        self.assertEqual(namespace["normalize_http_observation_status"]("RESPONDED"), "RESPONDED")
        self.assertEqual(namespace["normalize_http_observation_status"]("no_response"), "NO_RESPONSE")
        self.assertEqual(namespace["normalize_http_observation_status"](""), "UNKNOWN")
        self.assertEqual(namespace["normalize_http_observation_status"](None), "UNKNOWN")

        norm = normalized(text)
        self.assertIn("HTTP_OBSERVATION_STATUS", norm)
        self.assertIn("ROW.GET(\"HTTP_OBSERVATION_STATUS\", \"\")", norm)
        self.assertNotIn("HTTP_STATUS = 0 THEN 'NO_RESPONSE'", norm)

    def test_recon_artifact_writes_http_observation_status_column(self):
        text = source("recon.py")

        self.assertIn('"HTTP_Observation_Status"', text)
        self.assertIn('"http_observation_status": "UNKNOWN"', text)
        self.assertIn('data["http_observation_status"]', text)


class RecordingCursor:
    def __init__(self, rows):
        self.rows = rows
        self.executions = []
        self.rowcount = 1

    def execute(self, sql, params=None):
        self.executions.append((sql, params))

    def fetchall(self):
        return list(self.rows)


class FakeConnection:
    def __init__(self, cursor):
        self.cursor_obj = cursor
        self.committed = False
        self.closed = False

    def cursor(self):
        return self.cursor_obj

    def commit(self):
        self.committed = True

    def close(self):
        self.closed = True


class SanHttpOutcomePersistenceTests(unittest.TestCase):
    def load_worker(self, result):
        cursor = RecordingCursor([(7, "child.example", "192.0.2.1")])
        connection = FakeConnection(cursor)
        fake_db = types.ModuleType("db")
        fake_db.get_conn = mock.Mock(return_value=connection)
        fake_db.require_running_scan = mock.Mock()
        fake_probe = types.ModuleType("http_probe")
        fake_probe.http_probe = mock.Mock(return_value=result)

        module = load_module(
            "san_http_worker.py",
            {"db": fake_db, "http_probe": fake_probe},
            ["san_http_worker.py", "42"],
        )
        module.recheck_active_authorization = mock.Mock(
            return_value=(True, "authorized")
        )
        return module, cursor, connection

    def test_san_http_response_persists_responded(self):
        result = {
            "http_observation_status": "RESPONDED",
            "http_status": 404,
            "http_reason": "Not Found",
            "final_url": "https://child.example",
            "final_status": 404,
            "redirect_evidence": {
                "requested_url": "https://child.example/",
                "http_status": 404,
                "first_hop_location": None,
                "first_hop_destination": None,
                "observed_hops": [],
                "verified_terminal_url": "https://child.example/",
                "completion_status": "COMPLETE",
                "stop_reason": None,
            },
            "title": "",
        }
        module, cursor, connection = self.load_worker(result)

        module.main()

        update_sql, update_params = cursor.executions[1]
        self.assertIn("http_observation_status", update_sql)
        self.assertEqual(update_params[0], 404)
        self.assertIn('"completion_status": "COMPLETE"', update_params[5])
        self.assertEqual(update_params[7], "RESPONDED")
        self.assertTrue(connection.committed)

    def test_san_http_no_response_persists_outcome_without_response_evidence(self):
        module, cursor, connection = self.load_worker({
            "http_observation_status": "NO_RESPONSE",
            "http_status": 0,
            "redirect_evidence": {
                "requested_url": "http://child.example/",
                "http_status": None,
                "first_hop_location": None,
                "first_hop_destination": None,
                "observed_hops": [],
                "verified_terminal_url": None,
                "completion_status": "UNKNOWN",
                "stop_reason": "no_response",
            },
        })

        module.main()

        update_sql, update_params = cursor.executions[1]
        self.assertIn("SET http_observation_status = %s", update_sql)
        self.assertNotIn("http_status = %s", update_sql)
        self.assertEqual(update_params[0], "NO_RESPONSE")
        self.assertIn('"stop_reason": "no_response"', update_params[1])
        self.assertTrue(connection.committed)

    def test_san_http_failed_persists_failed_outcome(self):
        module, cursor, _ = self.load_worker({
            "http_observation_status": "FAILED",
            "http_status": 0,
        })

        module.main()

        update_sql, update_params = cursor.executions[1]
        self.assertIn("SET http_observation_status = %s", update_sql)
        self.assertEqual(update_params[0], "FAILED")

    def test_san_state_sync_creates_unknown_placeholder_rows(self):
        text = source("san_state_sync.py")
        norm = normalized(text)

        self.assertIn("HTTP_OBSERVATION_STATUS", norm)
        self.assertIn("'UNKNOWN'", norm)


class ProtectedBehaviorTests(unittest.TestCase):
    def test_risky_domains_weights_thresholds_and_authorization_policy_are_unchanged(self):
        engine = source("risk_engine.py")
        for snippet in (
            '"new_asset": 3',
            '"http_exposed": 1',
            '"resolves_no_http": 1',
            'score >= 8',
            'return "High"',
            'score >= 6',
            'return "Elevated"',
            'score >= 4',
            'return "Review"',
        ):
            self.assertIn(snippet, engine)

        policy = source("authorization_policy.py")
        self.assertIn("scannable IS TRUE", policy)
        self.assertIn("validation_source = 'manual'", policy)

    def test_known_shadow_and_risk_worker_are_not_modified_by_3a_contract(self):
        self.assertIn("d.is_known = FALSE", source("main.py"))
        self.assertIn("evidence.is_known is False", source("risk_engine.py"))
        self.assertIn("calculate_scan_risks(cur, scan_id)", source("risk_worker.py"))


if __name__ == "__main__":
    unittest.main()
