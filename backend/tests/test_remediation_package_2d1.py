import importlib.util
import logging
import os
import pathlib
import sys
import tempfile
import types
import unittest
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]


def load_backend_module(filename, extra_modules=None):
    module_name = f"pkg2d1_{filename.stem}_{id(filename)}_{len(sys.modules)}"
    spec = importlib.util.spec_from_file_location(module_name, filename)
    module = importlib.util.module_from_spec(spec)
    fake_db = types.ModuleType("db")
    fake_db.get_conn = lambda: None
    fake_db.require_running_scan = lambda cursor, scan_id: None
    replacements = {"db": fake_db}
    replacements.update(extra_modules or {})

    old_modules = {name: sys.modules.get(name) for name in replacements}
    old_path = sys.path[:]
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
    def __init__(self, result):
        self.result = result
        self.executions = []

    def execute(self, query, params=None):
        self.executions.append((query, params))

    def fetchone(self):
        return self.result

    def fetchall(self):
        return []


class FakeConnection:
    def __init__(self, result):
        self._cursor = RecordingCursor(result)
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


class OrchestrationExclusivityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_backend_module(BACKEND / "orchestration.py")
        cls.original_acquire = staticmethod(cls.module.acquire_orchestration_lock)
        cls.original_release = staticmethod(cls.module.release_orchestration_lock)
        cls.original_run_pipeline = staticmethod(cls.module.run_pipeline)
        cls.original_create_scan = staticmethod(cls.module.create_scan)

    def setUp(self):
        self.module.acquire_orchestration_lock = self.original_acquire
        self.module.release_orchestration_lock = self.original_release
        self.module.run_pipeline = self.original_run_pipeline
        self.module.create_scan = self.original_create_scan
        self.module.recover_orphaned_scans = mock.Mock(return_value=[])

    def test_first_orchestration_acquires_session_lock(self):
        connection = FakeConnection((True,))
        self.module.get_conn = lambda: connection

        result = self.module.acquire_orchestration_lock()

        self.assertIs(result, connection)
        self.assertFalse(connection.closed)
        self.assertEqual(connection.commits, 1)
        sql, params = connection._cursor.executions[0]
        self.assertIn("pg_try_advisory_lock", sql)
        self.assertEqual(params, (self.module.ASIP_ORCHESTRATION_LOCK_ID,))

    def test_second_orchestration_is_rejected_and_connection_closes(self):
        connection = FakeConnection((False,))
        self.module.get_conn = lambda: connection

        self.assertIsNone(self.module.acquire_orchestration_lock())

        self.assertTrue(connection.closed)
        self.assertEqual(connection.commits, 1)

    def test_lock_acquisition_error_rolls_back_and_closes(self):
        connection = FakeConnection((True,))
        connection._cursor.execute = mock.Mock(side_effect=RuntimeError("db error"))
        self.module.get_conn = lambda: connection

        with self.assertRaisesRegex(RuntimeError, "db error"):
            self.module.acquire_orchestration_lock()

        self.assertEqual(connection.rollbacks, 1)
        self.assertTrue(connection.closed)

    def test_rejected_attempt_does_not_create_scan_or_run_pipeline(self):
        module = self.module
        module.acquire_orchestration_lock = mock.Mock(return_value=None)
        module.run_pipeline = mock.Mock()
        module.create_scan = mock.Mock()

        with self.assertRaisesRegex(SystemExit, "0"):
            module.main()

        module.run_pipeline.assert_not_called()
        module.create_scan.assert_not_called()

    def test_lock_lifetime_covers_complete_pipeline(self):
        module = self.module
        lock_connection = object()
        events = []
        module.acquire_orchestration_lock = mock.Mock(return_value=lock_connection)
        module.run_pipeline = lambda: events.append("pipeline")
        module.release_orchestration_lock = (
            lambda connection: events.append(("release", connection))
        )

        module.main()

        self.assertEqual(events, ["pipeline", ("release", lock_connection)])

    def test_lock_cleanup_occurs_after_pipeline_exception(self):
        module = self.module
        lock_connection = object()
        module.acquire_orchestration_lock = mock.Mock(return_value=lock_connection)
        module.run_pipeline = mock.Mock(side_effect=RuntimeError("failure"))
        module.release_orchestration_lock = mock.Mock()

        with self.assertRaisesRegex(RuntimeError, "failure"):
            module.main()

        module.release_orchestration_lock.assert_called_once_with(lock_connection)

    def test_lock_cleanup_occurs_after_keyboard_interrupt(self):
        module = self.module
        lock_connection = object()
        module.acquire_orchestration_lock = mock.Mock(return_value=lock_connection)
        module.run_pipeline = mock.Mock(side_effect=KeyboardInterrupt())
        module.release_orchestration_lock = mock.Mock()

        with self.assertRaises(KeyboardInterrupt):
            module.main()

        module.release_orchestration_lock.assert_called_once_with(lock_connection)

    def test_explicit_unlock_uses_same_session_and_always_closes(self):
        connection = FakeConnection((True,))

        self.module.release_orchestration_lock(connection)

        sql, params = connection._cursor.executions[0]
        self.assertIn("pg_advisory_unlock", sql)
        self.assertEqual(params, (self.module.ASIP_ORCHESTRATION_LOCK_ID,))
        self.assertEqual(connection.commits, 1)
        self.assertTrue(connection.closed)

    def test_unlock_error_still_closes_session(self):
        connection = FakeConnection((True,))
        connection._cursor.execute = mock.Mock(side_effect=RuntimeError("db error"))

        with self.assertRaisesRegex(RuntimeError, "db error"):
            self.module.release_orchestration_lock(connection)

        self.assertTrue(connection.closed)


class ReconArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifacts = load_backend_module(BACKEND / "recon_artifact.py")

    @staticmethod
    def write_csv(path, rows=()):
        content = "domain,sources\n"
        content += "".join(f"{domain},{source}\n" for domain, source in rows)
        pathlib.Path(path).write_text(content, encoding="utf-8")

    def test_current_scan_artifact_is_accepted(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            source = root / "source.csv"
            artifact = root / "final_output.csv"
            self.write_csv(source, [("current.example", "test")])

            self.artifacts.publish_recon_artifact(source, artifact, 42, 1)
            manifest = self.artifacts.validate_recon_artifact(artifact, 42)

            self.assertEqual(manifest["scan_id"], 42)
            self.assertEqual(manifest["row_count"], 1)

    def test_previous_scan_artifact_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            source = root / "source.csv"
            artifact = root / "final_output.csv"
            self.write_csv(source, [("old.example", "test")])
            self.artifacts.publish_recon_artifact(source, artifact, 41, 1)

            with self.assertRaisesRegex(
                self.artifacts.ReconArtifactError, "belongs to scan 41"
            ):
                self.artifacts.validate_recon_artifact(artifact, 42)

    def test_missing_and_malformed_identity_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            artifact = root / "final_output.csv"
            self.write_csv(artifact)

            with self.assertRaisesRegex(
                self.artifacts.ReconArtifactError, "missing or invalid"
            ):
                self.artifacts.validate_recon_artifact(artifact, 42)

            manifest = self.artifacts.get_manifest_path(artifact)
            manifest.write_text('{"scan_id": "42"}', encoding="utf-8")
            with self.assertRaises(self.artifacts.ReconArtifactError):
                self.artifacts.validate_recon_artifact(artifact, 42)

            manifest.write_text("not-json", encoding="utf-8")
            with self.assertRaisesRegex(
                self.artifacts.ReconArtifactError, "missing or invalid"
            ):
                self.artifacts.validate_recon_artifact(artifact, 42)

    def test_publication_failure_preserves_rejection_of_old_artifact(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            old_source = root / "old.csv"
            new_source = root / "new.csv"
            artifact = root / "final_output.csv"
            self.write_csv(old_source, [("old.example", "test")])
            self.write_csv(new_source, [("new.example", "test")])
            self.artifacts.publish_recon_artifact(old_source, artifact, 41, 1)
            old_bytes = artifact.read_bytes()

            with mock.patch.object(
                self.artifacts.os, "replace", side_effect=OSError("disk failure")
            ):
                with self.assertRaisesRegex(OSError, "disk failure"):
                    self.artifacts.publish_recon_artifact(new_source, artifact, 42, 1)

            self.assertEqual(artifact.read_bytes(), old_bytes)
            with self.assertRaisesRegex(
                self.artifacts.ReconArtifactError, "belongs to scan 41"
            ):
                self.artifacts.validate_recon_artifact(artifact, 42)

    def test_partial_temporary_file_is_never_a_complete_artifact(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            artifact = root / "final_output.csv"
            partial = root / ".final_output.csv.partial.tmp"
            self.write_csv(partial, [("partial.example", "test")])

            with self.assertRaisesRegex(
                self.artifacts.ReconArtifactError, "missing or invalid"
            ):
                self.artifacts.validate_recon_artifact(artifact, 42)

    def test_successful_publication_atomically_replaces_previous_artifact(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            old_source = root / "old.csv"
            new_source = root / "new.csv"
            artifact = root / "final_output.csv"
            self.write_csv(old_source, [("old.example", "test")])
            self.write_csv(new_source, [("new.example", "test")])
            self.artifacts.publish_recon_artifact(old_source, artifact, 41, 1)
            real_replace = self.artifacts.os.replace
            replacements = []

            def recording_replace(source, destination):
                replacements.append((pathlib.Path(source), pathlib.Path(destination)))
                return real_replace(source, destination)

            with mock.patch.object(
                self.artifacts.os, "replace", side_effect=recording_replace
            ):
                self.artifacts.publish_recon_artifact(new_source, artifact, 42, 1)

            self.assertEqual(artifact.read_bytes(), new_source.read_bytes())
            self.artifacts.validate_recon_artifact(artifact, 42)
            self.assertEqual(len(replacements), 2)
            self.assertTrue(all(source.parent == root for source, _ in replacements))

    def test_header_only_current_scan_artifact_is_valid_zero_discovery(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            source = root / "empty.csv"
            artifact = root / "final_output.csv"
            self.write_csv(source)

            manifest = self.artifacts.publish_recon_artifact(source, artifact, 42, 0)
            validated = self.artifacts.validate_recon_artifact(artifact, 42)

            self.assertEqual(manifest["row_count"], 0)
            self.assertEqual(validated["row_count"], 0)
            self.assertEqual(artifact.read_text(encoding="utf-8"), "domain,sources\n")


class HandoffIntegrationTests(unittest.TestCase):
    @staticmethod
    def write_empty_recon_csv(path):
        pathlib.Path(path).write_text(
            "Domain,Source,Seed,IP,Reverse_DNS,HTTP_Status,HTTP_Reason,"
            "Redirect_Location,Final_URL,Final_Status,Title,"
            "HTTP_Observation_Status,Domain_Status\n",
            encoding="utf-8",
        )

    def test_recon_publication_failure_propagates(self):
        fake_config = types.ModuleType("config")
        fake_config.CERTSPOTTER_API_KEY = None
        fake_probe = types.ModuleType("http_probe")
        fake_probe.http_probe = lambda domain: None
        recon = load_backend_module(
            BACKEND / "recon.py",
            {"config": fake_config, "http_probe": fake_probe},
        )
        recon.load_known = lambda: set()
        recon.get_conn = lambda: FakeConnection(None)
        recon.require_running_scan = lambda cursor, scan_id: None

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            seeds = root / "seeds.txt"
            seeds.write_text("", encoding="utf-8")
            previous_directory = os.getcwd()
            try:
                os.chdir(root)
                recon.publish_recon_artifact = mock.Mock(
                    side_effect=OSError("publication failed")
                )
                with self.assertRaisesRegex(OSError, "publication failed"):
                    recon.main(str(seeds), deep=False, expand=False, scan_id=42)
            finally:
                os.chdir(previous_directory)

    def test_ingest_validates_identity_before_opening_database(self):
        source = (BACKEND / "ingest.py").read_text(encoding="utf-8")
        validation = source.index("manifest, artifact_data = read_validated_recon_artifact")
        database_open = source.index("\nconn = get_conn()")

        self.assertLess(validation, database_open)
        self.assertIn('artifact_path = "data/final_output.csv"', source)
        self.assertIn("pd.read_csv(io.BytesIO(artifact_data))", source)
        self.assertIn('manifest["row_count"]', source)

    def test_ingest_accepts_header_only_current_scan_artifact(self):
        artifacts = load_backend_module(BACKEND / "recon_artifact.py")
        fake_db = types.ModuleType("db")
        connection = FakeConnection(None)
        fake_db.get_conn = mock.Mock(return_value=connection)
        fake_db.require_running_scan = lambda cursor, scan_id: None

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            data = root / "data"
            data.mkdir()
            source = root / "empty.csv"
            artifact = data / "final_output.csv"
            self.write_empty_recon_csv(source)
            artifacts.publish_recon_artifact(source, artifact, 42, 0)
            previous_directory = os.getcwd()
            try:
                os.chdir(root)
                with mock.patch.object(sys, "argv", ["ingest.py", "42"]):
                    load_backend_module(BACKEND / "ingest.py", {"db": fake_db})
            finally:
                os.chdir(previous_directory)

        fake_db.get_conn.assert_called_once_with()
        self.assertEqual(connection.commits, 1)
        self.assertTrue(connection.closed)

    def test_ingest_rejects_previous_scan_artifact_before_database_access(self):
        artifacts = load_backend_module(BACKEND / "recon_artifact.py")
        fake_db = types.ModuleType("db")
        fake_db.get_conn = mock.Mock()
        fake_db.require_running_scan = lambda cursor, scan_id: None

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            data = root / "data"
            data.mkdir()
            source = root / "old.csv"
            artifact = data / "final_output.csv"
            self.write_empty_recon_csv(source)
            artifacts.publish_recon_artifact(source, artifact, 41, 0)
            previous_directory = os.getcwd()
            try:
                os.chdir(root)
                with mock.patch.object(sys, "argv", ["ingest.py", "42"]), \
                        self.assertRaisesRegex(RuntimeError, "belongs to scan 41"):
                    load_backend_module(BACKEND / "ingest.py", {"db": fake_db})
            finally:
                os.chdir(previous_directory)

        fake_db.get_conn.assert_not_called()

    def test_orchestration_passes_same_scan_id_to_recon_and_ingest(self):
        source = (BACKEND / "orchestration.py").read_text(encoding="utf-8")

        self.assertIn('recon.py --scan-id {scan_id}', source)
        self.assertIn('ingest.py {scan_id}', source)


if __name__ == "__main__":
    unittest.main()
