import ast
import hashlib
import importlib.util
import logging
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
RISK_COMPUTE_BASELINE_SHA256 = (
    "c797d4c35687eb5a329393f7d94a54488cdfbd5168a87c1c4845d99ff7c1fa33"
)


def make_db_module(connection=None, guard=None):
    module = types.ModuleType("db")
    module.get_conn = mock.Mock(return_value=connection)
    module.require_running_scan = guard or mock.Mock()
    return module


def load_backend_module(filename, replacements=None, argv=None):
    module_name = f"pkg2d1b_{filename.stem}_{id(filename)}_{len(sys.modules)}"
    spec = importlib.util.spec_from_file_location(module_name, filename)
    module = importlib.util.module_from_spec(spec)
    replacements = replacements or {}
    old_modules = {name: sys.modules.get(name) for name in replacements}
    old_path = sys.path[:]
    old_argv = sys.argv[:]
    try:
        sys.modules.update(replacements)
        sys.path.insert(0, str(BACKEND))
        if argv is not None:
            sys.argv = list(argv)
        with mock.patch("logging.FileHandler", return_value=logging.NullHandler()):
            spec.loader.exec_module(module)
    finally:
        sys.argv = old_argv
        sys.path[:] = old_path
        for name, previous in old_modules.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous
    return module


class RecordingCursor:
    def __init__(self, fetchone=None, fetchall=None):
        self.fetchone_result = fetchone
        self.fetchall_result = list(fetchall or [])
        self.executions = []
        self.rowcount = 0

    def execute(self, query, params=None):
        self.executions.append((query, params))
        self.rowcount = 1

    def fetchone(self):
        return self.fetchone_result

    def fetchall(self):
        return list(self.fetchall_result)


class FakeConnection:
    def __init__(self, cursor=None):
        self._cursor = cursor or RecordingCursor()
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


class RunningScanHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        config = types.ModuleType("config")
        config.DB_HOST = "unused"
        config.DB_NAME = "unused"
        config.DB_USER = "unused"
        config.DB_PASSWORD = "unused"
        cls.db = load_backend_module(BACKEND / "db.py", {"config": config})

    def test_running_scan_is_accepted_and_exact_row_is_locked(self):
        cursor = RecordingCursor(fetchone=("RUNNING",))

        self.db.require_running_scan(cursor, 42)

        sql, params = cursor.executions[0]
        normalized = " ".join(sql.split()).upper()
        self.assertIn("FROM SCANS", normalized)
        self.assertIn("WHERE ID = %S", normalized)
        self.assertIn("FOR UPDATE", normalized)
        self.assertNotIn("MAX(", normalized)
        self.assertNotIn("ORDER BY", normalized)
        self.assertEqual(params, (42,))

    def test_nonexistent_scan_is_rejected(self):
        cursor = RecordingCursor(fetchone=None)
        with self.assertRaisesRegex(self.db.ScanNotRunningError, "does not exist"):
            self.db.require_running_scan(cursor, 42)

    def test_all_non_running_states_are_rejected(self):
        for status in ("SUCCEEDED", "FAILED", "UNKNOWN"):
            with self.subTest(status=status):
                cursor = RecordingCursor(fetchone=(status,))
                with self.assertRaisesRegex(
                    self.db.ScanNotRunningError, f"is {status}, not RUNNING"
                ):
                    self.db.require_running_scan(cursor, 42)

    def test_helper_does_not_manage_caller_transaction(self):
        connection = FakeConnection(RecordingCursor(fetchone=("RUNNING",)))

        self.db.require_running_scan(connection.cursor(), 42)

        self.assertEqual(connection.commits, 0)
        self.assertEqual(connection.rollbacks, 0)
        self.assertFalse(connection.closed)


class PostgreSQLLockingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.initdb = shutil.which("initdb") or "/usr/lib/postgresql/18/bin/initdb"
        cls.pg_ctl = shutil.which("pg_ctl") or "/usr/lib/postgresql/18/bin/pg_ctl"
        if not pathlib.Path(cls.initdb).is_file() or not pathlib.Path(cls.pg_ctl).is_file():
            raise unittest.SkipTest("PostgreSQL server binaries are unavailable")

        cls.runtime = tempfile.TemporaryDirectory(prefix="asip-2d1b-pg-")
        root = pathlib.Path(cls.runtime.name)
        cls.data_dir = root / "data"
        cls.socket_dir = root / "socket"
        cls.log_file = root / "postgres.log"
        cls.socket_dir.mkdir()
        cls.port = 55439
        try:
            subprocess.run(
                [
                    cls.initdb,
                    f"--pgdata={cls.data_dir}",
                    "--auth=trust",
                    "--username=asip_2d1b_test",
                    "--no-locale",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [
                    cls.pg_ctl,
                    f"--pgdata={cls.data_dir}",
                    "start",
                    "--wait",
                    f"--log={cls.log_file}",
                    "--options",
                    (
                        f"-F -k {cls.socket_dir} -p {cls.port} "
                        "-c listen_addresses=''"
                    ),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            detail = getattr(exc, "stderr", "") or str(exc)
            if cls.log_file.exists():
                detail = f"{detail}\n{cls.log_file.read_text(encoding='utf-8')}"
            cls.runtime.cleanup()
            raise unittest.SkipTest(
                f"Disposable PostgreSQL could not be started: {detail.strip()}"
            ) from exc

        import psycopg2

        cls.psycopg2 = psycopg2
        cls.connection_args = {
            "host": str(cls.socket_dir),
            "port": cls.port,
            "dbname": "postgres",
            "user": "asip_2d1b_test",
        }
        setup = cls.psycopg2.connect(**cls.connection_args)
        with setup:
            with setup.cursor() as cursor:
                cursor.execute(
                    """
                    CREATE TABLE scans (
                        id integer PRIMARY KEY,
                        status text NOT NULL,
                        started_at timestamptz,
                        completed_at timestamptz
                    )
                    """
                )
                cursor.execute(
                    (BACKEND / "migrations" /
                     "007_add_scan_runner_lease.sql").read_text()
                )
        setup.close()

        config = types.ModuleType("config")
        config.DB_HOST = "unused"
        config.DB_NAME = "unused"
        config.DB_USER = "unused"
        config.DB_PASSWORD = "unused"
        cls.db = load_backend_module(BACKEND / "db.py", {"config": config})

    @classmethod
    def tearDownClass(cls):
        subprocess.run(
            [
                cls.pg_ctl,
                f"--pgdata={cls.data_dir}",
                "stop",
                "--mode=fast",
                "--wait",
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        cls.runtime.cleanup()

    def setUp(self):
        connection = self.psycopg2.connect(**self.connection_args)
        with connection:
            with connection.cursor() as cursor:
                cursor.execute("DELETE FROM scans")
                cursor.execute(
                    "INSERT INTO scans(id, status) VALUES (42, 'RUNNING')"
                )
        connection.close()

    def test_terminal_transition_waits_for_writer_lock(self):
        writer = self.psycopg2.connect(**self.connection_args)
        terminal = self.psycopg2.connect(**self.connection_args)
        writer_cursor = writer.cursor()
        self.db.require_running_scan(writer_cursor, 42)
        terminal_finished = threading.Event()
        thread_errors = []

        def transition():
            try:
                with terminal:
                    with terminal.cursor() as cursor:
                        cursor.execute(
                            "UPDATE scans SET status = 'SUCCEEDED' WHERE id = 42"
                        )
            except Exception as exc:
                thread_errors.append(exc)
            finally:
                terminal_finished.set()

        thread = threading.Thread(target=transition)
        thread.start()
        self.assertFalse(terminal_finished.wait(0.25))

        writer.commit()
        self.assertTrue(terminal_finished.wait(2))
        thread.join(timeout=2)
        self.assertEqual(thread_errors, [])

        with writer.cursor() as cursor:
            cursor.execute("SELECT status FROM scans WHERE id = 42")
            self.assertEqual(cursor.fetchone(), ("SUCCEEDED",))
        writer.close()
        terminal.close()

    def test_terminal_first_causes_subsequent_writer_rejection(self):
        terminal = self.psycopg2.connect(**self.connection_args)
        with terminal:
            with terminal.cursor() as cursor:
                cursor.execute("UPDATE scans SET status = 'FAILED' WHERE id = 42")
        terminal.close()

        writer = self.psycopg2.connect(**self.connection_args)
        with self.assertRaisesRegex(
            self.db.ScanNotRunningError, "is FAILED, not RUNNING"
        ):
            self.db.require_running_scan(writer.cursor(), 42)
        writer.rollback()
        writer.close()

    def test_runner_migration_is_idempotent_and_adds_only_lease_metadata(self):
        connection = self.psycopg2.connect(**self.connection_args)
        migration = (BACKEND / "migrations" /
                     "007_add_scan_runner_lease.sql").read_text()
        with connection:
            with connection.cursor() as cursor:
                cursor.execute(migration)
                cursor.execute(migration)
                cursor.execute(
                    """
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_name = 'scans'
                    ORDER BY ordinal_position
                    """
                )
                columns = [row[0] for row in cursor.fetchall()]
        connection.close()
        self.assertEqual(
            columns,
            [
                "id", "status", "started_at", "completed_at",
                "runner_token", "heartbeat_at", "failure_reason",
            ],
        )

    def test_expired_managed_lease_is_recovered_without_rewriting_history(self):
        orchestration = load_backend_module(BACKEND / "orchestration.py")
        connection = self.psycopg2.connect(**self.connection_args)
        with connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE scans
                    SET runner_token = 'runner-42',
                        heartbeat_at = NOW() - INTERVAL '10 seconds',
                        started_at = NOW() - INTERVAL '20 seconds'
                    WHERE id = 42
                    """
                )
        previous_started_at = None
        with connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT started_at FROM scans WHERE id = 42")
                previous_started_at = cursor.fetchone()[0]

        previous_grace = os.environ.get("ASIP_RUNNER_ORPHAN_GRACE_SECONDS")
        os.environ["ASIP_RUNNER_ORPHAN_GRACE_SECONDS"] = "1"
        try:
            recovered = orchestration.recover_orphaned_scans(connection)
        finally:
            if previous_grace is None:
                os.environ.pop("ASIP_RUNNER_ORPHAN_GRACE_SECONDS", None)
            else:
                os.environ["ASIP_RUNNER_ORPHAN_GRACE_SECONDS"] = previous_grace

        with connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT status, failure_reason, started_at FROM scans WHERE id = 42"
                )
                status, reason, started_at = cursor.fetchone()
        connection.close()

        self.assertEqual(recovered, [42])
        self.assertEqual(status, "FAILED")
        self.assertEqual(reason, "ORPHANED_RUNNER_RECOVERED")
        self.assertEqual(started_at, previous_started_at)

    def test_fresh_managed_lease_blocks_recovery(self):
        orchestration = load_backend_module(BACKEND / "orchestration.py")
        connection = self.psycopg2.connect(**self.connection_args)
        with connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE scans
                    SET runner_token = 'runner-42', heartbeat_at = NOW()
                    WHERE id = 42
                    """
                )

        previous_grace = os.environ.get("ASIP_RUNNER_ORPHAN_GRACE_SECONDS")
        os.environ["ASIP_RUNNER_ORPHAN_GRACE_SECONDS"] = "60"
        try:
            with self.assertRaisesRegex(RuntimeError, "fresh lease"):
                orchestration.recover_orphaned_scans(connection)
        finally:
            if previous_grace is None:
                os.environ.pop("ASIP_RUNNER_ORPHAN_GRACE_SECONDS", None)
            else:
                os.environ["ASIP_RUNNER_ORPHAN_GRACE_SECONDS"] = previous_grace
        connection.close()


class WriterWiringTests(unittest.TestCase):
    WRITERS = {
        "recon.py": "publish_recon_artifact(",
        "ingest.py": "INSERT INTO domains(",
        "san_worker.py": "INSERT INTO domain_san",
        "san_state_sync.py": "INSERT INTO domain_states(",
        "dns_worker.py": "INSERT INTO domain_dns",
        "san_http_worker.py": "UPDATE domain_states",
        "http_observation_worker.py": "UPDATE domain_states",
        "cert_worker.py": "INSERT INTO domain_cert(",
        "port_scan_worker.py": "INSERT INTO domain_ports(",
        "tech_worker.py": "INSERT INTO domain_tech(",
        "asn_worker.py": "INSERT INTO domain_asn(",
        "provider_worker.py": "INSERT INTO domain_provider(",
        "takeover_worker.py": "INSERT INTO domain_findings(",
        "discovery_validator.py": "UPDATE domains",
        "risk_worker.py": "INSERT INTO domain_risk(",
    }

    def test_every_active_writer_guards_before_first_mutation(self):
        for filename, mutation in self.WRITERS.items():
            with self.subTest(filename=filename):
                source = (BACKEND / filename).read_text(encoding="utf-8")
                guard = source.index("require_running_scan(cur, scan_id)")
                self.assertLess(guard, source.index(mutation))
                self.assertIn("require_running_scan", source.splitlines()[0:15].__str__())

    def test_selection_and_mutation_share_guarded_connection(self):
        for filename, mutation in {
            "cert_worker.py": "INSERT INTO domain_cert(",
            "port_scan_worker.py": "INSERT INTO domain_ports(",
            "asn_worker.py": "INSERT INTO domain_asn(",
        }.items():
            with self.subTest(filename=filename):
                source = (BACKEND / filename).read_text(encoding="utf-8")
                connection = source.index("conn = get_conn()")
                self.assertEqual(source.count("conn = get_conn()"), 1)
                guard = source.index("require_running_scan(cur, scan_id)", connection)
                selection = source.index("domains = get_", guard)
                mutation_position = source.index(mutation)
                self.assertGreater(guard, connection)
                self.assertLess(guard, selection)
                self.assertLess(selection, mutation_position)

    def test_checkpoint_workers_reacquire_after_commit(self):
        for filename in ("san_worker.py", "dns_worker.py"):
            with self.subTest(filename=filename):
                source = (BACKEND / filename).read_text(encoding="utf-8")
                checkpoint = source.index("conn.commit()")
                reacquire = source.index(
                    "require_running_scan(cur, scan_id)", checkpoint
                )
                self.assertGreater(reacquire, checkpoint)

    def test_orchestration_and_artifact_match_authorized_package_baselines(self):
        expected = {
            "orchestration.py": (
                "fc1ff6cbeadfb9be515d2f64110427b69d120f444abc472c428762924b219ee1"
            ),
            "recon_artifact.py": (
                "096c44848356e2f4b7f0587e5a26f8008724531101edf405098ed708916bb370"
            ),
        }
        for filename, digest in expected.items():
            with self.subTest(filename=filename):
                data = (BACKEND / filename).read_bytes()
                self.assertEqual(hashlib.sha256(data).hexdigest(), digest)


class FailClosedWriterTests(unittest.TestCase):
    @staticmethod
    def rejecting_guard():
        return mock.Mock(side_effect=RuntimeError("scan is not RUNNING"))

    def test_ingest_invalid_scan_performs_no_database_mutation(self):
        artifact_module = load_backend_module(BACKEND / "recon_artifact.py")
        connection = FakeConnection()
        guard = self.rejecting_guard()
        fake_db = make_db_module(connection, guard)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            data = root / "data"
            data.mkdir()
            source = root / "empty.csv"
            source.write_text(
                "Domain,Source,Seed,IP,Reverse_DNS,HTTP_Status,HTTP_Reason,"
                "Redirect_Location,Final_URL,Final_Status,Title,"
                "HTTP_Observation_Status,Domain_Status\n",
                encoding="utf-8",
            )
            artifact_module.publish_recon_artifact(
                source, data / "final_output.csv", 42, 0
            )
            previous_directory = os.getcwd()
            try:
                os.chdir(root)
                with self.assertRaisesRegex(RuntimeError, "not RUNNING"):
                    load_backend_module(
                        BACKEND / "ingest.py",
                        {"db": fake_db},
                        ["ingest.py", "42"],
                    )
            finally:
                os.chdir(previous_directory)

        guard.assert_called_once_with(connection.cursor(), 42)
        self.assertEqual(connection.cursor().executions, [])
        self.assertEqual(connection.commits, 0)

    def test_recon_invalid_scan_does_not_replace_stable_artifact(self):
        connection = FakeConnection()
        guard = self.rejecting_guard()
        fake_db = make_db_module(connection, guard)
        config = types.ModuleType("config")
        config.CERTSPOTTER_API_KEY = None
        http_probe = types.ModuleType("http_probe")
        http_probe.http_probe = lambda domain: None
        recon = load_backend_module(
            BACKEND / "recon.py",
            {"db": fake_db, "config": config, "http_probe": http_probe},
            ["recon.py"],
        )
        recon.load_known = lambda: set()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            (root / "data").mkdir()
            stable = root / "data" / "final_output.csv"
            stable.write_bytes(b"previous artifact\n")
            seeds = root / "seeds.txt"
            seeds.write_text("", encoding="utf-8")
            previous_directory = os.getcwd()
            try:
                os.chdir(root)
                with mock.patch("builtins.print"), self.assertRaisesRegex(
                    RuntimeError, "not RUNNING"
                ):
                    recon.main(str(seeds), False, False, 42)
            finally:
                os.chdir(previous_directory)

            self.assertEqual(stable.read_bytes(), b"previous artifact\n")
            self.assertFalse(
                (root / "data" / "final_output.csv.manifest.json").exists()
            )

        self.assertEqual(connection.rollbacks, 1)
        self.assertTrue(connection.closed)

    def test_discovery_validator_invalid_scan_cannot_update_domains(self):
        connection = FakeConnection()
        guard = self.rejecting_guard()
        module = load_backend_module(
            BACKEND / "discovery_validator.py",
            {"db": make_db_module(connection, guard)},
            ["discovery_validator.py", "42"],
        )

        with self.assertRaisesRegex(RuntimeError, "not RUNNING"):
            module.main()

        self.assertEqual(connection.cursor().executions, [])

    def test_san_invalid_scan_is_rejected_before_mutation(self):
        connection = FakeConnection()
        guard = self.rejecting_guard()
        module = load_backend_module(
            BACKEND / "san_worker.py",
            {"db": make_db_module(connection, guard)},
            ["san_worker.py", "42"],
        )

        with self.assertRaisesRegex(RuntimeError, "not RUNNING"):
            module.main()

        self.assertEqual(connection.cursor().executions, [])

    def test_dns_reacquires_guard_after_checkpoint_commit(self):
        rows = [(domain_id, f"d{domain_id}.example", True) for domain_id in range(50)]
        connection = FakeConnection(RecordingCursor(fetchall=rows))
        guard = mock.Mock()
        module = load_backend_module(
            BACKEND / "dns_worker.py",
            {"db": make_db_module(connection, guard)},
            ["dns_worker.py", "42"],
        )
        module.resolve_dns = lambda domain: [("A", "192.0.2.1")]

        with mock.patch("builtins.print"):
            module.main()

        self.assertEqual(guard.call_count, 2)
        self.assertEqual(connection.commits, 2)

    def test_dns_stops_before_next_mutation_if_scan_terminalizes_at_checkpoint(self):
        rows = [(domain_id, f"d{domain_id}.example", True) for domain_id in range(51)]
        cursor = RecordingCursor(fetchall=rows)
        connection = FakeConnection(cursor)
        guard = mock.Mock(
            side_effect=[None, RuntimeError("scan became terminal")]
        )
        module = load_backend_module(
            BACKEND / "dns_worker.py",
            {"db": make_db_module(connection, guard)},
            ["dns_worker.py", "42"],
        )
        module.resolve_dns = lambda domain: [("A", "192.0.2.1")]

        with mock.patch("builtins.print"), self.assertRaisesRegex(
            RuntimeError, "became terminal"
        ):
            module.main()

        inserts = [
            query for query, _ in cursor.executions
            if "INSERT INTO domain_dns" in query
        ]
        self.assertEqual(len(inserts), 50)
        self.assertEqual(connection.commits, 1)

    def test_shared_connection_workers_enforce_real_lifecycle_before_selection(self):
        config = types.ModuleType("config")
        real_db = load_backend_module(BACKEND / "db.py", {"config": config})
        cases = (
            ("cert_worker.py", (7, "cert.example", "192.0.2.7", None),
             "fetch_cert_expiry", (None, None, "no_cert"), "domain_cert"),
            ("port_scan_worker.py", (7, "port.example"),
             "scan_ports", [(443, "https")], "domain_ports"),
            ("asn_worker.py", (7, "asn.example", "192.0.2.7"),
             "enrich_asn", ("AS1", "example"), "domain_asn"),
        )
        for filename, row, observation, result, table in cases:
            for status in (None, "SUCCEEDED", "FAILED", "UNKNOWN", "RUNNING"):
                with self.subTest(worker=filename, status=status):
                    cursor = RecordingCursor(
                        fetchone=None if status is None else (status,), fetchall=[row]
                    )
                    connection = FakeConnection(cursor)
                    guard = mock.Mock(wraps=real_db.require_running_scan)
                    fake_db = make_db_module(connection, guard)
                    module = load_backend_module(
                        BACKEND / filename, {"db": fake_db}, [filename, "42"]
                    )
                    network = mock.Mock(return_value=result)
                    setattr(module, observation, network)
                    with mock.patch("builtins.print"):
                        if status == "RUNNING":
                            module.main()
                        else:
                            with self.assertRaises(real_db.ScanNotRunningError):
                                module.main()
                    fake_db.get_conn.assert_called_once_with()
                    guard.assert_called_once_with(cursor, 42)
                    self.assertIn("FROM scans", cursor.executions[0][0])
                    if status == "RUNNING":
                        self.assertIn("scan_results", cursor.executions[1][0])
                        self.assertTrue(any(
                            f"INSERT INTO {table}" in sql for sql, _ in cursor.executions
                        ))
                        network.assert_called_once()
                        expected_commits = 2 if filename == "port_scan_worker.py" else 1
                        self.assertEqual(connection.commits, expected_commits)
                    else:
                        self.assertEqual(len(cursor.executions), 1)
                        network.assert_not_called()
                        self.assertEqual(connection.commits, 0)

    def test_risk_invalid_scan_writes_no_risk_rows(self):
        connection = FakeConnection()
        guard = self.rejecting_guard()
        module = load_backend_module(
            BACKEND / "risk_worker.py",
            {"db": make_db_module(connection, guard)},
            ["risk_worker.py", "42"],
        )

        with self.assertRaisesRegex(RuntimeError, "not RUNNING"):
            module.main()

        self.assertEqual(connection.cursor().executions, [])

    def test_canonical_risk_mutation_is_lifecycle_guarded(self):
        worker = (BACKEND / "risk_worker.py").read_text(encoding="utf-8")
        engine = (BACKEND / "risk_engine.py").read_text(encoding="utf-8")
        self.assertIn("calculate_scan_risks(cur, scan_id)", worker)
        self.assertIn('"new_asset": 3', engine)
        self.assertIn('"high_finding": 2', engine)
        self.assertLess(worker.index("require_running_scan(cur, scan_id)"),
                        worker.index("calculate_scan_risks(cur, scan_id)"))
        self.assertLess(worker.index("require_running_scan(cur, scan_id)"),
                        worker.index("INSERT INTO domain_risk"))


if __name__ == "__main__":
    unittest.main()
