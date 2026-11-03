import csv
import importlib.util
import logging
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
CSV_COLUMNS = (
    "Domain",
    "Source",
    "Seed",
    "IP",
    "Reverse_DNS",
    "HTTP_Status",
    "HTTP_Reason",
    "Redirect_Location",
    "Final_URL",
    "Final_Status",
    "Title",
    "HTTP_Observation_Status",
    "Domain_Status",
)


def load_backend_module(filename, replacements=None, argv=None):
    module_name = f"pkg2d1c_{filename.stem}_{id(filename)}_{len(sys.modules)}"
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


def write_csv(path, rows):
    with pathlib.Path(path).open("w", encoding="utf-8", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column, "") for column in CSV_COLUMNS})


class ArtifactFailureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifacts = load_backend_module(BACKEND / "recon_artifact.py")

    def assert_rejected_before_database_access(self, artifact_setup, message):
        fake_db = types.ModuleType("db")
        fake_db.get_conn = mock.Mock(side_effect=AssertionError("database opened"))
        fake_db.require_running_scan = mock.Mock()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            data = root / "data"
            data.mkdir()
            artifact_setup(root, self.artifacts.scan_recon_artifact_path(data, 42))
            previous_directory = os.getcwd()
            try:
                os.chdir(root)
                with mock.patch.object(sys, "argv", ["ingest.py", "42"]), \
                        self.assertRaisesRegex(RuntimeError, message):
                    load_backend_module(BACKEND / "ingest.py", {"db": fake_db})
            finally:
                os.chdir(previous_directory)

        fake_db.get_conn.assert_not_called()

    def test_hash_mismatch_fails_before_database_access(self):
        def setup(root, artifact):
            source = root / "source.csv"
            write_csv(source, [{"Domain": "a.example", "Source": "subfinder"}])
            self.artifacts.publish_recon_artifact(source, artifact, 42, 1)
            artifact.write_bytes(artifact.read_bytes() + b"tampered\n")

        self.assert_rejected_before_database_access(setup, "SHA-256")

    def test_row_count_mismatch_fails_before_database_access(self):
        def setup(root, artifact):
            source = root / "source.csv"
            write_csv(source, [{"Domain": "a.example", "Source": "subfinder"}])
            self.artifacts.publish_recon_artifact(source, artifact, 42, 2)

        self.assert_rejected_before_database_access(setup, "row count")


class PostgreSQLIngestConvergenceTests(unittest.TestCase):
    TABLES = (
        "domain_risk",
        "domain_findings",
        "domain_provider",
        "domain_asn",
        "domain_tech",
        "domain_technology_observations",
        "domain_ports",
        "domain_cert",
        "domain_dns",
        "domain_san",
        "domain_sources",
        "domain_states",
        "scan_results",
        "domains",
        "known_domains",
        "scans",
    )

    @classmethod
    def setUpClass(cls):
        cls.initdb = shutil.which("initdb") or "/usr/lib/postgresql/18/bin/initdb"
        cls.pg_ctl = shutil.which("pg_ctl") or "/usr/lib/postgresql/18/bin/pg_ctl"
        if not pathlib.Path(cls.initdb).is_file() or not pathlib.Path(cls.pg_ctl).is_file():
            raise unittest.SkipTest("PostgreSQL server binaries are unavailable")

        cls.runtime = tempfile.TemporaryDirectory(prefix="asip-2d1c-pg-")
        root = pathlib.Path(cls.runtime.name)
        cls.data_dir = root / "data"
        cls.socket_dir = root / "socket"
        cls.log_file = root / "postgres.log"
        cls.socket_dir.mkdir()
        cls.port = 55440

        try:
            subprocess.run(
                [
                    cls.initdb,
                    f"--pgdata={cls.data_dir}",
                    "--auth=trust",
                    "--username=asip_2d1c_test",
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
                    f"-F -k {cls.socket_dir} -p {cls.port} -c listen_addresses=''",
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
            "user": "asip_2d1c_test",
        }
        setup = cls.psycopg2.connect(**cls.connection_args)
        with setup:
            with setup.cursor() as cursor:
                cursor.execute("""
                    CREATE TABLE scans (
                        id integer PRIMARY KEY,
                        status text NOT NULL
                    );
                    CREATE TABLE known_domains (
                        domain text UNIQUE
                    );
                    CREATE TABLE seed_domains (
                        domain text
                    );
                    CREATE TABLE domains (
                        id serial PRIMARY KEY,
                        domain text UNIQUE CHECK (domain <> 'explode.example'),
                        first_seen_scan integer,
                        last_seen_scan integer,
                        is_known boolean DEFAULT FALSE,
                        source text DEFAULT 'seed',
                        scannable boolean DEFAULT FALSE,
                        confidence_score integer DEFAULT 0,
                        confidence_label text DEFAULT 'low',
                        confidence_reasons text[],
                        validation_source text,
                        ownership_status text DEFAULT 'CONFIRMED' NOT NULL
                    );
                    CREATE TABLE scan_results (
                        scan_id integer,
                        domain_id integer,
                        seed text,
                        UNIQUE (scan_id, domain_id, seed),
                        UNIQUE (scan_id, domain_id)
                    );
                    CREATE TABLE domain_states (
                        scan_id integer,
                        domain_id integer,
                        ip text,
                        has_ip boolean,
                        http_status integer,
                        http_live boolean,
                        reverse_dns text,
                        http_reason text,
                        final_url text,
                        final_status integer,
                        title text,
                        http_observation_status text DEFAULT 'UNKNOWN' NOT NULL,
                        UNIQUE (domain_id, scan_id)
                    );
                    CREATE TABLE domain_sources (
                        domain_id integer,
                        scan_id integer,
                        source text,
                        seed text,
                        UNIQUE (domain_id, scan_id, source, seed)
                    );
                    CREATE TABLE domain_san (domain_id integer, scan_id integer);
                    CREATE TABLE domain_dns (
                        domain_id integer, scan_id integer, record_type text, value text
                    );
                    CREATE TABLE domain_cert (domain_id integer, scan_id integer);
                    CREATE TABLE domain_ports (domain_id integer, scan_id integer, port integer);
                    CREATE TABLE domain_tech (domain_id integer, scan_id integer, tech text);
                    CREATE TABLE domain_technology_observations (
                        id serial PRIMARY KEY,
                        scan_id integer,
                        domain_id integer,
                        technology text,
                        version text,
                        confidence text,
                        evidence_type text,
                        sanitized_evidence text,
                        observed_url text,
                        detector_version text,
                        created_at timestamp DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE (scan_id, domain_id, technology, version,
                                evidence_type, sanitized_evidence, observed_url,
                                detector_version)
                    );
                    CREATE TABLE domain_asn (domain_id integer, scan_id integer, asn text);
                    CREATE TABLE domain_provider (domain_id integer, scan_id integer, provider text);
                    CREATE TABLE domain_findings (domain_id integer, scan_id integer, finding text);
                    CREATE TABLE domain_risk (domain_id integer, scan_id integer, risk_score integer);
                """)
        setup.close()

        config = types.ModuleType("config")
        config.DB_HOST = "unused"
        config.DB_NAME = "unused"
        config.DB_USER = "unused"
        config.DB_PASSWORD = "unused"
        cls.db = load_backend_module(BACKEND / "db.py", {"config": config})
        cls.artifacts = load_backend_module(BACKEND / "recon_artifact.py")

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
        connection = self.connect()
        with connection:
            with connection.cursor() as cursor:
                cursor.execute("TRUNCATE " + ", ".join(self.TABLES) + " RESTART IDENTITY")
                cursor.execute(
                    "INSERT INTO scans(id, status) VALUES "
                    "(41, 'RUNNING'), (42, 'RUNNING'), (43, 'SUCCEEDED')"
                )
        connection.close()

    def connect(self):
        return self.psycopg2.connect(**self.connection_args)

    def ingest(self, scan_id, rows, manifest_scan_id=None, row_count=None):
        fake_db = types.ModuleType("db")
        fake_db.get_conn = self.connect
        fake_db.require_running_scan = self.db.require_running_scan
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            data = root / "data"
            data.mkdir()
            source = root / "source.csv"
            write_csv(source, rows)
            self.artifacts.publish_recon_artifact(
                source,
                self.artifacts.scan_recon_artifact_path(data, scan_id),
                scan_id if manifest_scan_id is None else manifest_scan_id,
                len(rows) if row_count is None else row_count,
            )
            previous_directory = os.getcwd()
            try:
                os.chdir(root)
                return load_backend_module(
                    BACKEND / "ingest.py",
                    {"db": fake_db},
                    ["ingest.py", str(scan_id)],
                )
            finally:
                os.chdir(previous_directory)

    def fetchall(self, query, params=()):
        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute(query, params)
                return cursor.fetchall()
        finally:
            connection.close()

    def projection(self, scan_id=42):
        return {
            "membership": self.fetchall(
                """
                SELECT d.domain, sr.seed
                FROM scan_results sr JOIN domains d ON d.id = sr.domain_id
                WHERE sr.scan_id = %s ORDER BY d.domain
                """,
                (scan_id,),
            ),
            "states": self.fetchall(
                """
                SELECT d.domain, ds.ip, ds.has_ip, ds.http_status, ds.http_live,
                       ds.reverse_dns, ds.http_reason, ds.final_url,
                       ds.final_status, ds.title
                FROM domain_states ds JOIN domains d ON d.id = ds.domain_id
                WHERE ds.scan_id = %s ORDER BY d.domain
                """,
                (scan_id,),
            ),
            "sources": self.fetchall(
                """
                SELECT d.domain, src.source, src.seed
                FROM domain_sources src JOIN domains d ON d.id = src.domain_id
                WHERE src.scan_id = %s ORDER BY d.domain, src.source, src.seed
                """,
                (scan_id,),
            ),
        }

    def global_inventory(self):
        return self.fetchall("""
            SELECT id, domain, first_seen_scan, last_seen_scan, is_known, source,
                   scannable, confidence_score, confidence_label,
                   confidence_reasons, validation_source
            FROM domains
            ORDER BY id
        """)

    def downstream_snapshot(self, scan_id=42):
        return {
            table: self.fetchall(
                f"SELECT * FROM {table} WHERE scan_id = %s ORDER BY domain_id",
                (scan_id,),
            )
            for table in (
                "domain_san",
                "domain_dns",
                "domain_cert",
                "domain_ports",
                "domain_tech",
                "domain_asn",
                "domain_provider",
                "domain_findings",
                "domain_risk",
            )
        }

    @staticmethod
    def row(domain, source="subfinder", seed="root.example", **values):
        row = {"Domain": domain, "Source": source, "Seed": seed}
        row.update(values)
        return row

    def test_first_ingest_and_identical_retry_are_duplicate_free(self):
        rows = [self.row("a.example"), self.row("b.example", source="assetfinder")]
        self.ingest(42, rows)
        first = self.projection()
        self.ingest(42, rows)

        self.assertEqual(self.projection(), first)
        self.assertEqual(len(first["membership"]), 2)
        self.assertEqual(len(first["states"]), 2)
        self.assertEqual(len(first["sources"]), 2)

    def test_shrinking_retry_converges_and_preserves_global_and_previous_scan(self):
        self.ingest(41, [self.row("previous.example", seed="previous-root.example")])
        previous = self.projection(41)
        self.ingest(
            42,
            [self.row("a.example"), self.row("b.example"), self.row("c.example")],
        )

        connection = self.connect()
        with connection:
            with connection.cursor() as cursor:
                cursor.execute("""
                    UPDATE domains
                    SET scannable = TRUE,
                        confidence_score = 77,
                        confidence_label = 'high',
                        confidence_reasons = ARRAY['manual evidence'],
                        validation_source = 'manual'
                    WHERE domain = 'c.example'
                """)
        connection.close()

        self.ingest(42, [self.row("a.example"), self.row("b.example")])

        current = self.projection()
        self.assertEqual([row[0] for row in current["membership"]], ["a.example", "b.example"])
        self.assertEqual([row[0] for row in current["states"]], ["a.example", "b.example"])
        self.assertEqual([row[0] for row in current["sources"]], ["a.example", "b.example"])
        self.assertEqual(self.projection(41), previous)
        self.assertEqual(
            self.fetchall("""
                SELECT domain, scannable, confidence_score, confidence_label,
                       confidence_reasons, validation_source
                FROM domains WHERE domain = 'c.example'
            """),
            [("c.example", True, 77, "high", ["manual evidence"], "manual")],
        )

    def test_zero_row_retry_clears_only_current_ingest_projection(self):
        self.ingest(42, [self.row("a.example"), self.row("b.example")])
        self.ingest(42, [])

        self.assertEqual(self.projection(), {"membership": [], "states": [], "sources": []})
        self.assertEqual(
            self.fetchall("SELECT domain FROM domains ORDER BY domain"),
            [("a.example",), ("b.example",)],
        )

    def test_expanding_retry_adds_new_domain(self):
        self.ingest(42, [self.row("a.example")])
        self.ingest(42, [self.row("a.example"), self.row("b.example")])

        self.assertEqual(
            [row[0] for row in self.projection()["membership"]],
            ["a.example", "b.example"],
        )

    def test_observations_converge_in_both_ip_directions(self):
        resolved = self.row(
            "a.example",
            IP="192.0.2.10",
            Reverse_DNS="old.ptr.example",
            HTTP_Status="200",
            HTTP_Reason="OK",
            Final_URL="https://a.example/old",
            Final_Status="200",
            Title="Old Title",
        )
        unresolved = self.row(
            "a.example",
            IP="",
            Reverse_DNS="no-ptr.example",
            HTTP_Status="0",
            HTTP_Reason="unresolved",
            Final_URL="",
            Final_Status="0",
            Title="New Empty Title",
        )
        self.ingest(42, [resolved])
        self.ingest(42, [unresolved])
        state = self.projection()["states"][0]
        self.assertEqual(state[1:6], ("", False, 0, False, "no-ptr.example"))
        self.assertEqual(state[6:], ("unresolved", "", 0, "New Empty Title"))

        improved = self.row(
            "a.example",
            IP="198.51.100.20",
            Reverse_DNS="new.ptr.example",
            HTTP_Status="302",
            HTTP_Reason="Found",
            Final_URL="https://a.example/new",
            Final_Status="200",
            Title="New Title",
        )
        self.ingest(42, [improved])
        state = self.projection()["states"][0]
        self.assertEqual(state[1:], (
            "198.51.100.20", True, 302, True, "new.ptr.example", "Found",
            "https://a.example/new", 200, "New Title",
        ))

    def test_http_observation_outcome_is_persisted_and_legacy_input_is_unknown(self):
        self.ingest(42, [self.row(
            "a.example",
            HTTP_Status="404",
            HTTP_Observation_Status="RESPONDED",
        )])
        self.assertEqual(
            self.fetchall(
                "SELECT http_observation_status FROM domain_states WHERE scan_id = 42"
            ),
            [("RESPONDED",)],
        )

        self.ingest(42, [self.row("a.example", HTTP_Status="0")])
        self.assertEqual(
            self.fetchall(
                "SELECT http_observation_status FROM domain_states WHERE scan_id = 42"
            ),
            [("UNKNOWN",)],
        )

    def test_missing_artifact_text_normalizes_to_empty_strings(self):
        populated = self.row(
            "a.example",
            source="certspotter",
            seed="root.example",
            IP="192.0.2.10",
            Reverse_DNS="ptr.example",
            HTTP_Status="200",
            HTTP_Reason="OK",
            Final_URL="https://a.example/",
            Final_Status="200",
            Title="Populated Title",
        )
        self.ingest(42, [populated])
        self.assertEqual(
            self.projection(),
            {
                "membership": [("a.example", "root.example")],
                "states": [(
                    "a.example", "192.0.2.10", True, 200, True,
                    "ptr.example", "OK", "https://a.example/", 200,
                    "Populated Title",
                )],
                "sources": [("a.example", "certspotter", "root.example")],
            },
        )

        self.ingest(42, [{"Domain": "a.example"}])

        projection = self.projection()
        self.assertEqual(projection["membership"], [("a.example", "")])
        self.assertEqual(
            projection["states"],
            [("a.example", "", False, 0, False, "", "", "", 0, "")],
        )
        self.assertEqual(projection["sources"], [])
        flattened = [str(value).lower() for rows in projection.values() for row in rows for value in row]
        self.assertNotIn("nan", flattened)
        self.assertNotIn("<na>", flattened)
        self.assertNotIn("none", flattened)

    def test_seed_and_source_replacement_converge(self):
        self.ingest(
            42,
            [self.row("a.example", source="subfinder,assetfinder", seed="old.example")],
        )
        self.ingest(
            42,
            [self.row("a.example", source="certspotter", seed="new.example")],
        )

        projection = self.projection()
        self.assertEqual(projection["membership"], [("a.example", "new.example")])
        self.assertEqual(projection["sources"], [("a.example", "certspotter", "new.example")])

    def test_each_downstream_evidence_source_rejects_before_mutation(self):
        evidence = {
            "domain_san": "INSERT INTO domain_san VALUES (%s, 42)",
            "domain_dns": "INSERT INTO domain_dns VALUES (%s, 42, 'A', '192.0.2.1')",
            "domain_cert": "INSERT INTO domain_cert VALUES (%s, 42)",
            "domain_ports": "INSERT INTO domain_ports VALUES (%s, 42, 443)",
            "domain_tech": "INSERT INTO domain_tech VALUES (%s, 42, 'nginx')",
            "domain_asn": "INSERT INTO domain_asn VALUES (%s, 42, 'AS64500')",
            "domain_provider": "INSERT INTO domain_provider VALUES (%s, 42, 'example')",
            "domain_findings": "INSERT INTO domain_findings VALUES (%s, 42, 'finding')",
            "domain_risk": "INSERT INTO domain_risk VALUES (%s, 42, 5)",
            "san provenance": (
                "INSERT INTO domain_sources(domain_id, scan_id, source, seed) "
                "VALUES (%s, 42, 'san', 'parent.example')"
            ),
        }
        for label, statement in evidence.items():
            with self.subTest(evidence=label):
                self.setUp()
                self.ingest(42, [self.row("a.example")])
                connection = self.connect()
                with connection:
                    with connection.cursor() as cursor:
                        cursor.execute("SELECT id FROM domains WHERE domain = 'a.example'")
                        cursor.execute(statement, (cursor.fetchone()[0],))
                connection.close()
                before = self.projection()
                global_before = self.global_inventory()

                with self.assertRaisesRegex(RuntimeError, "downstream"):
                    self.ingest(42, [self.row("b.example")])

                self.assertEqual(self.projection(), before)
                self.assertEqual(self.global_inventory(), global_before)

    def test_rejected_retry_preserves_san_and_later_enrichment(self):
        self.ingest(42, [self.row("parent.example")])
        connection = self.connect()
        with connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT id FROM domains WHERE domain = 'parent.example'")
                parent_id = cursor.fetchone()[0]
                cursor.execute("""
                    INSERT INTO domains(domain, first_seen_scan, last_seen_scan, source)
                    VALUES ('san-child.example', 42, 42, 'san') RETURNING id
                """)
                child_id = cursor.fetchone()[0]
                cursor.execute(
                    "INSERT INTO scan_results VALUES (42, %s, 'root.example')",
                    (child_id,),
                )
                cursor.execute(
                    "INSERT INTO domain_states("
                    "scan_id, domain_id, ip, has_ip, http_status, http_live, "
                    "reverse_dns, http_reason, final_url, final_status, title"
                    ") VALUES "
                    "(42, %s, '203.0.113.8', TRUE, 200, TRUE, 'ptr.example', "
                    "'OK', 'https://san-child.example', 200, 'SAN Child')",
                    (child_id,),
                )
                cursor.execute(
                    "INSERT INTO domain_sources VALUES (%s, 42, 'san', 'parent.example')",
                    (child_id,),
                )
                cursor.execute("INSERT INTO domain_san VALUES (%s, 42)", (parent_id,))
                cursor.execute(
                    "INSERT INTO domain_dns VALUES (%s, 42, 'A', '203.0.113.8')",
                    (child_id,),
                )
                cursor.execute("INSERT INTO domain_cert VALUES (%s, 42)", (child_id,))
                cursor.execute("INSERT INTO domain_ports VALUES (%s, 42, 443)", (child_id,))
                cursor.execute("INSERT INTO domain_tech VALUES (%s, 42, 'nginx')", (child_id,))
                cursor.execute("INSERT INTO domain_asn VALUES (%s, 42, 'AS64500')", (child_id,))
                cursor.execute("INSERT INTO domain_provider VALUES (%s, 42, 'provider')", (child_id,))
                cursor.execute("INSERT INTO domain_findings VALUES (%s, 42, 'finding')", (child_id,))
                cursor.execute("INSERT INTO domain_risk VALUES (%s, 42, 10)", (child_id,))
        connection.close()
        before_projection = self.projection()
        global_before = self.global_inventory()
        downstream_before = self.downstream_snapshot()

        with self.assertRaisesRegex(RuntimeError, "downstream"):
            self.ingest(42, [self.row("replacement.example")])

        self.assertEqual(self.projection(), before_projection)
        self.assertEqual(self.global_inventory(), global_before)
        self.assertEqual(self.downstream_snapshot(), downstream_before)

    def test_state_without_membership_rejects_retry_before_mutation(self):
        self.ingest(41, [self.row("previous.example", seed="previous.example")])
        previous_scan = self.projection(41)
        self.ingest(42, [self.row("orphan.example")])
        self.ingest(42, [])

        connection = self.connect()
        with connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT id FROM domains WHERE domain = 'orphan.example'")
                domain_id = cursor.fetchone()[0]
                cursor.execute(
                    """
                    INSERT INTO domain_states(
                        scan_id, domain_id, ip, has_ip, http_status, http_live,
                        reverse_dns, http_reason, final_url, final_status, title
                    )
                    VALUES (42, %s, '', FALSE, 0, FALSE, '', '', '', 0, '')
                    """,
                    (domain_id,),
                )
        connection.close()

        before_projection = self.projection()
        global_before = self.global_inventory()
        downstream_before = self.downstream_snapshot()
        self.assertEqual(before_projection["membership"], [])
        self.assertEqual(len(before_projection["states"]), 1)
        self.assertEqual(before_projection["sources"], [])
        self.assertTrue(all(not rows for rows in downstream_before.values()))

        with self.assertRaisesRegex(RuntimeError, "downstream state without membership"):
            self.ingest(42, [self.row("replacement.example")])

        self.assertEqual(self.projection(), before_projection)
        self.assertEqual(self.global_inventory(), global_before)
        self.assertEqual(self.projection(41), previous_scan)
        self.assertEqual(self.downstream_snapshot(), downstream_before)

    def test_middle_of_ingest_failure_rolls_back_cleanup_and_rebuild(self):
        self.ingest(42, [self.row("a.example"), self.row("c.example")])
        before = self.projection()
        global_before = self.global_inventory()

        with self.assertRaises(self.psycopg2.errors.CheckViolation):
            self.ingest(42, [self.row("a.example", seed="changed.example"), self.row("explode.example")])

        self.assertEqual(self.projection(), before)
        self.assertEqual(self.global_inventory(), global_before)

    def test_terminal_and_nonexistent_scans_fail_without_mutation(self):
        for scan_id, message in ((43, "SUCCEEDED"), (999, "does not exist")):
            with self.subTest(scan_id=scan_id):
                with self.assertRaisesRegex(RuntimeError, message):
                    self.ingest(scan_id, [self.row("blocked.example")])
        self.assertEqual(self.fetchall("SELECT domain FROM domains"), [])


if __name__ == "__main__":
    unittest.main()
