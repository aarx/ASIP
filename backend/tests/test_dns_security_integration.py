import os
import pathlib
import shutil
import socket
import sys
import tempfile
import subprocess
import unittest
from unittest import mock

BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

import dns_security_worker  # noqa: E402
import main  # noqa: E402
import orchestration  # noqa: E402
from scan_diagnostics import extract_worker_summary  # noqa: E402


class WorkerCursor:
    def __init__(self, targets=(), scan_row=("RUNNING", None)):
        self.targets = list(targets)
        self.sql = []
        self.fetchone_values = [scan_row]

    def execute(self, query, params=None):
        self.sql.append((query, params))

    def fetchone(self):
        return self.fetchone_values.pop(0) if self.fetchone_values else None

    def fetchall(self):
        return self.targets


class WorkerConnection:
    def __init__(self, cursor):
        self.cursor_value = cursor
        self.closed = False
        self.autocommit = False

    def cursor(self):
        return self.cursor_value

    def rollback(self):
        pass

    def close(self):
        self.closed = True

    def commit(self):
        pass


class CreateScanCursor:
    def __init__(self):
        self.statement = None

    def execute(self, query, params=None):
        self.statement = (query, params)

    def fetchone(self):
        return (902,)


class CreateScanConnection:
    def __init__(self):
        self.cursor_value = CreateScanCursor()
        self.closed = False

    def cursor(self):
        return self.cursor_value

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        self.closed = True


class DnsSecurityWorkerTests(unittest.TestCase):
    def test_normal_scan_persists_bounded_dns_target_ids_on_its_own_row(self):
        conn = CreateScanConnection()
        identity = {}
        with mock.patch.object(orchestration, "get_conn", return_value=conn):
            scan_id = orchestration.create_scan(identity, (4, 5, 6))
        query, params = conn.cursor_value.statement
        self.assertEqual(scan_id, 902)
        self.assertIn("dns_security_target_ids", query)
        self.assertEqual(params[1], [4, 5, 6])
        self.assertEqual(identity["scan_id"], 902)
        self.assertTrue(conn.closed)

    def test_disabled_stage_does_not_open_database_or_resolve(self):
        with mock.patch.object(dns_security_worker, "default_operation_enabled", return_value=False), \
             mock.patch.object(dns_security_worker, "get_conn") as get_conn, \
             mock.patch.object(dns_security_worker, "_emit") as emit:
            self.assertEqual(dns_security_worker.run_dns_security_stage(91), 0)
        get_conn.assert_not_called()
        self.assertTrue(emit.call_args.args[0]["disabled"])
        self.assertEqual(emit.call_args.args[0]["checks_persisted"], 0)

    def test_orchestration_registers_dns_stage_only_under_operation_gate(self):
        source = (BACKEND / "orchestration.py").read_text(encoding="utf-8")
        self.assertIn('if default_operation_enabled("DNS_SECURITY"):', source)
        self.assertIn('--dns-security-target-ids', source)
        self.assertIn('--enable-dns-security', source)
        self.assertIn('dns_security_target_ids', source)
        self.assertIn('dns_stage = (\n                "DNS Security",', source)
        self.assertIn('" --run-scoped" if dns_security_target_ids else ""', source)
        self.assertIn('insertion = next(i for i, item in enumerate(pipeline)', source)
        self.assertIn('if item[0] == "HTTP/TLS Observation"', source)

    def test_enabled_stage_selects_only_authorized_current_scan_members(self):
        cursor = WorkerCursor([(4, "known.example")])
        selection_conn = WorkerConnection(cursor)
        target_conn = WorkerConnection(WorkerCursor())
        connections = iter((selection_conn, target_conn))
        with mock.patch.dict(os.environ, {"ASIP_DEFAULT_SCAN_OPERATIONS": "DNS_SECURITY"}), \
             mock.patch.object(dns_security_worker, "default_operation_enabled", return_value=True), \
             mock.patch.object(dns_security_worker, "get_conn", side_effect=lambda: next(connections)), \
             mock.patch.object(dns_security_worker, "dns_security_query_authorizer", return_value=lambda _name: True), \
             mock.patch.object(dns_security_worker, "persist_dns_security_check", return_value=True) as persist, \
             mock.patch.object(dns_security_worker, "_emit") as emit:
            result = dns_security_worker.run_dns_security_stage(91, resolver_factory=lambda: _EmptyResolver())
        self.assertEqual(result, 0)
        self.assertEqual(len(cursor.sql), 2)
        selection_sql = cursor.sql[1][0]
        self.assertIn("sr.scan_id = %s", selection_sql)
        self.assertIn("d.scannable IS TRUE", selection_sql)
        self.assertIn("'KNOWN', 'SHADOW'", selection_sql)
        self.assertIn("DNS_SECURITY", selection_sql)
        self.assertEqual(persist.call_count, 6)
        self.assertTrue(selection_conn.closed)
        self.assertTrue(target_conn.closed)
        self.assertEqual(emit.call_args.args[0]["completed"], 1)
        self.assertEqual(emit.call_args.args[0]["checks_persisted"], 6)
        self.assertEqual(cursor.sql[0][1], (91,))
        self.assertIn("s.dns_security_target_ids", selection_sql)

    def test_run_scoped_stage_is_bounded_to_persisted_target_ids_when_operation_is_enabled(self):
        cursor = WorkerCursor(
            [(4, "known.example")], scan_row=("RUNNING", [4, 5, 6])
        )
        selection_conn = WorkerConnection(cursor)
        target_conn = WorkerConnection(WorkerCursor())
        connections = iter((selection_conn, target_conn))
        with mock.patch.object(dns_security_worker, "default_operation_enabled", return_value=True), \
             mock.patch.object(dns_security_worker, "get_conn", side_effect=lambda: next(connections)), \
             mock.patch.object(dns_security_worker, "dns_security_query_authorizer", return_value=lambda _name: True), \
             mock.patch.object(dns_security_worker, "persist_dns_security_check", return_value=True) as persist, \
             mock.patch.object(dns_security_worker, "_emit") as emit:
            result = dns_security_worker.run_dns_security_stage(
                91, run_scoped=True, resolver_factory=lambda: _EmptyResolver()
            )
        self.assertEqual(result, 0)
        selection_sql, params = cursor.sql[1]
        self.assertEqual(params, (91, [4, 5, 6], [4, 5, 6]))
        self.assertIn("d.id = ANY(%s::INTEGER[])", selection_sql)
        self.assertIn("s.dns_security_target_ids", selection_sql)
        self.assertIn("d.ownership_status = 'CONFIRMED'", selection_sql)
        self.assertIn("d.scannable IS TRUE", selection_sql)
        self.assertIn("'KNOWN', 'SHADOW'", selection_sql)
        self.assertEqual(persist.call_count, 6)
        summary = emit.call_args.args[0]
        self.assertTrue(summary["run_scoped"])
        self.assertEqual(summary["run_scope_target_count"], 3)
        self.assertEqual(summary["query_attempts"], 6)

    def test_run_scoped_flag_without_persisted_allowlist_performs_no_queries(self):
        cursor = WorkerCursor(scan_row=("RUNNING", None))
        conn = WorkerConnection(cursor)
        with mock.patch.object(dns_security_worker, "default_operation_enabled", return_value=True), \
             mock.patch.object(dns_security_worker, "get_conn", return_value=conn), \
             mock.patch.object(dns_security_worker, "assess_dns_domain") as assess, \
             mock.patch.object(dns_security_worker, "_emit") as emit:
            self.assertEqual(
                dns_security_worker.run_dns_security_stage(91, run_scoped=True), 0
            )
        assess.assert_not_called()
        self.assertTrue(conn.closed)
        self.assertTrue(emit.call_args.args[0]["disabled"])

    def test_target_allowlist_without_operation_grant_never_opens_database(self):
        with mock.patch.object(dns_security_worker, "default_operation_enabled", return_value=False), \
             mock.patch.object(dns_security_worker, "get_conn") as get_conn, \
             mock.patch.object(dns_security_worker, "_emit") as emit:
            self.assertEqual(
                dns_security_worker.run_dns_security_stage(
                    91, run_scoped=True, resolver_factory=lambda: _EmptyResolver()
                ),
                0,
            )
        get_conn.assert_not_called()
        self.assertTrue(emit.call_args.args[0]["disabled"])

    def test_process_scoped_enablement_reaches_run_and_is_restored(self):
        observed = []
        fake_lock = object()
        with mock.patch.dict(
                os.environ, {"ASIP_DEFAULT_SCAN_OPERATIONS": "HTTP_TLS_OBSERVATION"}), \
             mock.patch.object(orchestration, "acquire_orchestration_lock", return_value=fake_lock), \
             mock.patch.object(orchestration, "release_orchestration_lock"), \
             mock.patch.object(orchestration, "recover_orphaned_scans"), \
             mock.patch.object(orchestration, "run_pipeline", side_effect=lambda ids: observed.append((ids, os.environ.get("ASIP_DEFAULT_SCAN_OPERATIONS")))), \
             mock.patch.object(orchestration.signal, "signal"):
            orchestration.main([
                "--enable-dns-security", "--dns-security-target-ids", "4,5,6"
            ])
            self.assertEqual(observed, [((4, 5, 6), "DNS_SECURITY,HTTP_TLS_OBSERVATION")])
            self.assertEqual(os.environ.get("ASIP_DEFAULT_SCAN_OPERATIONS"), "HTTP_TLS_OBSERVATION")

    def test_target_ids_alone_are_rejected_before_scan_creation(self):
        with mock.patch.object(orchestration, "acquire_orchestration_lock") as acquire, \
             mock.patch.object(orchestration, "run_pipeline") as run_pipeline, \
             mock.patch.object(orchestration.signal, "signal"):
            with self.assertRaises(SystemExit) as raised:
                orchestration.main(["--dns-security-target-ids", "4"])
        self.assertEqual(raised.exception.code, 2)
        acquire.assert_not_called()
        run_pipeline.assert_not_called()

    def test_existing_central_operation_grant_allows_target_restriction(self):
        fake_lock = object()
        with mock.patch.dict(os.environ, {"ASIP_DEFAULT_SCAN_OPERATIONS": "DNS_SECURITY"}), \
             mock.patch.object(orchestration, "acquire_orchestration_lock", return_value=fake_lock), \
             mock.patch.object(orchestration, "release_orchestration_lock"), \
             mock.patch.object(orchestration, "recover_orphaned_scans"), \
             mock.patch.object(orchestration, "run_pipeline") as run_pipeline, \
             mock.patch.object(orchestration.signal, "signal"):
            orchestration.main(["--dns-security-target-ids", "4,5"])
        run_pipeline.assert_called_once_with((4, 5))

    def test_run_scoped_query_summary_is_persistable_and_bounded(self):
        summary = extract_worker_summary(
            'dns_security_stage {"run_scoped":true,"run_scope_target_count":3,'
            '"query_attempts":60,"query_budget_exhausted":true}'
        )
        self.assertEqual(summary, {
            "run_scoped": True,
            "run_scope_target_count": 3,
            "query_attempts": 60,
            "query_budget_exhausted": True,
        })


class _EmptyResolver:
    def __init__(self):
        self.timeout = None
        self.lifetime = None
        self.retry_servfail = True

    def resolve(self, name, rrtype, **kwargs):
        return []


class ApiCursor:
    def __init__(self, responses):
        self.responses = list(responses)
        self.executions = []

    def execute(self, query, params=None):
        self.executions.append((query, params))

    def fetchone(self):
        value = self.responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return value

    def fetchall(self):
        return self.responses.pop(0)


class ApiConnection:
    def __init__(self, cursor):
        self.cursor_value = cursor
        self.closed = False
        self.rolled_back = False

    def cursor(self):
        return self.cursor_value

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


class MissingTableError(Exception):
    pgcode = "42P01"


class DnsSecurityApiTests(unittest.TestCase):
    def setUp(self):
        self.old_env = os.environ.get("ASIP_DEFAULT_SCAN_OPERATIONS")
        os.environ.pop("ASIP_DEFAULT_SCAN_OPERATIONS", None)

    def tearDown(self):
        if self.old_env is None:
            os.environ.pop("ASIP_DEFAULT_SCAN_OPERATIONS", None)
        else:
            os.environ["ASIP_DEFAULT_SCAN_OPERATIONS"] = self.old_env

    def test_summary_distinguishes_checked_unchecked_findings_and_not_executed(self):
        cursor = ApiCursor([
            ("SUCCEEDED", {"version": 1, "attempts": []}),
            (10, 3, 5, 4, 2),
            [("CLEAR", 5), ("WARNING", 2), ("INCONCLUSIVE", 2)],
            [("INFO", 5), ("LOW", 4)],
            [("dns_a_resolution", 5), ("cname_health", 4)],
        ])
        conn = ApiConnection(cursor)
        with mock.patch.object(main, "get_conn", return_value=conn):
            result = main.dns_security_summary(scan_id=91)
        self.assertEqual(result["execution_state"], "NOT_EXECUTED")
        self.assertEqual((result["eligible_assets"], result["checked_assets"],
                          result["unchecked_assets"], result["affected_assets"]), (10, 3, 7, 2))
        self.assertEqual(result["dns_finding_records"], 2)
        self.assertEqual(result["checks_executed"], 5)
        self.assertEqual(result["not_checked_records"], 4)
        self.assertEqual(result["counts_by_outcome"]["CLEAR"], 5)
        self.assertTrue(all("'KNOWN','SHADOW'" in sql or "'KNOWN', 'SHADOW'" in sql
                            for sql, _ in cursor.executions[1:]))
        self.assertTrue(conn.closed)

    def test_findings_pagination_filter_scope_and_order_are_bound(self):
        row = (7, 4, "synthetic.example", "SHADOW", "cname_health", "WARNING",
               "LOW", "MEDIUM", "CNAME", "alias.synthetic.example", {}, "Review the CNAME.", "2026-01-01T00:00:00Z")
        cursor = ApiCursor([
            ("SUCCEEDED", {"version": 1, "attempts": []}),
            (1,), [row],
        ])
        conn = ApiConnection(cursor)
        with mock.patch.object(main, "get_conn", return_value=conn):
            result = main.dns_security_findings(
                scan_id=91, category="cname_health", outcome="warning",
                asset_class="shadow", page=2, limit=1,
            )
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["findings"][0]["domain"], "synthetic.example")
        self.assertEqual(cursor.executions[1][1], (91, "cname_health", "WARNING", "SHADOW"))
        self.assertIn("EXISTS (SELECT 1 FROM scan_results sr", cursor.executions[1][0])
        self.assertNotIn("JOIN scan_results sr", cursor.executions[1][0])
        self.assertIn("ORDER BY c.checked_at DESC, d.domain ASC", cursor.executions[2][0])
        self.assertEqual(cursor.executions[2][1][-2:], (1, 1))

    def test_candidate_filter_is_rejected_before_database_access(self):
        with mock.patch.object(main, "get_conn") as get_conn:
            with self.assertRaises(main.HTTPException) as raised:
                main.dns_security_findings(asset_class="CANDIDATE")
        self.assertEqual(raised.exception.status_code, 400)
        get_conn.assert_not_called()

    def test_missing_migration_returns_explicit_unavailable_response(self):
        cursor = ApiCursor([("SUCCEEDED", {"version": 1, "attempts": []}), MissingTableError("missing")])
        conn = ApiConnection(cursor)
        with mock.patch.object(main, "get_conn", return_value=conn):
            result = main.dns_security_summary(scan_id=91)
        self.assertEqual(result.status_code, 503)
        self.assertEqual(result.body, b'{"scan_id":91,"availability_state":"SCHEMA_UNAVAILABLE","detail":"DNS Security storage is not installed"}')
        self.assertTrue(conn.rolled_back)

    def test_domain_evidence_is_stable_id_and_current_scan_scoped(self):
        cursor = ApiCursor([
            ("SUCCEEDED", {"version": 1, "attempts": []}),
            (4, "synthetic.example", "SHADOW"),
            [("cname_health", "POTENTIAL_EXPOSURE", "LOW", "LOW", "CNAME",
              "alias.synthetic.example", {"takeover_confirmed": False}, "Review target.",
              "2026-01-01T00:00:00Z")],
        ])
        conn = ApiConnection(cursor)
        with mock.patch.object(main, "get_conn", return_value=conn):
            result = main.dns_security_domain_evidence(4, scan_id=91)
        self.assertEqual(result["domain_id"], 4)
        self.assertEqual(result["execution_state"], "CHECKED")
        self.assertEqual(result["checks"][0]["verification_status"], "POTENTIAL_EXPOSURE")
        self.assertEqual(cursor.executions[1][1], (4, 91))
        self.assertEqual(cursor.executions[2][1], (91, 4))
        self.assertIn("WHERE scan_id = %s AND domain_id = %s", cursor.executions[2][0])

    def test_historical_execution_state_uses_only_persisted_diagnostics(self):
        with mock.patch.object(main, "default_operation_enabled", return_value=True):
            self.assertEqual(main._dns_security_execution({"version": 1, "attempts": []}),
                             ("NOT_EXECUTED", None))
            self.assertEqual(main._dns_security_execution(None), ("UNKNOWN", None))
            self.assertEqual(main._dns_security_execution({"version": 1}), ("UNKNOWN", None))

    def test_dns_stage_worker_summary_is_available_to_diagnostics(self):
        summary = extract_worker_summary(
            '2026-01-01 INFO dns_security_stage {"selected":3,"completed":2,"checks_persisted":14,"disabled":false}'
        )
        self.assertEqual(summary, {"selected": 3, "completed": 2,
                                   "checks_persisted": 14, "disabled": False})


class PostgreSQLDnsSecurityReportingTests(unittest.TestCase):
    """Exercise reporting SQL against a real disposable PostgreSQL instance."""

    @classmethod
    def setUpClass(cls):
        initdb = shutil.which("initdb") or "/usr/lib/postgresql/18/bin/initdb"
        pg_ctl = shutil.which("pg_ctl") or "/usr/lib/postgresql/18/bin/pg_ctl"
        if not pathlib.Path(initdb).is_file() or not pathlib.Path(pg_ctl).is_file():
            raise unittest.SkipTest("PostgreSQL server binaries are unavailable")
        cls.runtime = tempfile.TemporaryDirectory(prefix="asip-dns-reporting-pg-")
        root = pathlib.Path(cls.runtime.name)
        cls.data_dir, cls.socket_dir = root / "data", root / "socket"
        cls.socket_dir.mkdir()
        cls.log_file = root / "postgres.log"
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            cls.port = sock.getsockname()[1]
        cls.pg_ctl = pg_ctl
        cls.initdb = initdb
        try:
            subprocess.run([initdb, f"--pgdata={cls.data_dir}", "--auth=trust",
                            "--username=asip_dns_report_test", "--no-locale"],
                           check=True, capture_output=True, text=True)
            subprocess.run([pg_ctl, f"--pgdata={cls.data_dir}", "start", "--wait",
                            f"--log={cls.log_file}", "--options",
                            f"-F -k {cls.socket_dir} -p {cls.port} -c listen_addresses=''"],
                           check=True, capture_output=True, text=True)
        except (OSError, subprocess.CalledProcessError) as exc:
            cls.runtime.cleanup()
            raise unittest.SkipTest(f"Disposable PostgreSQL could not start: {exc}") from exc
        import psycopg2
        cls.psycopg2 = psycopg2
        cls.db_args = {"host": str(cls.socket_dir), "port": cls.port,
                       "dbname": "postgres", "user": "asip_dns_report_test"}
        with psycopg2.connect(**cls.db_args) as conn, conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE scans (id integer PRIMARY KEY, status text NOT NULL,
                                    stage_diagnostics jsonb);
                CREATE TABLE seed_domains (domain text);
                CREATE TABLE known_domains (domain text);
                CREATE TABLE domains (id integer PRIMARY KEY, domain text UNIQUE,
                                      ownership_status text NOT NULL,
                                      scannable boolean NOT NULL);
                CREATE TABLE scan_results (scan_id integer NOT NULL, domain_id integer NOT NULL,
                                           seed text NOT NULL);
                CREATE TABLE dns_security_checks (
                    id integer PRIMARY KEY, scan_id integer NOT NULL, domain_id integer NOT NULL,
                    check_key text NOT NULL, target_identity text NOT NULL DEFAULT '',
                    record_type text NOT NULL DEFAULT '', outcome text NOT NULL,
                    severity text NOT NULL, confidence text NOT NULL, evidence jsonb NOT NULL,
                    remediation text, checked_at timestamptz NOT NULL
                );
                INSERT INTO scans VALUES (91, 'SUCCEEDED', '{"version":1,"attempts":[]}');
                INSERT INTO seed_domains VALUES ('example.test');
                INSERT INTO domains VALUES
                  (1,'zero.example.test','CONFIRMED',true),
                  (2,'one.example.test','CONFIRMED',true),
                  (3,'multi.example.test','CONFIRMED',true),
                  (4,'unchecked.example.test','CONFIRMED',true),
                  (5,'mixed.example.test','CONFIRMED',true),
                  (6,'affected.example.test','CONFIRMED',true),
                  (7,'candidate.example.test','CANDIDATE',true),
                  (8,'external.example.test','EXTERNAL',true);
                INSERT INTO scan_results
                  SELECT 91, id, 'seed-a' FROM domains
                  UNION ALL SELECT 91, id, 'seed-b' FROM domains WHERE id IN (3,6);
                INSERT INTO dns_security_checks VALUES
                  (1,91,2,'dns_a_resolution','','A','CLEAR','INFO','HIGH','{}',NULL,'2026-01-01'),
                  (2,91,3,'dns_a_resolution','','A','CLEAR','INFO','HIGH','{}',NULL,'2026-01-02'),
                  (3,91,3,'spf_configuration','','TXT','WARNING','LOW','MEDIUM','{}',NULL,'2026-01-03'),
                  (4,91,4,'dns_a_resolution','','A','NOT_CHECKED','UNKNOWN','UNKNOWN','{}',NULL,'2026-01-04'),
                  (5,91,5,'dns_a_resolution','','A','NOT_CHECKED','UNKNOWN','UNKNOWN','{}',NULL,'2026-01-05'),
                  (6,91,5,'dns_aaaa_resolution','','AAAA','INCONCLUSIVE','UNKNOWN','LOW','{}',NULL,'2026-01-06'),
                  (7,91,6,'cname_health','a.example.test','CNAME','POTENTIAL_EXPOSURE','MEDIUM','MEDIUM','{}',NULL,'2026-01-07'),
                  (8,91,6,'cname_health','b.example.test','CNAME','WARNING','LOW','MEDIUM','{}',NULL,'2026-01-08'),
                  (9,91,7,'dns_a_resolution','','A','CONFIRMED_ISSUE','HIGH','HIGH','{}',NULL,'2026-01-09'),
                  (10,91,8,'dns_a_resolution','','A','CONFIRMED_ISSUE','HIGH','HIGH','{}',NULL,'2026-01-10');
            """)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "data_dir") and cls.data_dir.exists():
            subprocess.run([cls.pg_ctl, f"--pgdata={cls.data_dir}", "stop", "--wait"],
                           check=False, capture_output=True, text=True)
        if hasattr(cls, "runtime"):
            cls.runtime.cleanup()

    def connect(self):
        return self.psycopg2.connect(**self.db_args)

    def test_real_sql_counts_are_domain_and_assessment_accurate(self):
        with mock.patch.object(main, "get_conn", side_effect=self.connect), \
             mock.patch.object(main, "default_operation_enabled", return_value=True):
            result = main.dns_security_summary(scan_id=91)
        self.assertEqual(result["eligible_assets"], 6)
        self.assertEqual(result["checked_assets"], 4)
        self.assertEqual(result["unchecked_assets"], 2)
        self.assertEqual(result["checks_executed"], 6)
        self.assertEqual(result["not_checked_records"], 2)
        self.assertEqual(result["affected_assets"], 2)
        self.assertEqual(result["dns_finding_records"], 3)
        self.assertEqual(result["counts_by_outcome"], {
            "CLEAR": 2, "INCONCLUSIVE": 1, "NOT_CHECKED": 2,
            "POTENTIAL_EXPOSURE": 1, "WARNING": 2,
        })
        self.assertEqual(sum(result["counts_by_category"].values()), 8)

    def test_real_sql_findings_and_domain_evidence_deduplicate_seed_membership(self):
        with mock.patch.object(main, "get_conn", side_effect=self.connect):
            page = main.dns_security_findings(scan_id=91, outcome="WARNING", limit=20)
            evidence = main.dns_security_domain_evidence(3, scan_id=91)
        self.assertEqual(page["total"], 2)
        self.assertEqual([row["domain_id"] for row in page["findings"]], [6, 3])
        self.assertEqual(len(evidence["checks"]), 2)
        self.assertEqual(evidence["domain_id"], 3)

if __name__ == "__main__":
    unittest.main()
