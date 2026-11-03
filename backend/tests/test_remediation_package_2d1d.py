import ast
import hashlib
import os
import pathlib
import types
import unittest
from unittest import mock

from backend.tests import test_remediation_package_2d1c as convergence
from backend.authorization_policy import recheck_active_authorization


BACKEND = pathlib.Path(__file__).resolve().parents[1]

PROTECTED_SHA256 = {
    "discovery_validator.py": "545dfad14226f1b2b1e2b609b49d7ae9f2738502e3dc68756c243f5d73e3ae81",
}

CONSUMERS = (
    "san_worker.py",
    "san_state_sync.py",
    "dns_worker.py",
    "san_http_worker.py",
    "cert_worker.py",
    "port_scan_worker.py",
    "tech_worker.py",
    "asn_worker.py",
    "provider_worker.py",
    "takeover_worker.py",
    "risk_worker.py",
)

ATOMIC_WRITERS = {
    "san_worker.py": ("INSERT INTO domain_san", "INSERT INTO domain_sources"),
    "dns_worker.py": ("INSERT INTO domain_dns", "UPDATE domain_states"),
    "san_http_worker.py": ("UPDATE domain_states",),
    "cert_worker.py": ("INSERT INTO domain_cert",),
    "port_scan_worker.py": ("INSERT INTO domain_ports",),
    "tech_worker.py": ("INSERT INTO domain_tech(", "INSERT INTO domain_technology_observations"),
    "asn_worker.py": ("INSERT INTO domain_asn",),
    "provider_worker.py": ("INSERT INTO domain_provider",),
    "takeover_worker.py": ("INSERT INTO domain_findings",),
    "risk_worker.py": ("INSERT INTO domain_risk",),
}


def source(filename):
    return (BACKEND / filename).read_text(encoding="utf-8")


def normalized_sql(text):
    return " ".join(text.split()).upper()


def sql_statements(filename):
    statements = []
    for node in ast.walk(ast.parse(source(filename))):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == 'execute' and node.args):
            continue
        sql_arg = node.args[0]
        if isinstance(sql_arg, ast.Constant) and isinstance(sql_arg.value, str):
            statements.append(normalized_sql(sql_arg.value))
        elif isinstance(sql_arg, ast.JoinedStr):
            text = ''.join(
                part.value if isinstance(part, ast.Constant) and isinstance(part.value, str)
                else '%s'
                for part in sql_arg.values
            )
            statements.append(normalized_sql(text))
    return statements


class StaticMembershipContractTests(unittest.TestCase):
    def test_every_consumer_mentions_authoritative_membership(self):
        for filename in CONSUMERS:
            with self.subTest(filename=filename):
                contract_file = "risk_engine.py" if filename == "risk_worker.py" else filename
                candidates = [sql for sql in sql_statements(contract_file)
                              if sql.startswith('SELECT') and
                              ('JOIN DOMAIN_STATES' in sql or 'FROM DOMAIN_STATES' in sql
                               or 'JOIN DOMAIN_ASN' in sql or 'FROM DOMAIN_DNS' in sql)]
                if filename == 'san_state_sync.py':
                    candidates = [sql for sql in sql_statements(filename)
                                  if sql.startswith('INSERT INTO DOMAIN_STATES')]
                self.assertTrue(candidates)
                for sql in candidates:
                    self.assertIn('SCAN_RESULTS SR', sql)
                    self.assertRegex(sql, r'SR\.DOMAIN_ID\s*=|=\s*SR\.DOMAIN_ID')
                    self.assertRegex(sql, r'SR\.SCAN_ID\s*=|=\s*SR\.SCAN_ID')
                    self.assertRegex(sql, r'SCAN_ID\s*=\s*%S')

    def test_scan_state_sync_is_sourced_from_membership_not_last_seen(self):
        text = normalized_sql(source("san_state_sync.py"))
        self.assertIn("FROM SCAN_RESULTS", text)
        self.assertIn("JOIN DOMAINS", text)
        self.assertNotIn("LAST_SEEN_SCAN", text)

    def test_scan_scoped_writes_are_membership_conditional(self):
        for filename, statements in ATOMIC_WRITERS.items():
            for statement in statements:
                with self.subTest(filename=filename, statement=statement):
                    writes = [sql for sql in sql_statements(filename)
                              if sql.startswith(statement.upper())]
                    self.assertTrue(writes)
                    for sql in writes:
                        self.assertIn('EXISTS ( SELECT 1 FROM SCAN_RESULTS SR', sql)
                        self.assertRegex(sql, r'SR\.SCAN_ID\s*=\s*(%S|DOMAIN_STATES.SCAN_ID)')
                        self.assertRegex(sql, r'SR\.DOMAIN_ID\s*=\s*(%S|DOMAIN_STATES.DOMAIN_ID)')

    def test_split_connection_workers_select_with_mutation_cursor(self):
        for filename in ("cert_worker.py", "port_scan_worker.py", "asn_worker.py"):
            with self.subTest(filename=filename):
                text = source(filename)
                self.assertRegex(text, r"def get_[a-z_]+\(cur, scan_id\):")
                expected_connections = 2 if filename == "port_scan_worker.py" else 1
                self.assertEqual(text.count("get_conn()"), expected_connections)

    def test_san_parent_membership_precedes_network_observation(self):
        text = source("san_worker.py")
        loop = text.index("for i, (domain_id, domain)")
        membership = text.index("scan_results", loop)
        network = text.index("fetch_san_domains(", loop)
        san_write = text.index("INSERT INTO domain_san", loop)
        self.assertLess(membership, network)
        self.assertLess(membership, san_write)

    def test_scannable_is_not_the_membership_predicate(self):
        for filename in CONSUMERS:
            with self.subTest(filename=filename):
                text = normalized_sql(source(filename))
                if "SCANNABLE" in text:
                    self.assertIn("SCAN_RESULTS", text)

    def test_risk_worker_uses_shared_canonical_engine(self):
        worker = source("risk_worker.py")
        engine = source("risk_engine.py")
        self.assertIn("calculate_scan_risks(cur, scan_id)", worker)
        self.assertNotIn("def compute_risk(", worker)
        self.assertIn("def calculate_risk(evidence", engine)
        self.assertIn("FROM scan_results sr", engine)

    def test_out_of_scope_backend_files_are_unchanged(self):
        for filename, expected in PROTECTED_SHA256.items():
            with self.subTest(filename=filename):
                digest = hashlib.sha256((BACKEND / filename).read_bytes()).hexdigest()
                self.assertEqual(digest, expected)


class RecordingConnection:
    """Real disposable PostgreSQL connection with controllable race boundaries."""

    def __init__(self, connection, executions, after_commit=None, before_write=None):
        self.connection = connection
        self.executions = executions
        self.after_commit = after_commit
        self.before_write = before_write

    def cursor(self):
        owner = self
        cursor = self.connection.cursor()

        class Cursor:
            def execute(self, sql, params=None):
                if owner.before_write and normalized_sql(sql).startswith(("INSERT", "UPDATE")):
                    owner.before_write(cursor, sql, params)
                cursor.execute(sql, params)
                owner.executions.append((sql, params, cursor.rowcount))

            def __getattr__(self, name):
                return getattr(cursor, name)

        return Cursor()

    def commit(self):
        self.connection.commit()
        if self.after_commit:
            self.after_commit()

    def __getattr__(self, name):
        return getattr(self.connection, name)


class PostgreSQLMembershipTests(unittest.TestCase):
    # Reuse only the disposable server setup; never use application credentials.
    TABLES = convergence.PostgreSQLIngestConvergenceTests.TABLES
    connect = convergence.PostgreSQLIngestConvergenceTests.connect
    ingest = convergence.PostgreSQLIngestConvergenceTests.ingest

    @classmethod
    def setUpClass(cls):
        try:
            convergence.PostgreSQLIngestConvergenceTests.setUpClass.__func__(cls)
        except unittest.SkipTest as exc:
            raise RuntimeError(f"2D1-D requires executable disposable PostgreSQL: {exc}") from exc
        cls.addClassCleanup(
            convergence.PostgreSQLIngestConvergenceTests.tearDownClass.__func__, cls
        )
        # The disposable no-locale cluster defaults to ASCII; workers contain
        # existing Unicode SQL comments, so use an explicit UTF-8 client.
        cls.connection_args["options"] = "-c client_encoding=UTF8"
        connection = cls.psycopg2.connect(**cls.connection_args)
        try:
            with connection:
                with connection.cursor() as cur:
                    cur.execute("""
                        ALTER TABLE domains ADD first_seen_at timestamp, ADD last_seen_at timestamp;
                        INSERT INTO seed_domains VALUES ('example');
                        CREATE TABLE sensitive_ports (port integer, risk integer);
                        INSERT INTO sensitive_ports VALUES (443, 10);
                        ALTER TABLE domain_san ADD UNIQUE(domain_id, scan_id);
                        ALTER TABLE domain_cert ADD expiry_date date,
                            ADD days_to_expiry integer, ADD cert_status text,
                            ADD UNIQUE(domain_id, scan_id);
                        ALTER TABLE domain_ports ADD service text,
                            ADD UNIQUE(domain_id, port, scan_id);
                        ALTER TABLE domain_asn ADD ip text, ADD org text,
                            ADD UNIQUE(domain_id, scan_id);
                        ALTER TABLE domain_provider ADD UNIQUE(domain_id, scan_id);
                        ALTER TABLE domain_findings ADD severity text, ADD evidence text,
                            ADD UNIQUE(domain_id, scan_id, finding);
                        ALTER TABLE domain_risk ADD reasons text, ADD UNIQUE(domain_id, scan_id);
                        CREATE TABLE active_scan_scopes (
                            id BIGSERIAL PRIMARY KEY,
                            scope_domain text NOT NULL,
                            include_subdomains boolean NOT NULL,
                            testing_level text NOT NULL,
                            approved_by text NOT NULL,
                            approved_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
                            status text NOT NULL DEFAULT 'ACTIVE',
                            expires_at timestamptz,
                            excluded_domains text[] NOT NULL DEFAULT ARRAY[]::text[],
                            revoked_by text,
                            revoked_at timestamptz,
                            revocation_reason text
                        );
                        ALTER TABLE active_scan_scopes
                            ADD CONSTRAINT active_scan_scopes_testing_level
                            CHECK (testing_level IN (
                                'TECHNOLOGY_HTTP', 'PORT_SCAN', 'ADHOC_CHECK',
                                'HTTP_TLS_OBSERVATION'
                            ));
                    """)
        finally:
            connection.close()

    def setUp(self):
        policy_patch = mock.patch.dict(
            os.environ,
            {"ASIP_DEFAULT_SCAN_OPERATIONS": (
                "HTTP_TLS_OBSERVATION,TECHNOLOGY_HTTP,PORT_SCAN,ADHOC_CHECK"
            )},
        )
        policy_patch.start()
        self.addCleanup(policy_patch.stop)
        convergence.PostgreSQLIngestConvergenceTests.setUp(self)
        self.sql("INSERT INTO scans VALUES (44, 'FAILED')")
        self.sql("DELETE FROM active_scan_scopes")

    def sql(self, statement, params=None):
        connection = self.connect()
        try:
            with connection:
                with connection.cursor() as cur:
                    cur.execute(statement, params)
                    return cur.fetchall() if cur.description else cur.rowcount
        finally:
            connection.close()

    def domain(self, name, member_scan=None, state_scan=42, has_ip=True,
               http_status=200, last_seen=42, scannable=True):
        domain_id = self.sql("""
            INSERT INTO domains(domain, first_seen_scan, last_seen_scan, scannable)
            VALUES (%s, 41, %s, %s) RETURNING id
        """, (name, last_seen, scannable))[0][0]
        if member_scan is not None:
            self.sql("INSERT INTO scan_results VALUES (%s, %s, 'root.example')",
                     (member_scan, domain_id))
        if state_scan is not None:
            self.sql("""
                INSERT INTO domain_states(domain_id,scan_id,ip,has_ip,http_status,http_live)
                VALUES (%s,%s,'192.0.2.1',%s,%s,%s)
            """, (domain_id, state_scan, has_ip, http_status, http_status > 0))
        return domain_id

    def snapshot(self):
        return {table: self.sql(f"SELECT to_jsonb(t)::text FROM {table} t ORDER BY 1")
                for table in self.TABLES}

    def run_worker(self, filename, scan_id=42, overrides=None, after_commit=None,
                   before_write=None, expect_terminal=False):
        executions, connections = [], []
        fake_db = types.ModuleType('db')

        def connect():
            connection = RecordingConnection(self.connect(), executions, after_commit, before_write)
            connections.append(connection)
            return connection

        fake_db.get_conn = mock.Mock(side_effect=connect)
        fake_db.require_running_scan = self.db.require_running_scan
        with mock.patch('os.makedirs'), mock.patch('builtins.print'):
            module = convergence.load_backend_module(
                BACKEND / filename, {'db': fake_db}, [filename, str(scan_id)]
            )
            observations = {
                'fetch_san_domains': [],
                'resolve_dns': [('A', '192.0.2.1'), ('CNAME', 'target.github.io')],
                'reverse_dns': 'ptr.example',
                'http_probe': {'http_status': 200, 'http_reason': 'OK',
                               'final_url': 'https://child.example', 'final_status': 200,
                               'title': 'Child'},
                'fetch_cert_expiry': (None, 10, 'critical'),
                'scan_ports': [(443, 'https')],
                'detect_tech': ['nginx'],
                'enrich_asn': ('AS1', 'AS1 Amazon'),
                'get_live_cname': 'target.github.io',
                'check_takeover': {'body': "There isn't a GitHub Pages site here",
                                   'status': 404, 'length': 100},
            }
            mocks = {}
            for name, result in observations.items():
                if hasattr(module, name):
                    mocks[name] = mock.Mock(return_value=result)
                    setattr(module, name, mocks[name])
            for name, value in (overrides or {}).items():
                setattr(module, name, value)
            try:
                if expect_terminal:
                    with self.assertRaises(self.db.ScanNotRunningError):
                        module.main()
                    for observer in mocks.values():
                        observer.assert_not_called()
                else:
                    module.main()
            finally:
                for connection in connections:
                    connection.close()
        self.assertEqual(fake_db.get_conn.call_count, len(connections))
        if filename != "port_scan_worker.py":
            fake_db.get_conn.assert_called_once_with()
        return executions, mocks

    def test_all_consumers_exclude_historical_wrong_scan_and_orphan_inputs(self):
        for membership in (None, 41, 43):
            for filename in CONSUMERS:
                with self.subTest(membership=membership, worker=filename):
                    self.setUp()
                    old = self.domain('old.example', membership,
                                      http_status=0 if filename == 'san_http_worker.py' else 200)
                    self.sql("INSERT INTO domain_sources VALUES (%s,42,'san','parent.example')", (old,))
                    self.sql("INSERT INTO domain_dns VALUES (%s,42,'CNAME','target.github.io')", (old,))
                    self.sql("INSERT INTO domain_asn VALUES (%s,42,'AS1','192.0.2.1','AS1 Amazon')", (old,))
                    # Also retain historical evidence independently of the orphan state.
                    self.sql("INSERT INTO domain_states(domain_id,scan_id,has_ip) VALUES (%s,41,TRUE)", (old,))
                    before = self.snapshot()
                    _, observers = self.run_worker(filename)
                    self.assertEqual(self.snapshot(), before)
                    for observer in observers.values():
                        observer.assert_not_called()

    def test_state_sync_uses_membership_even_when_last_seen_disagrees(self):
        self.domain('misleading.example', None, None, last_seen=42)
        member = self.domain('member.example', 42, None, last_seen=41)
        self.run_worker('san_state_sync.py')
        self.assertEqual(self.sql('SELECT domain_id,scan_id,ip,has_ip,http_status,http_live FROM domain_states'),
                         [(member, 42, '', False, 0, False)])

    def test_ingest_trusts_both_root_tables_and_preserves_manual_rejection_and_history(self):
        self.sql("INSERT INTO seed_domains VALUES ('seed.test')")
        self.sql("INSERT INTO known_domains(domain) VALUES ('known.test')")
        rejected = self.domain('denied.known.test', 41, state_scan=41, scannable=False)
        self.sql("UPDATE domains SET validation_source='manual' WHERE id=%s", (rejected,))
        historic = self.domain('history.seed.test', 41, state_scan=41, scannable=False)

        self.ingest(42, [
            {'Domain': 'seed.test', 'Seed': 'different-file-input.test', 'Source': 'passive'},
            {'Domain': 'api.seed.test', 'Seed': 'different-file-input.test', 'Source': 'ct'},
            {'Domain': 'known.test', 'Seed': 'unknown.test', 'Source': 'passive'},
            {'Domain': 'a.b.known.test', 'Seed': 'unknown.test', 'Source': 'san'},
            {'Domain': 'random.known.test', 'Seed': 'unknown.test', 'Source': 'ct'},
            {'Domain': 'outside.test', 'Seed': 'known.test', 'Source': 'ct'},
            {'Domain': 'denied.known.test', 'Seed': 'known.test', 'Source': 'passive'},
        ])
        self.run_worker('eligibility_worker.py')

        self.assertEqual(self.sql("""
            SELECT domain, ownership_status, is_known, scannable
            FROM domains WHERE domain IN (
                'seed.test', 'api.seed.test', 'a.b.known.test',
                'known.test', 'random.known.test', 'outside.test', 'denied.known.test'
            ) ORDER BY domain
        """), [
            ('a.b.known.test', 'CANDIDATE', False, False),
            ('api.seed.test', 'CONFIRMED', False, True),
            ('denied.known.test', 'CONFIRMED', False, False),
            ('known.test', 'CONFIRMED', True, True),
            ('outside.test', 'CANDIDATE', False, False),
            ('random.known.test', 'CANDIDATE', False, False),
            ('seed.test', 'CONFIRMED', False, True),
        ])
        self.assertEqual(
            self.sql('SELECT scan_id FROM scan_results WHERE domain_id=%s ORDER BY scan_id', (historic,)),
            [(41,)],
        )
        self.assertEqual(
            self.sql('SELECT scan_id FROM domain_states WHERE domain_id=%s ORDER BY scan_id', (historic,)),
            [(41,)],
        )

    def test_san_child_uses_its_own_trusted_boundary_not_parent_or_relationship(self):
        self.sql("INSERT INTO known_domains(domain) VALUES ('known.vendor.test')")
        parent = self.domain('parent.example', 42)
        self.authorize_scope('example', 'HTTP_TLS_OBSERVATION')
        self.run_worker('san_worker.py', overrides={
            'fetch_san_domains': mock.Mock(return_value=[
                'known.vendor.test', 'api.known.vendor.test', 'unrelated.vendor.test'
            ]),
        })
        self.assertEqual(self.sql("""
            SELECT d.domain, d.ownership_status, d.scannable
            FROM domains d JOIN scan_results sr ON sr.domain_id=d.id
            WHERE sr.scan_id=42 AND d.domain IN (
                'known.vendor.test', 'api.known.vendor.test', 'unrelated.vendor.test'
            ) ORDER BY d.domain
        """), [
            ('api.known.vendor.test', 'CANDIDATE', False),
            ('known.vendor.test', 'CONFIRMED', False),
            ('unrelated.vendor.test', 'CANDIDATE', False),
        ])
        self.assertEqual(self.sql(
            'SELECT COUNT(*) FROM domain_san WHERE domain_id=%s AND scan_id=42', (parent,)
        ), [(1,)])

    def test_automatic_eligibility_uses_trusted_roots_and_current_members(self):
        self.sql("INSERT INTO seed_domains VALUES ('example.com')")
        self.sql("INSERT INTO known_domains(domain) VALUES ('known.example.net')")
        member = self.domain('app.example.com', 42, state_scan=None, scannable=False)
        known = self.domain('known.example.net', 42, state_scan=None, scannable=False)
        known_child = self.domain('child.known.example.net', 42, state_scan=None, scannable=False)
        historical = self.domain('old.example.com', 41, state_scan=None, scannable=False)
        outside = self.domain('outside.example.net', 42, state_scan=None, scannable=False)
        self.run_worker('eligibility_worker.py')

        self.assertEqual(
            self.sql("SELECT domain, scannable FROM domains WHERE id IN (%s,%s,%s,%s,%s) ORDER BY id",
                     (member, known, known_child, historical, outside)),
            [('app.example.com', True), ('known.example.net', True),
             ('child.known.example.net', False),
             ('old.example.com', False), ('outside.example.net', False)],
        )

    def test_automatic_eligibility_preserves_manual_decisions_without_scopes(self):
        self.sql("INSERT INTO seed_domains VALUES ('example.com')")
        manual_approved = self.domain('approved.example.com', 42, state_scan=None, scannable=True)
        manual_rejected = self.domain('rejected.example.com', 42, state_scan=None, scannable=False)
        automatic = self.domain('automatic.example.com', 42, state_scan=None, scannable=False)
        self.sql("UPDATE domains SET validation_source='manual' WHERE id IN (%s,%s)",
                 (manual_approved, manual_rejected))

        self.run_worker('eligibility_worker.py')
        self.assertEqual(
            self.sql("SELECT scannable FROM domains WHERE id IN (%s,%s,%s) ORDER BY id",
                     (manual_approved, manual_rejected, automatic)),
            [(True,), (False,), (True,)],
        )

        self.run_worker('eligibility_worker.py')
        self.assertEqual(self.sql("SELECT scannable FROM domains WHERE id=%s", (automatic,)), [(True,)])

    def test_eligibility_is_independent_of_operation_exclusions_and_expiry(self):
        self.sql("INSERT INTO seed_domains VALUES ('example.com')")
        self.sql("INSERT INTO seed_domains VALUES ('expired.example')")
        lookalike = self.domain('evil-example.com', 42, state_scan=None, scannable=False)
        candidate = self.domain('candidate.example.com', 42, state_scan=None, scannable=False)
        external = self.domain('external.example.com', 42, state_scan=None, scannable=False)
        excluded = self.domain('blocked.example.com', 42, state_scan=None, scannable=False)
        expired = self.domain('child.expired.example', 42, state_scan=None, scannable=False)
        self.sql("UPDATE domains SET ownership_status='CANDIDATE' WHERE id=%s", (candidate,))
        self.sql("UPDATE domains SET ownership_status='EXTERNAL' WHERE id=%s", (external,))
        self.authorize_scope('example.com', 'TECHNOLOGY_HTTP', excluded_domains=['blocked.example.com'])
        self.authorize_scope('expired.example', 'TECHNOLOGY_HTTP', expires_at='2000-01-01T00:00:00Z')
        self.run_worker('eligibility_worker.py')
        self.assertEqual(
            self.sql("SELECT scannable FROM domains WHERE id IN (%s,%s,%s,%s,%s) ORDER BY id",
                     (lookalike, candidate, external, excluded, expired)),
            [(False,), (True,), (False,), (True,), (True,)],
        )

    def test_automatic_eligibility_is_idempotent_and_does_not_require_http_or_dns(self):
        self.sql("INSERT INTO seed_domains VALUES ('example.com')")
        member = self.domain('no-evidence.example.com', 42, state_scan=None, scannable=False)
        self.authorize_scope('example.com', 'PORT_SCAN')
        first, _ = self.run_worker('eligibility_worker.py')
        second, _ = self.run_worker('eligibility_worker.py')
        self.assertTrue(any('UPDATE DOMAINS D' in normalized_sql(query) for query, _, _ in first))
        self.assertEqual(self.sql("SELECT scannable FROM domains WHERE id=%s", (member,)), [(True,)])
        self.assertEqual(self.sql("SELECT scannable FROM domains WHERE id=%s", (member,)), [(True,)])
        self.assertTrue(any('D.SCANNABLE IS NOT TRUE' in normalized_sql(query) for query, _, _ in second))

    def test_http_tls_scope_migration_is_repeatable_and_preserves_rows(self):
        self.authorize_scope('example.com', 'TECHNOLOGY_HTTP')
        self.sql("""
            ALTER TABLE active_scan_scopes
                DROP CONSTRAINT active_scan_scopes_testing_level;
            ALTER TABLE active_scan_scopes
                ADD CONSTRAINT active_scan_scopes_testing_level
                CHECK (testing_level IN (
                    'TECHNOLOGY_HTTP', 'PORT_SCAN', 'ADHOC_CHECK'
                ));
        """)
        migration = (BACKEND / 'migrations' /
                     '008_add_http_tls_observation_scope.sql').read_text()
        for _ in range(2):
            self.sql(migration)
        self.assertEqual(self.sql(
            "SELECT count(*) FROM active_scan_scopes"
        ), [(1,)])
        self.sql("""
            INSERT INTO active_scan_scopes(
                scope_domain, include_subdomains, testing_level, approved_by
            ) VALUES ('tls.example.com', TRUE, 'HTTP_TLS_OBSERVATION', 'test')
        """)
        self.assertEqual(self.sql(
            "SELECT testing_level FROM active_scan_scopes "
            "WHERE scope_domain='tls.example.com'"
        ), [('HTTP_TLS_OBSERVATION',)])

    def test_legacy_ingest_insert_supplies_ownership_status_explicitly(self):
        source = (BACKEND / 'ingest_scan.py').read_text(encoding='utf-8')
        insert = source[source.index('INSERT INTO domains'):source.index('domain_id = cur.fetchone()[0]')]
        self.assertIn('ownership_status', insert)
        self.assertIn('ownership_for_discovery', source)

    def test_other_orphans_are_preserved_and_authorize_nothing(self):
        orphan = self.domain('orphan.example', 41)
        for table, extra in (
            ('domain_san', ''), ('domain_cert', ',NULL,1,\'critical\''),
            ('domain_ports', ',443,\'https\''), ('domain_tech', ',\'nginx\''),
            ('domain_provider', ',\'AWS\''), ('domain_findings', ',\'old\',\'HIGH\',\'old\''),
            ('domain_risk', ',99,\'preserve\''),
        ):
            self.sql(f'INSERT INTO {table} VALUES (%s,42{extra})', (orphan,))
        before = self.snapshot()
        for filename in CONSUMERS:
            self.run_worker(filename)
        self.assertEqual(self.snapshot(), before)

    def test_san_new_and_historical_children_gain_membership_and_enrichment(self):
        parent = self.domain('parent.example', 42)
        historic = self.domain('historic.example', 41, state_scan=41)
        previous = self.sql('SELECT to_jsonb(t)::text FROM domain_states t WHERE scan_id=41')
        self.authorize_scope('example', 'HTTP_TLS_OBSERVATION')
        self.run_worker('san_worker.py', overrides={
            'fetch_san_domains': mock.Mock(return_value=['new.example', 'historic.example'])
        })
        members = self.sql('SELECT d.domain,sr.seed FROM scan_results sr JOIN domains d ON d.id=sr.domain_id WHERE sr.scan_id=42 ORDER BY 1')
        self.assertEqual(members, [('historic.example','root.example'), ('new.example','root.example'), ('parent.example','root.example')])
        self.assertEqual(self.sql("SELECT count(*) FROM domain_sources WHERE scan_id=42 AND source='san'"), [(2,)])
        self.run_worker('san_state_sync.py')
        _, calls = self.run_worker('dns_worker.py')
        self.assertEqual({c.args[0] for c in calls['resolve_dns'].call_args_list},
                         {'parent.example', 'new.example', 'historic.example'})
        for filename in ('san_http_worker.py', 'cert_worker.py', 'port_scan_worker.py',
                         'tech_worker.py', 'asn_worker.py', 'provider_worker.py',
                         'takeover_worker.py', 'risk_worker.py'):
            self.run_worker(filename)
        self.assertEqual(self.sql('SELECT count(*) FROM domain_risk WHERE scan_id=42'), [(3,)])
        self.assertEqual(self.sql('SELECT to_jsonb(t)::text FROM domain_states t WHERE scan_id=41'), previous)
        self.assertEqual(self.sql('SELECT domain_id FROM scan_results WHERE scan_id=41'), [(historic,)])
        self.assertEqual(self.sql('SELECT domain_id FROM domain_san WHERE scan_id=42'), [(parent,)])

    def test_nonmember_san_parent_never_observed_or_produces_child(self):
        self.domain('orphan.example', 41)
        observer = mock.Mock(return_value=['forbidden.example'])
        before = self.snapshot()
        self.run_worker('san_worker.py', overrides={'fetch_san_domains': observer})
        observer.assert_not_called()
        self.assertEqual(self.snapshot(), before)

    def test_lifecycle_is_independent_for_all_consumers(self):
        for scan in (43, 44, 999):
            for filename in CONSUMERS:
                with self.subTest(scan=scan, worker=filename):
                    self.setUp()
                    self.domain('member.example', scan, scan)
                    before = self.snapshot()
                    self.run_worker(filename, scan_id=scan, expect_terminal=True)
                    self.assertEqual(self.snapshot(), before)

    def test_conditional_dml_rejects_stale_candidates_for_every_write_path(self):
        for filename in ATOMIC_WRITERS:
            for low_finding in ([False, True] if filename == 'takeover_worker.py' else [False]):
                with self.subTest(worker=filename, low_finding=low_finding):
                    self.setUp()
                    member = self.domain('parent.example', 42, http_status=0 if filename in ('dns_worker.py','san_http_worker.py') else 200,
                                         has_ip=filename != 'dns_worker.py')
                    if filename in ('port_scan_worker.py', 'tech_worker.py'):
                        self.sql("UPDATE domains SET validation_source='manual' WHERE id=%s", (member,))
                        level = 'PORT_SCAN' if filename == 'port_scan_worker.py' else 'TECHNOLOGY_HTTP'
                        self.authorize_scope('example', level)
                    if filename in ('san_worker.py', 'san_http_worker.py', 'cert_worker.py'):
                        self.authorize_scope('example', 'HTTP_TLS_OBSERVATION')
                    self.sql("INSERT INTO domain_sources VALUES (%s,42,'san','root.example')", (member,))
                    self.sql("INSERT INTO domain_dns VALUES (%s,42,'CNAME','target.github.io')", (member,))
                    self.sql("INSERT INTO domain_asn VALUES (%s,42,'AS1','192.0.2.1','AS1 Amazon')", (member,))
                    if filename == 'asn_worker.py':
                        self.sql('DELETE FROM domain_asn WHERE scan_id=42')
                    overrides = {}
                    if filename == 'san_worker.py':
                        overrides['fetch_san_domains'] = mock.Mock(return_value=['child.example'])
                    if low_finding:
                        overrides['check_takeover'] = mock.Mock(return_value={'body':'', 'status':404, 'length':100})
                    executions, _ = self.run_worker(filename, overrides=overrides)
                    writes = [(q,p) for q,p,_ in executions
                              if any(normalized_sql(q).startswith(s.upper()) for s in ATOMIC_WRITERS[filename])]
                    self.assertTrue(writes)
                    # Wrong-scan membership must not permit replay of any worker DML.
                    self.sql('INSERT INTO scan_results SELECT 41,domain_id,seed FROM scan_results WHERE scan_id=42 ON CONFLICT DO NOTHING')
                    self.sql('DELETE FROM scan_results WHERE scan_id=42')
                    before = self.snapshot()
                    for query, params in writes:
                        self.assertEqual(self.sql(query, params), 0)
                    self.assertEqual(self.snapshot(), before)

    def test_split_workers_stale_result_cannot_write_at_mutation_boundary(self):
        for filename in ('cert_worker.py','port_scan_worker.py','asn_worker.py'):
            with self.subTest(worker=filename):
                self.setUp()
                member = self.domain('member.example', 42)
                if filename == 'port_scan_worker.py':
                    self.sql("UPDATE domains SET validation_source='manual' WHERE id=%s", (member,))
                    self.authorize_scope('example', 'PORT_SCAN')
                elif filename == 'cert_worker.py':
                    self.authorize_scope('example', 'HTTP_TLS_OBSERVATION')
                def remove_member(cur, query, params):
                    cur.execute('DELETE FROM scan_results WHERE scan_id=42 AND domain_id=%s', (member,))
                executions, _ = self.run_worker(filename, before_write=remove_member)
                writes = [(q,n) for q,_,n in executions if normalized_sql(q).startswith('INSERT')]
                self.assertTrue(writes)
                self.assertTrue(all(n == 0 for _,n in writes))

    def test_checkpoint_membership_loss_prevents_later_network_work(self):
        for filename, count, observer in (('dns_worker.py',50,'resolve_dns'), ('san_worker.py',100,'fetch_san_domains')):
            with self.subTest(worker=filename):
                self.setUp()
                ids = [self.domain(f'd{i:03}.example',42) for i in range(count+1)]
                if filename == 'san_worker.py':
                    self.authorize_scope('example', 'HTTP_TLS_OBSERVATION')
                removed = []
                def after_commit():
                    if not removed:
                        self.sql('DELETE FROM scan_results WHERE scan_id=42 AND domain_id=%s', (ids[-1],))
                        removed.append(ids[-1])
                _, calls = self.run_worker(filename, after_commit=after_commit)
                self.assertEqual(calls[observer].call_count, count)
                self.assertNotIn(f'd{count:03}.example', [c.args[0] for c in calls[observer].call_args_list])
                table = 'domain_dns' if filename == 'dns_worker.py' else 'domain_san'
                self.assertEqual(self.sql(f'SELECT count(*) FROM {table} WHERE scan_id=42 AND domain_id=%s', (ids[-1],)), [(0,)])

    def test_risk_golden_member_and_orphan_risk_preservation(self):
        member = self.domain('member.example',42)
        orphan = self.domain('orphan.example',41)
        self.sql("INSERT INTO domain_risk VALUES (%s,42,99,'preserve')", (orphan,))
        self.sql("INSERT INTO domain_ports VALUES (%s,42,443,'https')", (member,))
        self.sql("INSERT INTO domain_cert VALUES (%s,42,NULL,10,'critical')", (member,))
        self.run_worker('risk_worker.py')
        self.assertEqual(self.sql('SELECT risk_score,reasons FROM domain_risk WHERE domain_id=%s', (member,)),
                         [(5,'["sensitive_ports","shadow_asset"]')])
        self.assertEqual(self.sql('SELECT risk_score,reasons FROM domain_risk WHERE domain_id=%s', (orphan,)), [(99,'preserve')])

    def test_ingest_retry_then_membership_sync_and_downstream_retry_rejection(self):
        self.ingest(42, [{'Domain':'removed.example'}])
        self.ingest(42, [{'Domain':'member.example'}])
        self.run_worker('san_state_sync.py')
        self.assertEqual(self.sql('SELECT d.domain FROM domain_states ds JOIN domains d ON d.id=ds.domain_id WHERE scan_id=42'), [('member.example',)])
        self.run_worker('dns_worker.py')
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'downstream'):
            self.ingest(42, [{'Domain':'replacement.example'}])
        self.assertEqual(self.snapshot(), before)

    def authorize_scope(self, scope_domain="example.com", testing_level="TECHNOLOGY_HTTP",
                        include_subdomains=True, expires_at=None, status="ACTIVE",
                        excluded_domains=None):
        self.sql(
            """
            INSERT INTO active_scan_scopes(
                scope_domain, include_subdomains, testing_level, approved_by,
                status, expires_at, excluded_domains
            ) VALUES (%s, %s, %s, 'test-operator', %s, %s, %s)
            """,
            (scope_domain, include_subdomains, testing_level, status,
             expires_at, excluded_domains or []),
        )

    def runtime_check(self, domain_id, testing_level="TECHNOLOGY_HTTP",
                      scan_id=42, required_scan_status="RUNNING"):
        connection = self.connect()
        try:
            with connection:
                with connection.cursor() as cursor:
                    return recheck_active_authorization(
                        cursor,
                        scan_id=scan_id,
                        domain_id=domain_id,
                        testing_level=testing_level,
                        required_scan_status=required_scan_status,
                    )
        finally:
            connection.close()

    def runtime_check_by_name(self, domain_name, testing_level="HTTP_TLS_OBSERVATION",
                              scan_id=42, required_scan_status="RUNNING"):
        connection = self.connect()
        try:
            with connection:
                with connection.cursor() as cursor:
                    return recheck_active_authorization(
                        cursor,
                        scan_id=scan_id,
                        domain_name=domain_name,
                        testing_level=testing_level,
                        required_scan_status=required_scan_status,
                    )
        finally:
            connection.close()

    def test_runtime_recheck_enforces_current_sql_authorization_state(self):
        domain_id = self.domain("app.example.com", 42)
        self.assertEqual(self.runtime_check(domain_id), (True, "authorized"))

        self.authorize_scope()
        self.sql("UPDATE active_scan_scopes SET status='REVOKED', revoked_by='test', revoked_at=CURRENT_TIMESTAMP")
        self.assertFalse(self.runtime_check(domain_id)[0])

        self.sql("UPDATE active_scan_scopes SET status='ACTIVE', revoked_by=NULL, revoked_at=NULL, expires_at=CURRENT_TIMESTAMP - INTERVAL '1 second'")
        # A legacy per-domain grant expiry no longer controls the central
        # organization policy. Explicit revocation above remains a denial.
        self.assertTrue(self.runtime_check(domain_id)[0])

        self.sql("UPDATE active_scan_scopes SET expires_at=NULL, testing_level='PORT_SCAN'")
        self.assertTrue(self.runtime_check(domain_id, "TECHNOLOGY_HTTP")[0])

        self.sql("UPDATE domains SET ownership_status='CANDIDATE' WHERE id=%s", (domain_id,))
        self.assertFalse(self.runtime_check(domain_id, "PORT_SCAN")[0])

        self.sql("UPDATE domains SET ownership_status='CONFIRMED', scannable=FALSE WHERE id=%s", (domain_id,))
        self.assertFalse(self.runtime_check(domain_id, "PORT_SCAN")[0])

        self.sql("UPDATE domains SET scannable=TRUE WHERE id=%s", (domain_id,))
        self.assertFalse(self.runtime_check(domain_id, "PORT_SCAN", scan_id=41)[0])
        self.assertFalse(self.runtime_check(domain_id, "PORT_SCAN", scan_id=43, required_scan_status="SUCCEEDED")[0])

        self.sql("UPDATE active_scan_scopes SET testing_level='PORT_SCAN'")
        self.sql("UPDATE scans SET status='SUCCEEDED' WHERE id=42")
        self.assertFalse(self.runtime_check(domain_id, "PORT_SCAN")[0])

    def test_redirect_host_recheck_requires_current_membership_and_full_policy(self):
        domain_id = self.domain("child.example.com", 42)
        self.sql("UPDATE domains SET ownership_status='CONFIRMED' WHERE id=%s", (domain_id,))
        self.sql("INSERT INTO seed_domains VALUES ('example.com')")
        self.authorize_scope("example.com", "HTTP_TLS_OBSERVATION")
        self.assertEqual(self.runtime_check_by_name("CHILD.EXAMPLE.COM."),
                         (True, "authorized"))
        self.assertFalse(self.runtime_check_by_name("outside.example.com")[0])
        self.sql("UPDATE domains SET scannable=FALSE WHERE id=%s", (domain_id,))
        self.assertFalse(self.runtime_check_by_name("child.example.com")[0])


    def test_runtime_recheck_requires_central_operation_policy_for_manual_rows(self):
        domain_id = self.domain("manual.example.com", 42)
        self.sql("UPDATE domains SET validation_source='manual' WHERE id=%s", (domain_id,))
        with mock.patch.dict(os.environ, {"ASIP_DEFAULT_SCAN_OPERATIONS": ""}):
            self.assertFalse(self.runtime_check(domain_id, "PORT_SCAN")[0])
        with mock.patch.dict(os.environ, {"ASIP_DEFAULT_SCAN_OPERATIONS": "PORT_SCAN"}):
            self.assertTrue(self.runtime_check(domain_id, "PORT_SCAN")[0])

    def test_runtime_recheck_fails_closed_on_database_error(self):
        class BrokenConnection:
            def __init__(self):
                self.rollbacks = 0

            def rollback(self):
                self.rollbacks += 1

        class BrokenCursor:
            def __init__(self):
                self.connection = BrokenConnection()

            def execute(self, *_args, **_kwargs):
                raise RuntimeError("database unavailable")

        cursor = BrokenCursor()
        self.assertEqual(
            recheck_active_authorization(
                cursor, scan_id=42, domain_id=1, testing_level="PORT_SCAN"
            ),
            (False, "authorization check failed"),
        )
        self.assertEqual(cursor.connection.rollbacks, 1)

    def test_http_tls_worker_requires_current_scope_and_uses_mocked_observer(self):
        domain_id = self.domain('observe.example.com', 42, http_status=0)
        self.authorize_scope('example.com', 'HTTP_TLS_OBSERVATION')
        _, observers = self.run_worker('http_observation_worker.py')
        observers['http_probe'].assert_called_once()
        self.assertEqual(self.runtime_check(
            domain_id, 'HTTP_TLS_OBSERVATION'
        ), (True, 'authorized'))

        self.sql("""
            UPDATE active_scan_scopes
               SET status='REVOKED', revoked_by='test',
                   revoked_at=CURRENT_TIMESTAMP
        """)
        self.assertFalse(self.runtime_check(
            domain_id, 'HTTP_TLS_OBSERVATION'
        )[0])

    def test_runtime_known_inventory_is_exact_not_a_parent_namespace(self):
        self.sql("INSERT INTO known_domains(domain) VALUES ('vpn.othercompany.net')")
        exact = self.domain('vpn.othercompany.net', 42)
        descendant = self.domain('random.vpn.othercompany.net', 42)
        self.authorize_scope('othercompany.net', 'PORT_SCAN')
        self.assertEqual(self.runtime_check(exact, 'PORT_SCAN'), (True, 'authorized'))
        self.assertFalse(self.runtime_check(descendant, 'PORT_SCAN')[0])

    def test_scannable_trusted_asset_without_operation_permission_makes_no_request(self):
        domain_id = self.domain('observe.example.com', 42, http_status=0)
        observer = mock.Mock(return_value={
            'http_observation_status': 'RESPONDED', 'http_status': 200,
            'http_reason': 'OK', 'final_url': 'https://observe.example.com',
            'final_status': 200, 'title': 'not reached',
        })
        with mock.patch.dict(os.environ, {"ASIP_DEFAULT_SCAN_OPERATIONS": ""}):
            self.run_worker('http_observation_worker.py', overrides={'http_probe': observer})
            self.assertFalse(self.runtime_check(
                domain_id, 'HTTP_TLS_OBSERVATION'
            )[0])
        observer.assert_not_called()

    def test_operation_scope_exclusion_blocks_manual_scannable_target(self):
        domain_id = self.domain('blocked.example.com', 42, http_status=0)
        self.sql("UPDATE domains SET validation_source='manual' WHERE id=%s", (domain_id,))
        self.authorize_scope(
            'example.com', 'HTTP_TLS_OBSERVATION', excluded_domains=['blocked.example.com']
        )
        observer = mock.Mock()
        self.run_worker('http_observation_worker.py', overrides={'http_probe': observer})
        observer.assert_not_called()
        self.assertFalse(self.runtime_check(
            domain_id, 'HTTP_TLS_OBSERVATION'
        )[0])

    def test_unknown_recon_http_state_is_ingested_then_updated_by_authorized_observer(self):
        self.sql("INSERT INTO seed_domains VALUES ('example.com')")
        self.authorize_scope('example.com', 'HTTP_TLS_OBSERVATION')
        self.ingest(42, [{
            'Domain': 'app.example.com',
            'Source': 'subfinder',
            'Seed': 'example.com',
            'IP': '8.8.8.8',
            'HTTP_Status': 0,
            'HTTP_Observation_Status': 'UNKNOWN',
        }])
        domain_id = self.sql(
            "SELECT id FROM domains WHERE domain='app.example.com'"
        )[0][0]
        self.assertEqual(self.sql(
            "SELECT http_status, http_observation_status FROM domain_states "
            "WHERE domain_id=%s AND scan_id=42", (domain_id,)
        ), [(0, 'UNKNOWN')])

        self.run_worker('eligibility_worker.py')
        observed = mock.Mock(return_value={
            'http_observation_status': 'RESPONDED',
            'http_status': 200,
            'http_reason': 'OK',
            'final_url': 'https://app.example.com/',
            'final_status': 200,
            'title': 'Authorized observation',
        })
        self.run_worker('http_observation_worker.py', overrides={
            'http_probe': observed,
        })

        self.assertEqual(self.sql(
            "SELECT http_status, http_observation_status, title FROM domain_states "
            "WHERE domain_id=%s AND scan_id=42", (domain_id,)
        ), [(200, 'RESPONDED', 'Authorized observation')])
        observed.assert_called_once()

    def test_technology_worker_rechecks_before_network_after_scope_revocation(self):
        domain_id = self.domain("tech.example.com", 42)
        self.authorize_scope()
        detected = mock.Mock(return_value=["nginx"])
        revoked = False

        def revoke_before_check(cursor, **kwargs):
            nonlocal revoked
            if not revoked:
                self.sql("UPDATE active_scan_scopes SET status='REVOKED', revoked_by='test', revoked_at=CURRENT_TIMESTAMP")
                revoked = True
            return recheck_active_authorization(cursor, **kwargs)

        self.run_worker(
            "tech_worker.py",
            overrides={
                "detect_tech": detected,
                "recheck_active_authorization": revoke_before_check,
            },
        )
        detected.assert_not_called()

    def test_expired_legacy_grant_does_not_override_default_operation_policy(self):
        domain_id = self.domain("port.example.com", 42)
        self.authorize_scope("example.com", "PORT_SCAN")
        scanned = mock.Mock(return_value=[(443, "https")])
        expired = False

        def expire_before_check(cursor, **kwargs):
            nonlocal expired
            if not expired:
                self.sql("UPDATE active_scan_scopes SET expires_at=CURRENT_TIMESTAMP - INTERVAL '1 second'")
                expired = True
            return recheck_active_authorization(cursor, **kwargs)

        self.run_worker(
            "port_scan_worker.py",
            overrides={
                "scan_ports": scanned,
                "recheck_active_authorization": expire_before_check,
            },
        )
        scanned.assert_called_once()
        self.assertEqual(scanned.call_args.args[0], "port.example.com")
        self.assertIsNotNone(scanned.call_args.kwargs.get("cancel_event"))

    def test_default_policy_allows_trusted_technology_and_port_network_work(self):
        self.domain("tech.example.com", 42)
        self.domain("port.example.com", 42)
        self.authorize_scope("tech.example.com", "TECHNOLOGY_HTTP", include_subdomains=False)
        self.authorize_scope("port.example.com", "PORT_SCAN", include_subdomains=False)
        detected = mock.Mock(return_value=["nginx"])
        scanned = mock.Mock(return_value=[])

        self.run_worker("tech_worker.py", overrides={"detect_tech": detected})
        self.run_worker("port_scan_worker.py", overrides={"scan_ports": scanned})

        self.assertEqual(
            [call.args[0] for call in detected.call_args_list],
            ["tech.example.com", "port.example.com"],
        )
        self.assertCountEqual(
            [call.args[0] for call in scanned.call_args_list],
            ["tech.example.com", "port.example.com"],
        )

    def test_denied_target_does_not_block_later_authorized_target(self):
        first = self.domain("first.example.com", 42)
        second = self.domain("second.example.com", 42)
        self.authorize_scope()
        detected = mock.Mock(return_value=["nginx"])

        def deny_first(cursor, **kwargs):
            if kwargs["domain_id"] == first:
                return False, "authorization no longer valid"
            return recheck_active_authorization(cursor, **kwargs)

        self.run_worker(
            "tech_worker.py",
            overrides={
                "detect_tech": detected,
                "recheck_active_authorization": deny_first,
            },
        )
        self.assertEqual([call.args[0] for call in detected.call_args_list], ["second.example.com"])


if __name__ == "__main__":
    unittest.main()
