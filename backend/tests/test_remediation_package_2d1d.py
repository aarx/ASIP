import ast
import hashlib
import pathlib
import types
import unittest
from unittest import mock

from backend.tests import test_remediation_package_2d1c as convergence


BACKEND = pathlib.Path(__file__).resolve().parents[1]

PROTECTED_SHA256 = {
    "ingest.py": "b1180a94fb9bcd39313f7f8b5ddef8ebd007300562710088ff589b378c38d880",
    "orchestration.py": "2813d097152f3e7deb5d3b235c3e2777b30f527e361a270485cfb7b286a43960",
    "discovery_validator.py": "545dfad14226f1b2b1e2b609b49d7ae9f2738502e3dc68756c243f5d73e3ae81",
    "main.py": "664fc6ff862c793d92f63dcde055c7b169e330d4ca4f167c2c939d7f696bef80",
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
    "tech_worker.py": ("INSERT INTO domain_tech",),
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
                self.assertEqual(text.count("get_conn()"), 1)

    def test_san_parent_membership_precedes_network_observation(self):
        text = source("san_worker.py")
        loop = text.index("for i, (domain_id, domain)")
        membership = text.index("scan_results", loop)
        network = text.index("fetch_san_domains(domain)", loop)
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
                        CREATE TABLE seed_domains (domain text);
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
                    """)
        finally:
            connection.close()

    def setUp(self):
        convergence.PostgreSQLIngestConvergenceTests.setUp(self)
        self.sql("INSERT INTO scans VALUES (44, 'FAILED')")

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
                    if filename == 'port_scan_worker.py':
                        self.sql("UPDATE domains SET validation_source='manual' WHERE id=%s", (member,))
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


if __name__ == "__main__":
    unittest.main()
