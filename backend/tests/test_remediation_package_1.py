import importlib.util
import logging
import pathlib
import sys
import tempfile
import types
import unittest
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]


def load_backend_module(filename, argv=None, extra_modules=None):
    module_name = f"test_{filename.stem}_{id(filename)}_{len(sys.modules)}"
    spec = importlib.util.spec_from_file_location(module_name, filename)
    module = importlib.util.module_from_spec(spec)
    fake_db = types.ModuleType("db")
    fake_db.get_conn = lambda: None
    fake_db.require_running_scan = lambda cursor, scan_id: None
    def get_latest_authoritative_scan_id(cursor):
        cursor.execute("""
            SELECT id
            FROM scans
            WHERE status = 'SUCCEEDED'
            ORDER BY id DESC
            LIMIT 1
        """)
        row = cursor.fetchone()
        return row[0] if row else None
    fake_db.get_latest_authoritative_scan_id = get_latest_authoritative_scan_id
    fake_db.get_previous_authoritative_scan_id = lambda cursor, current_scan_id=None: None
    replacements = {"db": fake_db}
    replacements.update(extra_modules or {})

    old_modules = {name: sys.modules.get(name) for name in replacements}
    old_argv = sys.argv[:]
    old_path = sys.path[:]
    with tempfile.TemporaryDirectory() as temp_dir:
        pathlib.Path(temp_dir, "logs").mkdir()
        try:
            sys.modules.update(replacements)
            sys.argv = argv or [str(filename)]
            sys.path.insert(0, str(BACKEND))
            with mock.patch("os.getcwd", return_value=temp_dir), \
                    mock.patch("logging.FileHandler", return_value=logging.NullHandler()):
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
    def __init__(self, fetchones=None, fetchalls=None, rowcount=1):
        self.fetchones = list(fetchones or [])
        self.fetchalls = list(fetchalls or [])
        self.executions = []
        self.rowcount = rowcount

    def execute(self, query, params=None):
        self.executions.append((query, params))

    def fetchone(self):
        return self.fetchones.pop(0)

    def fetchall(self):
        return self.fetchalls.pop(0)


class FakeConnection:
    def __init__(self, cursor):
        self._cursor = cursor
        self.committed = False
        self.closed = False

    def cursor(self):
        return self._cursor

    def commit(self):
        self.committed = True

    def close(self):
        self.closed = True


class SanPipelineTests(unittest.TestCase):
    def test_san_child_inherits_parent_current_scan_membership(self):
        module = load_backend_module(
            BACKEND / "san_worker.py",
            ["san_worker.py", "42"]
        )
        cursor = RecordingCursor(fetchones=[("seed.example",)])

        module.add_current_scan_membership(cursor, 10, 20)

        self.assertEqual(cursor.executions[0][1], (42, 10))
        insert_sql, insert_params = cursor.executions[1]
        self.assertIn("INSERT INTO scan_results", insert_sql)
        self.assertIn("ON CONFLICT (scan_id, domain_id) DO NOTHING", insert_sql)
        self.assertEqual(insert_params, (42, 20, "seed.example"))

    def test_san_membership_fails_if_parent_is_not_in_current_scan(self):
        module = load_backend_module(
            BACKEND / "san_worker.py",
            ["san_worker.py", "42"]
        )
        cursor = RecordingCursor(fetchones=[None])

        with self.assertRaisesRegex(RuntimeError, "missing scan_results"):
            module.add_current_scan_membership(cursor, 10, 20)

        self.assertEqual(len(cursor.executions), 1)

    def test_dns_promotes_unresolved_state_without_touching_http(self):
        module = load_backend_module(
            BACKEND / "dns_worker.py",
            ["dns_worker.py", "42"]
        )
        cursor = RecordingCursor(fetchalls=[[(20, "child.example", False)]])
        connection = FakeConnection(cursor)
        module.get_conn = lambda: connection
        module.resolve_dns = lambda domain: [
            ("A", "192.0.2.20"),
            ("A", "192.0.2.10"),
            ("CNAME", "target.example")
        ]
        module.reverse_dns = lambda ip: "child-rdns.example"

        module.main()

        select_sql = cursor.executions[0][0]
        self.assertNotIn("WHERE ds.has_ip = TRUE", select_sql)
        update_sql, update_params = next(
            item for item in cursor.executions if "UPDATE domain_states" in item[0]
        )
        self.assertNotIn("http_", update_sql)
        self.assertIn("has_ip IS NOT TRUE", update_sql)
        self.assertEqual(
            update_params,
            ("192.0.2.10", "child-rdns.example", 20, 42)
        )
        self.assertTrue(connection.committed)

    def test_dns_does_not_replace_an_existing_resolved_state(self):
        module = load_backend_module(
            BACKEND / "dns_worker.py",
            ["dns_worker.py", "42"]
        )
        cursor = RecordingCursor(fetchalls=[[(20, "child.example", True)]])
        connection = FakeConnection(cursor)
        module.get_conn = lambda: connection
        module.resolve_dns = lambda domain: [("A", "192.0.2.50")]

        module.main()

        self.assertFalse(any(
            "UPDATE domain_states" in query for query, _ in cursor.executions
        ))

    def test_san_http_worker_reuses_probe_and_preserves_guardrails(self):
        module = load_backend_module(
            BACKEND / "san_http_worker.py",
            ["san_http_worker.py", "42"]
        )
        cursor = RecordingCursor(fetchalls=[[(20, "child.example")]])
        connection = FakeConnection(cursor)
        module.get_conn = lambda: connection
        module.http_probe = lambda domain: {
            "http_observation_status": "RESPONDED",
            "http_status": 301,
            "http_reason": "Moved Permanently",
            "final_url": "https://www.example/final",
            "final_status": 200,
            "redirect_count": 1,
            "title": "Child"
        }

        module.main()

        select_sql = cursor.executions[0][0]
        self.assertNotIn("scannable", select_sql.lower())
        self.assertIn("src.source = 'san'", select_sql)
        self.assertIn("ds.has_ip = TRUE", select_sql)
        update_sql, update_params = cursor.executions[1]
        self.assertIn("COALESCE(http_status, 0) = 0", update_sql)
        self.assertEqual(update_params[0:2], (301, True))
        self.assertEqual(update_params[-2:], (20, 42))

    def test_san_http_worker_leaves_state_unchanged_when_probe_fails(self):
        module = load_backend_module(
            BACKEND / "san_http_worker.py",
            ["san_http_worker.py", "42"]
        )
        cursor = RecordingCursor(fetchalls=[[(20, "child.example")]])
        connection = FakeConnection(cursor)
        module.get_conn = lambda: connection
        module.http_probe = lambda domain: None

        module.main()

        self.assertEqual(len(cursor.executions), 1)
        self.assertTrue(connection.committed)

    def test_orchestration_places_san_http_after_dns_before_cert(self):
        source = (BACKEND / "orchestration.py").read_text()
        dns = source.index('("DNS Resolution"')
        san_http = source.index('("SAN HTTP Observation"')
        cert = source.index('("Cert Worker"')
        self.assertLess(dns, san_http)
        self.assertLess(san_http, cert)


class ApiAndWorkerRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fake_llm = types.ModuleType("llm_service")
        fake_llm.ask_llm = lambda prompt: ""
        cls.main = load_backend_module(
            BACKEND / "main.py",
            extra_modules={"llm_service": fake_llm}
        )
        cls.mcp = load_backend_module(BACKEND / "mcp_server.py")

    def test_summary_new_domains_uses_first_seen_current_scan_membership(self):
        cursor = RecordingCursor(fetchones=[
            (100,), (42,), (80,), (7,), (5,), (20,), (30,), (60,), (4,)
        ])
        connection = FakeConnection(cursor)
        self.main.get_conn = lambda: connection

        result = self.main.summary()

        self.assertEqual(result["new_domains"], 7)
        new_query, params = cursor.executions[3]
        self.assertIn("JOIN scan_results", new_query)
        self.assertIn("d.first_seen_scan = %s", new_query)
        self.assertEqual(params, (42, 42))

    def test_new_domains_endpoint_uses_first_seen_current_scan_model(self):
        cursor = RecordingCursor(
            fetchones=[(42,)],
            fetchalls=[[('new.example',)]]
        )
        connection = FakeConnection(cursor)
        self.main.get_conn = lambda: connection

        result = self.main.new_domains()

        self.assertEqual(result, {
            "latest_scan": 42,
            "new_domains": ["new.example"]
        })
        query, params = cursor.executions[1]
        self.assertIn("JOIN scan_results", query)
        self.assertNotIn("scan_domains", query)
        self.assertIn("d.first_seen_scan = %s", query)
        self.assertEqual(params, (42, 42))

    def test_risk_leaderboard_scopes_risk_and_state_to_latest_scan(self):
        cursor = RecordingCursor(fetchones=[(42,)])
        connection = FakeConnection(cursor)
        self.main.get_conn = lambda: connection
        self.main.calculate_scan_risks = mock.Mock(return_value=[
            types.SimpleNamespace(
                domain="risk.example",
                has_ip=True,
                result=types.SimpleNamespace(
                    score=4, priority="Review", reasons=("shadow_asset",)
                ),
            )
        ])

        result = self.main.risk_leaderboard()

        self.assertEqual(result, [{
            "domain": "risk.example",
            "risk": 4,
            "priority": "Review",
            "reasons": ["shadow_asset"],
        }])
        self.main.calculate_scan_risks.assert_called_once_with(cursor, 42)
        self.assertIn("FROM scans", cursor.executions[0][0])

    def test_mcp_findings_uses_finding_column_and_preserves_issue_key(self):
        cursor = RecordingCursor(
            fetchones=[(42,)],
            fetchalls=[[('asset.example', 'dangling_dns')]]
        )
        connection = FakeConnection(cursor)
        self.mcp.get_conn = lambda: connection

        result = self.mcp.get_findings()

        self.assertEqual(result, [{
            "domain": "asset.example",
            "issue": "dangling_dns"
        }])
        self.assertIn("f.finding", cursor.executions[1][0])
        self.assertNotIn("f.issue", cursor.executions[1][0])

    def test_ssl_guide_normalizes_to_existing_ssl_issue_guide(self):
        result = self.mcp.investigation_guide("ssl")
        self.assertEqual(result["finding"], "ssl_issue")
        self.assertIn("Verify expiry date", result["steps"])

    def test_empty_provider_org_maps_to_unknown(self):
        module = load_backend_module(
            BACKEND / "provider_worker.py",
            ["provider_worker.py", "42"]
        )
        self.assertEqual(module.map_provider(None), "Unknown")
        self.assertEqual(module.map_provider(""), "Unknown")

    def test_canonical_risk_excludes_legacy_certificate_signal(self):
        worker = (BACKEND / "risk_worker.py").read_text()
        engine = (BACKEND / "risk_engine.py").read_text()
        self.assertIn("calculate_scan_risks(cur, scan_id)", worker)
        self.assertNotIn("domain_cert", engine)
        self.assertNotIn("cert_expiring", engine)


if __name__ == "__main__":
    unittest.main()
