import importlib.util
import io
import logging
import pathlib
import sys
import types
import unittest
from contextlib import redirect_stdout
from unittest import mock

import scan_diagnostics


BACKEND = pathlib.Path(__file__).resolve().parents[1]


class Cursor:
    def __init__(self, rows=()):
        self.rows = list(rows)
        self.executions = []

    def execute(self, sql, params=None):
        self.executions.append((sql, params))

    def fetchall(self):
        return list(self.rows)


def load_worker(filename):
    fake_db = types.ModuleType("db")
    fake_db.get_conn = mock.Mock()
    fake_db.require_running_scan = mock.Mock()
    auth = types.ModuleType("authorization_policy")
    auth.active_scan_authorization_sql = mock.Mock(return_value="AUTHORIZED")
    auth.passive_dns_discovery_sql = mock.Mock(return_value="DISCOVERY_ALLOWED")
    auth.default_operation_enabled = mock.Mock(return_value=False)
    spec = importlib.util.spec_from_file_location(
        f"{filename[:-3]}_ip_test_{id(fake_db)}", BACKEND / filename
    )
    module = importlib.util.module_from_spec(spec)
    names = ("db", "authorization_policy")
    prior = {key: sys.modules.get(key) for key in names}
    argv = sys.argv[:]
    try:
        sys.modules.update({"db": fake_db, "authorization_policy": auth})
        sys.argv = [filename, "36"]
        with mock.patch("logging.FileHandler", return_value=logging.NullHandler()):
            spec.loader.exec_module(module)
    finally:
        sys.argv = argv
        for key, value in prior.items():
            if value is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = value
    module._test_db = fake_db
    module._test_auth = auth
    return module


class Connection:
    def __init__(self, cursor):
        self._cursor = cursor
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


class AsnProviderIpEligibilityTests(unittest.TestCase):
    def test_asn_selection_requires_current_scan_ip_and_authorization(self):
        worker = load_worker("asn_worker.py")
        cursor = Cursor([(1, "host.example", "8.8.8.8")])
        self.assertEqual(worker.get_domains(cursor, 36), cursor.rows)
        sql, params = cursor.executions[0]
        self.assertIn("s.scan_id = %s", sql)
        self.assertIn("s.has_ip = TRUE", sql)
        self.assertIn("active_scan_authorization_sql", worker.get_domains.__code__.co_names)
        self.assertIn("passive_dns_discovery_sql", worker.get_domains.__code__.co_names)
        self.assertEqual(params, (36, 36))

    def test_asn_accepts_only_valid_public_current_ip_values(self):
        worker = load_worker("asn_worker.py")
        self.assertEqual(worker.normalize_public_ip("8.8.8.8"), ("8.8.8.8", None))
        self.assertEqual(worker.normalize_public_ip("2001:4860:4860::8888"),
                         ("2001:4860:4860::8888", None))
        self.assertEqual(worker.normalize_public_ip("not-an-ip"), (None, "invalid_ip"))
        self.assertEqual(worker.normalize_public_ip("10.0.0.1"), (None, "non_public_ip"))

    def test_provider_input_must_match_current_scan_ip_and_asn_authorization(self):
        worker = load_worker("provider_worker.py")
        cursor = Cursor([(1, "host.example", "8.8.8.8", "AS1 Example")])
        self.assertEqual(worker.get_provider_candidates(cursor, 36), cursor.rows)
        sql, params = cursor.executions[0]
        self.assertIn("JOIN domain_states ds", sql)
        self.assertIn("ds.has_ip IS TRUE", sql)
        self.assertIn("ds.ip = a.ip", sql)
        self.assertIn("active_scan_authorization_sql", worker.get_provider_candidates.__code__.co_names)
        self.assertEqual(params, (36, 36))

    def test_provider_rejects_invalid_or_nonpublic_asn_ip(self):
        worker = load_worker("provider_worker.py")
        self.assertEqual(worker.normalize_public_ip("8.8.4.4"), ("8.8.4.4", None))
        self.assertEqual(worker.normalize_public_ip("bad"), (None, "invalid_ip"))
        self.assertEqual(worker.normalize_public_ip("192.168.1.1"), (None, "non_public_ip"))

    def test_provider_mapping_remains_local_and_does_not_promote_ownership(self):
        provider = load_worker("provider_worker.py")
        self.assertEqual(provider.map_provider("AS15169 Google LLC"), "GCP")
        validator = (BACKEND / "discovery_validator.py").read_text()
        score_function = validator[validator.index("def compute_score"):validator.index("def label")]
        self.assertIn('data["same_provider"]', score_function)
        self.assertNotIn("ownership_status", score_function)

    def test_zero_work_summary_surfaces_policy_disabled_without_claiming_mappings(self):
        output = (
            'ASIP_WORKER_SUMMARY {"selected":0,"candidate_targets":0,'
            '"eligible_targets":0,"processed_targets":0,"mapped_targets":0,'
            '"disabled_by_policy":true}'
        )
        summary = scan_diagnostics.extract_worker_summary(output)
        self.assertEqual(summary["selected"], 0)
        self.assertEqual(summary["mapped_targets"], 0)
        self.assertTrue(summary["disabled_by_policy"])

    def test_disabled_asn_stage_makes_no_external_lookup_and_reports_zero_work(self):
        worker = load_worker("asn_worker.py")
        conn = Connection(Cursor())
        worker._test_db.get_conn.return_value = conn
        worker.get_domains = mock.Mock(return_value=[])
        output = io.StringIO()
        with mock.patch.object(worker, "enrich_asn") as lookup, redirect_stdout(output):
            worker.main()
        lookup.assert_not_called()
        summary = scan_diagnostics.extract_worker_summary(output.getvalue())
        self.assertEqual(summary["selected"], 0)
        self.assertEqual(summary["processed_targets"], 0)
        self.assertEqual(summary["mapped_targets"], 0)
        self.assertTrue(summary["disabled_by_policy"])
        self.assertTrue(conn.closed)

    def test_duplicate_authorized_ips_share_lookup_but_persist_per_hostname(self):
        worker = load_worker("asn_worker.py")
        conn = Connection(Cursor())
        conn._cursor.rowcount = 1
        worker._test_db.get_conn.return_value = conn
        worker._test_auth.default_operation_enabled.return_value = True
        worker.get_domains = mock.Mock(return_value=[
            (1, "one.example", "8.8.8.8"),
            (2, "two.example", "8.8.8.8"),
        ])
        worker.asn_target_authorized = mock.Mock(return_value=True)
        output = io.StringIO()
        with mock.patch.object(worker, "enrich_asn", return_value=("AS1", "Example")) as lookup, \
                redirect_stdout(output):
            worker.main()
        lookup.assert_called_once_with("8.8.8.8")
        writes = [sql for sql, _ in conn._cursor.executions if "INSERT INTO domain_asn" in sql]
        self.assertEqual(len(writes), 2)
        summary = scan_diagnostics.extract_worker_summary(output.getvalue())
        self.assertEqual(summary["unique_ips_queried"], 1)
        self.assertEqual(summary["duplicate_ip_lookup_reuses"], 1)
        self.assertEqual(summary["mapped_targets"], 2)

    def test_asn_authorization_uncertainty_never_calls_external_service(self):
        worker = load_worker("asn_worker.py")
        conn = Connection(Cursor())
        worker._test_db.get_conn.return_value = conn
        worker._test_auth.default_operation_enabled.return_value = True
        worker.get_domains = mock.Mock(return_value=[(1, "host.example", "8.8.8.8")])
        worker.asn_target_authorized = mock.Mock(return_value=False)
        output = io.StringIO()
        with mock.patch.object(worker, "enrich_asn") as lookup, redirect_stdout(output):
            worker.main()
        lookup.assert_not_called()
        summary = scan_diagnostics.extract_worker_summary(output.getvalue())
        self.assertEqual(summary["authorization_skips"], 1)
        self.assertEqual(summary["mapped_targets"], 0)

    def test_provider_stage_reports_policy_disabled_zero_inputs(self):
        worker = load_worker("provider_worker.py")
        conn = Connection(Cursor())
        worker._test_db.get_conn.return_value = conn
        worker.get_provider_candidates = mock.Mock(return_value=[])
        output = io.StringIO()
        with redirect_stdout(output):
            worker.main()
        summary = scan_diagnostics.extract_worker_summary(output.getvalue())
        self.assertEqual(summary["asn_input_rows"], 0)
        self.assertEqual(summary["mapped_targets"], 0)
        self.assertTrue(summary["disabled_by_policy"])


if __name__ == "__main__":
    unittest.main()
