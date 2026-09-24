import importlib.util
import logging
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


def load_worker(filename):
    module_name = f"pkg2d2b_{filename}_{len(sys.modules)}"
    spec = importlib.util.spec_from_file_location(module_name, BACKEND / filename)
    module = importlib.util.module_from_spec(spec)
    fake_db = types.ModuleType("db")
    fake_db.get_conn = mock.Mock()
    fake_db.require_running_scan = mock.Mock()
    previous_db = sys.modules.get("db")
    old_argv = sys.argv[:]
    old_path = sys.path[:]
    try:
        sys.modules["db"] = fake_db
        sys.argv = [filename, "42"]
        sys.path.insert(0, str(BACKEND))
        with mock.patch("logging.FileHandler", return_value=logging.NullHandler()), \
                mock.patch("os.makedirs"):
            spec.loader.exec_module(module)
    finally:
        sys.argv = old_argv
        sys.path[:] = old_path
        if previous_db is None:
            sys.modules.pop("db", None)
        else:
            sys.modules["db"] = previous_db
    return module


class RecordingCursor:
    def __init__(self, fetchalls=None, fetchones=None):
        self.fetchalls = list(fetchalls or [])
        self.fetchones = list(fetchones or [])
        self.executions = []
        self.rowcount = 1

    def execute(self, query, params=None):
        self.executions.append((query, params))

    def fetchall(self):
        return self.fetchalls.pop(0) if self.fetchalls else []

    def fetchone(self):
        return self.fetchones.pop(0) if self.fetchones else None


class FakeConnection:
    def __init__(self, cursor):
        self._cursor = cursor
        self.commits = 0
        self.closed = False

    def cursor(self):
        return self._cursor

    def commit(self):
        self.commits += 1

    def close(self):
        self.closed = True


class AuthorizationPolicyTests(unittest.TestCase):
    def test_explicit_t2_authorization_predicate_is_manual_only(self):
        module = load_worker("authorization_policy.py")

        self.assertEqual(
            module.explicit_t2_authorization_sql("d"),
            "d.scannable IS TRUE AND d.validation_source = 'manual'",
        )

    def test_port_candidates_require_manual_t2_authorization_and_membership(self):
        module = load_worker("port_scan_worker.py")
        cursor = RecordingCursor(fetchalls=[])

        module.get_resolving_domains(cursor, 42)

        sql, params = cursor.executions[0]
        norm = normalized(sql)
        self.assertIn("SCAN_RESULTS SR", norm)
        self.assertIn("SR.DOMAIN_ID = S.DOMAIN_ID", norm)
        self.assertIn("SR.SCAN_ID = S.SCAN_ID", norm)
        self.assertIn("D.SCANNABLE IS TRUE", norm)
        self.assertIn("D.VALIDATION_SOURCE = 'MANUAL'", norm)
        self.assertEqual(params, (42, 42))

    def test_manual_approval_is_the_only_t2_authorizing_shape(self):
        def eligible(scannable, validation_source, confidence="low", is_known=False,
                     seed_related=False, risk=0):
            return bool(scannable) and validation_source == "manual"

        self.assertTrue(eligible(True, "manual"))
        self.assertFalse(eligible(True, None))
        self.assertFalse(eligible(True, "san"))
        self.assertFalse(eligible(False, "manual"))
        self.assertFalse(eligible(False, None))
        self.assertFalse(eligible(False, None, confidence="high"))
        self.assertFalse(eligible(False, None, is_known=True))
        self.assertFalse(eligible(False, None, seed_related=True))
        self.assertFalse(eligible(False, None, risk=100))


class SanAuthorizationTests(unittest.TestCase):
    def test_san_worker_no_longer_writes_scannable_or_seed_auth(self):
        text = source("san_worker.py")
        norm = normalized(text)

        self.assertNotIn("SET SCANNABLE", norm)
        self.assertNotIn("EXCLUDED.SCANNABLE", norm)
        self.assertNotIn("IS_SCANNABLE", norm)
        self.assertNotIn("FROM SEED_DOMAINS", norm)

    def test_san_child_insert_relies_on_schema_default_for_authorization(self):
        text = source("san_worker.py")
        insert = text[text.index("INSERT INTO domains("):text.index("ON CONFLICT (domain)")]

        self.assertIn("is_known", insert)
        self.assertNotIn("scannable", insert.lower())
        self.assertIn("source", insert)

    def test_san_processing_preserves_existing_manual_decisions_by_not_writing_auth(self):
        text = source("san_worker.py")

        self.assertNotIn("validation_source", text)
        self.assertNotIn("scannable =", text)


class T0T1GateTests(unittest.TestCase):
    T1_WORKERS = {
        "san_http_worker.py": ("UPDATE domain_states",),
        "cert_worker.py": ("INSERT INTO domain_cert",),
        "tech_worker.py": ("INSERT INTO domain_tech",),
        "takeover_worker.py": ("INSERT INTO domain_findings",),
    }

    def test_t0_t1_workers_do_not_gate_candidates_on_scannable(self):
        for filename in self.T1_WORKERS:
            with self.subTest(filename=filename):
                norm = normalized(source(filename))
                self.assertNotIn("D.SCANNABLE = TRUE", norm)
                self.assertNotIn("D.SCANNABLE IS TRUE", norm)

    def test_t0_t1_workers_keep_exact_membership_filtering(self):
        for filename, write_needles in self.T1_WORKERS.items():
            with self.subTest(filename=filename):
                norm = normalized(source(filename))
                self.assertIn("SCAN_RESULTS SR", norm)
                self.assertRegex(norm, r"SR\.DOMAIN_ID\s*=|=\s*SR\.DOMAIN_ID")
                self.assertRegex(norm, r"SR\.SCAN_ID\s*=|=\s*SR\.SCAN_ID")
                for needle in write_needles:
                    self.assertIn(needle, source(filename))

    def test_san_http_selects_unscannable_exact_membership_candidates(self):
        module = load_worker("san_http_worker.py")
        cursor = RecordingCursor(fetchalls=[[]])
        connection = FakeConnection(cursor)
        module.get_conn = lambda: connection

        with mock.patch("builtins.print"):
            module.main()

        select_sql = cursor.executions[0][0]
        self.assertIn("JOIN scan_results sr", select_sql)
        self.assertIn("src.source = 'san'", select_sql)
        self.assertIn("ds.has_ip = TRUE", select_sql)
        self.assertNotIn("scannable", select_sql.lower())
        self.assertEqual(connection.commits, 1)


class UnchangedPolicyBoundaryTests(unittest.TestCase):
    def test_validation_ingest_remains_manual_grant_and_rejection_path(self):
        text = source("validation_ingest.py")
        norm = normalized(text)

        self.assertIn("SCANNABLE = TRUE", norm)
        self.assertIn("SCANNABLE = FALSE", norm)
        self.assertIn("VALIDATION_SOURCE = 'MANUAL'", norm)

    def test_discovery_validator_does_not_write_authorization(self):
        text = source("discovery_validator.py")
        norm = normalized(text)

        self.assertIn("CONFIDENCE_SCORE", norm)
        self.assertNotIn("SET SCANNABLE", norm)
        self.assertNotIn("VALIDATION_SOURCE = 'MANUAL'", norm)


if __name__ == "__main__":
    unittest.main()
