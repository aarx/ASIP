import builtins
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


def load_module(filename, replacements=None):
    module_name = f"pkg2c_{filename}_{len(sys.modules)}"
    spec = importlib.util.spec_from_file_location(module_name, BACKEND / filename)
    module = importlib.util.module_from_spec(spec)
    replacements = replacements or {}
    previous = {name: sys.modules.get(name) for name in replacements}
    old_path = sys.path[:]
    try:
        sys.modules.update(replacements)
        sys.path.insert(0, str(BACKEND))
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path[:] = old_path
        for name, old in previous.items():
            if old is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = old


class RecordingCursor:
    def __init__(self):
        self.executions = []

    def execute(self, sql, params=None):
        self.executions.append((sql, params))


class FakeConnection:
    def __init__(self):
        self.cursor_obj = RecordingCursor()
        self.commits = 0
        self.rollbacks = 0
        self.closed = False

    def cursor(self):
        return self.cursor_obj

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True


class KnownInventoryLoaderTests(unittest.TestCase):
    def test_loader_obtains_connection_and_loads_known_domains(self):
        connection = FakeConnection()
        fake_db = types.ModuleType("db")
        fake_db.get_conn = mock.Mock(return_value=connection)
        csv_data = "Domains\nKnown.Example\nSecond.Example\n"

        with mock.patch.object(
            builtins, "open", mock.mock_open(read_data=csv_data)
        ), mock.patch("builtins.print"):
            load_module("load_known_domains.py", {"db": fake_db})

        fake_db.get_conn.assert_called_once_with()
        self.assertEqual(connection.commits, 1)
        self.assertEqual(connection.rollbacks, 0)
        self.assertTrue(connection.closed)
        self.assertEqual(
            [params for _, params in connection.cursor_obj.executions],
            [("known.example", "initial_import"), ("second.example", "initial_import")],
        )
        self.assertTrue(all("INSERT INTO known_domains" in sql
                            for sql, _ in connection.cursor_obj.executions))


class KnownShadowSourceOfTruthTests(unittest.TestCase):
    def test_ingest_derives_is_known_from_known_domains_not_recon_status(self):
        text = source("ingest.py")
        insert = text[text.index("INSERT INTO domains("):text.index("RETURNING id")]

        self.assertIn("is_known", insert)
        self.assertIn("SELECT 1 FROM known_domains", insert)
        self.assertNotIn("Domain_Status", insert)

    def test_san_child_classification_uses_known_domains(self):
        text = source("san_worker.py")
        insert = text[text.index("INSERT INTO domains("):text.index("RETURNING id")]

        self.assertIn("is_known", insert)
        self.assertIn("SELECT 1 FROM known_domains", insert)
        self.assertNotIn("scannable", insert.lower())
        self.assertNotIn("validation_source", insert)

    def test_independent_fields_do_not_define_known_shadow(self):
        classification_sources = source("ingest.py") + source("san_worker.py")
        relevant = normalized(classification_sources)

        self.assertIn("KNOWN_DOMAINS", relevant)
        self.assertNotIn("CONFIDENCE_SCORE = (", relevant)
        self.assertNotIn("CONFIDENCE_LABEL = (", relevant)
        self.assertNotIn("SCANNABLE = (", relevant)
        self.assertNotIn("VALIDATION_SOURCE = (", relevant)
        self.assertNotIn("FROM SEED_DOMAINS", relevant)


class ShadowEndpointTests(unittest.TestCase):
    def endpoint_block(self, name):
        text = source("main.py")
        start = text.index(f"def {name}(")
        end = text.find("\n@app.get", start)
        return text[start:end if end != -1 else None]

    def test_shadow_assets_requires_is_known_false(self):
        block = self.endpoint_block("shadow_assets")
        norm = normalized(block)

        self.assertIn("RISK.IS_KNOWN IS FALSE", norm)
        engine = normalized(source("risk_engine.py"))
        self.assertIn("FROM SCAN_RESULTS SR", engine)
        self.assertIn("WHERE SR.SCAN_ID = %S", engine)

    def test_shadow_summary_requires_is_known_false(self):
        block = self.endpoint_block("shadow_summary")
        norm = normalized(block)

        self.assertIn("RISK.IS_KNOWN IS FALSE", norm)
        self.assertIn("RISK.HAS_IP", norm)
        self.assertIn('RISK.HTTP_OBSERVATION_STATUS == "NO_RESPONSE"', norm)

    def test_other_shadow_surfaces_already_use_is_known_false(self):
        for endpoint in ("shadow_by_provider", "unknown_high_risk"):
            with self.subTest(endpoint=endpoint):
                block = normalized(self.endpoint_block(endpoint))
                expected = (
                    "RISK.IS_KNOWN IS FALSE"
                    if endpoint == "unknown_high_risk"
                    else "D.IS_KNOWN = FALSE"
                )
                self.assertIn(expected, block)

    def test_export_shadow_type_is_known_shadow_only(self):
        block = self.endpoint_block("export_enriched_csv")
        shadow_logic = block[
            block.index("def get_shadow(row):"):
            block.index('df["shadow_type"]')
        ]

        self.assertIn('"known" if row["is_known"] else "shadow"', shadow_logic)
        self.assertNotIn("http_live", shadow_logic)
        self.assertNotIn("has_ip", shadow_logic)


class AuthorizationSeparationTests(unittest.TestCase):
    def test_2d2b_t2_authorization_remains_manual_only(self):
        policy = load_module("authorization_policy.py")

        self.assertEqual(
            policy.explicit_t2_authorization_sql("d"),
            "d.scannable IS TRUE AND d.validation_source = 'manual'",
        )

    def test_confidence_seed_known_and_risk_do_not_authorize_t2(self):
        text = source("port_scan_worker.py")
        norm = normalized(text)

        self.assertIn("EXPLICIT_T2_AUTHORIZATION_SQL(\"D\")", norm)
        self.assertNotIn("D.IS_KNOWN = TRUE", norm)
        self.assertNotIn("CONFIDENCE_LABEL", norm)
        self.assertNotIn("CONFIDENCE_SCORE", norm)
        self.assertNotIn("SEED_DOMAINS", norm)
        self.assertNotIn("DOMAIN_RISK", norm)


if __name__ == "__main__":
    unittest.main()
