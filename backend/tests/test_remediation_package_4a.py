import pathlib
import sys
import unittest


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from authorization_policy import explicit_t2_authorization_sql  # noqa: E402
from ownership import (  # noqa: E402
    OWNERSHIP_CANDIDATE,
    OWNERSHIP_CONFIRMED,
    OWNERSHIP_EXTERNAL,
    ownership_for_discovery,
)
from ownership_ingest import apply_ownership  # noqa: E402
from risk_engine import RiskEvidence, calculate_risk  # noqa: E402


def source(filename):
    return (BACKEND / filename).read_text(encoding="utf-8")


def normalized(text):
    return " ".join(text.split()).upper()


def endpoint_block(name, filename="main.py"):
    text = source(filename)
    start = text.index(f"def {name}(")
    end = text.find("\n@app.", start)
    return text[start:end if end != -1 else None]


def risk_evidence(ownership_status, is_known=False):
    return RiskEvidence(
        scan_id=20,
        domain_id=1,
        domain="dev.example.test",
        first_seen_scan=20,
        is_known=is_known,
        has_ip=True,
        http_observation_status="RESPONDED",
        port_count=4,
        sensitive_port_count=1,
        provider="AWS",
        volatility_flips=2,
        finding_count=1,
        high_finding_count=1,
        ownership_status=ownership_status,
    )


class OwnershipClassificationTests(unittest.TestCase):
    def test_known_inventory_and_confirmed_shadow_remain_organizational(self):
        self.assertEqual(
            ownership_for_discovery(
                "known.example.test", ["brand_tld"], "unrelated.test", is_known=True
            ),
            OWNERSHIP_CONFIRMED,
        )
        self.assertEqual(
            ownership_for_discovery(
                "dev.example.test", ["subfinder"], "example.test", is_known=False
            ),
            OWNERSHIP_CONFIRMED,
        )

    def test_speculative_alternate_tld_and_pattern_are_candidates(self):
        for source_name, domain in (
            ("brand_tld", "example.net"),
            ("brand_pattern", "example-login.com"),
            ("brand_ct", "example-services.org"),
        ):
            with self.subTest(source=source_name):
                self.assertEqual(
                    ownership_for_discovery(
                        domain, [source_name], "example.com", is_known=False
                    ),
                    OWNERSHIP_CANDIDATE,
                )

    def test_passive_subdomain_of_confirmed_root_is_not_candidate(self):
        self.assertEqual(
            ownership_for_discovery(
                "dev.example.com", ["brand_pattern"], "example.com"
            ),
            OWNERSHIP_CONFIRMED,
        )

    def test_approved_namespace_is_the_only_prospective_confirmation(self):
        cases = (
            ("abc.com", [], "abc.com", False, OWNERSHIP_CONFIRMED),
            ("dev.abc.com", ["subfinder"], "abc.com", False, OWNERSHIP_CONFIRMED),
            ("abc.org", ["subfinder"], "abc.com", False, OWNERSHIP_CANDIDATE),
            (
                "abc.org",
                ["brand_tld", "subfinder"],
                "abc.com",
                False,
                OWNERSHIP_CANDIDATE,
            ),
            ("abc.net", ["certspotter"], "abc.com", False, OWNERSHIP_CANDIDATE),
            ("abc.net", ["certspotter"], "abc.com", True, OWNERSHIP_CONFIRMED),
            ("outside.example", [], "abc.com", False, OWNERSHIP_CANDIDATE),
            (
                "outside.example",
                ["unrecognized_source"],
                "abc.com",
                False,
                OWNERSHIP_CANDIDATE,
            ),
        )
        for domain, sources, seeds, is_known, expected in cases:
            with self.subTest(domain=domain, sources=sources, is_known=is_known):
                self.assertEqual(
                    ownership_for_discovery(domain, sources, seeds, is_known),
                    expected,
                )

    def test_san_namespace_classification_does_not_inherit_parent_ownership(self):
        self.assertEqual(
            ownership_for_discovery("api.abc.com", ["san"], "abc.com"),
            OWNERSHIP_CONFIRMED,
        )
        self.assertEqual(
            ownership_for_discovery("vendor.example", ["san"], "abc.com"),
            OWNERSHIP_CANDIDATE,
        )


class RiskAndAuthorizationSeparationTests(unittest.TestCase):
    def test_candidate_and_external_have_no_organizational_risk(self):
        for status in (OWNERSHIP_CANDIDATE, OWNERSHIP_EXTERNAL):
            with self.subTest(status=status):
                result = calculate_risk(risk_evidence(status))
                self.assertEqual((result.score, result.priority, result.reasons), (0, "Low", ()))

    def test_confirmed_known_and_shadow_keep_existing_risk_semantics(self):
        known = calculate_risk(risk_evidence(OWNERSHIP_CONFIRMED, is_known=True))
        shadow = calculate_risk(risk_evidence(OWNERSHIP_CONFIRMED, is_known=False))
        self.assertNotIn("shadow_asset", known.reasons)
        self.assertIn("shadow_asset", shadow.reasons)
        self.assertEqual(shadow.score - known.score, 2)

    def test_ownership_and_t2_authorization_are_independent(self):
        self.assertEqual(
            explicit_t2_authorization_sql("d"),
            "d.scannable IS TRUE AND d.validation_source = 'manual'",
        )
        policy = source("authorization_policy.py")
        self.assertNotIn("ownership_status", policy)
        self.assertNotIn("scannable", source("ownership.py"))
        self.assertNotIn("validation_source", source("ownership.py"))


class PersistenceContractTests(unittest.TestCase):
    class OwnershipCursor:
        def __init__(self, known=False, updated=True):
            self.results = iter([(known,), ("asset.example",) if updated else None])
            self.executions = []

        def execute(self, sql, params=None):
            self.executions.append((sql, params))

        def fetchone(self):
            return next(self.results)

    def test_manual_ownership_classification_is_narrow_and_durable(self):
        cursor = self.OwnershipCursor()
        self.assertTrue(apply_ownership(cursor, "Asset.Example", "external"))
        update_sql, update_params = cursor.executions[1]
        self.assertIn("SET ownership_status = %s", update_sql)
        self.assertEqual(update_params, (OWNERSHIP_EXTERNAL, "asset.example"))

    def test_known_inventory_cannot_be_marked_candidate_or_external(self):
        for status in (OWNERSHIP_CANDIDATE, OWNERSHIP_EXTERNAL):
            with self.subTest(status=status):
                with self.assertRaises(ValueError):
                    apply_ownership(self.OwnershipCursor(known=True), "known.example", status)

    def test_migration_is_conservative_and_constrained(self):
        migration = normalized(source("migrations/003_add_ownership_status.sql"))
        self.assertIn(
            "ADD COLUMN IF NOT EXISTS OWNERSHIP_STATUS TEXT NOT NULL DEFAULT 'CONFIRMED'",
            migration,
        )
        for status in (OWNERSHIP_CONFIRMED, OWNERSHIP_CANDIDATE, OWNERSHIP_EXTERNAL):
            self.assertIn(status, migration)
        self.assertNotIn("UPDATE DOMAINS", migration)
        self.assertNotIn("IS_KNOWN = FALSE", migration)

    def test_schema_snapshots_match_migration(self):
        for filename in (
            "asm_schema.sql",
            "asm_schema_post_guardrails.sql",
            "asm_schema_post_guardrails-schema-only.sql",
        ):
            with self.subTest(filename=filename):
                text = normalized(source(filename))
                self.assertIn(
                    "OWNERSHIP_STATUS TEXT DEFAULT 'CONFIRMED'::TEXT NOT NULL",
                    text,
                )
                self.assertIn("DOMAINS_OWNERSHIP_STATUS_CHECK", text)

    def test_ingest_retains_provenance_and_preserves_explicit_status(self):
        text = normalized(source("ingest.py"))
        self.assertIn("OWNERSHIP_FOR_DISCOVERY", text)
        self.assertIn("INSERT INTO DOMAIN_SOURCES", text)
        self.assertIn("WHEN DOMAINS.OWNERSHIP_STATUS = 'EXTERNAL' THEN 'EXTERNAL'", text)
        self.assertIn("WHEN DOMAINS.OWNERSHIP_STATUS = 'CONFIRMED' THEN 'CONFIRMED'", text)

    def test_known_inventory_confirms_ownership(self):
        loader = normalized(source("load_known_domains.py"))
        self.assertIn("SET IS_KNOWN = TRUE", loader)
        self.assertIn("OWNERSHIP_STATUS = 'CONFIRMED'", loader)

    def test_san_keeps_known_inventory_semantics_without_downgrading(self):
        san = normalized(source("san_worker.py"))
        self.assertIn("'CONFIRMED'", san)
        self.assertIn("ELSE 'CANDIDATE'", san)
        self.assertIn("SELECT 1 FROM SEED_DOMAINS ROOT", san)
        self.assertNotIn("PARENT.OWNERSHIP_STATUS = 'CONFIRMED'", san)
        self.assertIn("SELECT 1 FROM KNOWN_DOMAINS", san)
        self.assertIn("WHEN DOMAINS.OWNERSHIP_STATUS = 'EXTERNAL' THEN 'EXTERNAL'", san)
        self.assertIn("WHEN DOMAINS.OWNERSHIP_STATUS = 'CONFIRMED' THEN 'CONFIRMED'", san)
        self.assertIn("ELSE DOMAINS.OWNERSHIP_STATUS", san)

    def test_external_and_candidate_rows_are_retained_not_deleted(self):
        production = "\n".join(
            source(filename)
            for filename in ("ingest.py", "ownership_ingest.py", "discovery_validator.py")
        ).upper()
        self.assertNotIn("DELETE FROM DOMAINS", production)


class SurfaceSemanticsTests(unittest.TestCase):
    def test_known_shadow_surfaces_require_confirmed_ownership(self):
        for name in ("summary", "assets", "shadow_by_provider"):
            with self.subTest(endpoint=name):
                block = normalized(endpoint_block(name))
                self.assertIn("OWNERSHIP_STATUS = 'CONFIRMED'", block)
        mcp = normalized(source("mcp_server.py"))
        self.assertIn("D.OWNERSHIP_STATUS = 'CONFIRMED'", mcp)

    def test_brand_validation_metrics_use_candidate_not_scannable(self):
        for name in ("unvalidated_brand_footprint", "unvalidated_breakdown"):
            block = normalized(endpoint_block(name))
            self.assertIn("OWNERSHIP_STATUS = 'CANDIDATE'", block)
            self.assertNotIn("SCANNABLE = FALSE", block)
        validator = normalized(source("discovery_validator.py"))
        self.assertIn("WHERE D.OWNERSHIP_STATUS = 'CANDIDATE'", validator)

    def test_export_distinguishes_all_ownership_populations(self):
        block = endpoint_block("export_enriched_csv")
        self.assertIn('row["ownership_status"] == "CANDIDATE"', block)
        self.assertIn('row["ownership_status"] == "EXTERNAL"', block)
        self.assertIn('"known" if row["is_known"] else "shadow"', block)

    def test_risk_adapter_and_worker_exclude_nonconfirmed_rows(self):
        engine = normalized(source("risk_engine.py"))
        worker = normalized(source("risk_worker.py"))
        self.assertIn("D.OWNERSHIP_STATUS = 'CONFIRMED'", engine)
        self.assertIn("D.OWNERSHIP_STATUS <> 'CONFIRMED'", worker)
        self.assertIn("DELETE FROM DOMAIN_RISK", worker)


if __name__ == "__main__":
    unittest.main()
