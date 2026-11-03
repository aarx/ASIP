import os
import pathlib
import sys
import unittest
from datetime import datetime, timezone
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from adhoc_campaigns import validate_explicit_target_selection  # noqa: E402
from authorization_policy import (  # noqa: E402
    ScopeApproval,
    active_scan_authorization_sql,
    configured_scan_operations,
    default_operation_enabled,
    is_authorized,
)
from http_probe import http_probe  # noqa: E402
from ownership import TrustedDomainBoundary  # noqa: E402


NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)
TRUSTED = TrustedDomainBoundary(
    seed_domains=frozenset({"example.com"}),
    known_domains=frozenset({"www.other.net"}),
)


class DefaultScanningPolicyTests(unittest.TestCase):
    def setUp(self):
        self.env = mock.patch.dict(os.environ, {}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_missing_or_invalid_policy_fails_closed(self):
        self.assertEqual(configured_scan_operations(), frozenset())
        os.environ["ASIP_DEFAULT_SCAN_OPERATIONS"] = "HTTP_TLS_OBSERVATION,MADE_UP"
        self.assertEqual(configured_scan_operations(), frozenset())
        self.assertFalse(default_operation_enabled("HTTP_TLS_OBSERVATION"))

    def test_operations_are_explicit_independent_and_reloaded(self):
        os.environ["ASIP_DEFAULT_SCAN_OPERATIONS"] = "technology_http, PORT_SCAN"
        self.assertTrue(default_operation_enabled("TECHNOLOGY_HTTP"))
        self.assertTrue(default_operation_enabled("PORT_SCAN"))
        self.assertFalse(default_operation_enabled("ADHOC_CHECK"))
        first = active_scan_authorization_sql("d", "TECHNOLOGY_HTTP")
        os.environ["ASIP_DEFAULT_SCAN_OPERATIONS"] = "PORT_SCAN"
        second = active_scan_authorization_sql("d", "TECHNOLOGY_HTTP")
        self.assertIn("AND TRUE", first)
        self.assertIn("AND FALSE", second)

    def test_trusted_known_and_shadow_hosts_are_policy_authorized(self):
        os.environ["ASIP_DEFAULT_SCAN_OPERATIONS"] = "TECHNOLOGY_HTTP,ADHOC_CHECK"
        base = dict(
            ownership_status="CONFIRMED", scannable=True,
            validation_source="automatic", testing_level="TECHNOLOGY_HTTP",
            trusted_domains=TRUSTED,
        )
        self.assertTrue(is_authorized(**base, domain="api.example.com"))
        self.assertTrue(is_authorized(**base, domain="www.other.net"))
        self.assertFalse(is_authorized(**base, domain="child.www.other.net"))
        self.assertFalse(is_authorized(**base, domain="lookalike-example.com"))

    def test_ownership_scannability_policy_and_manual_rejection_gate(self):
        os.environ["ASIP_DEFAULT_SCAN_OPERATIONS"] = "PORT_SCAN"
        base = dict(
            domain="api.example.com", testing_level="PORT_SCAN",
            trusted_domains=TRUSTED, validation_source=None, scopes=(), now=NOW,
        )
        self.assertFalse(is_authorized(**base, ownership_status="CANDIDATE", scannable=True))
        self.assertFalse(is_authorized(**base, ownership_status="CONFIRMED", scannable=False))
        self.assertFalse(is_authorized(
            **{**base, "validation_source": "manual",
               "confidence_reasons": ["manually rejected"]},
            ownership_status="CONFIRMED", scannable=True,
        ))
        self.assertFalse(is_authorized(**{**base, "testing_level": "ADHOC_CHECK"},
                                       ownership_status="CONFIRMED", scannable=True))
        self.assertIn("manually rejected", active_scan_authorization_sql("d", "PORT_SCAN"))

    def test_unpermitted_policy_stops_before_resolution_and_http_contact(self):
        with mock.patch("http_probe._resolve_allowed_addresses") as resolve:
            result = http_probe(
                "api.example.com",
                before_request=lambda: default_operation_enabled("HTTP_TLS_OBSERVATION"),
            )
        resolve.assert_not_called()
        self.assertEqual(result["http_observation_status"], "UNKNOWN")

    def test_adhoc_selection_and_runtime_check_remain_scan_bound(self):
        from adhoc_campaigns import runtime_authorization_query

        query, params = runtime_authorization_query(12, 34)
        self.assertEqual(params, (34, 12))
        self.assertIn("JOIN scan_results sr", query)
        self.assertIn("sr.scan_id = %s", query)

    def test_normal_technology_pipeline_does_not_dispatch_adhoc_checks(self):
        tech_source = (BACKEND / "tech_worker.py").read_text()
        orchestration_source = (BACKEND / "orchestration.py").read_text()
        self.assertNotIn("adhoc_runner", tech_source)
        self.assertNotIn("run_campaign", orchestration_source)

    def test_scope_exclusions_and_revocations_remain_operation_denials(self):
        os.environ["ASIP_DEFAULT_SCAN_OPERATIONS"] = "PORT_SCAN"
        excluded = ScopeApproval(
            "example.com", True, "PORT_SCAN", "operator", NOW,
            excluded_domains=("blocked.example.com",),
        )
        revoked = ScopeApproval(
            "old.example.com", True, "PORT_SCAN", "operator", NOW,
            status="REVOKED", revoked_by="operator", revoked_at=NOW,
        )
        base = dict(
            ownership_status="CONFIRMED", scannable=True, validation_source=None,
            testing_level="PORT_SCAN", trusted_domains=TRUSTED, now=NOW,
        )
        self.assertFalse(is_authorized(**base, domain="blocked.example.com", scopes=[excluded]))
        self.assertFalse(is_authorized(**base, domain="x.old.example.com", scopes=[revoked]))
        sql = active_scan_authorization_sql("d", "PORT_SCAN")
        self.assertIn("scope_block.status = 'REVOKED'", sql)
        self.assertIn("ANY(scope_block.excluded_domains)", sql)

    def test_campaign_selection_accepts_automatically_scannable_members(self):
        members = [
            (1, "known.example", "CONFIRMED", True, "automatic"),
            (2, "shadow.example", "CONFIRMED", True, None),
        ]
        selected = validate_explicit_target_selection(
            ["known.example", "shadow.example"], members,
        )
        self.assertEqual([item["domain_id"] for item in selected], [1, 2])
        self.assertTrue(all(item["scannable_snapshot"] for item in selected))


if __name__ == "__main__":
    unittest.main()
