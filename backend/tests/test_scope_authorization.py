import pathlib
import sys
import unittest
from datetime import datetime, timedelta, timezone


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from authorization_policy import (  # noqa: E402
    ScopeApproval,
    ScopePolicyError,
    active_scan_authorization_sql,
    is_authorized,
    scope_authorizes,
    scope_covers_domain,
)
from scope_admin import ScopeAdministrationError, create_scope  # noqa: E402


NOW = datetime(2026, 11, 2, tzinfo=timezone.utc)


def scope(**overrides):
    values = {
        "scope_domain": "example.com",
        "include_subdomains": True,
        "testing_level": "TECHNOLOGY_HTTP",
        "approved_by": "analyst",
        "approved_at": NOW,
    }
    values.update(overrides)
    return ScopeApproval(**values)


class ScopeMatchingTests(unittest.TestCase):
    def test_exact_and_subdomain_matching_is_boundary_safe(self):
        approved = scope()
        self.assertTrue(scope_covers_domain(approved, "EXAMPLE.COM."))
        self.assertTrue(scope_covers_domain(approved, "app.example.com"))
        for domain in ("evil-example.com", "example.com.evil.net", "otherexample.com"):
            with self.subTest(domain=domain):
                self.assertFalse(scope_covers_domain(approved, domain))

    def test_subdomain_inheritance_can_be_disabled(self):
        approved = scope(include_subdomains=False)
        self.assertTrue(scope_covers_domain(approved, "example.com"))
        self.assertFalse(scope_covers_domain(approved, "app.example.com"))

    def test_malformed_scope_and_asset_names_fail_closed(self):
        for value in ("", "*.example.com", "example..com", "https://example.com"):
            with self.subTest(value=value):
                with self.assertRaises(ScopePolicyError):
                    scope(scope_domain=value)
        with self.assertRaises(ScopePolicyError):
            scope_covers_domain(scope(), "bad host.example.com")

    def test_explicit_exclusion_overrides_inclusion(self):
        approved = scope(excluded_domains=("app.example.com",))
        self.assertFalse(scope_covers_domain(approved, "app.example.com"))
        self.assertTrue(scope_covers_domain(approved, "api.example.com"))

    def test_expiry_and_revocation_are_not_active(self):
        expired = scope(expires_at=NOW + timedelta(seconds=1))
        self.assertTrue(scope_authorizes([expired], "app.example.com", "TECHNOLOGY_HTTP", NOW))
        self.assertFalse(scope_authorizes([expired], "app.example.com", "TECHNOLOGY_HTTP", NOW + timedelta(seconds=1)))
        revoked = scope(status="REVOKED", revoked_by="admin", revoked_at=NOW)
        self.assertFalse(scope_authorizes([revoked], "app.example.com", "TECHNOLOGY_HTTP", NOW))

    def test_overlapping_scopes_and_exclusions_fail_closed(self):
        broad = scope()
        blocked = scope(scope_domain="app.example.com", include_subdomains=False,
                        excluded_domains=("app.example.com",))
        self.assertFalse(scope_authorizes([broad, blocked], "app.example.com", "TECHNOLOGY_HTTP", NOW))


class AuthorizationDecisionTests(unittest.TestCase):
    def test_scope_requires_confirmed_and_scannable(self):
        approved = scope()
        for ownership, scannable in (("CANDIDATE", True), ("EXTERNAL", True), ("CONFIRMED", False)):
            with self.subTest(ownership=ownership, scannable=scannable):
                self.assertFalse(is_authorized(
                    ownership_status=ownership, scannable=scannable,
                    validation_source=None, domain="app.example.com",
                    testing_level="TECHNOLOGY_HTTP", scopes=[approved], now=NOW,
                ))

    def test_manual_scannability_does_not_grant_test_permission(self):
        self.assertFalse(is_authorized(
            ownership_status="CONFIRMED", scannable=True,
            validation_source="manual", domain="legacy.example.com",
            testing_level="PORT_SCAN", now=NOW,
        ))

    def test_legacy_scannable_without_manual_or_scope_is_denied(self):
        self.assertFalse(is_authorized(
            ownership_status="CONFIRMED", scannable=True,
            validation_source=None, domain="legacy.example.com",
            testing_level="PORT_SCAN", now=NOW,
        ))

    def test_scope_testing_levels_are_not_interchangeable(self):
        approved = scope(testing_level="TECHNOLOGY_HTTP")
        self.assertTrue(scope_authorizes([approved], "app.example.com", "TECHNOLOGY_HTTP", NOW))
        self.assertFalse(scope_authorizes([approved], "app.example.com", "PORT_SCAN", NOW))

    def test_zero_scopes_never_grant_direct_target_permission(self):
        cases = (("CONFIRMED", True, "manual", False), ("CONFIRMED", True, None, False),
                 ("CANDIDATE", True, "manual", False), ("CONFIRMED", False, "manual", False))
        for ownership, scannable, source, expected in cases:
            with self.subTest(ownership=ownership, scannable=scannable, source=source):
                self.assertEqual(is_authorized(
                    ownership_status=ownership, scannable=scannable,
                    validation_source=source, domain="app.example.com",
                    testing_level="TECHNOLOGY_HTTP", scopes=[], now=NOW,
                ), expected)

    def test_worker_sql_contains_scope_and_direct_paths(self):
        sql = active_scan_authorization_sql("d", "PORT_SCAN")
        self.assertNotIn("d.validation_source = 'manual'", sql)
        self.assertIn("FROM active_scan_scopes scope_allow", sql)
        self.assertIn("scope_allow.testing_level = 'PORT_SCAN'", sql)
        self.assertIn("FROM active_scan_scopes scope_block", sql)
        self.assertIn("LOWER(TRIM(TRAILING '.' FROM d.domain))", sql)

    def test_http_tls_observation_requires_scope_and_does_not_expand_manual_path(self):
        sql = active_scan_authorization_sql("d", "HTTP_TLS_OBSERVATION")
        self.assertNotIn("d.validation_source = 'manual'", sql)
        self.assertIn("scope_allow.testing_level = 'HTTP_TLS_OBSERVATION'", sql)
        self.assertFalse(is_authorized(
            ownership_status="CONFIRMED", scannable=True,
            validation_source="manual", domain="app.example.com",
            testing_level="HTTP_TLS_OBSERVATION", scopes=[], now=NOW,
        ))


class ScopeAdministrationTests(unittest.TestCase):
    def test_scope_creation_requires_a_trusted_operator_callback(self):
        with self.assertRaises(ScopeAdministrationError):
            create_scope(
                object(), scope_domain="example.com", include_subdomains=True,
                testing_level="TECHNOLOGY_HTTP", approved_by="analyst",
                operator_authorizer=None,
            )


if __name__ == "__main__":
    unittest.main()
