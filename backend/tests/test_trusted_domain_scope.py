import pathlib
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from authorization_policy import (  # noqa: E402
    ScopeApproval,
    active_scan_authorization_sql,
    is_authorized,
)
from eligibility_worker import (  # noqa: E402
    automatic_eligibility_sql,
    automatic_ineligibility_sql,
)
from http_probe import http_probe  # noqa: E402
from ownership import (  # noqa: E402
    OWNERSHIP_CANDIDATE,
    OWNERSHIP_CONFIRMED,
    TrustedDomainBoundary,
    is_within_trusted_boundary,
    normalize_hostname,
    ownership_for_discovery,
    trusted_boundary_sql,
)


NOW = datetime(2026, 11, 2, tzinfo=timezone.utc)
TRUSTED = {"example.com", "example.org", "example.co.in"}


def operation_scope(level="TECHNOLOGY_HTTP", **overrides):
    values = {
        "scope_domain": "example.com",
        "include_subdomains": True,
        "testing_level": level,
        "approved_by": "offline-test",
        "approved_at": NOW,
    }
    values.update(overrides)
    return ScopeApproval(**values)


class TrustedHostnameTests(unittest.TestCase):
    def test_exact_seed_and_seed_descendants(self):
        for domain in (
            "example.com", "api.example.com", "a.b.example.com",
            "example.org", "dev.example.org", "example.co.in",
            "api.example.co.in",
        ):
            with self.subTest(domain=domain):
                self.assertTrue(is_within_trusted_boundary(domain, TRUSTED))
                self.assertEqual(
                    ownership_for_discovery(
                        domain, ("cert-sans",), "untrusted-file-seed.test",
                        trusted_domains=TRUSTED,
                    ),
                    OWNERSHIP_CONFIRMED,
                )

    def test_known_hosts_match_exactly_without_becoming_parent_namespaces(self):
        boundary = TrustedDomainBoundary(
            seed_domains=frozenset({"example.com"}),
            known_domains=frozenset({"www.example.com", "vpn.othercompany.net"}),
        )
        for domain in ("example.com", "api.example.com", "a.b.example.com",
                       "www.example.com", "vpn.othercompany.net"):
            with self.subTest(domain=domain):
                self.assertTrue(is_within_trusted_boundary(domain, boundary))
                self.assertEqual(
                    ownership_for_discovery(
                        domain, ("ct",), "unused.test", trusted_domains=boundary
                    ),
                    OWNERSHIP_CONFIRMED,
                )
        for domain in (
            "random.vpn.othercompany.net", "example.net", "example.com.evil.net",
            "notexample.com",
        ):
            with self.subTest(domain=domain):
                self.assertFalse(is_within_trusted_boundary(domain, boundary))
                self.assertEqual(
                    ownership_for_discovery(
                        domain, ("san",), "example.com", trusted_domains=boundary
                    ),
                    OWNERSHIP_CANDIDATE,
                )

    def test_case_trailing_dot_and_label_boundaries(self):
        self.assertTrue(is_within_trusted_boundary("API.Example.COM.", TRUSTED))
        for domain in (
            "example.net", "login-example.com", "notexample.com",
            "example.com.evil.net", "evil-example.org",
        ):
            with self.subTest(domain=domain):
                self.assertFalse(is_within_trusted_boundary(domain, TRUSTED))

    def test_malformed_hostnames_fail_closed(self):
        for value in (
            "", "example.com..", "bad host.example.com", "https://example.com",
            "*.example.com", "example..com", "-bad.example.com",
            "bad_.example.com", "a" * 64 + ".example.com",
        ):
            with self.subTest(value=value):
                self.assertIsNone(normalize_hostname(value))
                self.assertFalse(is_within_trusted_boundary(value, TRUSTED))
                self.assertEqual(
                    ownership_for_discovery(
                        value, (), "example.com", trusted_domains=TRUSTED
                    ),
                    OWNERSHIP_CANDIDATE,
                )

    def test_discovery_source_or_relationship_does_not_transfer_trust(self):
        for source in ("san", "cname", "redirect", "same_ip", "same_provider"):
            with self.subTest(source=source):
                self.assertEqual(
                    ownership_for_discovery(
                        "unrelated-vendor.net", (source,), "example.com",
                        trusted_domains=TRUSTED,
                    ),
                    OWNERSHIP_CANDIDATE,
                )


class EligibilityAndAuthorizationTests(unittest.TestCase):
    def test_eligibility_uses_union_and_current_membership_without_test_grant(self):
        sql = " ".join(automatic_eligibility_sql().split()).upper()
        self.assertIn("UPDATE DOMAINS D", sql)
        self.assertIn("FROM SCAN_RESULTS SR", sql)
        self.assertIn("SR.SCAN_ID = %S", sql)
        self.assertIn("SR.DOMAIN_ID = D.ID", sql)
        self.assertIn("FROM SEED_DOMAINS", sql)
        self.assertIn("FROM KNOWN_DOMAINS", sql)
        self.assertIn("D.VALIDATION_SOURCE IS NULL", sql)
        self.assertIn("D.OWNERSHIP_STATUS <> 'EXTERNAL'", sql)
        self.assertNotIn("ACTIVE_SCAN_SCOPES", sql)

    def test_stale_automatic_scannability_is_cleared_only_for_current_members(self):
        sql = " ".join(automatic_ineligibility_sql().split()).upper()
        self.assertIn("SET SCANNABLE = FALSE", sql)
        self.assertIn("SR.SCAN_ID = %S", sql)
        self.assertIn("NOT (", sql)
        self.assertIn("FROM SEED_DOMAINS", sql)
        self.assertIn("FROM KNOWN_DOMAINS", sql)

    def test_operation_permission_is_required_even_when_scannable_or_manual(self):
        for source in (None, "manual"):
            self.assertFalse(is_authorized(
                ownership_status="CONFIRMED", scannable=True,
                validation_source=source, domain="api.example.com",
                testing_level="TECHNOLOGY_HTTP", scopes=[], now=NOW,
                trusted_domains=TRUSTED,
            ))

    def test_trusted_boundary_and_exact_operation_scope_are_both_required(self):
        common = dict(
            ownership_status="CONFIRMED", scannable=True,
            validation_source=None, domain="api.example.com", now=NOW,
            trusted_domains=TRUSTED,
        )
        with mock.patch.dict(os.environ, {"ASIP_DEFAULT_SCAN_OPERATIONS": "TECHNOLOGY_HTTP"}):
            self.assertTrue(is_authorized(**common, testing_level="TECHNOLOGY_HTTP"))
            self.assertFalse(is_authorized(
                **{**common, "domain": "api.external.net"},
                testing_level="TECHNOLOGY_HTTP",
            ))
            self.assertFalse(is_authorized(**common, testing_level="PORT_SCAN"))

    def test_expiry_revocation_and_operation_exclusion_deny(self):
        common = dict(
            ownership_status="CONFIRMED", scannable=True,
            validation_source="manual", domain="blocked.example.com",
            testing_level="PORT_SCAN", now=NOW, trusted_domains=TRUSTED,
        )
        excluded = operation_scope(
            "PORT_SCAN", excluded_domains=("blocked.example.com",)
        )
        self.assertFalse(is_authorized(**common, scopes=[excluded]))
        expired = operation_scope(
            "PORT_SCAN", approved_at=NOW - timedelta(seconds=10),
            expires_at=NOW - timedelta(seconds=1)
        )
        self.assertFalse(is_authorized(
            **{**common, "domain": "api.example.com"}, scopes=[expired]
        ))
        revoked = operation_scope(
            "PORT_SCAN", status="REVOKED", revoked_by="operator",
            revoked_at=NOW,
        )
        self.assertFalse(is_authorized(
            **{**common, "domain": "api.example.com"}, scopes=[revoked]
        ))

    def test_runtime_sql_contains_trusted_boundary_and_denies_manual_bypass(self):
        with mock.patch.dict(os.environ, {"ASIP_DEFAULT_SCAN_OPERATIONS": "PORT_SCAN"}):
            sql = active_scan_authorization_sql("d", "PORT_SCAN")
        self.assertIn("FROM seed_domains", sql)
        self.assertIn("FROM known_domains", sql)
        self.assertIn("AND TRUE", sql)
        self.assertNotIn("scope_allow", sql)
        self.assertIn("scope_block.excluded_domains", sql)
        self.assertIn("scope_block.status = 'REVOKED'", sql)
        self.assertNotIn("d.validation_source = 'manual' OR", sql)

    def test_scannable_without_operation_permission_never_starts_http_probe(self):
        with mock.patch("http_probe._resolve_allowed_addresses") as resolve:
            result = http_probe(
                "api.example.com", before_request=mock.Mock(return_value=False)
            )
        resolve.assert_not_called()
        self.assertEqual(result["http_observation_status"], "UNKNOWN")

    def test_recon_uses_only_seed_file_with_large_known_inventory(self):
        import os
        import tempfile
        import recon

        class InventoryCursor:
            def __init__(self):
                self.statements = []

            def execute(self, statement, *_args):
                self.statements.append(statement)

            def fetchall(self):
                return [(f"host-{index}.inventory.test",) for index in range(10_000)]

        class InventoryConnection:
            def __init__(self, cursor):
                self.test_cursor = cursor

            def cursor(self):
                return self.test_cursor

            def commit(self):
                pass

            def close(self):
                pass

            def rollback(self):
                pass

        cursor = InventoryCursor()
        connection = InventoryConnection(cursor)
        roots_started = []
        recon.domain_registry.clear()
        with tempfile.TemporaryDirectory() as temp_dir:
            seed_path = os.path.join(temp_dir, "seeds.txt")
            os.makedirs(os.path.join(temp_dir, "data"))
            with open(seed_path, "w", encoding="utf-8") as seed_file:
                seed_file.write("Example.com\nexample.COM\nsecond.example.org\n")
            previous_dir = os.getcwd()
            try:
                os.chdir(temp_dir)
                with mock.patch.object(recon, "get_conn", return_value=connection), \
                     mock.patch.object(recon, "require_running_scan"), \
                     mock.patch.object(recon, "publish_recon_artifact"), \
                     mock.patch.object(recon, "load_known", return_value=set()), \
                     mock.patch.object(
                         recon, "run_subdomain_enum",
                         side_effect=lambda root, _deep: roots_started.append(root),
                     ), \
                     mock.patch("builtins.print"):
                    recon.main(seed_path, deep=False, expand=False, scan_id=987)
            finally:
                os.chdir(previous_dir)

        self.assertEqual(roots_started, ["example.com", "second.example.org"])
        self.assertEqual(cursor.statements, [])
        self.assertEqual(len(cursor.fetchall()), 10_000)
        self.assertIn("trusted_domains=trusted_domains", (BACKEND / "ingest.py").read_text())
        self.assertIn("trusted_domains=trusted_domains", (BACKEND / "san_worker.py").read_text())

    def test_trusted_sql_checks_valid_hosts_and_label_boundaries(self):
        sql = trusted_boundary_sql("d.domain")
        self.assertIn("FROM seed_domains", sql)
        self.assertIn("FROM known_domains known_host", sql)
        self.assertIn("RIGHT(", sql)
        self.assertIn("LENGTH(", sql)
        self.assertIn("TRIM(TRAILING '.'", sql)
        self.assertIn("AND TRIM(TRAILING '.' FROM LOWER(BTRIM(d.domain))) = TRIM(TRAILING '.' FROM LOWER(BTRIM(known_host.domain)))", " ".join(sql.split()))


if __name__ == "__main__":
    unittest.main()
