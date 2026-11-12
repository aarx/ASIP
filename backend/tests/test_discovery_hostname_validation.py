import contextlib
import importlib.util
import io
import pathlib
import sys
import unittest
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from ownership import normalize_hostname  # noqa: E402
from dns_security import normalize_dns_name  # noqa: E402
from backend.tests.test_remediation_package_2d1e2 import (  # noqa: E402
    FakeResponse,
    load_recon,
)


class CanonicalHostnameTests(unittest.TestCase):
    def test_ascii_hostnames_case_and_existing_alabels_are_canonical(self):
        self.assertEqual(
            normalize_hostname("API.Example.COM.", require_fqdn=True),
            "api.example.com",
        )
        self.assertEqual(
            normalize_hostname("xn--bcher-kva.example", require_fqdn=True),
            "xn--bcher-kva.example",
        )

    def test_unicode_idn_is_stored_as_canonical_alabel(self):
        self.assertEqual(
            normalize_hostname("BÜCHER.Example", require_fqdn=True),
            "xn--bcher-kva.example",
        )

    def test_wildcards_are_only_allowed_for_explicit_certificate_paths(self):
        self.assertIsNone(
            normalize_hostname("*.bücher.example", require_fqdn=True)
        )
        self.assertEqual(
            normalize_hostname(
                "*.bücher.example", allow_wildcard=True, require_fqdn=True
            ),
            "xn--bcher-kva.example",
        )
        self.assertIsNone(
            normalize_hostname(
                "*.*.example.com", allow_wildcard=True, require_fqdn=True
            )
        )

    def test_dns_security_owner_names_share_idna_canonicalization(self):
        self.assertEqual(
            normalize_dns_name("_dmarc.BÜCHER.example", allow_dmarc=True),
            "_dmarc.xn--bcher-kva.example",
        )
        with self.assertRaises(ValueError):
            normalize_dns_name("_dmarc.bad host.example", allow_dmarc=True)

    def test_malformed_values_and_whitespace_are_rejected(self):
        for value in (
            "bad\\305\\233.example",
            "Acme Example Holdings, Inc. LLC",
            "bad host.example.com",
            " host.example.com",
            "host.example.com ",
            "bad_.example.com",
            "bad..example.com",
            "https://example.com/path",
            "example.com:443",
            "a" * 64 + ".example.com",
            "example.com..",
            "single-label",
        ):
            with self.subTest(value=value):
                self.assertIsNone(
                    normalize_hostname(value, require_fqdn=True)
                )

    def test_equivalent_unicode_and_alabel_inputs_have_one_identity(self):
        recon = load_recon()
        recon.domain_registry.clear()
        recon.rejected_discovery.clear()
        self.assertTrue(recon.add_domain("BÜCHER.example", "subfinder", "example"))
        self.assertTrue(recon.add_domain("xn--bcher-kva.example", "assetfinder", "example"))
        self.assertEqual(list(recon.domain_registry), ["xn--bcher-kva.example"])
        self.assertEqual(
            recon.domain_registry["xn--bcher-kva.example"]["sources"],
            {"subfinder", "assetfinder"},
        )


class DiscoveryIngressTests(unittest.TestCase):
    def setUp(self):
        self.recon = load_recon(api_key="test-key")
        self.recon.domain_registry.clear()
        self.recon.source_stats.clear()
        self.recon.source_outcomes.clear()
        self.recon.rejected_discovery.clear()

    def test_ct_results_accept_valid_idn_and_aggregate_rejections(self):
        payload = [{
            "name_value": "*.bücher.example\nAcme Example Holdings, Inc. LLC\n"
        }]
        with mock.patch.object(
            self.recon.requests, "get", return_value=FakeResponse(payload=payload)
        ):
            self.recon.crtsh_expand("example.com")

        self.assertIn("xn--bcher-kva.example", self.recon.domain_registry)
        self.assertEqual(
            self.recon.rejected_discovery[("brand_ct", "invalid_hostname")]["count"],
            1,
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.recon.print_source_summary()
        self.assertIn("distinct_seed_provenance", output.getvalue())
        self.assertNotIn("Acme Example Holdings", output.getvalue())

    def test_certspotter_names_use_same_wildcard_idn_and_rejection_policy(self):
        payload = [{
            "dns_names": [
                "*.bücher.example",
                "Acme Example Holdings LLC",
                "bad\\305\\233.example",
            ]
        }]
        with mock.patch.object(
            self.recon.requests, "get", return_value=FakeResponse(payload=payload)
        ):
            self.recon.certspotter_expand("example.com")

        self.assertIn("xn--bcher-kva.example", self.recon.domain_registry)
        self.assertEqual(
            self.recon.rejected_discovery[("certspotter", "invalid_hostname")]["count"],
            2,
        )

    def test_cli_discovery_rejects_bad_values_and_deduplicates_idns(self):
        values = [
            "api.example.com",
            "BÜCHER.example",
            "xn--bcher-kva.example",
            "bad host.example.com",
            "Acme Example LLC",
        ]
        with mock.patch.object(
            self.recon, "run_tool", return_value=(True, values, None)
        ):
            self.recon.run_subdomain_enum("example.com", deep=False)

        self.assertEqual(
            set(self.recon.domain_registry),
            {"api.example.com", "xn--bcher-kva.example"},
        )
        self.assertEqual(
            self.recon.rejected_discovery[("subfinder", "invalid_hostname")]["count"],
            2,
        )

    def test_invalid_values_never_reach_legacy_gethostbyname(self):
        with mock.patch.object(self.recon.socket, "gethostbyname") as resolver:
            self.assertEqual(self.recon.resolve_ip("Acme Example LLC"), "")
            resolver.assert_not_called()

    def test_idn_resolution_uses_canonical_alabel(self):
        with mock.patch.object(
            self.recon.socket, "gethostbyname", return_value="192.0.2.7"
        ) as resolver:
            self.assertEqual(self.recon.resolve_ip("BÜCHER.example"), "192.0.2.7")
            resolver.assert_called_once_with("xn--bcher-kva.example")

    def test_passive_dns_worker_does_not_instantiate_resolver_for_invalid_name(self):
        from backend.tests.test_dns_worker_policy import load_worker

        worker = load_worker()
        with mock.patch.object(worker.dns.resolver, "Resolver") as resolver_factory:
            self.assertEqual(worker.resolve_dns("bad host.example"), [])
            resolver_factory.assert_not_called()

    def test_http_resolution_rejects_invalid_hostname_before_getaddrinfo(self):
        import http_probe

        with mock.patch.object(http_probe.socket, "getaddrinfo") as resolver:
            self.assertEqual(
                http_probe._resolve_allowed_addresses("Acme Example LLC", 443), []
            )
            resolver.assert_not_called()

    def test_san_wildcard_uses_shared_idna_normalization(self):
        from backend.tests.test_san_concurrency import load_worker

        worker = load_worker()
        self.assertEqual(
            worker._normalized_san_names(
                "parent.example",
                ["*.BÜCHER.example", "*.*.example.com", "bad host.example"],
            ),
            {"xn--bcher-kva.example"},
        )

    def test_takeover_dns_refresh_rejects_invalid_hostname_before_query(self):
        spec = importlib.util.spec_from_file_location(
            f"takeover_validation_{id(self)}", BACKEND / "takeover_worker.py"
        )
        worker = importlib.util.module_from_spec(spec)
        old_argv = sys.argv[:]
        try:
            sys.argv = ["takeover_worker.py", "19"]
            spec.loader.exec_module(worker)
        finally:
            sys.argv = old_argv

        with mock.patch.object(worker.dns.resolver, "resolve") as resolver:
            self.assertIsNone(worker.get_live_cname("Acme Example LLC"))
            resolver.assert_not_called()

    def test_ingestion_has_a_final_canonical_validation_before_domain_insert(self):
        source = (BACKEND / "ingest.py").read_text(encoding="utf-8")
        validation = source.index(
            "domain = normalize_hostname(raw_domain, require_fqdn=True)"
        )
        rejected_continue = source.index("if domain is None:", validation)
        domain_insert = source.index("INSERT INTO domains(", rejected_continue)
        self.assertLess(validation, rejected_continue)
        self.assertLess(rejected_continue, domain_insert)


if __name__ == "__main__":
    unittest.main()
