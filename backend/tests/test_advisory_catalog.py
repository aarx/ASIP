import pathlib
import socket
import sys
import unittest
from datetime import date
from dataclasses import FrozenInstanceError
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from advisory_catalog import (  # noqa: E402
    AdvisoryRecord,
    VersionRange,
    evaluate_advisory_catalog,
    normalize_product_label,
)


ASSESSED = date(2026, 10, 28)


def advisory(*ranges, status="verified_vendor_advisory_range", product="PHP"):
    return AdvisoryRecord(
        cve_id="CVE-2099-0001",
        product=product,
        publication_date="2099-01-01",
        source_url="https://example.invalid/advisory",
        severity="unknown",
        verification_status=status,
        affected_ranges=tuple(ranges),
        applicability_conditions=("test-only prerequisite",),
        advisory_id="CVE-2099-0001",
        vendor="Example Vendor",
        canonical_technology="php",
        dataset_revision="test-revision",
    )


class AdvisoryCatalogTests(unittest.TestCase):
    def test_exact_product_normalization(self):
        expected = {
            "php": ("php", "PHP", "PHP"),
            "apache": ("apache_http_server", "Apache Software Foundation", "Apache HTTP Server"),
            "nginx": ("nginx", "NGINX", "Nginx"),
            "microsoft-iis": ("microsoft_iis", "Microsoft", "Microsoft IIS"),
            "tomcat": ("apache_tomcat", "Apache Software Foundation", "Apache Tomcat"),
        }
        for label, identity in expected.items():
            with self.subTest(label=label):
                self.assertEqual(
                    (normalize_product_label(label).canonical_technology,
                     normalize_product_label(label).vendor,
                     normalize_product_label(label).product),
                    identity,
                )
        self.assertEqual(normalize_product_label(" PHP ").canonical_technology, "php")

    def test_unknown_and_ambiguous_labels_remain_unknown(self):
        for label in (None, "", "wordpress", "apache-coyote", "asp", "asp.net"):
            with self.subTest(label=label):
                self.assertIsNone(normalize_product_label(label))

    def test_records_are_immutable(self):
        with self.assertRaises(FrozenInstanceError):
            normalize_product_label("php").product = "changed"

    def test_numeric_boundaries_and_lower_upper_inclusivity(self):
        record = advisory(VersionRange(
            branch="8.2",
            lower_bound=(8, 2, 0),
            lower_inclusive=True,
            upper_bound=(8, 2, 10),
            upper_inclusive=False,
            fixed_version="8.2.10",
            range_text="8.2.0 <= version < 8.2.10",
        ))
        self.assertEqual(
            evaluate_advisory_catalog("php", "8.2.0", (record,), "test", ASSESSED)["candidates"][0]["applicability_status"],
            "potentially_affected",
        )
        self.assertEqual(
            evaluate_advisory_catalog("php", "8.2.10", (record,), "test", ASSESSED)["candidates"][0]["applicability_status"],
            "not_affected_by_version",
        )
        self.assertEqual(
            evaluate_advisory_catalog("php", "8.1.99", (record,), "test", ASSESSED)["candidates"][0]["applicability_status"],
            "insufficient_evidence",
        )

    def test_multiple_ranges_and_documented_gap(self):
        record = advisory(
            VersionRange("8.2", (8, 2, 10), False, "8.2.10", "< 8.2.10", lower_bound=(8, 2, 0)),
            VersionRange("8.2", (8, 2, 20), False, "8.2.20", "8.2.15 <= version < 8.2.20", lower_bound=(8, 2, 15)),
        )
        self.assertEqual(
            evaluate_advisory_catalog("php", "8.2.12", (record,), "test", ASSESSED)["candidates"][0]["applicability_status"],
            "not_affected_by_version",
        )
        self.assertEqual(
            evaluate_advisory_catalog("php", "8.2.16", (record,), "test", ASSESSED)["candidates"][0]["applicability_status"],
            "potentially_affected",
        )

    def test_absent_malformed_and_unsupported_versions_are_insufficient(self):
        record = advisory(VersionRange("8.2", (8, 2, 10), False, "8.2.10", "< 8.2.10"))
        for version, code in ((None, "php_version_absent"), ("8.2", "php_version_malformed"), ("8.x.1", "php_version_malformed")):
            with self.subTest(version=version):
                candidate = evaluate_advisory_catalog("php", version, (record,), "test", ASSESSED)["candidates"][0]
                self.assertEqual(candidate["applicability_status"], "insufficient_evidence")
                self.assertEqual(candidate["explanation_code"], code)

    def test_incomplete_advisory_data_cannot_conclude_not_affected(self):
        record = advisory(status="incomplete")
        result = evaluate_advisory_catalog("php", "8.2.12", (record,), "test", ASSESSED)
        self.assertEqual(result["candidates"][0]["applicability_status"], "insufficient_evidence")
        self.assertEqual(result["candidates"][0]["patch_status"], "unknown")

    def test_known_products_without_comparators_are_unsupported(self):
        record = advisory(VersionRange("2.4", (2, 4, 60), False, "2.4.60", "< 2.4.60"), product="Apache HTTP Server")
        record = AdvisoryRecord(**{**record.__dict__, "canonical_technology": "apache_http_server"})
        result = evaluate_advisory_catalog("apache", "2.4.59", (record,), "test", ASSESSED)
        self.assertEqual(result["coverage"], "unsupported")
        self.assertEqual(result["candidates"], [])
        self.assertEqual(result["explanation_code"], "unsupported_product_comparator")

    def test_duplicate_cve_suppression_and_unknown_patch_state(self):
        record = advisory(VersionRange("8.2", (8, 2, 10), False, "8.2.10", "< 8.2.10"))
        result = evaluate_advisory_catalog("php", "8.2.9", (record, record), "test", ASSESSED)
        self.assertEqual(len(result["candidates"]), 1)
        self.assertEqual(result["candidates"][0]["patch_status"], "unknown")

    def test_unknown_product_is_not_evaluated(self):
        result = evaluate_advisory_catalog("unknown-product", "1.2.3", (), "test", ASSESSED)
        self.assertEqual(result["coverage"], "not_applicable")
        self.assertEqual(result["candidates"], [])

    def test_no_network_database_finding_or_risk_dependency(self):
        source = (BACKEND / "advisory_catalog.py").read_text(encoding="utf-8")
        for forbidden in ("requests", "psycopg", "get_conn", "domain_findings", "risk_engine"):
            self.assertNotIn(forbidden, source)
        with mock.patch.object(socket, "socket", side_effect=AssertionError("network access")):
            result = evaluate_advisory_catalog("php", "8.2.9", (), "test", ASSESSED)
        self.assertEqual(result["candidates"], [])


if __name__ == "__main__":
    unittest.main()
