import pathlib
import socket
import sys
import unittest
from datetime import date
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from php_cve_intelligence import (  # noqa: E402
    PHPAdvisory,
    PHPVersionRange,
    PHP_CVE_ADVISORIES,
    PHP_CVE_DATASET_REVISION,
    evaluate_php_cve_applicability,
)


_BASELINE_SOURCES = {
    "CVE-2026-109618": "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
    "CVE-2026-109619": "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp",
}


def _baseline_candidate(cve_id, version, status, range_text, fixed, code, confidence):
    return {
        "cve_id": cve_id,
        "applicability_status": status,
        "reported_version": version,
        "affected_version_range": range_text,
        "fixed_version": fixed,
        "source_url": _BASELINE_SOURCES[cve_id],
        "dataset_revision": "2026-10-28",
        "evidence_confidence": confidence,
        "patch_status": "unknown",
        "explanation_code": code,
    }


def _baseline_result(version, status, range_text, fixed, code, confidence):
    return {
        "assessment_date": "2026-10-28",
        "dataset_revision": "2026-10-28",
        "coverage": "partial",
        "candidates": [
            _baseline_candidate(
                cve_id,
                version,
                status,
                range_text,
                fixed,
                code,
                confidence,
            )
            for cve_id in _BASELINE_SOURCES
        ],
    }


class PHPCVEApplicabilityTests(unittest.TestCase):
    assessed = date(2026, 10, 28)

    def evaluate(self, version, dataset=PHP_CVE_ADVISORIES):
        return evaluate_php_cve_applicability(
            "php", version, dataset, self.assessed
        )

    def test_refactor_matches_captured_pre_refactor_php_baseline(self):
        fixtures = (
            ("8.2.34", "potentially_affected", "< 8.2.35 (PHP 8.2 branch)", "8.2.35", "php_version_within_verified_affected_range", "high_version_range_match"),
            ("8.2.35", "not_affected_by_version", None, "8.2.35", "php_reported_version_at_or_above_verified_fix", "high_version_range_match"),
            ("8.3.35", "potentially_affected", "< 8.3.36 (PHP 8.3 branch)", "8.3.36", "php_version_within_verified_affected_range", "high_version_range_match"),
            ("8.4.26", "potentially_affected", "< 8.4.27 (PHP 8.4 branch)", "8.4.27", "php_version_within_verified_affected_range", "high_version_range_match"),
            ("8.5.11", "potentially_affected", "< 8.5.12 (PHP 8.5 branch)", "8.5.12", "php_version_within_verified_affected_range", "high_version_range_match"),
            ("8.6.0", "insufficient_evidence", None, None, "php_branch_not_covered_by_dataset", "insufficient"),
            (None, "insufficient_evidence", None, None, "php_version_absent", "insufficient"),
        )
        for version, status, range_text, fixed, code, confidence in fixtures:
            with self.subTest(version=version):
                self.assertEqual(
                    self.evaluate(version),
                    _baseline_result(version, status, range_text, fixed, code, confidence),
                )

    def test_verified_affected_range_and_lower_boundary(self):
        for version in ("8.2.0", "8.2.34"):
            with self.subTest(version=version):
                candidate = self.evaluate(version)["candidates"][0]
                self.assertEqual(candidate["applicability_status"], "potentially_affected")
                self.assertEqual(candidate["fixed_version"], "8.2.35")
                self.assertEqual(candidate["patch_status"], "unknown")

    def test_fixed_boundary_and_above_are_not_affected_by_reported_version(self):
        for version in ("8.2.35", "8.3.36", "8.5.12"):
            with self.subTest(version=version):
                candidates = self.evaluate(version)["candidates"]
                self.assertTrue(all(
                    item["applicability_status"] == "not_affected_by_version"
                    for item in candidates
                ))
                self.assertTrue(all(
                    item["patch_status"] == "unknown" for item in candidates
                ))

    def test_different_minor_branches_match_their_own_fixed_versions(self):
        for version, fixed in (
            ("8.3.35", "8.3.36"),
            ("8.4.26", "8.4.27"),
            ("8.5.11", "8.5.12"),
        ):
            with self.subTest(version=version):
                self.assertEqual(
                    self.evaluate(version)["candidates"][0]["fixed_version"],
                    fixed,
                )

    def test_absent_invalid_and_unknown_future_versions_are_insufficient(self):
        for version in (None, "", "8.2", "8.x.1", "8.6.0", "9.0.0"):
            with self.subTest(version=version):
                result = self.evaluate(version)
                self.assertTrue(all(
                    item["applicability_status"] == "insufficient_evidence"
                    for item in result["candidates"]
                ))
                self.assertTrue(all(
                    item["patch_status"] == "unknown"
                    for item in result["candidates"]
                ))

    def test_incomplete_advisory_evidence_does_not_claim_affected(self):
        incomplete = (PHPAdvisory(
            cve_id="CVE-2099-0001",
            product="PHP",
            publication_date="2099-01-01",
            source_url="https://example.invalid/advisory",
            severity="unknown",
            verification_status="incomplete",
            affected_ranges=(),
            applicability_conditions=(),
        ),)
        candidate = self.evaluate("8.2.12", incomplete)["candidates"][0]
        self.assertEqual(candidate["applicability_status"], "insufficient_evidence")
        self.assertEqual(candidate["explanation_code"], "php_branch_not_covered_by_dataset")

    def test_multiple_ranges_and_exceptions_are_evaluated_without_inference(self):
        advisory = PHPAdvisory(
            cve_id="CVE-2099-0002",
            product="PHP",
            publication_date="2099-01-01",
            source_url="https://example.invalid/advisory",
            severity="unknown",
            verification_status="verified_vendor_advisory_range",
            affected_ranges=(
                PHPVersionRange(
                    "8.2", (8, 2, 10), False, "8.2.10",
                    "8.2.0 <= version < 8.2.10",
                    lower_bound=(8, 2, 0),
                ),
                PHPVersionRange(
                    "8.2", (8, 2, 20), False, "8.2.20",
                    "8.2.15 <= version < 8.2.20",
                    lower_bound=(8, 2, 15),
                ),
            ),
            applicability_conditions=("test-only condition",),
        )
        exception = self.evaluate("8.2.12", (advisory,))["candidates"][0]
        self.assertEqual(exception["applicability_status"], "not_affected_by_version")

        match = self.evaluate("8.2.16", (advisory,))["candidates"][0]
        self.assertEqual(match["applicability_status"], "potentially_affected")
        self.assertEqual(match["fixed_version"], "8.2.20")

        fixed = self.evaluate("8.2.20", (advisory,))["candidates"][0]
        self.assertEqual(fixed["applicability_status"], "not_affected_by_version")

    def test_source_conditions_and_backport_uncertainty_are_retained(self):
        stale_state = PHP_CVE_ADVISORIES[1]
        self.assertTrue(stale_state.applicability_conditions)
        self.assertIn("persistent worker", " ".join(stale_state.applicability_conditions))
        for candidate in self.evaluate("8.5.11")["candidates"]:
            self.assertEqual(candidate["patch_status"], "unknown")
            self.assertNotEqual(candidate["applicability_status"], "confirmed_vulnerable")

    def test_candidates_are_not_findings_or_risk_results(self):
        result = self.evaluate("8.2.12")
        self.assertNotIn("finding", result)
        self.assertNotIn("risk", result)
        self.assertTrue(all("severity" not in item for item in result["candidates"]))

    def test_duplicate_dataset_entries_emit_one_candidate_per_cve(self):
        result = self.evaluate("8.2.12", PHP_CVE_ADVISORIES * 2)
        ids = [item["cve_id"] for item in result["candidates"]]
        self.assertEqual(ids, ["CVE-2026-109618", "CVE-2026-109619"])

    def test_non_php_isolated_and_metadata_is_versioned(self):
        result = evaluate_php_cve_applicability(
            "nginx", "1.24.0", PHP_CVE_ADVISORIES, self.assessed
        )
        self.assertEqual(result["coverage"], "not_applicable")
        self.assertEqual(result["candidates"], [])
        self.assertEqual(result["dataset_revision"], PHP_CVE_DATASET_REVISION)

    def test_no_network_access(self):
        with mock.patch.object(
            socket, "socket", side_effect=AssertionError("network access")
        ):
            result = self.evaluate("8.2.12")
        self.assertEqual(len(result["candidates"]), 2)


if __name__ == "__main__":
    unittest.main()
