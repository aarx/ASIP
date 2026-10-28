import pathlib
import socket
import sys
import unittest
from datetime import date
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from php_lifecycle import (  # noqa: E402
    PHP_EOL_SOURCE_URL,
    PHP_POLICY_DATASET_REVISION,
    PHP_SUPPORTED_SOURCE_URL,
    evaluate_php_lifecycle,
)


class PHPLifecycleTests(unittest.TestCase):
    def evaluate(self, version, assessed):
        return evaluate_php_lifecycle("php", version, assessed)

    def test_active_support_branch(self):
        result = self.evaluate("8.4.26", date(2026, 6, 30))
        self.assertEqual(result["status"], "active_support")
        self.assertEqual(result["matched_release_branch"], "8.4")
        self.assertEqual(result["active_support_until"], "2026-12-31")

    def test_security_support_branch(self):
        result = self.evaluate("8.3.35", "2026-01-01")
        self.assertEqual(result["status"], "security_support")
        self.assertEqual(result["security_support_until"], "2027-12-31")

    def test_end_of_life_branch(self):
        result = self.evaluate("8.1.34", date(2026, 1, 1))
        self.assertEqual(result["status"], "end_of_life")
        self.assertEqual(result["end_of_life"], "2025-12-31")
        self.assertIsNone(result["active_support_until"])

    def test_missing_invalid_and_future_versions_are_unknown(self):
        for version, code in (
            (None, "php_version_absent"),
            ("", "php_version_absent"),
            ("PHP/8.4", "php_version_unrecognized"),
            ("8.x", "php_version_unrecognized"),
            ("8.6.0", "php_release_branch_unrecognized"),
            ("9.0.0", "php_release_branch_unrecognized"),
        ):
            with self.subTest(version=version):
                result = self.evaluate(version, date(2026, 10, 28))
                self.assertEqual(result["status"], "unknown")
                self.assertEqual(result["explanation_code"], code)

    def test_support_boundaries_are_explicit(self):
        self.assertEqual(
            self.evaluate("8.4.0", date(2026, 12, 31))["status"],
            "active_support",
        )
        self.assertEqual(
            self.evaluate("8.4.0", date(2027, 1, 1))["status"],
            "security_support",
        )
        self.assertEqual(
            self.evaluate("8.4.0", date(2028, 12, 31))["status"],
            "security_support",
        )
        self.assertEqual(
            self.evaluate("8.4.0", date(2029, 1, 1))["status"],
            "end_of_life",
        )

    def test_non_php_observation_is_unknown_and_not_php_intelligence(self):
        result = evaluate_php_lifecycle("nginx", "1.24.0", date(2026, 10, 28))
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["explanation_code"], "non_php_observation")
        self.assertIsNone(result["source_url"])

    def test_policy_source_and_revision_are_returned(self):
        current = self.evaluate("8.5.0", date(2026, 10, 28))
        old = self.evaluate("7.4.33", date(2026, 10, 28))
        self.assertEqual(current["source_url"], PHP_SUPPORTED_SOURCE_URL)
        self.assertEqual(old["source_url"], PHP_EOL_SOURCE_URL)
        self.assertEqual(current["dataset_revision"], PHP_POLICY_DATASET_REVISION)

    def test_evaluator_performs_no_network_access(self):
        with mock.patch.object(
            socket, "socket", side_effect=AssertionError("network access")
        ):
            result = self.evaluate("8.4.26", date(2026, 10, 28))
        self.assertEqual(result["status"], "active_support")


if __name__ == "__main__":
    unittest.main()
