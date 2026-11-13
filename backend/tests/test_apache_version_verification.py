import contextlib
import io
import json
import pathlib
import sys
import unittest
from unittest import mock


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

import apache_version_verification as verification  # noqa: E402
from capd_cli import main as capd_cli_main  # noqa: E402


def target(**overrides):
    value = {
        "domain_id": 11,
        "domain": "web.example.test",
        "asset_class": "KNOWN",
        "scannable": True,
        "inventory_eligible": True,
        "classification": "VERSION_UNKNOWN",
        "evidence": [{
            "source": "domain_technology_observations",
            "technology": "apache",
            "evidence_type": "server_header",
            "observed_url": "https://web.example.test/",
        }],
    }
    value.update(overrides)
    return value


class ApacheVersionVerificationTests(unittest.TestCase):
    def test_dry_run_is_an_inert_bounded_plan(self):
        plan = verification.build_apache_dry_run(target())
        self.assertEqual(plan["method"], "GET")
        self.assertEqual(plan["url"], "https://web.example.test/")
        self.assertFalse(plan["follow_redirects"])
        self.assertEqual(plan["network_requests"], 0)
        self.assertEqual(plan["database_writes"], 0)
        self.assertFalse(plan["live_execution_enabled"])
        with self.assertRaises(verification.ApacheVerificationError):
            verification.build_apache_dry_run(target(), timeout=6)
        with self.assertRaises(verification.ApacheVerificationError):
            verification.build_apache_dry_run(target(), timeout=0)

    def test_target_selection_requires_product_evidence_and_known_shadow_scannable(self):
        for invalid in (
            target(asset_class="CANDIDATE"),
            target(asset_class="EXTERNAL"),
            target(scannable=False),
            target(inventory_eligible=False),
            target(classification="SERVICE_ONLY_CANDIDATE"),
            target(evidence=[]),
        ):
            with self.subTest(target=invalid), self.assertRaises(verification.ApacheVerificationError):
                verification.build_apache_dry_run(invalid)
        shadow = target(asset_class="SHADOW")
        self.assertEqual(verification.build_apache_dry_run(shadow)["network_requests"], 0)

    def test_destination_validation_requires_exact_asset_and_public_addresses(self):
        url = "https://web.example.test/"
        self.assertEqual(
            verification.validate_public_destination(url, "web.example.test", ["8.8.8.8"]),
            url,
        )
        for invalid_url, addresses in (
            ("https://evil.example.test/", ["8.8.8.8"]),
            ("https://user:pass@web.example.test/", ["8.8.8.8"]),
            ("http://127.0.0.1/", ["127.0.0.1"]),
            (url, ["10.0.0.1"]),
            (url, []),
            ("https://web.example.test/path", ["8.8.8.8"]),
        ):
            with self.subTest(url=invalid_url), self.assertRaises(verification.ApacheVerificationError):
                verification.validate_public_destination(invalid_url, "web.example.test", addresses)

    def test_authorization_requires_enabled_adhoc_and_fresh_target_recheck(self):
        callback = mock.Mock(return_value=True)
        with mock.patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(verification.ApacheVerificationError):
                verification.authorize_apache_target(target(), callback)
        callback.assert_not_called()

        with mock.patch.dict("os.environ", {"ASIP_DEFAULT_SCAN_OPERATIONS": "ADHOC_CHECK"}):
            with self.assertRaises(verification.ApacheVerificationError):
                verification.authorize_apache_target(target(), None)
            callback.return_value = False
            with self.assertRaises(verification.ApacheVerificationError):
                verification.authorize_apache_target(target(), callback)
            callback.assert_called_with(target(), testing_level="ADHOC_CHECK")
            callback.return_value = True
            self.assertEqual(
                verification.authorize_apache_target(target(), callback),
                "https://web.example.test/",
            )

    def test_response_adapter_parses_server_header_without_following_redirects(self):
        response = mock.Mock(status_code=200, headers={"sErVeR": "Apache/2.4.58 (Unix)"})
        result = verification.classify_apache_http_response(
            target(), response, request_url="https://web.example.test/",
            resolved_addresses=["8.8.8.8"],
        )
        self.assertEqual(result["outcome"], "VERSION_IDENTIFIED")
        self.assertEqual(result["version"], "2.4.58")
        redirect = mock.Mock(status_code=302, headers={"Location": "https://outside.example/"})
        redirected = verification.classify_apache_http_response(
            target(), redirect, request_url="https://web.example.test/",
            resolved_addresses=["8.8.8.8"],
        )
        self.assertEqual(redirected["outcome"], "INSUFFICIENT_EVIDENCE")
        self.assertFalse(redirected["redirect_followed"])
        self.assertEqual(redirected["error_code"], "redirect_not_followed")

    def test_redirect_destination_is_checked_but_never_implicitly_followed(self):
        origin = "https://web.example.test/"
        self.assertTrue(verification.validate_redirect_destination(
            "/console", origin, "web.example.test", ["8.8.8.8"]
        )["allowed"])
        self.assertFalse(verification.validate_redirect_destination(
            "https://outside.example/", origin, "web.example.test", ["8.8.8.8"]
        )["allowed"])
        self.assertFalse(verification.validate_redirect_destination(
            "http://web.example.test/", origin, "web.example.test", ["8.8.8.8"]
        )["allowed"])

    def test_request_errors_are_sanitized_and_timeout_is_identified(self):
        TimeoutErrorType = type("ReadTimeout", (Exception,), {})
        self.assertEqual(verification.classify_request_error(TimeoutErrorType("secret payload")),
                         {"outcome": "ERROR", "error_code": "timeout"})
        self.assertEqual(verification.classify_request_error(RuntimeError("token=secret")),
                         {"outcome": "ERROR", "error_code": "request_failed"})

    def test_cli_apache_dry_run_opens_read_only_preview_only(self):
        preview = {
            "source_scan": {"scan_id": 19, "status": "SUCCEEDED"},
            "product": "Apache HTTP Server", "selection": {"eligible_targets": 829},
            "populations": {"selected_candidate_counts": {"product_matched_candidates": 12}},
            "targets": [
                {"domain_id": 1, "domain": "web.example.test", "asset_class": "KNOWN",
                 "classification": "VERSION_UNKNOWN"},
                {"domain_id": 2, "domain": "service.example.test", "asset_class": "SHADOW",
                 "classification": "SERVICE_ONLY_CANDIDATE"},
            ],
        }
        connection = mock.Mock()
        output = io.StringIO()
        with mock.patch("capd_cli.get_conn", return_value=connection), \
                mock.patch("capd_cli.preview_product_targets", return_value=preview) as select, \
                contextlib.redirect_stdout(output):
            self.assertEqual(capd_cli_main(["apache-version", "--dry-run", "--scan-id", "19"]), 0)
        select.assert_called_once_with(connection, "apache", scan_id=19, limit=1000)
        connection.close.assert_called_once()
        rendered = json.loads(output.getvalue())
        self.assertEqual(rendered["network_requests"], 0)
        self.assertEqual(rendered["database_writes"], 0)
        self.assertFalse(rendered["live_execution_enabled"])
        self.assertEqual(rendered["candidate_count"], 1)
        self.assertEqual(rendered["authorization"]["state"], "NOT_EVALUATED_DRY_RUN_ONLY")

    def test_cli_requires_dry_run_flag_and_has_no_live_mode(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            capd_cli_main(["apache-version"])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            capd_cli_main(["apache-version", "--live"])


if __name__ == "__main__":
    unittest.main()
