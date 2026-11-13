import contextlib
import io
import json
from datetime import datetime, timedelta, timezone
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

    def test_authorization_adapter_requires_operation_and_both_run_scoped_gates(self):
        now = datetime(2026, 11, 13, tzinfo=timezone.utc)
        context = verification.create_authorization_context(
            verification.APACHE_CHECK_ID, verification.APACHE_CHECK_REVISION, 19, now=now
        )
        selected_target = {**target(), "source_scan_id": 19}
        approval = mock.Mock(return_value=True)
        recheck = mock.Mock(return_value=True)
        with mock.patch.dict("os.environ", {}, clear=True):
            denied = verification.authorize_apache_target(
                context, selected_target, trusted_operator_approval=approval,
                fresh_target_recheck=recheck, now=now,
            )
        self.assertEqual(denied["decision"], "NOT_AUTHORIZED")
        self.assertIn("ADHOC_CHECK_OPERATION_DISABLED", denied["reason_codes"])
        approval.assert_not_called()

        with mock.patch.dict("os.environ", {"ASIP_DEFAULT_SCAN_OPERATIONS": "ADHOC_CHECK"}):
            allowed = verification.authorize_apache_target(
                context, selected_target, trusted_operator_approval=approval,
                fresh_target_recheck=recheck, now=now,
            )
        self.assertEqual(allowed["decision"], "AUTHORIZED")
        approval.assert_called_once_with(context, selected_target)
        self.assertEqual(recheck.call_count, 2)
        recheck.assert_called_with(context, selected_target, testing_level="ADHOC_CHECK")

    def test_run_context_requires_trusted_approval_and_fresh_target_recheck(self):
        now = datetime(2026, 11, 13, tzinfo=timezone.utc)
        context = verification.create_authorization_context(
            verification.APACHE_CHECK_ID, verification.APACHE_CHECK_REVISION, 19, now=now
        )
        selected_target = {**target(), "source_scan_id": 19}
        with mock.patch.dict("os.environ", {"ASIP_DEFAULT_SCAN_OPERATIONS": "ADHOC_CHECK"}):
            denied = verification.evaluate_apache_authorization(
                context, selected_target, now=now
            )
            self.assertEqual(denied["decision"], "NOT_AUTHORIZED")
            self.assertIn("TRUSTED_CAPD_OPERATOR_APPROVAL_UNAVAILABLE", denied["reason_codes"])
            self.assertIn("FRESH_TARGET_AUTHORIZATION_RECHECK_UNAVAILABLE", denied["reason_codes"])

            approval = mock.Mock(return_value=True)
            recheck = mock.Mock(return_value=True)
            accepted = verification.evaluate_apache_authorization(
                context, selected_target, trusted_operator_approval=approval,
                fresh_target_recheck=recheck, now=now,
            )
            self.assertEqual(accepted["decision"], "AUTHORIZED")
            approval.assert_called_once_with(context, selected_target)
            recheck.assert_called_once_with(context, selected_target, testing_level="ADHOC_CHECK")

            stale = verification.evaluate_apache_authorization(
                context, selected_target, trusted_operator_approval=approval,
                fresh_target_recheck=recheck, now=now + timedelta(minutes=6),
            )
            self.assertEqual(stale["decision"], "NOT_AUTHORIZED")
            self.assertIn("AUTHORIZATION_CONTEXT_EXPIRED_OR_STALE", stale["reason_codes"])
            changed_scan = verification.evaluate_apache_authorization(
                context, {**selected_target, "source_scan_id": 18},
                trusted_operator_approval=approval, fresh_target_recheck=recheck, now=now,
            )
            self.assertIn("SOURCE_SCAN_CONTEXT_MISMATCH", changed_scan["reason_codes"])

    def test_run_context_rejects_untrusted_and_non_service_targets(self):
        now = datetime(2026, 11, 13, tzinfo=timezone.utc)
        context = verification.create_authorization_context(
            verification.APACHE_CHECK_ID, verification.APACHE_CHECK_REVISION, 19, now=now
        )
        with mock.patch.dict("os.environ", {"ASIP_DEFAULT_SCAN_OPERATIONS": "ADHOC_CHECK"}):
            for candidate in (
                {**target(asset_class="CANDIDATE"), "source_scan_id": 19},
                {**target(asset_class="EXTERNAL"), "source_scan_id": 19},
                {**target(scannable=False), "source_scan_id": 19},
                {**target(classification="SERVICE_ONLY_CANDIDATE"), "source_scan_id": 19},
                {**target(), "source_scan_id": 18},
                {**target(evidence=[{
                    "source": "domain_technology_observations", "technology": "apache",
                    "evidence_type": "server_header", "observed_url": "https://other.example/",
                }]), "source_scan_id": 19},
            ):
                decision = verification.evaluate_apache_authorization(
                    context, candidate, trusted_operator_approval=lambda *_: True,
                    fresh_target_recheck=lambda *_args, **_kwargs: True, now=now,
                )
                self.assertEqual(decision["decision"], "NOT_AUTHORIZED")

    def test_disabled_adhoc_operation_fails_closed_without_callbacks(self):
        now = datetime(2026, 11, 13, tzinfo=timezone.utc)
        context = verification.create_authorization_context(
            verification.APACHE_CHECK_ID, verification.APACHE_CHECK_REVISION, 19, now=now
        )
        with mock.patch.dict("os.environ", {}, clear=True):
            decision = verification.evaluate_apache_authorization(
                context, {**target(), "source_scan_id": 19}, now=now
            )
        self.assertEqual(decision["decision"], "NOT_AUTHORIZED")
        self.assertIn("ADHOC_CHECK_OPERATION_DISABLED", decision["reason_codes"])

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
                {**target(), "domain_id": 1, "classification": "VERSION_UNKNOWN"},
                {"domain_id": 2, "domain": "service.example.test", "asset_class": "SHADOW",
                 "classification": "SERVICE_ONLY_CANDIDATE"},
            ],
        }
        connection = mock.Mock()
        inventory_check = mock.Mock(return_value={
            "inventory_policy_passed": False, "reason_codes": ["ADHOC_CHECK_OPERATION_DISABLED"],
        })
        output = io.StringIO()
        with mock.patch("capd_cli.get_conn", return_value=connection), \
                mock.patch("capd_cli.preview_product_targets", return_value=preview) as select, \
                mock.patch("capd_cli.recheck_apache_target_from_inventory", inventory_check), \
                mock.patch.dict("os.environ", {}, clear=True), \
                contextlib.redirect_stdout(output):
            self.assertEqual(capd_cli_main(["apache-version", "--dry-run", "--scan-id", "19"]), 0)
        select.assert_called_once_with(connection, "apache", scan_id=19, limit=1000)
        inventory_check.assert_called_once()
        connection.close.assert_called_once()
        rendered = json.loads(output.getvalue())
        self.assertEqual(rendered["network_requests"], 0)
        self.assertEqual(rendered["database_writes"], 0)
        self.assertFalse(rendered["live_execution_enabled"])
        self.assertEqual(rendered["candidate_count"], 1)
        self.assertEqual(rendered["authorization"]["state"], "NOT_AUTHORIZED")
        self.assertEqual(rendered["authorization"]["approved_target_count"], 0)
        self.assertEqual(rendered["authorization"]["blocked_target_count"], 1)
        self.assertFalse(rendered["authorization"]["authorization_evaluated"])
        self.assertTrue(rendered["authorization"]["inventory_target_recheck_evaluated"])
        self.assertFalse(rendered["authorization"]["full_authorization_grant_evaluated"])
        self.assertIn(
            "ADHOC_CHECK_OPERATION_DISABLED",
            rendered["authorization"]["reason_counts"],
        )

    def test_cli_requires_dry_run_flag_and_has_no_live_mode(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            capd_cli_main(["apache-version"])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            capd_cli_main(["apache-version", "--live"])


if __name__ == "__main__":
    unittest.main()
