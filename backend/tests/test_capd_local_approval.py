import io
import json
import pathlib
import stat
import sys
import os
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock
import uuid


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

import capd_local_approval as approval  # noqa: E402
import capd_cli  # noqa: E402
from capd_approval_contract import (  # noqa: E402
    APACHE_CHECK_ID, APACHE_CHECK_REVISION, CAPD_HTTP_HEADER_VERIFY,
)
from authorization_policy import default_operation_enabled  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from apache_version_verification import create_authorization_context  # noqa: E402


class TTYInput(io.StringIO):
    def isatty(self):
        return True


class ApprovalInput:
    def __init__(self, document):
        self.buffer = io.BytesIO(document.encode("utf-8"))


class CapdLocalApprovalTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.payload = approval.build_approval_payload(
            run_id=str(uuid.uuid4()), source_scan_id=19, asset_id=11,
            domain="web.example.test", origin="https://web.example.test/",
            operator_uid=1001, operator_name="capd-operator", now=self.now,
        )

    def signed(self, payload=None):
        return approval.sign_approval(payload or self.payload, self.private_key)

    def test_signed_approval_is_short_lived_single_target_and_bound(self):
        verified = approval.verify_approval(
            self.signed(), self.public_key, now=self.now + timedelta(seconds=10)
        )
        context = create_authorization_context(
            APACHE_CHECK_ID, APACHE_CHECK_REVISION, 19,
            run_id=verified["run_id"], now=self.now,
            expires_at=datetime.fromisoformat(verified["expires_at"]),
        )
        target = {
            "domain_id": 11, "domain": "web.example.test",
            "evidence": [{
                "source": "domain_technology_observations", "technology": "apache",
                "evidence_type": "server_header", "observed_url": "https://web.example.test/",
            }],
        }
        self.assertTrue(approval.approval_matches_target(verified, context, target))
        for changed in (
            {**target, "domain_id": 12},
            {**target, "domain": "other.example.test"},
            {**target, "evidence": []},
        ):
            self.assertFalse(approval.approval_matches_target(verified, context, changed))
        self.assertEqual(verified["operation"], CAPD_HTTP_HEADER_VERIFY)
        self.assertEqual(verified["max_requests"], 1)
        self.assertEqual(verified["method"], "GET")

    def test_tampered_expired_wrong_revision_and_unbounded_approvals_fail(self):
        valid = self.signed()
        envelope = json.loads(valid)
        envelope["payload"]["asset"]["asset_id"] = 12
        with self.assertRaises(approval.LocalApprovalError):
            approval.verify_approval(json.dumps(envelope), self.public_key, now=self.now)
        with self.assertRaises(approval.LocalApprovalError):
            approval.verify_approval(valid, self.public_key, now=self.now + timedelta(seconds=121))
        for field, value in (("check_revision", "9.9.9"), ("max_requests", 2), ("max_requests", True)):
            payload = dict(self.payload)
            payload[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(approval.LocalApprovalError):
                approval.verify_approval(self.signed(payload), self.public_key, now=self.now)

    def test_check_scan_and_destination_binding_are_enforced(self):
        for field, value in (("check_id", "OTHER"),):
            payload = dict(self.payload)
            payload[field] = value
            with self.subTest(field=field), self.assertRaises(approval.LocalApprovalError):
                approval.verify_approval(self.signed(payload), self.public_key, now=self.now)
        mismatch_context = create_authorization_context(
            APACHE_CHECK_ID, APACHE_CHECK_REVISION, 20,
            run_id=self.payload["run_id"], now=self.now,
            expires_at=datetime.fromisoformat(self.payload["expires_at"]),
        )
        target = {
            "domain_id": 11, "domain": "web.example.test",
            "evidence": [{
                "source": "domain_technology_observations", "technology": "apache",
                "evidence_type": "server_header", "observed_url": "https://web.example.test/",
            }],
        }
        self.assertFalse(approval.approval_matches_target(self.payload, mismatch_context, target))
        with self.assertRaises(approval.LocalApprovalError):
            approval.build_approval_payload(
                run_id=str(uuid.uuid4()), source_scan_id=19, asset_id=11,
                domain="web.example.test", origin="https://evil.example/",
                operator_uid=1001, operator_name="capd-operator", now=self.now,
            )

    def test_operation_is_separate_and_disabled_by_default(self):
        with mock.patch.dict("os.environ", {"ASIP_DEFAULT_SCAN_OPERATIONS": "ADHOC_CHECK,HTTP_TLS_OBSERVATION"}):
            self.assertTrue(default_operation_enabled("ADHOC_CHECK"))
            self.assertTrue(default_operation_enabled("HTTP_TLS_OBSERVATION"))
            self.assertFalse(default_operation_enabled(CAPD_HTTP_HEADER_VERIFY))
        with mock.patch.dict("os.environ", {"ASIP_DEFAULT_SCAN_OPERATIONS": CAPD_HTTP_HEADER_VERIFY}):
            self.assertTrue(default_operation_enabled(CAPD_HTTP_HEADER_VERIFY))
            self.assertFalse(default_operation_enabled("ADHOC_CHECK"))

    def test_host_issuer_requires_protected_launcher_root_and_operator_group(self):
        executable = pathlib.Path("/trusted/asip-capd-approve")
        file_mode = stat.S_IFREG | 0o755
        dir_mode = stat.S_IFDIR | 0o755
        fake_stat = lambda path: SimpleNamespace(
            st_mode=file_mode if path == executable else dir_mode, st_uid=0
        )
        operator = SimpleNamespace(pw_name="approved", pw_gid=1001)
        group = SimpleNamespace(gr_gid=9001)
        with mock.patch.object(approval, "APPROVER_PATH", executable), \
                mock.patch.object(approval.Path, "lstat", autospec=True, side_effect=lambda self: fake_stat(self)), \
                mock.patch.object(approval.os, "geteuid", return_value=0), \
                mock.patch.object(approval, "_sudo_invoking_identity", return_value=(1001, "approved")), \
                mock.patch.object(approval.pwd, "getpwuid", return_value=operator), \
                mock.patch.object(approval.grp, "getgrnam", return_value=group), \
                mock.patch.object(approval.os, "getgrouplist", return_value=[1001, 9001]), \
                mock.patch.object(approval.sys, "argv", [str(executable)]):
            self.assertEqual(approval._verify_protected_installation(), (1001, "approved"))
        with mock.patch.object(approval, "APPROVER_PATH", executable), \
                mock.patch.object(approval.Path, "lstat", autospec=True, side_effect=lambda self: fake_stat(self)), \
                mock.patch.object(approval.os, "geteuid", return_value=0), \
                mock.patch.object(approval, "_sudo_invoking_identity", side_effect=approval.LocalApprovalError("not sudo")), \
                mock.patch.object(approval.sys, "argv", [str(executable)]), \
                self.assertRaises(approval.LocalApprovalError):
            approval._verify_protected_installation()
        with mock.patch.object(approval, "APPROVER_PATH", executable), \
                mock.patch.object(approval.Path, "lstat", autospec=True, side_effect=lambda self: fake_stat(self)), \
                mock.patch.object(approval.os, "geteuid", return_value=0), \
                mock.patch.object(approval, "_sudo_invoking_identity", return_value=(1002, "other")), \
                mock.patch.object(approval.pwd, "getpwuid", return_value=operator), \
                mock.patch.object(approval.grp, "getgrnam", return_value=group), \
                mock.patch.object(approval.os, "getgrouplist", return_value=[1001]), \
                mock.patch.object(approval.sys, "argv", [str(executable)]), \
                self.assertRaises(approval.LocalApprovalError):
            approval._verify_protected_installation()
        insecure_stat = lambda _path: SimpleNamespace(st_mode=file_mode | 0o020, st_uid=0)
        with mock.patch.object(approval, "APPROVER_PATH", executable), \
                mock.patch.object(approval.Path, "lstat", autospec=True, side_effect=lambda self: insecure_stat(self)), \
                mock.patch.object(approval.os, "geteuid", return_value=0), \
                mock.patch.object(approval.os, "getuid", return_value=1001), \
                mock.patch.object(approval.sys, "argv", [str(executable)]), \
                self.assertRaises(approval.LocalApprovalError):
            approval._verify_protected_installation()

    def test_sudo_identity_uses_verified_sudo_metadata_when_real_uid_is_root(self):
        sudo_stat = SimpleNamespace(
            st_mode=stat.S_IFREG | stat.S_ISUID | 0o755, st_uid=0,
        )
        status = "Name:\tsudo\nUid:\t1001\t0\t0\t0\n"
        with mock.patch.object(approval.Path, "stat", autospec=True, return_value=sudo_stat), \
                mock.patch.object(approval.Path, "resolve", autospec=True, side_effect=lambda self, **_kw: pathlib.Path("/usr/bin/sudo") if str(self).endswith("/exe") else pathlib.Path("/usr/bin/sudo")), \
                mock.patch.object(approval.os, "getppid", return_value=55), \
                mock.patch.object(approval.os, "getuid", return_value=0), \
                mock.patch.object(approval.Path, "read_text", return_value=status), \
                mock.patch.dict(os.environ, {
                    "SUDO_UID": "1001", "SUDO_USER": "approved",
                    "SUDO_COMMAND": "/usr/local/libexec/asip-capd-approve --asset-id 11",
                }), \
                mock.patch.object(approval.pwd, "getpwuid", return_value=SimpleNamespace(pw_name="approved")):
            self.assertEqual(approval._sudo_invoking_identity(), (1001, "approved"))

    def test_sudo_identity_rejects_forged_environment_or_untrusted_parent(self):
        sudo_stat = SimpleNamespace(st_mode=stat.S_IFREG | stat.S_ISUID | 0o755, st_uid=0)
        with mock.patch.object(approval.Path, "stat", autospec=True, return_value=sudo_stat), \
                mock.patch.object(approval.Path, "resolve", autospec=True, side_effect=lambda self, **_kw: pathlib.Path("/tmp/fake") if str(self).startswith("/proc/") else pathlib.Path("/usr/bin/sudo")), \
                mock.patch.object(approval.os, "getppid", return_value=55), \
                mock.patch.object(approval.Path, "read_text", return_value="Uid:\t1001\t0\t0\t0\n"), \
                mock.patch.dict(os.environ, {
                    "SUDO_UID": "1001", "SUDO_USER": "approved",
                    "SUDO_COMMAND": "/usr/local/libexec/asip-capd-approve",
                }), \
                self.assertRaises(approval.LocalApprovalError):
            approval._sudo_invoking_identity()

    def test_complete_signed_cli_dry_run_rechecks_target_and_never_performs_io(self):
        argv = [
            "--run-id", self.payload["run_id"], "--scan-id", "19", "--asset-id", "11",
            "--domain", "web.example.test", "--origin", "https://web.example.test/",
        ]
        token_out = io.StringIO()
        with mock.patch.object(approval, "_verify_protected_installation", return_value=(1001, "approved")), \
                mock.patch.object(approval, "_read_private_key", return_value=self.private_key), \
                mock.patch.object(approval.sys, "stdin", TTYInput("APPROVE 11\n")), \
                mock.patch.object(approval.sys, "stdout", token_out), \
                mock.patch.object(approval.sys, "stderr", io.StringIO()):
            self.assertEqual(approval.issue_main(argv), 0)
        document = token_out.getvalue().strip()
        target = {
            "domain_id": 11, "domain": "web.example.test", "asset_class": "SHADOW",
            "scannable": True, "inventory_eligible": True,
            "classification": "VERSION_UNKNOWN",
            "evidence": [{
                "source": "domain_technology_observations", "technology": "apache",
                "evidence_type": "server_header", "observed_url": "https://web.example.test/",
            }],
        }
        preview = {
            "source_scan": {"scan_id": 19, "status": "SUCCEEDED"},
            "product": {"name": "Apache HTTP Server"},
            "selection": {"limit": 10}, "populations": {"eligible_inventory": 1},
            "targets": [target],
        }
        conn = mock.MagicMock()
        conn.cursor.return_value = object()
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"ASIP_DEFAULT_SCAN_OPERATIONS": CAPD_HTTP_HEADER_VERIFY}), \
                mock.patch.object(capd_cli, "get_conn", return_value=conn), \
                mock.patch.object(capd_cli, "preview_product_targets", return_value=preview), \
                mock.patch.object(capd_cli, "_read_public_key", return_value=self.public_key), \
                mock.patch.object(capd_cli, "recheck_apache_target_from_inventory", return_value={"inventory_policy_passed": True, "reason_codes": []}) as fresh_check, \
                mock.patch.object(capd_cli.sys, "stdin", ApprovalInput(document)), \
                mock.patch.object(capd_cli.sys, "stdout", stdout), \
                mock.patch.object(capd_cli.sys, "stderr", stderr):
            # Replaying a token remains a dry-run only; no transport is wired.
            for _ in range(2):
                stdout.seek(0)
                stdout.truncate(0)
                capd_cli.sys.stdin.buffer.seek(0)
                self.assertEqual(capd_cli.main([
                    "apache-version", "--dry-run", "--scan-id", "19",
                    "--asset-id", "11", "--approval-stdin",
                ]), 0, stderr.getvalue())
                result = json.loads(stdout.getvalue())
                self.assertEqual(result["authorization"]["state"], "AUTHORIZED")
                self.assertEqual(result["network_requests"], 0)
                self.assertEqual(result["database_writes"], 0)
                self.assertFalse(result["live_execution_enabled"])
            self.assertEqual(fresh_check.call_count, 4)
            conn.close.assert_called()

    def test_cli_dry_run_denies_revoked_scope_or_disabled_operation(self):
        current_payload = approval.build_approval_payload(
            run_id=str(uuid.uuid4()), source_scan_id=19, asset_id=11,
            domain="web.example.test", origin="https://web.example.test/",
            operator_uid=1001, operator_name="approved",
        )
        document = self.signed(current_payload)
        target = {
            "domain_id": 11, "domain": "web.example.test", "asset_class": "SHADOW",
            "scannable": True, "inventory_eligible": True,
            "classification": "VERSION_UNKNOWN",
            "evidence": [{
                "source": "domain_technology_observations", "technology": "apache",
                "evidence_type": "server_header", "observed_url": "https://web.example.test/",
            }],
        }
        preview = {
            "source_scan": {"scan_id": 19, "status": "SUCCEEDED"},
            "product": {}, "selection": {}, "populations": {}, "targets": [target],
        }
        for enabled, fresh in ((CAPD_HTTP_HEADER_VERIFY, False), ("HTTP_TLS_OBSERVATION", True)):
            conn, stdout = mock.MagicMock(), io.StringIO()
            with self.subTest(enabled=enabled, fresh=fresh), \
                    mock.patch.dict(os.environ, {"ASIP_DEFAULT_SCAN_OPERATIONS": enabled}), \
                    mock.patch.object(capd_cli, "get_conn", return_value=conn), \
                    mock.patch.object(capd_cli, "preview_product_targets", return_value=preview), \
                    mock.patch.object(capd_cli, "_read_public_key", return_value=self.public_key), \
                    mock.patch.object(capd_cli, "recheck_apache_target_from_inventory", return_value={"inventory_policy_passed": fresh, "reason_codes": []}), \
                    mock.patch.object(capd_cli.sys, "stdin", ApprovalInput(document)), \
                    mock.patch.object(capd_cli.sys, "stdout", stdout), \
                    mock.patch.object(capd_cli.sys, "stderr", io.StringIO()):
                self.assertEqual(capd_cli.main([
                    "apache-version", "--dry-run", "--scan-id", "19",
                    "--asset-id", "11", "--approval-stdin",
                ]), 0, "see captured CLI error")
                result = json.loads(stdout.getvalue())
                self.assertEqual(result["authorization"]["state"], "NOT_AUTHORIZED")
                self.assertEqual(result["network_requests"], 0)

    def test_interactive_host_confirmation_emits_signed_document_only_after_confirmation(self):
        argv = [
            "--run-id", self.payload["run_id"], "--scan-id", "19", "--asset-id", "11",
            "--domain", "web.example.test", "--origin", "https://web.example.test/",
        ]
        output, errors = io.StringIO(), io.StringIO()
        with mock.patch.object(approval, "_verify_protected_installation", return_value=(1001, "approved")), \
                mock.patch.object(approval, "_read_private_key", return_value=self.private_key), \
                mock.patch.object(approval.sys, "stdin", TTYInput("APPROVE 11\n")), \
                mock.patch.object(approval.sys, "stdout", output), \
                mock.patch.object(approval.sys, "stderr", errors):
            self.assertEqual(approval.issue_main(argv), 0)
        verified = approval.verify_approval(output.getvalue().strip(), self.public_key)
        self.assertEqual(verified["operator_uid"], 1001)
        self.assertIn("https://web.example.test/", errors.getvalue())

        with mock.patch.object(approval, "_verify_protected_installation", return_value=(1001, "approved")), \
                mock.patch.object(approval.sys, "stdin", TTYInput("no\n")), \
                mock.patch.object(approval.sys, "stderr", io.StringIO()):
            self.assertEqual(approval.issue_main(argv), 2)


if __name__ == "__main__":
    unittest.main()
