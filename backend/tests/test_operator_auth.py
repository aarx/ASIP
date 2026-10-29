import pathlib
import sys
import unittest
from datetime import datetime, timedelta, timezone


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from operator_auth import (  # noqa: E402
    AuthenticationRequired,
    PermissionDenied,
    PERMISSION_CANCEL_CAMPAIGN,
    PERMISSION_CREATE_CAMPAIGN,
    PERMISSION_READ_ADHOC,
    PERMISSION_RUN_CAMPAIGN,
    ROLE_ADMINISTRATOR,
    ROLE_ANALYST,
    VerifiedPrincipal,
    authorize_permission,
    reject_unverified_identity_input,
)


class OperatorAuthorizationTests(unittest.TestCase):
    def principal(self, role=ROLE_ANALYST, **overrides):
        values = {
            "subject": "operator@example.test",
            "roles": frozenset({role}),
            "authentication_source": "test-idp",
            "verified": True,
        }
        values.update(overrides)
        return VerifiedPrincipal(**values)

    def test_missing_invalid_and_expired_identity_fails_closed(self):
        for principal in (
            None,
            self.principal(verified=False),
            self.principal(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1)),
        ):
            with self.subTest(principal=principal):
                with self.assertRaises(AuthenticationRequired):
                    authorize_permission(principal, PERMISSION_READ_ADHOC)

    def test_analyst_is_read_only_for_adhoc_data(self):
        self.assertIsNotNone(authorize_permission(self.principal(), PERMISSION_READ_ADHOC))
        for permission in (
            PERMISSION_CREATE_CAMPAIGN,
            PERMISSION_CANCEL_CAMPAIGN,
            PERMISSION_RUN_CAMPAIGN,
        ):
            with self.subTest(permission=permission):
                with self.assertRaises(PermissionDenied):
                    authorize_permission(self.principal(), permission)

    def test_administrator_has_explicit_campaign_permissions(self):
        principal = self.principal(ROLE_ADMINISTRATOR)
        for permission in (
            PERMISSION_READ_ADHOC,
            PERMISSION_CREATE_CAMPAIGN,
            PERMISSION_CANCEL_CAMPAIGN,
            PERMISSION_RUN_CAMPAIGN,
        ):
            with self.subTest(permission=permission):
                authorize_permission(principal, permission)

    def test_unknown_roles_cannot_escalate_privileges(self):
        principal = self.principal(roles=frozenset({"administrator", "superuser"}))
        with self.assertRaises(PermissionDenied):
            authorize_permission(principal, PERMISSION_CREATE_CAMPAIGN)

    def test_unverified_client_identity_is_rejected(self):
        with self.assertRaises(AuthenticationRequired):
            reject_unverified_identity_input("administrator", source="X-Role")

    def test_audit_events_are_safe_and_denials_are_recorded(self):
        events = []
        authorize_permission(
            self.principal(), PERMISSION_READ_ADHOC, audit_sink=events.append
        )
        with self.assertRaises(PermissionDenied):
            authorize_permission(
                self.principal(), PERMISSION_CREATE_CAMPAIGN,
                audit_sink=events.append,
            )
        self.assertEqual([event["outcome"] for event in events], ["allowed", "denied"])
        self.assertTrue(all("token" not in event and "claims" not in event for event in events))
        self.assertEqual(events[1]["reason_code"], "permission_denied")

    def test_audit_sink_failure_fails_closed(self):
        def broken_sink(_event):
            raise RuntimeError("audit unavailable")

        with self.assertRaises(AuthenticationRequired):
            authorize_permission(
                self.principal(), PERMISSION_READ_ADHOC, audit_sink=broken_sink
            )

    def test_existing_adhoc_surface_has_no_mutation_route(self):
        source = (BACKEND / "main.py").read_text(encoding="utf-8")
        self.assertIn('@app.get("/v2/adhoc/checks/php-rce")', source)
        self.assertIn('@app.get("/v2/adhoc/campaigns")', source)
        self.assertNotIn('@app.post("/v2/adhoc', source)
        self.assertNotIn('@app.delete("/v2/adhoc', source)


if __name__ == "__main__":
    unittest.main()
