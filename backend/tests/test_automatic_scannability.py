import pathlib
import sys
import unittest
from datetime import datetime, timezone


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from adhoc_runner import ExecutionContext, validate_execution_context  # noqa: E402
from authorization_policy import active_scope_coverage_sql  # noqa: E402
from eligibility_worker import automatic_eligibility_sql  # noqa: E402
from ownership import ownership_for_discovery  # noqa: E402


class AutomaticEligibilitySqlTests(unittest.TestCase):
    def test_update_is_current_scan_scoped_and_idempotent(self):
        sql = " ".join(automatic_eligibility_sql().split()).upper()
        self.assertIn("UPDATE DOMAINS D", sql)
        self.assertIn("FROM SCAN_RESULTS SR", sql)
        self.assertIn("SR.SCAN_ID = %S", sql)
        self.assertIn("SR.DOMAIN_ID = D.ID", sql)
        self.assertIn("D.SCANNABLE IS NOT TRUE", sql)
        self.assertIn("D.VALIDATION_SOURCE IS NULL", sql)
        self.assertIn("D.OWNERSHIP_STATUS = 'CONFIRMED'", sql)
        self.assertIn("FROM KNOWN_DOMAINS KD", sql)
        self.assertIn("FROM SEED_DOMAINS ROOT", sql)
        self.assertIn("FROM ACTIVE_SCAN_SCOPES SCOPE_ALLOW", sql)
        self.assertIn("SCOPE_BLOCK.EXCLUDED_DOMAINS", sql)

    def test_scope_sql_keeps_testing_level_exclusions_correlated(self):
        sql = " ".join(active_scope_coverage_sql("d", "PORT_SCAN").split()).upper()
        self.assertIn("SCOPE_ALLOW.TESTING_LEVEL = 'PORT_SCAN'", sql)
        self.assertIn("SCOPE_BLOCK.TESTING_LEVEL = SCOPE_ALLOW.TESTING_LEVEL", sql)

    def test_seed_matching_is_boundary_safe(self):
        self.assertEqual(
            ownership_for_discovery("app.example.com", (), "example.com"),
            "CONFIRMED",
        )
        self.assertEqual(
            ownership_for_discovery("evil-example.com", (), "example.com"),
            "CANDIDATE",
        )

    def test_no_scope_does_not_change_technical_context_or_manual_path(self):
        now = datetime(2026, 11, 2, 12, 0, tzinfo=timezone.utc)
        context = ExecutionContext(
            campaign_id=1, target_id=2, source_scan_id=3, domain_id=4,
            domain="app.example.com", campaign_status="RUNNING",
            target_status="PENDING", source_scan_status="SUCCEEDED",
            created_at=now, ownership_status="CONFIRMED", scannable=True,
            validation_source=None,
        )
        self.assertTrue(validate_execution_context(context, now=now))

        rejected = ExecutionContext(
            **{**context.__dict__, "scannable": False}
        )
        with self.assertRaises(Exception):
            validate_execution_context(rejected, now=now)


if __name__ == "__main__":
    unittest.main()
