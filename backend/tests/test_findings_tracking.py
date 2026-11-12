import pathlib
import sys
import unittest


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from findings_tracking import (  # noqa: E402
    FindingTrackingError,
    TRACKING_MUTATIONS_ENABLED,
    is_trackable_record,
    stable_issue_identity,
    validate_status_transition,
    was_reobserved_after_handling,
)


class FindingTrackingFoundationTests(unittest.TestCase):
    DEFAULT_DISCRIMINATOR = {"target": "edge.example", "rrtype": "CNAME"}

    def identity(self, *, domain_id=7, source="dns_security_checks",
                 finding_type="dangling_cname", discriminator=DEFAULT_DISCRIMINATOR):
        return stable_issue_identity(
            domain_id=domain_id,
            source=source,
            finding_type=finding_type,
            discriminator=discriminator,
        )

    def test_identity_is_stable_across_scans_and_mapping_order(self):
        first = self.identity(discriminator={"target": "edge.example", "rrtype": "CNAME"})
        second = self.identity(discriminator={"rrtype": "CNAME", "target": "edge.example"})
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("sfi:v1:"))

    def test_distinct_issues_on_one_asset_do_not_collide(self):
        base = self.identity()
        self.assertNotEqual(base, self.identity(discriminator={"target": "other.example", "rrtype": "CNAME"}))
        self.assertNotEqual(base, self.identity(source="domain_findings"))
        self.assertNotEqual(base, self.identity(finding_type="mx_target_warning"))
        self.assertNotEqual(base, self.identity(domain_id=8))

    def test_missing_identity_inputs_fail_conservatively(self):
        cases = [
            {"domain_id": 0, "source": "src", "finding_type": "type", "discriminator": "x"},
            {"domain_id": 1, "source": "", "finding_type": "type", "discriminator": "x"},
            {"domain_id": 1, "source": "src", "finding_type": "", "discriminator": "x"},
            {"domain_id": 1, "source": "src", "finding_type": "type", "discriminator": None},
            {"domain_id": 1, "source": "src", "finding_type": "type", "discriminator": float("nan")},
        ]
        for values in cases:
            with self.subTest(values=values), self.assertRaises(FindingTrackingError):
                stable_issue_identity(**values)

    def test_only_findings_and_verification_records_for_known_shadow_qualify(self):
        self.assertTrue(is_trackable_record(category="FINDING", asset_class="KNOWN"))
        self.assertTrue(is_trackable_record(category="needs_verification", asset_class="SHADOW"))
        for category, asset_class in (
            ("EXPOSURE_SIGNAL", "KNOWN"), ("FINDING", "CANDIDATE"),
            ("NEEDS_VERIFICATION", "EXTERNAL"),
        ):
            with self.subTest(category=category, asset_class=asset_class):
                self.assertFalse(is_trackable_record(category=category, asset_class=asset_class))

    def test_status_transitions_and_reopening(self):
        self.assertEqual(validate_status_transition("OPEN", "IN_REVIEW"), "STATUS_CHANGED")
        self.assertEqual(validate_status_transition("IN_REVIEW", "REMEDIATED"), "STATUS_CHANGED")
        self.assertEqual(validate_status_transition("REMEDIATED", "OPEN"), "REOPENED")
        self.assertEqual(validate_status_transition("FALSE_POSITIVE", "OPEN"), "REOPENED")
        self.assertEqual(validate_status_transition("RISK_ACCEPTED", "OPEN"), "REOPENED")

    def test_invalid_status_transitions_are_rejected(self):
        for current, next_status in (
            ("OPEN", "UNKNOWN"), ("OPEN", "OPEN"),
            ("REMEDIATED", "IN_REVIEW"), ("FALSE_POSITIVE", "RISK_ACCEPTED"),
        ):
            with self.subTest(current=current, next_status=next_status), self.assertRaises(FindingTrackingError):
                validate_status_transition(current, next_status)

    def test_reobservation_is_flag_only_and_does_not_change_analyst_state(self):
        import datetime

        changed = datetime.datetime(2026, 1, 2, tzinfo=datetime.timezone.utc)
        later = datetime.datetime(2026, 1, 3, tzinfo=datetime.timezone.utc)
        self.assertTrue(was_reobserved_after_handling(
            analyst_status="REMEDIATED", observation_at=later,
            status_changed_at=changed,
        ))
        self.assertFalse(was_reobserved_after_handling(
            analyst_status="OPEN", observation_at=later,
            status_changed_at=changed,
        ))
        self.assertFalse(was_reobserved_after_handling(
            analyst_status="RISK_ACCEPTED", observation_at=changed,
            status_changed_at=changed,
        ))

    def test_tracking_writes_stay_disabled_without_verified_http_identity(self):
        self.assertFalse(TRACKING_MUTATIONS_ENABLED)

    def test_migration_is_additive_and_keeps_source_status_separate(self):
        migration = (BACKEND / "migrations" / "014_add_security_finding_tracking.sql").read_text()
        normalized = " ".join(migration.split()).upper()
        self.assertIn("CREATE TABLE PUBLIC.TRACKED_SECURITY_ISSUES", normalized)
        self.assertIn("CREATE TABLE PUBLIC.TRACKED_SECURITY_ISSUE_HISTORY", normalized)
        self.assertIn("SOURCE_OUTCOME TEXT", normalized)
        self.assertIn("SOURCE_CONFIDENCE TEXT", normalized)
        self.assertIn("ASSET_CLASS_SNAPSHOT IN ('KNOWN', 'SHADOW')", normalized)
        self.assertIn("ANALYST_STATUS TEXT NOT NULL DEFAULT 'OPEN'", normalized)
        self.assertIn("UNIQUE (DOMAIN_ID, SOURCE, FINDING_TYPE, IDENTITY_DISCRIMINATOR)", normalized)
        self.assertIn("BEFORE UPDATE OR DELETE ON PUBLIC.TRACKED_SECURITY_ISSUE_HISTORY", normalized)
        self.assertNotIn("UPDATE PUBLIC.DOMAIN_FINDINGS", normalized)
        self.assertNotIn("DELETE FROM", normalized)
        self.assertNotIn("INSERT INTO PUBLIC.TRACKED_SECURITY_ISSUES", normalized)


if __name__ == "__main__":
    unittest.main()
