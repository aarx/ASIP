import importlib.util
import logging
import pathlib
import sys
import types
import unittest
from unittest import mock

from fastapi import HTTPException
from pydantic import ValidationError


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from authorization_policy import explicit_t2_authorization_sql  # noqa: E402
from risk_engine import RiskEvidence, calculate_risk  # noqa: E402


def source(filename):
    return (BACKEND / filename).read_text(encoding="utf-8")


def load_main():
    fake_db = types.ModuleType("db")
    fake_db.get_conn = lambda: None
    fake_db.get_latest_authoritative_scan_id = lambda cursor: 42
    fake_db.get_previous_authoritative_scan_id = lambda cursor, current=None: 41
    fake_llm = types.ModuleType("llm_service")
    fake_llm.ask_llm = lambda prompt: "unused"
    spec = importlib.util.spec_from_file_location("pkgf65_main", BACKEND / "main.py")
    module = importlib.util.module_from_spec(spec)
    previous = {name: sys.modules.get(name) for name in ("db", "llm_service")}
    try:
        sys.modules.update({"db": fake_db, "llm_service": fake_llm})
        with mock.patch("logging.FileHandler", return_value=logging.NullHandler()):
            spec.loader.exec_module(module)
    finally:
        for name, value in previous.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value
    return module


class QueueCursor:
    def __init__(self, rows):
        self.rows = iter(rows)
        self.executions = []

    def execute(self, sql, params=None):
        self.executions.append((sql, params))

    def fetchone(self):
        return next(self.rows)


class FakeConnection:
    def __init__(self, cursor):
        self._cursor = cursor
        self.commits = 0
        self.rollbacks = 0
        self.closed = False

    def cursor(self):
        return self._cursor

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True


class OwnershipReviewApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = load_main()

    def call_review(self, target, rows, domain="candidate.example"):
        cursor = QueueCursor(rows)
        connection = FakeConnection(cursor)
        self.main.get_conn = lambda: connection
        self.main._current_scan_asset_classes = mock.Mock(return_value={
            99: "EXTERNAL" if target == "EXTERNAL" else "SHADOW",
        })
        request = self.main.OwnershipReviewRequest(ownership_status=target)
        result = self.main.frontend_v2_review_ownership(domain, request)
        return result, connection, cursor

    def test_candidate_can_be_confirmed_and_remains_shadow_when_not_known(self):
        result, connection, cursor = self.call_review(
            "CONFIRMED",
            [(99, False, "CANDIDATE"), (False,), ("candidate.example",)],
        )

        self.assertEqual(result["ownership_status"], "CONFIRMED")
        self.assertEqual(result["asset_class"], "SHADOW")
        self.assertFalse(result["is_known"])
        self.assertEqual(connection.commits, 1)
        update_sql, update_params = cursor.executions[2]
        self.assertIn("SET ownership_status = %s", update_sql)
        self.assertIn("WHERE domain = %s", update_sql)
        self.assertEqual(update_params, ("CONFIRMED", "candidate.example"))

    def test_candidate_can_be_marked_external_for_only_requested_domain(self):
        result, connection, cursor = self.call_review(
            "EXTERNAL",
            [(99, False, "CANDIDATE"), (False,), ("candidate.example",)],
        )

        self.assertEqual(result["ownership_status"], "EXTERNAL")
        self.assertEqual(result["asset_class"], "EXTERNAL")
        self.assertEqual(cursor.executions[0][1], (42, "candidate.example"))
        self.assertEqual(cursor.executions[2][1], ("EXTERNAL", "candidate.example"))
        all_sql = " ".join(sql for sql, _ in cursor.executions).lower()
        self.assertNotIn("final_url", all_sql)
        self.assertEqual(connection.commits, 1)

    def test_invalid_or_noncurrent_mutation_cannot_partially_modify_state(self):
        self.main.get_conn = mock.Mock()
        with self.assertRaises(HTTPException) as invalid:
            self.main.frontend_v2_review_ownership(
                "candidate.example",
                self.main.OwnershipReviewRequest(ownership_status="CANDIDATE"),
            )
        self.assertEqual(invalid.exception.status_code, 400)
        self.main.get_conn.assert_not_called()

        cursor = QueueCursor([None])
        connection = FakeConnection(cursor)
        self.main.get_conn = lambda: connection
        with self.assertRaises(HTTPException) as missing:
            self.main.frontend_v2_review_ownership(
                "historical.example",
                self.main.OwnershipReviewRequest(ownership_status="EXTERNAL"),
            )
        self.assertEqual(missing.exception.status_code, 404)
        self.assertEqual(connection.commits, 0)
        self.assertEqual(connection.rollbacks, 1)
        self.assertEqual(len(cursor.executions), 1)
        self.assertIn("scan_results", cursor.executions[0][0])

    def test_mutation_contract_rejects_arbitrary_asset_fields(self):
        with self.assertRaises(ValidationError):
            self.main.OwnershipReviewRequest(
                ownership_status="CONFIRMED",
                scannable=True,
            )

    def test_known_inventory_cannot_be_marked_external(self):
        cursor = QueueCursor([(99, True, "CONFIRMED"), (True,)])
        connection = FakeConnection(cursor)
        self.main.get_conn = lambda: connection
        with self.assertRaises(HTTPException) as rejected:
            self.main.frontend_v2_review_ownership(
                "known.example",
                self.main.OwnershipReviewRequest(ownership_status="EXTERNAL"),
            )
        self.assertEqual(rejected.exception.status_code, 409)
        self.assertEqual(connection.commits, 0)
        self.assertEqual(connection.rollbacks, 1)


class OwnershipDurabilityAndSafetyTests(unittest.TestCase):
    def test_normal_discovery_preserves_explicit_confirmed_and_external_decisions(self):
        for filename in ("ingest.py", "san_worker.py"):
            with self.subTest(filename=filename):
                text = " ".join(source(filename).split()).upper()
                self.assertIn(
                    "WHEN DOMAINS.OWNERSHIP_STATUS = 'EXTERNAL' THEN 'EXTERNAL'",
                    text,
                )
                self.assertIn(
                    "WHEN DOMAINS.OWNERSHIP_STATUS = 'CONFIRMED' THEN 'CONFIRMED'",
                    text,
                )

    def test_candidate_and_external_are_blocked_even_if_manual_scan_flags_exist(self):
        predicate = explicit_t2_authorization_sql("d")
        self.assertIn("d.ownership_status = 'CONFIRMED'", predicate)
        self.assertIn("d.scannable IS TRUE", predicate)
        self.assertIn("d.validation_source = 'manual'", predicate)

    def test_confirming_ownership_does_not_grant_authorization(self):
        endpoint = source("main.py")
        start = endpoint.index("def frontend_v2_review_ownership(")
        end = endpoint.index("FRONTEND_V2_ASSISTANT_ACTIONS", start)
        block = endpoint[start:end]
        self.assertNotIn("scannable", block)
        self.assertNotIn("validation_source", block)

    def test_candidate_and_external_still_have_no_canonical_risk(self):
        for ownership in ("CANDIDATE", "EXTERNAL"):
            evidence = RiskEvidence(
                scan_id=42,
                domain_id=1,
                domain="candidate.example",
                first_seen_scan=42,
                is_known=False,
                has_ip=True,
                http_observation_status="RESPONDED",
                port_count=4,
                sensitive_port_count=1,
                provider="AWS",
                volatility_flips=2,
                finding_count=1,
                high_finding_count=1,
                ownership_status=ownership,
            )
            result = calculate_risk(evidence)
            self.assertEqual((result.score, result.priority, result.reasons), (0, "Low", ()))

    def test_redirect_evidence_is_not_an_ownership_or_authorization_writer(self):
        endpoint = source("main.py")
        start = endpoint.index("def frontend_v2_review_ownership(")
        end = endpoint.index("FRONTEND_V2_ASSISTANT_ACTIONS", start)
        block = endpoint[start:end]
        self.assertNotIn("final_url", block)
        self.assertNotIn("domain_states", block)
        self.assertNotIn("scannable", block)


if __name__ == "__main__":
    unittest.main()
