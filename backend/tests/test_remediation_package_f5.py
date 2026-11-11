import importlib.util
import logging
import pathlib
import sys
import types
import unittest
from unittest import mock

from fastapi import HTTPException


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))


def load_main():
    fake_db = types.ModuleType("db")
    fake_db.get_conn = lambda: None
    fake_db.get_latest_authoritative_scan_id = lambda cursor: 42
    fake_db.get_previous_authoritative_scan_id = lambda cursor, current=None: 41
    fake_llm = types.ModuleType("llm_service")
    fake_llm.ask_llm = lambda prompt: "unused"
    spec = importlib.util.spec_from_file_location("pkgf5_main", BACKEND / "main.py")
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


def detail(ownership="CONFIRMED", risk=None):
    return {
        "scan_id": 42,
        "domain": "asset.example",
        "ownership_status": ownership,
        "is_known": ownership == "CONFIRMED",
        "asset_class": "KNOWN" if ownership == "CONFIRMED" else ownership,
        "first_seen_scan": 40,
        "last_seen_scan": 42,
        "first_seen_at": "2026-09-20T10:00:00",
        "last_seen_at": "2026-09-25T10:00:00",
        "seed": "example.com",
        "risk": risk,
        "dns": {"ip": "192.0.2.10", "has_ip": True, "reverse_dns": None},
        "http": {"observation_status": "UNKNOWN", "status": 0, "final_url": None},
        "ports": [{"port": 443, "service": "https"}],
        "asn": {"asn": "AS64500", "organization": "Example", "ip": "192.0.2.10"},
        "provider": "Example Cloud",
        "technologies": ["nginx"],
        "certificate": None,
        "discovery": {"sources": [{"source": "subfinder", "seed": "example.com"}]},
        "findings": [],
    }


class GroundedAssetAssistantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = load_main()

    def setUp(self):
        self.main.ask_llm = mock.Mock(return_value="Grounded response")

    def test_rejects_unsupported_action_before_loading_asset(self):
        self.main.frontend_v2_asset_detail = mock.Mock()
        with self.assertRaises(HTTPException) as raised:
            self.main.frontend_v2_asset_assistant("asset.example", "score_asset")
        self.assertEqual(raised.exception.status_code, 400)
        self.main.frontend_v2_asset_detail.assert_not_called()
        self.main.ask_llm.assert_not_called()

    def test_requires_current_authoritative_membership(self):
        self.main.frontend_v2_asset_detail = mock.Mock(return_value={
            "error": "domain not found in current authoritative scan"
        })
        with self.assertRaises(HTTPException) as raised:
            self.main.frontend_v2_asset_assistant("historical.example", "summarize_asset")
        self.assertEqual(raised.exception.status_code, 404)
        self.main.ask_llm.assert_not_called()

    def test_explain_risk_uses_deterministic_canonical_evidence(self):
        self.main.frontend_v2_asset_detail = mock.Mock(return_value=detail(
            risk={"score": 8, "priority": "High", "reasons": ["finding", "shadow_asset"]}
        ))
        result = self.main.frontend_v2_asset_assistant("asset.example", "explain_risk")
        self.main.ask_llm.assert_not_called()
        self.assertIn("canonical risk 8 (High)", result["response"])
        self.assertIn("shadow_asset", result["response"])
        self.assertEqual(result["action"], "explain_risk")
        self.assertEqual(result["source"], "ShadowRecon deterministic evidence")
        self.assertEqual(result["mode"], "model_free")

    def test_candidate_and_external_never_receive_organizational_risk(self):
        for ownership in ("CANDIDATE", "EXTERNAL"):
            with self.subTest(ownership=ownership):
                self.main.ask_llm.reset_mock()
                self.main.frontend_v2_asset_detail = mock.Mock(return_value=detail(
                    ownership=ownership,
                    risk={"score": 12, "priority": "High", "reasons": ["finding"]},
                ))
                self.main.frontend_v2_asset_assistant("asset.example", "explain_risk")
                self.main.ask_llm.assert_not_called()
                self.assertIn(f"is {ownership} in authoritative scan", self.main.frontend_v2_asset_assistant("asset.example", "explain_risk")["response"])
                self.assertNotIn("risk 12", self.main.frontend_v2_asset_assistant("asset.example", "explain_risk")["response"])

    def test_investigation_plan_is_evidence_conditioned_and_advisory(self):
        self.main.frontend_v2_asset_detail = mock.Mock(return_value=detail())
        result = self.main.frontend_v2_asset_assistant("asset.example", "investigation_plan")
        self.main.ask_llm.assert_not_called()
        self.assertIn("no checks are launched", result["response"])
        self.assertIn("requires separate authorization", result["response"])
        self.assertTrue(result["next_actions"])

    def test_all_three_actions_work_without_provider_configuration_or_calls(self):
        self.main.frontend_v2_asset_detail = mock.Mock(return_value=detail())
        self.main.ask_llm.side_effect = RuntimeError("offline")
        with mock.patch.dict("os.environ", {}, clear=True):
            for action in ("explain_risk", "investigation_plan", "summarize_asset"):
                with self.subTest(action=action):
                    result = self.main.frontend_v2_asset_assistant("asset.example", action)
                    self.assertTrue(result["response"])
                    self.assertEqual(result["mode"], "model_free")
                    self.assertEqual(result["context"]["scan_id"], 42)
        self.main.ask_llm.assert_not_called()

    def test_partial_evidence_remains_unknown_not_clear(self):
        self.main.frontend_v2_asset_detail = mock.Mock(return_value={
            "scan_id": 42, "domain": "asset.example", "asset_class": "SHADOW",
            "ownership_status": "CONFIRMED", "dns": {"has_ip": None, "observation_available": False},
            "http": {"observation_status": "UNKNOWN", "observation_available": False},
            "ports": [], "findings": [],
        })
        result = self.main.frontend_v2_asset_assistant("asset.example", "summarize_asset")
        self.assertEqual(result["coverage"]["dns"], "UNKNOWN")
        self.assertEqual(result["coverage"]["http"], "UNKNOWN")
        self.assertIn("coverage is unknown", result["response"])

    def test_http_zero_is_not_reported_as_a_response_status(self):
        evidence = detail()
        evidence["http"] = {"observation_status": "UNKNOWN", "status": 0}
        self.main.frontend_v2_asset_detail = mock.Mock(return_value=evidence)

        result = self.main.frontend_v2_asset_assistant("asset.example", "summarize_asset")

        self.assertIn("HTTP: UNKNOWN; status=status not recorded", result["response"])
        self.assertNotIn("status=0", result["response"])
        self.assertEqual(result["coverage"]["http"], "UNKNOWN")

    def test_no_response_state_is_preserved_when_status_is_zero(self):
        evidence = detail()
        evidence["http"] = {"observation_status": "NO_RESPONSE", "status": 0}
        self.main.frontend_v2_asset_detail = mock.Mock(return_value=evidence)

        result = self.main.frontend_v2_asset_assistant("asset.example", "summarize_asset")

        self.assertIn("HTTP: NO_RESPONSE; status=status not recorded", result["response"])
        self.assertNotIn("HTTP: UNKNOWN", result["response"])
        self.assertEqual(result["coverage"]["http"], "NO_RESPONSE")

    def test_valid_http_status_codes_are_preserved(self):
        for status in (200, 302, 599):
            with self.subTest(status=status):
                evidence = detail()
                evidence["http"] = {"observation_status": "RESPONDED", "status": status}
                self.main.frontend_v2_asset_detail = mock.Mock(return_value=evidence)
                result = self.main.frontend_v2_asset_assistant("asset.example", "summarize_asset")
                self.assertIn(f"HTTP: RESPONDED; status={status}", result["response"])

    def test_dns_security_outcomes_motivate_advisory_review_without_vulnerability_claim(self):
        evidence = detail()
        evidence["dns_security"] = [{
            "check_key": "cname_health", "outcome": "WARNING",
            "severity": "MEDIUM", "confidence": "LOW",
        }]
        self.main.frontend_v2_asset_detail = mock.Mock(return_value=evidence)
        plan = self.main.frontend_v2_asset_assistant("asset.example", "investigation_plan")
        summary = self.main.frontend_v2_asset_assistant("asset.example", "summarize_asset")
        self.main.ask_llm.assert_not_called()
        self.assertIn("cname_health: WARNING", plan["response"])
        self.assertIn("not all confirmed vulnerabilities", summary["response"])


if __name__ == "__main__":
    unittest.main()
