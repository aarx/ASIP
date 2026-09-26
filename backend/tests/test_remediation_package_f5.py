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

    def test_explain_risk_grounds_prompt_in_canonical_values(self):
        self.main.frontend_v2_asset_detail = mock.Mock(return_value=detail(
            risk={"score": 8, "priority": "High", "reasons": ["finding", "shadow_asset"]}
        ))
        result = self.main.frontend_v2_asset_assistant("asset.example", "explain_risk")
        prompt = self.main.ask_llm.call_args.args[0]

        self.assertIn('"score": 8', prompt)
        self.assertIn('"priority": "High"', prompt)
        self.assertIn('"shadow_asset"', prompt)
        self.assertIn("Never calculate, modify, or infer a risk score", prompt)
        self.assertEqual(result["action"], "explain_risk")
        self.assertEqual(result["source"], "ASIP deterministic evidence + Gemma")

    def test_candidate_and_external_never_receive_organizational_risk(self):
        for ownership in ("CANDIDATE", "EXTERNAL"):
            with self.subTest(ownership=ownership):
                self.main.ask_llm.reset_mock()
                self.main.frontend_v2_asset_detail = mock.Mock(return_value=detail(
                    ownership=ownership,
                    risk={"score": 12, "priority": "High", "reasons": ["finding"]},
                ))
                self.main.frontend_v2_asset_assistant("asset.example", "explain_risk")
                prompt = self.main.ask_llm.call_args.args[0]
                self.assertIn(f'"ownership_status": "{ownership}"', prompt)
                self.assertIn('"risk": null', prompt)
                self.assertNotIn('"score": 12', prompt)

    def test_investigation_plan_prompt_is_passive_only(self):
        self.main.frontend_v2_asset_detail = mock.Mock(return_value=detail())
        self.main.frontend_v2_asset_assistant("asset.example", "investigation_plan")
        prompt = self.main.ask_llm.call_args.args[0].lower()
        for prohibited in (
            "network requests", "scanning", "probing", "exploitation",
            "brute force", "authentication attempts", "resource claiming",
            "destructive actions", "authorization changes",
        ):
            self.assertIn(prohibited, prompt)
        self.assertIn("passive review", prompt)

    def test_llm_failure_is_a_clean_gateway_error(self):
        self.main.frontend_v2_asset_detail = mock.Mock(return_value=detail())
        for failure in ("LLM request failed: timeout", "", None):
            with self.subTest(failure=failure):
                self.main.ask_llm = mock.Mock(return_value=failure)
                with self.assertRaises(HTTPException) as raised:
                    self.main.frontend_v2_asset_assistant("asset.example", "summarize_asset")
                self.assertEqual(raised.exception.status_code, 502)

        self.main.ask_llm = mock.Mock(side_effect=RuntimeError("offline"))
        with self.assertRaises(HTTPException) as raised:
            self.main.frontend_v2_asset_assistant("asset.example", "summarize_asset")
        self.assertEqual(raised.exception.status_code, 502)


if __name__ == "__main__":
    unittest.main()
