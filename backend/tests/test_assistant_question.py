import pathlib
import sys
import importlib.util
import logging
import types
import unittest
from unittest import mock

from fastapi import HTTPException


BACKEND = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from assistant_question import answer_question, match_intent


def handlers(**overrides):
    defaults = {
        "summary": mock.Mock(return_value={
            "answer": "Scan #19 has 10 members.",
            "scan_id": 19,
            "context": {"scan_id": 19, "scan_time": "2026-11-01T00:00:00"},
            "coverage": {"asset_classification": "CURRENT_AUTHORITATIVE_SCAN"},
            "limitations": ["Candidates are separate."],
            "next_actions": ["Review inventory."],
            "total_domains": 10, "known_assets": 3, "total_shadow_assets": 4,
            "candidate_assets": 2, "external_assets": 1,
        }),
        "high_risk": mock.Mock(return_value=[]),
        "overview": mock.Mock(return_value={
            "current_scan_id": 19,
            "risk_distribution": {"High": 0, "Elevated": 2, "Review": 1, "Low": 0},
            "needs_attention": [{"domain": "elevated.example", "priority": "Elevated", "score": 7}],
        }),
        "asset_assistant": mock.Mock(return_value={
            "domain": "asset.example", "response": "Evidence-backed asset summary.",
            "mode": "model_free", "model": None,
            "context": {"scan_id": 19, "asset_class": "KNOWN"},
            "coverage": {"http": "UNKNOWN"}, "limitations": ["Some evidence is absent."],
            "next_actions": ["Review HTTP coverage."],
        }),
        "shadow_assets": mock.Mock(return_value=[{"domain": "shadow.example", "ip": "192.0.2.4"}]),
        "evidence": mock.Mock(return_value={
            "answer": "Evidence rows.", "context": {"scan_id": 19},
            "data": {"category": "ports", "items": [{"domain": "asset.example", "port": 443}],
                     "total": 1, "page": 1, "limit": 25},
            "coverage": {"meaning": "Positive rows only."},
            "limitations": ["Absence is not clearance."],
        }),
        "dns_security": mock.Mock(return_value={
            "answer": "1 assessed and 9 unchecked; 1 warning outcome.",
            "context": {"scan_id": 19},
            "data": {"eligible_assets": 10, "checked_assets": 1, "unchecked_assets": 9,
                     "distinct_affected_assets": 1,
                     "outcomes_by_check_record": {"WARNING": 1},
                     "checks": [{"outcome": "WARNING"}]},
            "coverage": {"execution_state": "SUCCEEDED"},
            "limitations": [],
        }),
        "scan_health": mock.Mock(return_value={
            "answer": "Scan #19 is SUCCEEDED.", "context": {"scan_id": 19},
            "data": {"status": "SUCCEEDED", "stage_diagnostics": {"attempts": []}},
            "coverage": {"diagnostics_available": True}, "limitations": [],
        }),
        "scan_comparison": mock.Mock(return_value={
            "answer": "Compared scans #18 and #19: 12 additions.",
            "context": {"before": {"scan_id": 18}, "after": {"scan_id": 19}},
            "data": {"added": [{"domain_id": i} for i in range(12)],
                     "removed": [], "http_dns_state_changes": []},
            "coverage": {"membership_additions_total": 12,
                         "membership_additions_returned": 12,
                         "membership_removals_total": 0,
                         "membership_removals_returned": 0,
                         "state_changes_total": 0, "state_changes_returned": 0},
            "limitations": ["Historical risk is unavailable."],
        }),
    }
    defaults.update(overrides)
    return defaults


class AssistantQuestionRoutingTests(unittest.TestCase):
    def assert_contract(self, result, intent):
        self.assertEqual(result["matched_intent"], intent)
        self.assertEqual(result["mode"], "model_free")
        self.assertIsNone(result["model"])
        self.assertEqual(result["source"], "ShadowRecon deterministic evidence")
        for field in ("answer", "data", "context", "coverage", "limitations",
                      "next_actions", "suggested_questions"):
            self.assertIn(field, result)

    def test_supported_global_intents_and_wording_variations(self):
        cases = {
            "How many assets do we have?": "attack_surface",
            "Show priority assets": "investigation_priorities",
            "Show Shadow assets": "shadow_assets",
            "Which sensitive services are exposed?": "sensitive_ports",
            "Are there DNS Security concerns?": "dns_security",
            "Which certificates need attention?": "certificates",
            "Show technology versions": "technologies",
            "Which scan stages failed?": "scan_health",
            "What changed between scans 18 and 19?": "scan_comparison",
        }
        for question, expected in cases.items():
            with self.subTest(question=question):
                self.assertEqual(match_intent(question)[0], expected)
                result = answer_question(question, "selected.example", handlers())
                self.assert_contract(result, expected)

    def test_global_inventory_is_not_restricted_by_selected_asset(self):
        deps = handlers()
        answer_question("What is our attack surface?", "selected.example", deps)
        deps["summary"].assert_called_once()
        deps["asset_assistant"].assert_not_called()

    def test_asset_intents_reuse_existing_deterministic_assistant(self):
        deps = handlers()
        cases = (
            ("Why is this domain risky?", "explain_risk"),
            ("What should I investigate next?", "investigation_plan"),
            ("Summarize this asset", "summarize_asset"),
        )
        for question, action in cases:
            result = answer_question(question, "asset.example", deps)
            self.assertEqual(result["answer"], "Evidence-backed asset summary.")
            self.assertEqual(result["context"]["scan_id"], 19)
            self.assertEqual(result["mode"], "model_free")
            self.assertEqual(deps["asset_assistant"].call_args.args, ("asset.example", action))

    def test_asset_question_requires_selection_but_global_question_does_not(self):
        deps = handlers()
        result = answer_question("Tell me about this asset", None, deps)
        self.assertEqual(result["coverage"]["asset"], "SELECTION_REQUIRED")
        deps["asset_assistant"].assert_not_called()
        global_result = answer_question("What is our attack surface?", None, deps)
        self.assertEqual(global_result["matched_intent"], "attack_surface")

    def test_empty_high_priority_result_shows_next_tier_without_relabeling(self):
        result = answer_question("Which assets need attention?", None, handlers())
        self.assertIn("No assets are classified High", result["answer"])
        self.assertEqual(result["data"]["next_priority_tier"], "Elevated")
        self.assertEqual(result["data"]["next_tier_assets"][0]["priority"], "Elevated")
        self.assertIn("not relabeled as High", result["limitations"][0])

    def test_new_shadow_question_does_not_claim_temporal_discovery(self):
        result = answer_question("Show newly discovered Shadow assets", None, handlers())
        self.assertEqual(result["data"]["total_shadow_assets"], 4)
        self.assertTrue(any("does not establish" in item for item in result["limitations"]))

    def test_dns_warning_and_missing_evidence_are_not_overstated(self):
        result = answer_question("Show DNS Security warnings", None, handlers())
        self.assertIn("do not by themselves confirm", result["answer"])
        self.assertEqual(result["data"]["unchecked_assets"], 9)

    def test_comparison_honors_explicit_ids_and_bounds_details(self):
        deps = handlers()
        result = answer_question("Compare scans 18 and 19", None, deps)
        deps["scan_comparison"].assert_called_once_with(18, 19)
        self.assertEqual(len(result["data"]["added"]), 10)
        self.assertEqual(result["coverage"]["membership_additions_total"], 12)
        self.assertEqual(result["coverage"]["membership_additions_returned"], 10)
        self.assertIn("10 details returned", result["answer"])
        self.assertNotIn("12 details returned", result["answer"])

    def test_unsupported_and_ambiguous_questions_do_not_call_handlers(self):
        deps = handlers()
        unsupported = answer_question("Can you write a penetration test?", None, deps)
        self.assertEqual(unsupported["coverage"]["routing"], "UNSUPPORTED")
        self.assertGreaterEqual(len(unsupported["suggested_questions"]), 2)
        ambiguous = answer_question("Show DNS security concerns and certificates", None, deps)
        self.assertEqual(ambiguous["coverage"]["routing"], "AMBIGUOUS")
        deps["summary"].assert_not_called()
        deps["dns_security"].assert_not_called()
        deps["evidence"].assert_not_called()

    def test_handler_calls_are_read_only_and_bounded(self):
        deps = handlers()
        answer_question("Which sensitive ports are exposed?", None, deps)
        deps["evidence"].assert_called_once_with("ports", None, 1, 25)
        answer_question("Which technologies were detected?", None, deps)
        self.assertEqual(deps["evidence"].call_args.args, ("technologies", None, 1, 25))

    def test_http_endpoint_uses_allowlisted_handlers_and_validates_domain(self):
        fake_db = types.ModuleType("db")
        fake_db.get_conn = lambda: None
        fake_db.get_latest_authoritative_scan_id = lambda cursor: 42
        fake_db.get_previous_authoritative_scan_id = lambda cursor, current=None: 41
        fake_llm = types.ModuleType("llm_service")
        fake_llm.ask_llm = mock.Mock(side_effect=AssertionError("LLM must not be called"))
        spec = importlib.util.spec_from_file_location("assistant_question_test_main", BACKEND / "main.py")
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

        fake_mcp = types.ModuleType("mcp_server")
        fake_mcp.get_summary = mock.Mock(return_value={
            "answer": "Scan #19 includes 5 assets.", "context": {"scan_id": 19},
            "total_domains": 5,
        })
        fake_mcp.high_risk = mock.Mock(return_value=[])
        fake_mcp.get_shadow_assets = mock.Mock(return_value=[])
        fake_mcp.evidence = mock.Mock()
        fake_mcp.dns_security_intelligence = mock.Mock()
        fake_mcp.scan_health = mock.Mock()
        fake_mcp.scan_comparison = mock.Mock()
        with mock.patch.dict(sys.modules, {"mcp_server": fake_mcp}):
            result = module.assistant_ask(module.AssistantQuestionRequest(
                question="What is our attack surface?", domain="selected.example"))
            self.assertEqual(result["context"]["scan_id"], 19)
            self.assertEqual(result["mode"], "model_free")
            self.assertIsNone(result["model"])
            with self.assertRaises(HTTPException) as raised:
                module.assistant_ask(module.AssistantQuestionRequest(
                    question="Summarize this asset", domain="not a hostname"))
            self.assertEqual(raised.exception.status_code, 422)

    def test_question_request_rejects_extra_fields_and_overlong_text(self):
        from pydantic import ValidationError
        spec = importlib.util.spec_from_file_location("assistant_question_test_main_model", BACKEND / "main.py")
        module = importlib.util.module_from_spec(spec)
        fake_db = types.ModuleType("db")
        fake_db.get_conn = lambda: None
        fake_db.get_latest_authoritative_scan_id = lambda cursor: None
        fake_db.get_previous_authoritative_scan_id = lambda cursor, current=None: None
        fake_llm = types.ModuleType("llm_service")
        fake_llm.ask_llm = mock.Mock()
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
        with self.assertRaises(ValidationError):
            module.AssistantQuestionRequest(question="x" * 501)
        with self.assertRaises(ValidationError):
            module.AssistantQuestionRequest(question="supported", unexpected=True)


if __name__ == "__main__":
    unittest.main()
