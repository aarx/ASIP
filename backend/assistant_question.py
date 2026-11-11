"""Small deterministic routing for supported ShadowRecon analyst questions."""

import re
import json


SUGGESTED_QUESTIONS = [
    "What is our current attack surface?",
    "Which assets need attention?",
    "Tell me about this asset",
    "Show Shadow assets",
    "Which sensitive ports are exposed?",
    "Are there DNS Security concerns?",
    "Which certificates need attention?",
    "Which technologies were detected?",
    "Did the latest scan complete?",
    "Compare the last two successful scans",
]


# Explicit phrases keep routing predictable. Order is not used to hide ambiguity:
# if a question matches more than one intent, the caller is asked to clarify.
INTENT_PHRASES = {
    "attack_surface": (
        "attack surface", "asset inventory", "how many assets",
        "assets do we have", "show asset inventory",
    ),
    "investigation_priorities": (
        "assets need attention", "asset needs attention", "priority assets",
        "highest risks", "highest risk",
        "top risks", "high risk assets", "risky assets",
    ),
    "asset_explain_risk": (
        "why is this domain risky", "why is this asset risky",
        "explain this asset risk", "explain this domain risk",
        "explain this asset's risk", "explain this domain's risk",
    ),
    "asset_investigation_plan": (
        "what should i investigate next", "what should we investigate next",
        "investigation plan for this asset", "investigate this asset next",
        "what should i check on this asset",
    ),
    "asset_summary": (
        "tell me about this asset", "tell me about this domain",
        "summarize this asset", "summarize this domain",
        "summary of this asset", "summary of this domain",
    ),
    "shadow_assets": (
        "shadow assets", "shadow asset count", "how many shadow",
        "new shadow assets", "newly discovered shadow",
    ),
    "sensitive_ports": (
        "sensitive ports", "sensitive services", "exposed ports",
        "port observations",
    ),
    "dns_security": (
        "dns security", "dns concerns", "dns warnings", "dns issues",
        "dangling dns",
    ),
    "certificates": (
        "certificates", "certificate warnings", "certificate expiry",
        "certificate expiration", "tls certificates",
        "certificates need attention",
    ),
    "technologies": (
        "technologies", "technology versions", "technology detected",
        "technology fingerprints", "software versions",
    ),
    "scan_health": (
        "scan health", "scan complete", "scan completed", "scan stages",
        "stages failed", "checks skipped", "scan failures",
    ),
    "scan_comparison": (
        "compare scans", "comparison between scans", "what changed between scans",
        "changed between scans", "last two successful scans",
    ),
}

ASSET_INTENTS = {
    "asset_explain_risk": "explain_risk",
    "asset_investigation_plan": "investigation_plan",
    "asset_summary": "summarize_asset",
}


def normalize_question(question):
    value = (question or "").replace("’", "'").replace("‘", "'").lower()
    value = re.sub(r"\s+", " ", value).strip()
    return re.sub(r"[?!.,;:]+$", "", value).strip()


def match_intent(question):
    normalized = normalize_question(question)
    matches = [intent for intent, phrases in INTENT_PHRASES.items()
               if any(phrase in normalized for phrase in phrases)]
    if len(matches) == 1:
        return matches[0], None
    if len(matches) > 1:
        return None, matches
    return None, None


def _common_response(question, intent, answer, data=None, context=None,
                     coverage=None, limitations=None, next_actions=None,
                     suggested_questions=None):
    return {
        "question": question,
        "matched_intent": intent,
        "answer": answer,
        "data": data if data is not None else {},
        "context": context if context is not None else {},
        "coverage": coverage if coverage is not None else {},
        "limitations": limitations if limitations is not None else [],
        "next_actions": next_actions if next_actions is not None else [],
        "suggested_questions": suggested_questions if suggested_questions is not None else [],
        "mode": "model_free",
        "source": "ShadowRecon deterministic evidence",
        "model": None,
    }


def _result_payload(question, intent, result, data=None, answer=None,
                    extra_limitations=None):
    if not isinstance(result, dict) and hasattr(result, "body"):
        try:
            result = json.loads(result.body)
        except (TypeError, ValueError):
            result = {"availability_state": "UNAVAILABLE"}
    if isinstance(result, dict) and result.get("availability_state") == "SCHEMA_UNAVAILABLE":
        return _common_response(
            question, intent,
            "DNS Security reporting is unavailable because its evidence schema is not installed.",
            data={"availability_state": "SCHEMA_UNAVAILABLE"},
            context={"scan_id": result.get("scan_id")},
            coverage={"state": "UNAVAILABLE"},
            limitations=[result.get("detail", "DNS Security evidence is unavailable.")],
        )
    payload = dict(result) if isinstance(result, dict) else {"results": result}
    response_answer = answer or payload.pop("answer", None) or "Stored ShadowRecon evidence is available."
    context = payload.pop("context", {})
    coverage = payload.pop("coverage", {})
    limitations = list(payload.pop("limitations", []) or [])
    actions = list(payload.pop("next_actions", []) or [])
    if extra_limitations:
        limitations.extend(extra_limitations)
    structured = data if data is not None else payload
    return _common_response(question, intent, response_answer, structured,
                            context, coverage, limitations, actions)


def _asset_action(question, intent, domain, handlers):
    if not domain:
        return _common_response(
            question, intent,
            "Select an asset from the current authoritative scan to investigate it.",
            coverage={"asset": "SELECTION_REQUIRED"},
            next_actions=["Select a current-scan Known or Shadow asset and ask again."],
        )
    result = handlers["asset_assistant"](domain, ASSET_INTENTS[intent])
    return _result_payload(question, intent, result,
                           answer=result.get("response"))


def answer_question(question, domain, handlers):
    """Route one question using only the supplied allowlisted read-only handlers."""
    normalized = normalize_question(question)
    intent, ambiguous = match_intent(question)
    if ambiguous:
        return _common_response(
            question, None,
            "That question matches more than one supported topic. Please ask about one topic at a time.",
            coverage={"routing": "AMBIGUOUS"},
            suggested_questions=[SUGGESTED_QUESTIONS[0], SUGGESTED_QUESTIONS[2],
                                SUGGESTED_QUESTIONS[5]],
        )
    if intent is None:
        return _common_response(
            question, None,
            "I cannot answer that question with the currently supported ShadowRecon evidence.",
            coverage={"routing": "UNSUPPORTED"},
            limitations=["This endpoint supports a fixed set of read-only intelligence questions."],
            suggested_questions=SUGGESTED_QUESTIONS[:4],
        )
    if intent in ASSET_INTENTS:
        return _asset_action(question, intent, domain, handlers)

    if intent == "attack_surface":
        result = handlers["summary"]()
        data = {key: value for key, value in result.items()
                if key not in ("answer", "context", "coverage", "limitations", "next_actions")}
        return _result_payload(question, intent, result, data=data)

    if intent == "investigation_priorities":
        high_assets = handlers["high_risk"]()
        if high_assets:
            return _result_payload(
                question, intent, {
                    "results": high_assets,
                    "context": {"scan_id": high_assets[0].get("scan_id")},
                    "coverage": {"risk_scope": "CURRENT_SCAN_KNOWN_AND_SHADOW_CANONICAL_RISK",
                                 "returned_limit": 20},
                    "limitations": ["The existing High-risk tool returns at most 20 ranked assets."],
                },
                data={"priority": "High", "count": len(high_assets), "assets": high_assets},
                answer=f"{len(high_assets)} High-priority organizational assets are returned from the current canonical risk ranking.",
            )
        overview = handlers["overview"]()
        if overview.get("current_scan_id") is None:
            return _result_payload(
                question, intent, overview,
                data={"risk_distribution": overview.get("risk_distribution", {}),
                      "next_priority_tier": None, "next_tier_assets": []},
                answer="No successful authoritative scan is available, so current risk priorities cannot be reported.",
                extra_limitations=["No scan-backed risk assessment is available."],
            )
        distribution = overview.get("risk_distribution", {})
        next_tier = next((tier for tier in ("Elevated", "Review", "Low")
                          if distribution.get(tier, 0) > 0), None)
        assets = [item for item in overview.get("needs_attention", [])
                  if item.get("priority") == next_tier][:10] if next_tier else []
        if next_tier:
            answer = (f"No assets are classified High priority in scan #{overview.get('current_scan_id')}. "
                      f"The next populated tier is {next_tier} ({distribution[next_tier]} assets); "
                      f"{len(assets)} ranked examples are included.")
        else:
            answer = f"No High-priority assets or populated lower risk tiers are reported in scan #{overview.get('current_scan_id')}."
        data = {"risk_distribution": distribution, "next_priority_tier": next_tier,
                "next_tier_assets": assets}
        return _result_payload(question, intent, overview, data=data, answer=answer,
                               extra_limitations=["Elevated, Review, and Low priorities are not relabeled as High."])

    if intent == "shadow_assets":
        summary = handlers["summary"]()
        assets = handlers["shadow_assets"]()
        newly = "new" in normalized or "newly discovered" in normalized
        if summary.get("scan_id") is None:
            return _result_payload(
                question, intent, summary,
                data={"availability_state": "NO_AUTHORITATIVE_SCAN", "assets": []},
                answer=summary.get("answer", "No successful authoritative scan is available."),
                extra_limitations=["No current scan is available to determine Shadow asset counts."],
            )
        count = summary.get("total_shadow_assets", summary.get("shadow_assets", 0))
        answer = (f"The current authoritative scan contains {count} Shadow assets. "
                  f"The list contains {len(assets)} current-scan Shadow assets with recorded IP evidence.")
        limitations = ["This list is bounded and includes only assets with recorded IP evidence; it is not a complete Shadow asset inventory."]
        if newly:
            limitations.append("The current Shadow listing does not establish which assets are newly discovered; no temporal Shadow-only result is available here.")
        data = {"total_shadow_assets": count, "ip_present_shadow_assets": summary.get("ip_present_shadow_assets"),
                "returned_assets": len(assets), "assets": assets}
        return _result_payload(question, intent, summary, data=data, answer=answer,
                               extra_limitations=limitations)

    capability = {
        "sensitive_ports": ("evidence", "ports"),
        "certificates": ("evidence", "certificates"),
        "technologies": ("evidence", "technologies"),
    }
    if intent in capability:
        handler_name, category = capability[intent]
        result = handlers[handler_name](category, None, 1, 25)
        result_data = result.get("data", {})
        if intent == "sensitive_ports":
            total = result_data.get("total", 0)
            answer = (f"Scan #{result.get('context', {}).get('scan_id')} has {total} persisted sensitive-port observations. "
                      "These are positive observations; no rows do not establish that all assets were assessed and clear.")
        elif intent == "certificates":
            answer = (f"Scan #{result.get('context', {}).get('scan_id')} has "
                      f"{result_data.get('total', 0)} stored certificate observations. "
                      "Days-to-expiry values are the recorded scan-time values, not recalculated today.")
        else:
            answer = (f"Scan #{result.get('context', {}).get('scan_id')} has "
                      f"{result_data.get('total', 0)} stored technology observations. "
                      "A missing version means no version was recorded, not that the software is safe.")
        limitations = None
        if intent == "certificates":
            limitations = ["These are stored observations, not a new expiry-threshold evaluation; review their recorded status and scan-time expiry fields."]
        return _result_payload(question, intent, result, answer=answer,
                               extra_limitations=limitations)

    if intent == "dns_security":
        result = handlers["dns_security"](None)
        if not isinstance(result, dict) and hasattr(result, "body"):
            try:
                result = json.loads(result.body)
            except (TypeError, ValueError):
                result = {"availability_state": "UNAVAILABLE"}
        if isinstance(result, dict) and result.get("availability_state") == "SCHEMA_UNAVAILABLE":
            return _result_payload(question, intent, result)
        data = result.get("data", {}) if isinstance(result, dict) else {}
        checks = data.get("checks", [])
        if len(checks) > 25:
            data = {**data, "checks": checks[:25], "checks_returned": 25}
        answer = result.get("answer", "DNS Security evidence is unavailable.")
        outcomes = data.get("outcomes_by_check_record", {})
        if outcomes.get("WARNING"):
            answer += " WARNING outcomes indicate items for review and do not by themselves confirm an exploitable vulnerability."
        return _result_payload(question, intent, result, data=data, answer=answer)

    if intent == "scan_health":
        result = handlers["scan_health"](None)
        scan_data = result.get("data", {})
        diagnostics = scan_data.get("stage_diagnostics")
        attempts = diagnostics.get("attempts", []) if isinstance(diagnostics, dict) else []
        if len(attempts) > 25:
            scan_data = {**scan_data, "stage_diagnostics": {**diagnostics,
                                                              "attempts": attempts[:25],
                                                              "attempts_returned": 25}}
        answer = result.get("answer", "Scan diagnostics are unavailable.")
        extra = ["Overall scan success does not establish complete per-asset assessment."]
        return _result_payload(question, intent, result, data=scan_data,
                               answer=answer, extra_limitations=extra)

    if intent == "scan_comparison":
        explicit_ids = re.search(
            r"(?:scans?\s*)?#?(\d+)\s+(?:and|to|versus|vs\.?|with)\s+#?(\d+)",
            normalized,
        )
        if explicit_ids:
            before_id, after_id = (int(explicit_ids.group(1)), int(explicit_ids.group(2)))
            result = handlers["scan_comparison"](before_id, after_id)
        else:
            result = handlers["scan_comparison"](None, None)
        data = result.get("data", {})
        bounded = {}
        for key, value in data.items():
            if isinstance(value, list):
                bounded[key] = value[:10]
            else:
                bounded[key] = value
        coverage = dict(result.get("coverage", {}))
        if bounded != data:
            coverage["question_response_detail_limit"] = 10
            for total_key, returned_key in (
                ("membership_additions_total", "membership_additions_returned"),
                ("membership_removals_total", "membership_removals_returned"),
                ("state_changes_total", "state_changes_returned"),
                ("state_changes_total", "state_change_rows_returned"),
            ):
                if total_key in coverage:
                    category = ("added" if "additions" in total_key else
                                "removed" if "removals" in total_key else
                                "http_dns_state_changes")
                    actual_returned = len(bounded.get(category, []))
                    coverage[returned_key] = actual_returned
        before_id = result.get("context", {}).get("before", {}).get("scan_id")
        after_id = result.get("context", {}).get("after", {}).get("scan_id")
        if before_id is not None and after_id is not None:
            answer = (
                f"Compared scans #{before_id} and #{after_id}: "
                f"{coverage.get('membership_additions_total', 0)} members added "
                f"({len(bounded.get('added', []))} details returned), "
                f"{coverage.get('membership_removals_total', 0)} removed "
                f"({len(bounded.get('removed', []))} details returned), and "
                f"{coverage.get('state_changes_total', 0)} HTTP/DNS state changes "
                f"({len(bounded.get('http_dns_state_changes', []))} details returned)."
            )
        else:
            answer = result.get("answer", "Scan comparison evidence is unavailable.")
        result = {**result, "coverage": coverage}
        return _result_payload(question, intent, result, data=bounded, answer=answer,
                               extra_limitations=["Returned comparison detail is limited to 10 records per category; totals describe the full comparison."])

    return _common_response(question, None, "This question is not supported.",
                            coverage={"routing": "UNSUPPORTED"},
                            suggested_questions=SUGGESTED_QUESTIONS[:4])
