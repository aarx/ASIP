"""Deterministic, evidence-bound responses for the Investigate workspace."""


MAX_RESPONSE_CHARS = 3000
MAX_ACTIONS = 5


def _clean(value, limit=240):
    if value is None:
        return None
    text = " ".join(str(value).split())
    return text[:limit] if text else None


def _http_status_label(value):
    """Render only an actual HTTP status code; 0 is a storage sentinel."""
    if isinstance(value, bool):
        return "status not recorded"
    if isinstance(value, int) and 100 <= value <= 599:
        return str(value)
    return "status not recorded"


def _risk_evidence(evidence, reason):
    domain = evidence.get("domain")
    dns = evidence.get("dns") or {}
    http = evidence.get("http") or {}
    ports = evidence.get("ports") or []
    findings = evidence.get("findings") or []
    provider = evidence.get("provider")
    if reason == "new_asset":
        return f"first seen in scan {evidence.get('first_seen_scan')}"
    if reason == "http_exposed":
        return f"HTTP observation {http.get('observation_status')}, status {http.get('status')}"
    if reason == "resolves_no_http":
        return f"IP present={bool(dns.get('has_ip'))}; HTTP observation {http.get('observation_status')}"
    if reason in {"sensitive_ports", "many_ports"}:
        return ", ".join(
            f"{item.get('port')}/{item.get('service') or 'service unknown'}"
            for item in ports[:8]
        ) or "risk engine recorded this reason; port details unavailable"
    if reason == "shadow_asset":
        return f"effective class {evidence.get('asset_class')}"
    if reason == "cloud":
        return _clean(provider) or "provider detail unavailable"
    if reason.startswith("asset_exposure"):
        return domain
    if reason in {"finding", "high_finding"}:
        return "; ".join(_clean(item.get("finding"), 120) or "finding recorded"
                          for item in findings[:5]) or "finding count is present; details unavailable"
    return "canonical risk engine recorded this reason; supporting detail is unavailable"


def _response_lines(action, evidence):
    domain = _clean(evidence.get("domain"), 253) or "Selected asset"
    scan_id = evidence.get("scan_id")
    asset_class = evidence.get("asset_class") or "UNKNOWN"
    risk = evidence.get("risk")
    dns = evidence.get("dns") or {}
    http = evidence.get("http") or {}
    certificate = evidence.get("certificate")
    findings = evidence.get("findings") or []
    dns_checks = evidence.get("dns_security") or []
    ports = evidence.get("ports") or []
    technologies = evidence.get("technology_observations") or []
    if not technologies:
        technologies = [{"technology": item, "version": None} for item in
                        (evidence.get("technologies") or [])]

    if action == "explain_risk":
        if asset_class not in {"KNOWN", "SHADOW"} or not risk:
            first = (f"{domain} is {asset_class} in authoritative scan #{scan_id}. "
                     "No organizational canonical risk score applies to this asset.")
            reasons = []
        else:
            first = (f"{domain} has canonical risk {risk.get('score')} "
                     f"({risk.get('priority')}) in authoritative scan #{scan_id}.")
            reasons = list(risk.get("reasons") or [])[:10]
        lines = [first]
        if reasons:
            lines.append("Recorded scoring reasons and available evidence:")
            lines.extend(f"- {reason}: {_risk_evidence(evidence, str(reason))}"
                         for reason in reasons)
        else:
            lines.append("No risk reasons are recorded for this asset.")
        lines.append("This score prioritizes exposure indicators; it is not a confirmed vulnerability.")
        return lines

    if action == "investigation_plan":
        steps = []
        if findings:
            steps.append(("Review recorded finding evidence with the responsible asset owner.",
                          f"{len(findings)} finding record(s) are stored for scan #{scan_id}."))
        noteworthy_dns = [item for item in dns_checks if item.get("outcome") in {
            "CONFIRMED_ISSUE", "POTENTIAL_EXPOSURE", "WARNING", "INCONCLUSIVE", "NOT_CHECKED"
        }]
        if noteworthy_dns:
            labels = ", ".join(
                f"{item.get('check_key')}: {item.get('outcome')}"
                for item in noteworthy_dns[:5]
            )
            steps.append(("Review scan-scoped DNS Security evidence and verification status.", labels))
        elif evidence.get("dns_security") is None:
            steps.append(("Confirm DNS Security storage and assessment coverage for this scan.",
                          "Scan-specific DNS Security evidence is unavailable."))
        else:
            steps.append(("Check whether DNS Security assessment ran for this asset.",
                          "No DNS Security check rows are recorded; this is not a clear result."))
        if ports:
            services = ", ".join(f"{p.get('port')}/{p.get('service') or 'unknown'}" for p in ports[:5])
            steps.append(("Confirm service purpose and ownership using internal inventory.",
                          f"Observed port evidence: {services}. Any active validation requires separate authorization."))
        if certificate:
            status = certificate.get("status") or "UNKNOWN"
            if str(status).lower() not in {"valid", "ok", "clear"}:
                steps.append(("Review the stored certificate status and renewal ownership.",
                              f"Scan #{scan_id} recorded certificate status {status}; expiry values are scan observations."))
        if http.get("redirect_evidence", {}).get("first_hop_destination"):
            steps.append(("Correlate the observed redirect destination with approved application inventory.",
                          "A stored redirect destination is evidence of routing, not ownership or trust."))
        if dns.get("has_ip") is True and not ports:
            steps.append(("Review port-assessment coverage before concluding anything about exposed services.",
                          "No positive port rows are present; this does not establish that all eligible ports were assessed."))
        if not technologies:
            steps.append(("Check technology-observation coverage and use the standard authorized enrichment workflow if needed.",
                          "No technology fingerprints are present in the supplied scan evidence."))
        if not steps:
            steps.append(("Review scan coverage and correlate this asset with the internal inventory owner.",
                          "The selected scan contains no recorded finding or positive sensitive-port evidence."))
        lines = [f"Advisory plan for {domain} from scan #{scan_id} (no checks are launched):"]
        lines.extend(f"{index}. {text} Why: {why}" for index, (text, why) in enumerate(steps[:MAX_ACTIONS], 1))
        lines.append("Intrusive testing or new probes require their own authorization and are not performed by this plan.")
        return lines

    lines = [f"{domain} — {asset_class} in authoritative scan #{scan_id}."]
    lines.append(f"Ownership status: {evidence.get('ownership_status') or 'UNKNOWN'}; "
                 f"scannable: {evidence.get('scannable', 'UNKNOWN')}.")
    lines.append(f"DNS: IP present={dns.get('has_ip', 'UNKNOWN')}; IP={_clean(dns.get('ip')) or 'not recorded'}; "
                 f"reverse DNS={_clean(dns.get('reverse_dns')) or 'not recorded'}.")
    lines.append(f"HTTP: {http.get('observation_status') or 'UNKNOWN'}; status={_http_status_label(http.get('status'))}; "
                 f"redirect completion={((http.get('redirect_evidence') or {}).get('completion_status')) or 'UNKNOWN'}.")
    lines.append("Technologies: " + (", ".join(
        f"{_clean(item.get('technology')) or 'unknown'}"
        + (f" {_clean(item.get('version'))}" if item.get("version") else " version not observed")
        + (f" (confidence {item.get('confidence')})" if item.get("confidence") else "")
        for item in technologies[:10]
    ) or "none recorded; coverage is not established"))
    if certificate:
        lines.append(f"Certificate: status={certificate.get('status') or 'UNKNOWN'}, "
                     f"expiry={certificate.get('expiry_date') or 'not recorded'}, "
                     f"scan-recorded days to expiry={certificate.get('days_to_expiry') if certificate.get('days_to_expiry') is not None else 'unknown'}.")
    else:
        lines.append("Certificate: no scan-specific certificate row is available.")
    lines.append("Sensitive ports: " + (", ".join(
        f"{item.get('port')}/{item.get('service') or 'unknown'}" for item in ports[:10]
    ) if ports else "no positive port rows; assessment coverage is unknown"))
    if risk and asset_class in {"KNOWN", "SHADOW"}:
        lines.append(f"Canonical risk: {risk.get('score')} ({risk.get('priority')}); reasons="
                     + (", ".join(risk.get("reasons") or []) or "none recorded") + ".")
    else:
        lines.append("Canonical organizational risk: not applicable or unavailable for this class.")
    lines.append(f"Security findings: {len(findings)} recorded; an empty list is not proof of absence outside assessed coverage.")
    dns_checks = evidence.get("dns_security")
    if dns_checks is None:
        lines.append("DNS Security: scan-specific check data unavailable (schema or query unavailable).")
    elif dns_checks:
        dns_outcomes = ", ".join(
            f"{item.get('check_key')}={item.get('outcome')}" for item in dns_checks[:10]
        )
        lines.append("DNS Security records: " + dns_outcomes
                     + ". These are assessment outcomes, not all confirmed vulnerabilities.")
    else:
        lines.append("DNS Security: no scan-specific check rows; assessment is unverified, not clear.")
    return lines


def deterministic_asset_assistance(action, evidence):
    """Return a concise answer plus a bounded structured evidence projection."""
    lines = _response_lines(action, evidence)
    response = "\n".join(lines)[:MAX_RESPONSE_CHARS]
    return {
        "response": response,
        "context": {
            "scan_id": evidence.get("scan_id"),
            "scan_time": evidence.get("scan_time"),
            "domain": evidence.get("domain"),
            "asset_class": evidence.get("asset_class") or "UNKNOWN",
        },
        "coverage": {
            "dns": (
                "OBSERVED" if (evidence.get("dns") or {}).get("observation_available")
                else "UNKNOWN"
            ),
            "http": (evidence.get("http") or {}).get("observation_status", "UNKNOWN"),
            "certificate": "OBSERVED" if evidence.get("certificate") else "NO_SCAN_ROW",
            "ports": "POSITIVE_OBSERVATIONS" if evidence.get("ports") else "NO_POSITIVE_ROWS_COVERAGE_UNKNOWN",
            "technologies": "OBSERVED" if evidence.get("technologies") or evidence.get("technology_observations") else "NO_ROWS_COVERAGE_UNKNOWN",
            "findings": "RECORDED" if evidence.get("findings") else "NO_ROWS_COVERAGE_UNKNOWN",
            "dns_security": (
                "SCHEMA_UNAVAILABLE" if evidence.get("dns_security") is None else
                "CHECK_RECORDS_RECORDED" if evidence.get("dns_security") else
                "NO_ROWS_UNASSESSED_OR_NOT_RUN"
            ),
        },
        "limitations": [
            "Only evidence attached to the authoritative scan is summarized.",
            "Missing observations are unknown, not negative security results.",
            "Technology versions and findings do not independently establish exploitability.",
        ],
        "next_actions": [
            "Use the advisory plan for internal evidence review; it does not launch checks."
        ] if action == "investigation_plan" else [],
    }
