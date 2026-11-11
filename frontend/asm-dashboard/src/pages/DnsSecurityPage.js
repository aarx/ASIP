import React, { useEffect, useMemo, useState } from "react";
import { getDnsSecurityDomainEvidence, getDnsSecurityFindings, getDnsSecuritySummary } from "../services/api";
import Panel from "../components/ui/Panel";
import StatusBadge from "../components/ui/StatusBadge";
import { ErrorState, LoadingState } from "../components/ui/AsyncState";
import { displayAssetClass } from "../utils/presentation";

const DEFAULT_LIMIT = 25;
const OUTCOMES = ["CONFIRMED_ISSUE", "POTENTIAL_EXPOSURE", "WARNING", "INFORMATIONAL", "CLEAR", "NOT_CHECKED", "INCONCLUSIVE"];
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"];
const CONFIDENCE = ["HIGH", "MEDIUM", "LOW", "UNKNOWN"];
const ASSET_CLASSES = ["KNOWN", "SHADOW"];
const CATEGORIES = [
  ["dns_a_resolution", "A resolution"],
  ["dns_aaaa_resolution", "AAAA resolution"],
  ["cname_health", "CNAME health"],
  ["mx_observation", "MX observation"],
  ["mx_target", "MX target"],
  ["spf_configuration", "SPF configuration"],
  ["dmarc_configuration", "DMARC configuration"],
];

function readQuery(query) {
  const params = new URLSearchParams(query);
  const requestedLimit = Number(params.get("limit"));
  return {
    page: Math.max(Number(params.get("page")) || 1, 1),
    limit: [25, 50, 100].includes(requestedLimit) ? requestedLimit : DEFAULT_LIMIT,
    category: params.get("category") || "",
    outcome: params.get("outcome") || "",
    severity: params.get("severity") || "",
    confidence: params.get("confidence") || "",
    asset_class: params.get("asset_class") || "",
  };
}

function dnsHash(filters, page = 1, limit = DEFAULT_LIMIT) {
  const params = new URLSearchParams();
  Object.entries(filters).forEach(([key, value]) => {
    if (key !== "page" && key !== "limit" && value) params.set(key, value);
  });
  if (page > 1) params.set("page", String(page));
  if (limit !== DEFAULT_LIMIT) params.set("limit", String(limit));
  return `#/risk/dns-security${params.toString() ? `?${params}` : ""}`;
}

function readableCategory(value) {
  return CATEGORIES.find(([key]) => key === value)?.[1] || String(value || "Unavailable").replaceAll("_", " ");
}

function readableValue(value, fallback = "Unavailable") {
  if (value === null || value === undefined || value === "") return fallback;
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function formatTimestamp(value) {
  if (!value) return "Unavailable";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "Unavailable" : parsed.toLocaleString();
}

function countValue(value) {
  return Number.isInteger(value) && value >= 0 ? value.toLocaleString() : "Unavailable";
}

function isUnavailableResponse(errorOrValue) {
  return errorOrValue?.response?.status === 503 || errorOrValue?.availability_state === "SCHEMA_UNAVAILABLE";
}

function FilterSelect({ label, value, options, onChange }) {
  return (
    <label className="dns-filter-control">
      <span>{label}</span>
      <select aria-label={label} value={value} onChange={onChange}>
        <option value="">All</option>
        {options.map(([optionValue, optionLabel]) => <option value={optionValue} key={optionValue}>{optionLabel}</option>)}
      </select>
    </label>
  );
}

function SummaryMetric({ label, value }) {
  return <div className="dns-summary-metric"><span>{label}</span><strong>{countValue(value)}</strong></div>;
}

function DnsSummary({ summary }) {
  const checked = Number.isInteger(summary.checked_assets) ? summary.checked_assets : null;
  const eligible = Number.isInteger(summary.eligible_assets) ? summary.eligible_assets : null;
  const affected = Number.isInteger(summary.affected_assets) ? summary.affected_assets : null;
  const partial = checked != null && eligible != null && checked > 0 && checked < eligible;
  const inconclusive = Number(summary.counts_by_outcome?.INCONCLUSIVE) > 0;

  let coverageMessage;
  if (checked === 0) {
    coverageMessage = <div className="dns-assessment-callout dns-assessment-not-assessed"><strong>Not Assessed</strong><span>No DNS checks have been executed for this scan.</span></div>;
  } else if (checked == null || eligible == null || affected == null) {
    coverageMessage = <div className="dns-assessment-callout"><strong>Assessment coverage unavailable</strong><span>The summary did not include enough coverage data to classify the assessment.</span></div>;
  } else if (partial) {
    coverageMessage = <div className="dns-assessment-callout"><strong>Partial assessment coverage</strong><span>{checkedValue(checked)} of {checkedValue(eligible)} eligible assets assessed.</span></div>;
  } else if (affected != null && affected > 0) {
    coverageMessage = <div className="dns-assessment-callout dns-assessment-attention"><strong>Actionable findings recorded</strong><span>{checkedValue(affected)} assessed assets have actionable DNS findings.</span></div>;
  } else {
    coverageMessage = <div className="dns-assessment-callout"><strong>No actionable findings recorded for the assessed assets</strong><span>{inconclusive ? "Inconclusive outcomes remain; this is not a validation of clear DNS." : "Assessment coverage is reported separately from finding totals."}</span></div>;
  }

  return (
    <Panel title="DNS assessment summary" meta={`SCAN #${summary.scan_id}`} className="dns-summary-panel">
      <div className="dns-summary-metrics" aria-label="DNS assessment summary metrics">
        <SummaryMetric label="Eligible Assets" value={summary.eligible_assets} />
        <SummaryMetric label="Assessed Assets" value={summary.checked_assets} />
        <SummaryMetric label="Not Assessed" value={summary.unchecked_assets} />
        <SummaryMetric label="Affected Assets" value={summary.affected_assets} />
      </div>
      <div className="dns-status-strip" aria-label="DNS assessment status">
        <span><small>Availability</small><strong>{readableValue(summary.availability_state)}</strong></span>
        <span><small>Execution</small><strong>{readableValue(summary.execution_state)}</strong></span>
        <span><small>Operation currently</small><strong>{summary.operation_enabled_currently === true ? "Enabled" : summary.operation_enabled_currently === false ? "Disabled" : "Unavailable"}</strong></span>
      </div>
      {coverageMessage}
    </Panel>
  );
}

function checkedValue(value) {
  return Number.isInteger(value) ? value.toLocaleString() : "Unavailable";
}

function EvidenceDetails({ detail, status, onRetry }) {
  if (status === "loading") return <div className="dns-detail-state" role="status">Loading DNS evidence…</div>;
  if (status === "error" || status === "unavailable") {
    return (
      <div className="dns-detail-state" role="alert">
        <strong>DNS evidence unavailable</strong>
        <button type="button" className="dns-inline-action" onClick={onRetry}>Retry</button>
      </div>
    );
  }
  if (!detail) return null;
  return (
    <div className="dns-evidence-details">
      <div className="dns-evidence-summary">
        <span><small>Domain</small><strong>{detail.domain}</strong></span>
        <span><small>Asset class</small><strong>{displayAssetClass(detail.asset_class)}</strong></span>
        <span><small>Scan ID</small><strong>{readableValue(detail.scan_id)}</strong></span>
        <span><small>Execution</small><strong>{readableValue(detail.execution_state)}</strong></span>
      </div>
      {detail.checks?.length ? (
        <div className="dns-evidence-list">
          {detail.checks.map((check, index) => (
            <details key={`${check.category}-${check.checked_at || index}`}>
              <summary>
                <span>{readableCategory(check.category)}</span>
                <StatusBadge value={check.outcome} />
              </summary>
              <div className="dns-evidence-grid">
                <div><small>Check type</small><strong>{readableCategory(check.category)}</strong></div>
                <div><small>Outcome</small><strong>{readableValue(check.outcome)}</strong></div>
                <div><small>Severity</small><strong>{readableValue(check.severity)}</strong></div>
                <div><small>Confidence</small><strong>{readableValue(check.confidence)}</strong></div>
                <div><small>Record type</small><strong>{readableValue(check.record_type)}</strong></div>
                <div><small>DNS target</small><strong className="technical-value">{readableValue(check.target)}</strong></div>
                <div className="dns-evidence-wide"><small>Evidence</small><strong className="technical-value">{readableValue(check.evidence)}</strong></div>
                <div className="dns-evidence-wide"><small>Remediation</small><strong>{readableValue(check.remediation)}</strong></div>
                <div className="dns-evidence-wide"><small>Checked</small><strong>{formatTimestamp(check.checked_at)}</strong></div>
              </div>
            </details>
          ))}
        </div>
      ) : <div className="dns-detail-empty">No DNS checks recorded for this asset.</div>}
    </div>
  );
}

export default function DnsSecurityPage({ query }) {
  const applied = useMemo(() => readQuery(query), [query]);
  const [draft, setDraft] = useState(applied);
  const [summary, setSummary] = useState(null);
  const [summaryStatus, setSummaryStatus] = useState("loading");
  const [summaryRequestVersion, setSummaryRequestVersion] = useState(0);
  const [findings, setFindings] = useState(null);
  const [findingsStatus, setFindingsStatus] = useState("idle");
  const [findingsRequestVersion, setFindingsRequestVersion] = useState(0);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [evidenceCache, setEvidenceCache] = useState({});
  const [evidenceStatus, setEvidenceStatus] = useState({});
  const [evidenceRequestVersion, setEvidenceRequestVersion] = useState(0);

  useEffect(() => setDraft(applied), [applied]);

  useEffect(() => {
    let active = true;
    setSummaryStatus("loading");
    getDnsSecuritySummary()
      .then((result) => {
        if (!active) return;
        if (isUnavailableResponse(result)) {
          setSummary(null);
          setSummaryStatus("unavailable");
        } else {
          setSummary(result);
          setSummaryStatus(result?.availability_state === "AVAILABLE" ? "ready" : "unavailable");
        }
      })
      .catch((error) => {
        if (active) {
          setSummary(null);
          setSummaryStatus(isUnavailableResponse(error) ? "unavailable" : "error");
        }
      });
    return () => { active = false; };
  }, [summaryRequestVersion]);

  useEffect(() => {
    if (!summary?.scan_id || summary.availability_state !== "AVAILABLE") {
      setFindingsStatus("idle");
      return undefined;
    }
    let active = true;
    setFindingsStatus("loading");
    const params = { scan_id: summary.scan_id, page: applied.page, limit: applied.limit };
    ["category", "outcome", "severity", "confidence", "asset_class"].forEach((key) => {
      if (applied[key]) params[key] = applied[key];
    });
    getDnsSecurityFindings(params)
      .then((result) => {
        if (!active) return;
        if (isUnavailableResponse(result)) {
          setFindings(null);
          setFindingsStatus("unavailable");
        } else {
          setFindings(result);
          setFindingsStatus(result?.availability_state === "AVAILABLE" ? "ready" : "unavailable");
        }
      })
      .catch((error) => {
        if (active) {
          setFindings(null);
          setFindingsStatus(isUnavailableResponse(error) ? "unavailable" : "error");
        }
      });
    return () => { active = false; };
  }, [applied, findingsRequestVersion, summary]);

  useEffect(() => {
    setSelectedFinding(null);
  }, [applied.page, applied.limit, applied.category, applied.outcome, applied.severity, applied.confidence, applied.asset_class]);

  useEffect(() => {
    if (!selectedFinding || !summary?.scan_id) return undefined;
    const key = `${summary.scan_id}:${selectedFinding.domain_id}`;
    if (evidenceCache[key]) return undefined;
    let active = true;
    setEvidenceStatus((current) => ({ ...current, [key]: "loading" }));
    getDnsSecurityDomainEvidence(selectedFinding.domain_id, summary.scan_id)
      .then((result) => {
        if (!active) return;
        if (isUnavailableResponse(result)) {
          setEvidenceStatus((current) => ({ ...current, [key]: "unavailable" }));
        } else {
          setEvidenceCache((current) => ({ ...current, [key]: result }));
          setEvidenceStatus((current) => ({ ...current, [key]: "ready" }));
        }
      })
      .catch((error) => {
        if (active) setEvidenceStatus((current) => ({ ...current, [key]: isUnavailableResponse(error) ? "unavailable" : "error" }));
      });
    return () => { active = false; };
  }, [evidenceRequestVersion, evidenceCache, selectedFinding, summary]);

  const applyFilters = (event) => {
    event.preventDefault();
    window.location.hash = dnsHash(draft, 1, draft.limit);
  };
  const clearFilters = () => { window.location.hash = dnsHash({}, 1, DEFAULT_LIMIT); };
  const movePage = (page) => { window.location.hash = dnsHash(applied, page, applied.limit); };
  const changeLimit = (event) => { window.location.hash = dnsHash(applied, 1, Number(event.target.value)); };
  const toggleFinding = (finding) => {
    setSelectedFinding((current) => current?.check_id === finding.check_id ? null : finding);
  };

  if (summaryStatus === "loading") return <LoadingState title="Loading DNS Security" copy="Reading the current authoritative DNS assessment." />;
  if (summaryStatus === "error" || summaryStatus === "unavailable") return <ErrorState title="DNS Security unavailable" copy="The DNS Security reporting service could not provide assessment data." onRetry={() => setSummaryRequestVersion((value) => value + 1)} />;
  if (!summary) return <ErrorState title="DNS Security unavailable" copy="No DNS Security summary was returned." onRetry={() => setSummaryRequestVersion((value) => value + 1)} />;

  const total = Number.isInteger(findings?.total) ? findings.total : 0;
  const totalPages = Math.max(Math.ceil(total / applied.limit), 1);
  const hasFilters = Boolean(applied.category || applied.outcome || applied.severity || applied.confidence || applied.asset_class);

  return (
    <div className="dns-security-page">
      <DnsSummary summary={summary} />

      <Panel title="DNS check results" meta={`SCAN #${summary.scan_id}`} className="dns-findings-panel">
        <form className="dns-filter-panel" onSubmit={applyFilters}>
          <FilterSelect label="Category" value={draft.category} options={CATEGORIES} onChange={(event) => setDraft((current) => ({ ...current, category: event.target.value }))} />
          <FilterSelect label="Outcome" value={draft.outcome} options={OUTCOMES.map((value) => [value, value])} onChange={(event) => setDraft((current) => ({ ...current, outcome: event.target.value }))} />
          <FilterSelect label="Severity" value={draft.severity} options={SEVERITIES.map((value) => [value, value])} onChange={(event) => setDraft((current) => ({ ...current, severity: event.target.value }))} />
          <FilterSelect label="Confidence" value={draft.confidence} options={CONFIDENCE.map((value) => [value, value])} onChange={(event) => setDraft((current) => ({ ...current, confidence: event.target.value }))} />
          <FilterSelect label="Asset class" value={draft.asset_class} options={ASSET_CLASSES.map((value) => [value, displayAssetClass(value)])} onChange={(event) => setDraft((current) => ({ ...current, asset_class: event.target.value }))} />
          <div className="dns-filter-actions"><button type="submit" className="dns-primary-action">Apply</button><button type="button" className="dns-secondary-action" onClick={clearFilters} disabled={!hasFilters}>Clear</button></div>
        </form>

        {findingsStatus === "loading" && <div className="dns-table-state" role="status">Loading DNS check results…</div>}
        {(findingsStatus === "error" || findingsStatus === "unavailable") && <ErrorState title="DNS check results unavailable" copy="The DNS check results request could not be loaded." onRetry={() => setFindingsRequestVersion((value) => value + 1)} />}
        {findingsStatus === "ready" && (
          findings?.findings?.length ? (
            <div className="dense-table-wrap dns-table-wrap">
              <table className="dense-table dns-findings-table">
                <thead><tr><th>Domain</th><th>Check</th><th>Outcome</th><th>Severity</th><th>Confidence</th><th>Record / Target</th><th>Last Checked</th></tr></thead>
                <tbody>
                  {findings.findings.map((finding) => {
                    const expanded = selectedFinding?.check_id === finding.check_id;
                    const key = `${summary.scan_id}:${finding.domain_id}`;
                    return (
                      <React.Fragment key={finding.check_id}>
                        <tr className={expanded ? "dns-finding-row-expanded" : ""}>
                          <td><button type="button" className="dns-domain-button" aria-label={`${expanded ? "Hide" : "Show"} DNS evidence for ${finding.domain}`} aria-expanded={expanded} aria-controls={`dns-evidence-${finding.check_id}`} onClick={() => toggleFinding(finding)}>{finding.domain}</button></td>
                          <td>{readableCategory(finding.category)}</td>
                          <td><StatusBadge value={finding.outcome} /></td>
                          <td><StatusBadge value={finding.severity} /></td>
                          <td><StatusBadge value={finding.confidence} /></td>
                          <td><span className="technical-value">{readableValue(finding.record_type)}{finding.target ? ` · ${finding.target}` : ""}</span></td>
                          <td>{formatTimestamp(finding.checked_at)}</td>
                        </tr>
                        {expanded && <tr id={`dns-evidence-${finding.check_id}`}><td colSpan="7"><EvidenceDetails detail={evidenceCache[key]} status={evidenceStatus[key] || "loading"} onRetry={() => setEvidenceRequestVersion((value) => value + 1)} /></td></tr>}
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : <div className="dns-table-state">{hasFilters ? "No matching results" : summary.checked_assets === 0 ? "Not Assessed" : Number.isInteger(summary.checked_assets) ? "No actionable findings recorded for the assessed assets" : "Assessment coverage unavailable"}</div>
        )}

        {findingsStatus === "ready" && total > 0 && (
          <div className="pagination-bar dns-pagination">
            <span>Page {applied.page} of {totalPages} · {total.toLocaleString()} matching</span>
            <div><label className="dns-page-size">Page size<select aria-label="Page size" value={applied.limit} onChange={changeLimit}><option value="25">25</option><option value="50">50</option><option value="100">100</option></select></label><button type="button" className="dns-secondary-action" disabled={applied.page <= 1} onClick={() => movePage(applied.page - 1)}>Previous</button><button type="button" className="dns-secondary-action" disabled={applied.page >= totalPages} onClick={() => movePage(applied.page + 1)}>Next</button></div>
          </div>
        )}
      </Panel>
    </div>
  );
}
