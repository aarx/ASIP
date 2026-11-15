import React, { useEffect, useMemo, useState } from "react";
import { getDnsSecurityHosts, getDnsSecuritySummary } from "../services/api";
import Panel from "../components/ui/Panel";
import StatusBadge from "../components/ui/StatusBadge";
import { ErrorState, LoadingState } from "../components/ui/AsyncState";
import { displayAssetClass } from "../utils/presentation";

const DEFAULT_LIMIT = 25;
const OUTCOMES = ["CONFIRMED_ISSUE", "POTENTIAL_EXPOSURE", "WARNING", "INFORMATIONAL", "CLEAR", "NOT_CHECKED", "INCONCLUSIVE"];
const ASSET_CLASSES = ["KNOWN", "SHADOW"];
const OUTCOME_ORDER = ["CONFIRMED_ISSUE", "POTENTIAL_EXPOSURE", "WARNING", "INFORMATIONAL", "INCONCLUSIVE", "CLEAR", "NOT_CHECKED"];

function readQuery(query) {
  const params = new URLSearchParams(query);
  const requestedLimit = Number(params.get("limit"));
  return {
    page: Math.max(Number(params.get("page")) || 1, 1),
    limit: [25, 50, 100].includes(requestedLimit) ? requestedLimit : DEFAULT_LIMIT,
    outcome: params.get("outcome") || "",
    asset_class: params.get("asset_class") || "",
    search: params.get("search") || "",
  };
}

function dnsHash(filters, page = 1, limit = DEFAULT_LIMIT) {
  const params = new URLSearchParams();
  Object.entries(filters).forEach(([key, value]) => {
    if (key !== "page" && key !== "limit" && value) params.set(key, key === "search" ? value.trim() : value);
  });
  if (page > 1) params.set("page", String(page));
  if (limit !== DEFAULT_LIMIT) params.set("limit", String(limit));
  return `#/risk/dns-security${params.toString() ? `?${params}` : ""}`;
}

function readableCategory(value) {
  return String(value || "Unavailable").replaceAll("_", " ");
}

function readableValue(value, fallback = "Unavailable") {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value);
}

function EvidenceValue({ value }) {
  if (value === null || value === undefined || value === "") return <span>Unavailable</span>;
  if (Array.isArray(value)) {
    return <ul className="dns-evidence-value-list">{value.map((item, index) => <li key={index}><EvidenceValue value={item} /></li>)}</ul>;
  }
  if (typeof value === "object") {
    return (
      <dl className="dns-evidence-value-object">
        {Object.entries(value).map(([key, item]) => (
          <div key={key}><dt>{key.replaceAll("_", " ")}</dt><dd><EvidenceValue value={item} /></dd></div>
        ))}
      </dl>
    );
  }
  return <span>{String(value)}</span>;
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

function outcomeSummary(distribution) {
  return OUTCOME_ORDER.filter((outcome) => Number.isInteger(distribution?.[outcome]) && distribution[outcome] > 0)
    .map((outcome) => ({ outcome, count: distribution[outcome] }));
}

function HostEvidenceDetails({ host }) {
  return (
    <div className="dns-evidence-details">
      <div className="dns-evidence-summary">
        <span><small>Host</small><strong>{host.domain}</strong></span>
        <span><small>Asset class</small><strong>{displayAssetClass(host.asset_class)}</strong></span>
        <span><small>Checks</small><strong>{readableValue(host.check_count, "0")}</strong></span>
        <span><small>Scan ID</small><strong>{readableValue(host.scan_id)}</strong></span>
      </div>
      {host.checks?.length ? (
        <div className="dns-evidence-list">
          {host.checks.map((check, index) => (
            <section className="dns-check-detail" key={`${check.check_id || check.check_key}-${check.checked_at || index}`}>
              <div className="dns-check-heading"><strong>{readableCategory(check.check_key)}</strong><StatusBadge value={check.outcome} /></div>
              <div className="dns-evidence-grid">
                <div><small>Check type</small><strong>{readableCategory(check.check_key)}</strong></div>
                <div><small>Outcome</small><strong>{readableValue(check.outcome)}</strong></div>
                <div><small>Severity</small><strong>{readableValue(check.severity)}</strong></div>
                <div><small>Confidence</small><strong>{readableValue(check.confidence)}</strong></div>
                <div><small>Record type</small><strong>{readableValue(check.record_type)}</strong></div>
                <div><small>DNS target</small><strong className="technical-value">{readableValue(check.target)}</strong></div>
                <div className="dns-evidence-wide"><small>Evidence</small><strong className="technical-value"><EvidenceValue value={check.evidence} /></strong></div>
                <div className="dns-evidence-wide"><small>Remediation</small><strong><EvidenceValue value={check.remediation} /></strong></div>
                <div className="dns-evidence-wide"><small>Checked</small><strong>{formatTimestamp(check.checked_at)}</strong></div>
              </div>
            </section>
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
  const [hosts, setHosts] = useState(null);
  const [hostsStatus, setHostsStatus] = useState("idle");
  const [hostsRequestVersion, setHostsRequestVersion] = useState(0);
  const [selectedHost, setSelectedHost] = useState(null);

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
      setHostsStatus("idle");
      return undefined;
    }
    if (applied.search.trim().length === 1) {
      setHosts(null);
      setHostsStatus("invalid-search");
      return undefined;
    }
    let active = true;
    setHostsStatus("loading");
    const params = { scan_id: summary.scan_id, page: applied.page, limit: applied.limit };
    ["outcome", "asset_class"].forEach((key) => {
      if (applied[key]) params[key] = applied[key];
    });
    if (applied.search.trim()) {
      params.search = applied.search.trim();
      params.search_mode = "fragment";
    }
    getDnsSecurityHosts(params)
      .then((result) => {
        if (!active) return;
        if (isUnavailableResponse(result)) {
          setHosts(null);
          setHostsStatus("unavailable");
        } else {
          setHosts(result);
          setHostsStatus(result?.availability_state === "AVAILABLE" ? "ready" : "unavailable");
        }
      })
      .catch((error) => {
        if (active) {
          setHosts(null);
          setHostsStatus(isUnavailableResponse(error) ? "unavailable" : "error");
        }
      });
    return () => { active = false; };
  }, [applied, hostsRequestVersion, summary]);

  useEffect(() => {
    setSelectedHost(null);
  }, [applied.page, applied.limit, applied.outcome, applied.asset_class, applied.search]);

  const applyFilters = (event) => {
    event.preventDefault();
    window.location.hash = dnsHash({ ...draft, search: draft.search.trim() }, 1, draft.limit);
  };
  const clearFilters = () => {
    setDraft({ page: 1, limit: DEFAULT_LIMIT, outcome: "", asset_class: "", search: "" });
    window.location.hash = dnsHash({}, 1, DEFAULT_LIMIT);
  };
  const movePage = (page) => { window.location.hash = dnsHash(applied, page, applied.limit); };
  const changeLimit = (event) => { window.location.hash = dnsHash(applied, 1, Number(event.target.value)); };

  if (summaryStatus === "loading") return <LoadingState title="Loading DNS Security" copy="Reading the current authoritative DNS assessment." />;
  if (summaryStatus === "error" || summaryStatus === "unavailable") return <ErrorState title="DNS Security unavailable" copy="The DNS Security reporting service could not provide assessment data." onRetry={() => setSummaryRequestVersion((value) => value + 1)} />;
  if (!summary) return <ErrorState title="DNS Security unavailable" copy="No DNS Security summary was returned." onRetry={() => setSummaryRequestVersion((value) => value + 1)} />;

  const total = Number.isInteger(hosts?.total) && hosts.total >= 0 ? hosts.total : null;
  const totalPages = total === null ? null : Math.max(Math.ceil(total / applied.limit), 1);
  const hasFilters = Boolean(draft.outcome || draft.asset_class || draft.search.trim());

  return (
    <div className="dns-security-page">
      <DnsSummary summary={summary} />

      <Panel title="DNS assessments by host" meta={`SCAN #${summary.scan_id}`} className="dns-findings-panel">
        <form className="dns-filter-panel" onSubmit={applyFilters}>
          <FilterSelect label="Outcome" value={draft.outcome} options={OUTCOMES.map((value) => [value, value])} onChange={(event) => setDraft((current) => ({ ...current, outcome: event.target.value }))} />
          <FilterSelect label="Asset class" value={draft.asset_class} options={ASSET_CLASSES.map((value) => [value, displayAssetClass(value)])} onChange={(event) => setDraft((current) => ({ ...current, asset_class: event.target.value }))} />
          <label className="dns-filter-control"><span>Hostname</span><input aria-label="Hostname" type="search" value={draft.search} onChange={(event) => setDraft((current) => ({ ...current, search: event.target.value }))} placeholder="Search hostnames" /></label>
          <div className="dns-filter-actions"><button type="submit" className="dns-primary-action">Apply</button><button type="button" className="dns-secondary-action" onClick={clearFilters} disabled={!hasFilters}>Clear</button></div>
        </form>

        {hostsStatus === "loading" && <div className="dns-table-state" role="status">Loading DNS host assessments…</div>}
        {hostsStatus === "invalid-search" && <div className="dns-table-state" role="alert">Enter at least 2 characters to search hostnames.</div>}
        {(hostsStatus === "error" || hostsStatus === "unavailable") && <ErrorState title="DNS host assessments unavailable" copy="The DNS host assessment request could not be loaded." onRetry={() => setHostsRequestVersion((value) => value + 1)} />}
        {hostsStatus === "ready" && (
          hosts?.hosts?.length ? (
            <div className="dense-table-wrap dns-table-wrap">
              <table className="dense-table dns-host-table">
                <thead><tr><th>Hostname</th><th>Asset class</th><th>Checks</th><th>Outcome summary</th><th>Assessment</th></tr></thead>
                <tbody>
                  {hosts.hosts.map((host) => {
                    const expanded = selectedHost?.domain_id === host.domain_id;
                    return (
                      <React.Fragment key={host.domain_id}>
                        <tr className={expanded ? "dns-finding-row-expanded" : ""}>
                          <td><button type="button" className="dns-domain-button" aria-label={`${expanded ? "Collapse" : "Expand"} DNS checks for ${host.domain}`} aria-expanded={expanded} aria-controls={`dns-evidence-${host.domain_id}`} onClick={() => setSelectedHost((current) => current?.domain_id === host.domain_id ? null : host)}>{host.domain}</button></td>
                          <td><StatusBadge value={displayAssetClass(host.asset_class)} /></td>
                          <td><strong>{host.check_count}</strong></td>
                          <td><div className="dns-outcome-summary">{outcomeSummary(host.outcome_distribution).map(({ outcome, count }) => <span className="dns-outcome-count" key={outcome}><StatusBadge value={outcome} /> <strong>{count}</strong></span>)}</div></td>
                          <td>{readableValue(host.assessment_state).replaceAll("_", " ")}</td>
                        </tr>
                        {expanded && <tr id={`dns-evidence-${host.domain_id}`}><td colSpan="5"><HostEvidenceDetails host={host} /></td></tr>}
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : <div className="dns-table-state">{total === null ? "Result count unavailable" : hasFilters ? "No matching hosts" : summary.checked_assets === 0 ? "Not Assessed" : Number.isInteger(summary.checked_assets) ? "No DNS host assessments recorded for the assessed assets" : "Assessment coverage unavailable"}</div>
        )}

        {hostsStatus === "ready" && total > 0 && (
          <div className="pagination-bar dns-pagination">
            <span>Page {applied.page} of {totalPages} · {total.toLocaleString()} matching hosts</span>
            <div><label className="dns-page-size">Page size<select aria-label="Page size" value={applied.limit} onChange={changeLimit}><option value="25">25</option><option value="50">50</option><option value="100">100</option></select></label><button type="button" className="dns-secondary-action" disabled={applied.page <= 1} onClick={() => movePage(applied.page - 1)}>Previous</button><button type="button" className="dns-secondary-action" disabled={applied.page >= totalPages} onClick={() => movePage(applied.page + 1)}>Next</button></div>
          </div>
        )}
      </Panel>
    </div>
  );
}
