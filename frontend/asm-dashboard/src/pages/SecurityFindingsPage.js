import React, { useEffect, useMemo, useState } from "react";
import AssetLink from "../components/ui/AssetLink";
import MetricCard from "../components/ui/MetricCard";
import Panel from "../components/ui/Panel";
import StatusBadge from "../components/ui/StatusBadge";
import { EmptyState, ErrorState, LoadingState } from "../components/ui/AsyncState";
import { getCertificateHosts, getDnsSecurityHosts, getSecurityFindings, getSecurityFindingsSummary, getSensitivePortHosts } from "../services/api";

const PAGE_SIZES = [25, 50, 100];
const VIEW_OPTIONS = [
  ["attention", "Needs attention"],
  ["signals", "Exposure signals"],
  ["all", "All evidence"],
];
const CATEGORY_OPTIONS = [
  ["", "All categories"],
  ["FINDING", "Recorded Findings"],
  ["NEEDS_VERIFICATION", "Needs verification"],
  ["EXPOSURE_SIGNAL", "Exposure signals"],
];
const SOURCE_LABELS = {
  domain_findings: "Recorded Findings",
  dns_security_checks: "DNS Security",
  domain_cert: "Certificates",
  redirect_review: "Redirects",
  domain_ports: "Sensitive ports",
  naming_indicator: "Naming indicators",
  shadow_asset: "Shadow assets",
};
const SOURCE_OPTIONS = [
  ["", "All sources"],
  ...Object.entries(SOURCE_LABELS),
];
const ASSET_CLASS_OPTIONS = [["", "All asset classes"], ["KNOWN", "Known"], ["SHADOW", "Shadow"]];

function readFilters(query) {
  const params = new URLSearchParams(query);
  const pageSize = PAGE_SIZES.includes(Number(params.get("limit"))) ? Number(params.get("limit")) : 25;
  const view = VIEW_OPTIONS.some(([value]) => value === params.get("view")) ? params.get("view") : "attention";
  const category = CATEGORY_OPTIONS.some(([value]) => value === (params.get("category") || "")) ? (params.get("category") || "") : "";
  const source = SOURCE_OPTIONS.some(([value]) => value === (params.get("source") || "")) ? (params.get("source") || "") : "";
  const assetClass = ASSET_CLASS_OPTIONS.some(([value]) => value === (params.get("asset_class") || "")) ? (params.get("asset_class") || "") : "";
  const coverageCategory = ["dns", "certificates", "ports"].includes(params.get("coverage")) ? params.get("coverage") : "";
  const coverageMode = ["domain", "exact", "fragment"].includes(params.get("coverage_mode")) ? params.get("coverage_mode") : "domain";
  return {
    page: Math.max(Number(params.get("page")) || 1, 1),
    pageSize,
    view,
    category,
    source,
    assetClass,
    coverageCategory,
    coverageSearch: (params.get("coverage_search") || "").slice(0, 253),
    coverageMode,
    coveragePage: Math.max(Number(params.get("coverage_page")) || 1, 1),
    dnsIncludeUnassessed: params.get("dns_include_unassessed") === "true",
    certificatesIncludeUnobserved: params.get("certificates_include_unobserved") === "true",
  };
}

function queryForFilters(filters, tab = null) {
  const params = new URLSearchParams();
  if (tab) params.set("tab", tab);
  if (filters.page > 1) params.set("page", String(filters.page));
  if (filters.pageSize !== 25) params.set("limit", String(filters.pageSize));
  if (filters.view !== "attention") params.set("view", filters.view);
  if (filters.category) params.set("category", filters.category);
  if (filters.source) params.set("source", filters.source);
  if (filters.assetClass) params.set("asset_class", filters.assetClass);
  if (filters.coverageCategory) params.set("coverage", filters.coverageCategory);
  if (filters.coverageSearch) params.set("coverage_search", filters.coverageSearch);
  if (filters.coverageCategory) params.set("coverage_mode", filters.coverageMode);
  if (filters.coveragePage > 1) params.set("coverage_page", String(filters.coveragePage));
  if (filters.dnsIncludeUnassessed) params.set("dns_include_unassessed", "true");
  if (filters.certificatesIncludeUnobserved) params.set("certificates_include_unobserved", "true");
  return params.toString();
}

function updateFilters(filters, routePrefix = "risk/findings", tab = null) {
  const query = queryForFilters(filters, tab);
  window.location.hash = `#/${routePrefix}${query ? `?${query}` : ""}`;
}

function updateCoverageFilters(filters, routePrefix = "risk/findings", tab = null) {
  const query = queryForFilters(filters, tab);
  window.location.hash = `#/${routePrefix}${query ? `?${query}` : ""}`;
}

function sourceLabel(source) {
  return SOURCE_LABELS[source] || source || "Unknown source";
}

function categoryLabel(category) {
  return category === "FINDING" ? "Recorded finding"
    : category === "NEEDS_VERIFICATION" ? "Needs verification"
      : category === "EXPOSURE_SIGNAL" ? "Exposure signal" : "Unknown category";
}

function displayOptional(value, fallback = "Not recorded") {
  return value === null || value === undefined || value === "" ? fallback : String(value);
}

function EvidenceValue({ value, depth = 0 }) {
  if (value === null || value === undefined || value === "") return <span className="not-applicable">Not recorded</span>;
  if (depth >= 3) return <span className="technical-value">{String(value)}</span>;
  if (Array.isArray(value)) {
    if (!value.length) return <span className="not-applicable">None recorded</span>;
    return (
      <ul className="finding-evidence-list">
        {value.slice(0, 20).map((item, index) => <li key={index}><EvidenceValue value={item} depth={depth + 1} /></li>)}
        {value.length > 20 && <li className="not-applicable">{value.length - 20} more entries not shown</li>}
      </ul>
    );
  }
  if (typeof value === "object") {
    const entries = Object.entries(value);
    if (!entries.length) return <span className="not-applicable">No structured evidence recorded</span>;
    return (
      <dl className="finding-evidence-grid">
        {entries.slice(0, 20).map(([key, item]) => (
          <div key={key}><dt>{key.replaceAll("_", " ")}</dt><dd><EvidenceValue value={item} depth={depth + 1} /></dd></div>
        ))}
        {entries.length > 20 && <div><dt>Additional fields</dt><dd>{entries.length - 20} not shown</dd></div>}
      </dl>
    );
  }
  return <span>{String(value)}</span>;
}

function CoverageValue({ children }) {
  return <span className="finding-coverage-value">{children}</span>;
}

function FindingsCoverage({ summary, status, selected, onSelect }) {
  if (status !== "ready" || summary?.availability_state !== "AVAILABLE") {
    return <Panel title="Assessment coverage" subtitle="Coverage is separate from findings." meta="UNAVAILABLE" className="operation-panel-full findings-coverage-panel"><div className="finding-coverage-unavailable">Coverage is unavailable; missing observations are not treated as clear.</div></Panel>;
  }
  const dns = summary.coverage?.dns_security || {};
  const certs = summary.coverage?.certificates || {};
  const ports = summary.coverage?.sensitive_ports || {};
  return (
    <Panel title="Assessment coverage" subtitle="Coverage is separate from findings." meta={`SCAN #${summary.scan_id}`} className="operation-panel-full findings-coverage-panel">
      <div className="findings-coverage-grid">
        <button type="button" className={`findings-coverage-card${selected === "dns" ? " selected" : ""}`} aria-pressed={selected === "dns"} onClick={() => onSelect("dns")}><span>DNS Security</span><CoverageValue>{Number.isInteger(dns.assessed_assets) && Number.isInteger(dns.eligible_assets) ? `${dns.assessed_assets.toLocaleString()} assessed / ${dns.eligible_assets.toLocaleString()} eligible` : "Unknown"}</CoverageValue><small>{Number.isInteger(dns.unassessed_assets) ? `${dns.unassessed_assets.toLocaleString()} unassessed` : "Coverage unavailable"}</small></button>
        <button type="button" className={`findings-coverage-card${selected === "certificates" ? " selected" : ""}`} aria-pressed={selected === "certificates"} onClick={() => onSelect("certificates")}><span>Certificates</span><CoverageValue>{Number.isInteger(certs.observed_assets) ? `${certs.observed_assets.toLocaleString()} observed assets` : "Unknown"}</CoverageValue><small>Absence does not establish TLS safety.</small></button>
        <button type="button" className={`findings-coverage-card${selected === "ports" ? " selected" : ""}`} aria-pressed={selected === "ports"} onClick={() => onSelect("ports")}><span>Sensitive ports</span><CoverageValue>{Number.isInteger(ports.positive_observations) ? `${ports.positive_observations.toLocaleString()} positive observations` : "Unknown"}</CoverageValue><small>Assessment coverage unknown.</small></button>
      </div>
    </Panel>
  );
}

const COVERAGE_PAGE_SIZE = 25;

function HostCoveragePanel({ filters, query, routePrefix, onChange, onRetry, onClose, requestVersion }) {
  const [data, setData] = useState(null);
  const [status, setStatus] = useState("loading");
  const [draftSearch, setDraftSearch] = useState(filters.coverageSearch);
  const category = filters.coverageCategory;
  const categoryTitle = category === "dns" ? "DNS Security hosts" : category === "certificates" ? "Certificate hosts" : "Sensitive port hosts";
  const returnQuery = queryForFilters(filters, routePrefix === "risk/security-review" ? "evidence-signals" : null);

  useEffect(() => { setDraftSearch(filters.coverageSearch); }, [filters.coverageSearch]);

  useEffect(() => {
    if (!category) return undefined;
    let active = true;
    setStatus("loading");
    setData(null);
    const params = { page: filters.coveragePage, limit: COVERAGE_PAGE_SIZE };
    if (filters.coverageSearch) {
      params.search = filters.coverageSearch;
      params.search_mode = filters.coverageMode;
    }
    if (category === "dns") {
      if (filters.dnsIncludeUnassessed) params.include_unassessed = true;
      getDnsSecurityHosts(params)
        .then((result) => { if (active) { setData(result); setStatus("ready"); } })
        .catch(() => { if (active) setStatus("error"); });
    } else if (category === "certificates") {
      if (filters.certificatesIncludeUnobserved) params.include_unobserved = true;
      getCertificateHosts(params)
        .then((result) => { if (active) { setData(result); setStatus("ready"); } })
        .catch(() => { if (active) setStatus("error"); });
    } else {
      getSensitivePortHosts(params)
        .then((result) => { if (active) { setData(result); setStatus("ready"); } })
        .catch(() => { if (active) { setData(null); setStatus("error"); } });
    }
    return () => { active = false; };
  }, [category, filters.coveragePage, filters.coverageSearch, filters.coverageMode, filters.dnsIncludeUnassessed, filters.certificatesIncludeUnobserved, requestVersion]);

  if (!category) return null;
  const hosts = Array.isArray(data?.hosts) ? data.hosts : [];
  const total = Number.isInteger(data?.total) ? data.total : 0;
  const page = Number.isInteger(data?.page) ? data.page : filters.coveragePage;
  const limit = Number.isInteger(data?.limit) ? data.limit : COVERAGE_PAGE_SIZE;
  const pages = Math.max(Math.ceil(total / limit), 1);
  const update = (changes) => onChange({ ...filters, ...changes, coveragePage: changes.coveragePage ?? 1 });

  const submitSearch = (event) => {
    event.preventDefault();
    update({ coverageSearch: draftSearch.trim().slice(0, 253) });
  };
  const clearSearch = () => {
    setDraftSearch("");
    update({ coverageSearch: "" });
  };
  const hostDomain = (host) => host.hostname || host.domain;

  return (
    <Panel title={categoryTitle} meta={status === "ready" ? `${total.toLocaleString()} HOSTS` : "HOST RESULTS"} className="operation-panel-full coverage-results-panel" id="assessment-host-results">
      <div className="coverage-panel-actions"><button type="button" className="coverage-close-button" onClick={onClose}>Close host results</button></div>
      <div className="coverage-results-toolbar">
        <form className="coverage-search-form" onSubmit={submitSearch}>
          <label className="coverage-search-input"><span className="sr-only">Search hostname or domain</span><input aria-label="Search hostname or domain" maxLength={253} placeholder="Search hostname or domain..." value={draftSearch} onChange={(event) => setDraftSearch(event.target.value)} /></label>
          <label className="coverage-search-mode"><span className="sr-only">Search mode</span><select aria-label="Search mode" value={filters.coverageMode} onChange={(event) => update({ coverageMode: event.target.value })}><option value="domain">Domain</option><option value="exact">Exact</option><option value="fragment">Fragment</option></select></label>
          <button type="submit" className="secondary-button">Search</button>
          {(draftSearch || filters.coverageSearch) && <button type="button" className="secondary-button" onClick={clearSearch}>Clear</button>}
        </form>
        {category === "dns" && <label className="coverage-include-toggle"><input type="checkbox" checked={filters.dnsIncludeUnassessed} onChange={(event) => update({ dnsIncludeUnassessed: event.target.checked })} />Show unassessed hosts</label>}
        {category === "certificates" && <label className="coverage-include-toggle"><input type="checkbox" checked={filters.certificatesIncludeUnobserved} onChange={(event) => update({ certificatesIncludeUnobserved: event.target.checked })} />Show hosts without observations</label>}
      </div>
      <div className="coverage-results-context">
        <span>Scan #{data?.scan_id ?? "—"}</span>
        {category === "dns" && <span>{filters.dnsIncludeUnassessed ? "Assessed and unassessed hosts are shown separately." : "Showing hosts with persisted DNS check records."}</span>}
        {category === "certificates" && <span>{filters.certificatesIncludeUnobserved ? "No observation is not a successful TLS assessment." : "Showing certificate-observed hosts."}</span>}
        {category === "ports" && <span>{total === 0 && !filters.coverageSearch ? "No positive observations recorded. Assessment coverage unknown." : filters.coverageSearch && total === 0 ? "No positive observations match this search. Assessment coverage unknown." : "Assessment coverage unknown."}</span>}
      </div>
      {status === "loading" && <LoadingState title={`Loading ${categoryTitle}`} copy="Searching current-scan hosts." />}
      {status === "error" && <ErrorState title={`${categoryTitle} unavailable`} copy="The host results could not be loaded." onRetry={onRetry} />}
      {status === "ready" && hosts.length === 0 && <div className="detail-empty">No matching {category === "dns" ? "DNS assessment" : category === "certificates" ? "certificate observation" : "sensitive-port observation"} hosts. This does not establish that the asset is absent or safe.</div>}
      {status === "ready" && hosts.length > 0 && (
        <div className="coverage-host-list">
          {hosts.map((host) => {
            const domain = hostDomain(host);
            const unassessed = host.assessment_state === "NOT_ASSESSED" || host.assessment_state === "NO_PERSISTED_OBSERVATION";
            return <article className="coverage-host-row" key={`${host.domain_id || domain}-${host.scan_id}`}>
              <div className="coverage-host-heading">
                <div><AssetLink domain={domain} returnTo={routePrefix} returnQuery={returnQuery} /><span className="coverage-host-class">{host.asset_class || "Unknown class"} · scan #{host.scan_id ?? data.scan_id}</span></div>
                <span className={`coverage-assessment-state${unassessed ? " unassessed" : ""}`}>{unassessed ? (category === "dns" ? "UNASSESSED · NO CHECKS" : "NO OBSERVATION") : (category === "dns" ? "ASSESSED · CHECKS RECORDED" : "OBSERVATION RECORDED")}</span>
              </div>
              {category === "dns" && !unassessed && <>
                <div className="coverage-host-outcomes"><span>{host.check_count ?? host.checks?.length ?? 0} checks</span>{Object.entries(host.outcome_distribution || {}).map(([outcome, count]) => <span key={outcome}>{outcome}: {count}</span>)}</div>
                {!!host.checks?.length && <details className="coverage-host-details"><summary>Recorded checks and evidence</summary><div className="coverage-check-list">{host.checks.map((check) => <section key={check.check_id}><strong>{check.check_key || "DNS check"}</strong><StatusBadge value={check.outcome} /><p>{[check.record_type, check.target].filter(Boolean).join(" · ") || "Target not recorded"}</p>{check.evidence != null && <div><b>Evidence</b><EvidenceValue value={check.evidence} /></div>}{check.remediation && <p><b>Recommended review:</b> {check.remediation}</p>}<small>{check.checked_at ? new Date(check.checked_at).toLocaleString() : "Timestamp not recorded"} · scan #{check.scan_id}</small></section>)}</div></details>}
              </>}
              {category === "certificates" && !unassessed && <div className="coverage-check-list">{(host.certificates || []).map((certificate, index) => <section key={`${certificate.scan_id || host.scan_id}-${index}`}><strong>{certificate.status || "Certificate status not recorded"}</strong><p>Expiry: {certificate.expiry || "Not recorded"}</p><p>Days to expiry at scan: {Number.isFinite(certificate.days_to_expiry_at_scan) ? certificate.days_to_expiry_at_scan : "Not recorded"}</p><small>Scan #{certificate.scan_id || host.scan_id}. Expiry interval is recorded at scan time.</small></section>)}</div>}
              {category === "ports" && <div className="coverage-check-list">{(host.ports || []).map((port) => <section key={`${port.port}-${port.service || "service"}`}><strong>{port.service || "Service not identified"} · port {port.port}</strong><p>{port.description || "No additional description recorded."}</p><small>{port.source_risk ? `Source risk ${port.source_risk}` : "Source risk not recorded"} · scan #{port.scan_id || host.scan_id}</small></section>)}</div>}
            </article>;
          })}
        </div>
      )}
      {status === "ready" && total > 0 && <div className="pagination-bar coverage-host-pagination"><span>Page {page} of {pages} · {total.toLocaleString()} matching hosts</span><div><button type="button" className="secondary-button" disabled={page <= 1} onClick={() => update({ coveragePage: page - 1 })}>Previous</button><button type="button" className="secondary-button" disabled={page >= pages} onClick={() => update({ coveragePage: page + 1 })}>Next</button></div></div>}
    </Panel>
  );
}

function FindingDetail({ finding, query, returnTo }) {
  const returnQuery = query || "";
  return (
    <Panel title="Finding details" meta={sourceLabel(finding.source)} className="operation-panel-full finding-detail-panel" id="finding-detail">
      <div className="finding-detail-grid">
        <section><span className="finding-detail-label">What</span><h3>{finding.title}</h3><p>{categoryLabel(finding.category)} · {displayOptional(finding.finding_type, "Observation type not recorded")}</p></section>
        <section><span className="finding-detail-label">Where</span><AssetLink domain={finding.asset_domain} returnTo={returnTo} returnQuery={returnQuery} /><p><StatusBadge value={finding.asset_class} /> · scan #{finding.scan_id}</p></section>
        <section className="finding-detail-wide"><span className="finding-detail-label">Why</span><p>{displayOptional(finding.why_it_matters, "No explanation recorded by the source contract.")}</p></section>
        <section className="finding-detail-wide"><span className="finding-detail-label">Evidence</span><EvidenceValue value={finding.evidence} /></section>
        <section className="finding-detail-wide"><span className="finding-detail-label">Action</span><p>{displayOptional(finding.recommended_action, "No recommended action recorded.")}</p></section>
        <section className="finding-detail-wide"><span className="finding-detail-label">Limitations</span>
          {finding.indicators_inferred && <p className="finding-inferred-note">Environment or role indicators are inferred from hostname text, not verified attributes.</p>}
          {finding.environment_indicators?.length > 0 && <p>Inferred environment indicators: {finding.environment_indicators.join(", ")}</p>}
          {finding.role_indicators?.length > 0 && <p>Inferred role indicators: {finding.role_indicators.join(", ")}</p>}
          {finding.limitations?.length > 0 ? <ul className="finding-limitations">{finding.limitations.map((item) => <li key={item}>{item}</li>)}</ul> : <p>No additional limitations recorded.</p>}
        </section>
      </div>
    </Panel>
  );
}

export default function SecurityFindingsPage({ query = "", routePrefix = "risk/findings" }) {
  const filters = useMemo(() => readFilters(query), [query]);
  const pageTab = routePrefix === "risk/security-review" ? "evidence-signals" : null;
  const pageQuery = queryForFilters(filters, pageTab);
  const [summary, setSummary] = useState(null);
  const [summaryStatus, setSummaryStatus] = useState("loading");
  const [data, setData] = useState(null);
  const [listStatus, setListStatus] = useState("loading");
  const [listRequestVersion, setListRequestVersion] = useState(0);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [coverageRequestVersion, setCoverageRequestVersion] = useState(0);

  useEffect(() => {
    let active = true;
    setSummaryStatus("loading");
    getSecurityFindingsSummary()
      .then((result) => { if (active) { setSummary(result); setSummaryStatus("ready"); } })
      .catch(() => { if (active) setSummaryStatus("error"); });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    let active = true;
    setListStatus("loading");
    setSelectedFinding(null);
    const params = {
      page: filters.page,
      limit: filters.pageSize,
      view: filters.view,
    };
    if (filters.category) params.category = filters.category;
    if (filters.source) params.source = filters.source;
    if (filters.assetClass) params.asset_class = filters.assetClass;
    getSecurityFindings(params)
      .then((result) => { if (active) { setData(result); setListStatus("ready"); } })
      .catch(() => { if (active) setListStatus("error"); });
    return () => { active = false; };
  }, [filters.page, filters.pageSize, filters.view, filters.category, filters.source, filters.assetClass, listRequestVersion]);

  const listScanId = Number.isInteger(data?.scan_id) ? data.scan_id : null;
  const summaryReady = summaryStatus === "ready"
    && summary?.availability_state === "AVAILABLE"
    && Number.isInteger(summary?.scan_id)
    && listScanId !== null
    && summary.scan_id === listScanId;
  const scanContext = listScanId !== null ? `CURRENT SCAN #${listScanId}`
    : listStatus === "loading" ? "Loading scan metadata" : "Scan metadata unavailable";
  const categoryCount = (category) => summaryReady ? (summary.counts_by_category?.[category]?.records ?? 0) : "—";
  const findings = Array.isArray(data?.findings) ? data.findings : [];
  const total = Number.isInteger(data?.total) ? data.total : 0;
  const totalPages = Math.max(Math.ceil(total / filters.pageSize), 1);
  const listAvailable = data?.availability_state === "AVAILABLE";

  const changeFilter = (key, value) => {
    const [, currentQuery = ""] = window.location.hash.replace(/^#\/?/, "").split("?");
    updateFilters({ ...readFilters(currentQuery), [key]: value, page: 1 }, routePrefix, pageTab);
  };
  const changeCoverage = (nextFilters) => updateCoverageFilters(nextFilters, routePrefix, pageTab);

  if (listStatus === "loading" && !data) return <LoadingState title="Loading Security Findings" copy="Retrieving current-scan observations and exposure signals." />;
  if (listStatus === "error") return <ErrorState title="Security Findings unavailable" copy="The unified findings request could not be loaded. No values have been inferred." onRetry={() => setListRequestVersion((value) => value + 1)} />;
  if (!listAvailable && data?.availability_state === "UNAVAILABLE") return <EmptyState title="No successful scan available" copy="Security findings will appear after a scan completes successfully." />;

  return (
    <div className="operations-grid security-findings-workspace">
      <section className="findings-page-heading operation-panel-full" aria-label="Security findings scan context">
        <span className="scan-context">{scanContext}</span>
      </section>

      <section className="findings-summary-grid operation-panel-full" aria-label="Security findings summary">
        <MetricCard label="Recorded Findings" value={categoryCount("FINDING")} support="Source-recorded · not independently verified" accent="#b43d4a" />
        <MetricCard label="Needs Verification" value={categoryCount("NEEDS_VERIFICATION")} support="Requires analyst review" accent="#d49a3a" />
        <MetricCard label="Exposure Signals" value={categoryCount("EXPOSURE_SIGNAL")} support="Context or exposure observations" accent="#3d9ac7" />
      </section>

      <FindingsCoverage
        summary={summary}
        status={summaryStatus}
        selected={filters.coverageCategory}
        onSelect={(coverageCategory) => changeCoverage({ ...filters, coverageCategory, coveragePage: 1 })}
      />
      <HostCoveragePanel
        filters={filters}
        query={query}
        routePrefix={routePrefix}
        onChange={changeCoverage}
        onRetry={() => setCoverageRequestVersion((value) => value + 1)}
        onClose={() => changeCoverage({ ...filters, coverageCategory: "", coveragePage: 1 })}
        requestVersion={coverageRequestVersion}
      />

      <Panel title="Evidence records" subtitle="Select a record to inspect its source evidence and limitations." meta={listAvailable ? `${total.toLocaleString()} MATCHING` : "UNAVAILABLE"} className="operation-panel-full">
        <div className="findings-filter-panel">
          <label><span>View</span><select aria-label="Finding view" value={filters.view} onChange={(event) => changeFilter("view", event.target.value)}>{VIEW_OPTIONS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
          <label><span>Category</span><select aria-label="Finding category" value={filters.category} onChange={(event) => changeFilter("category", event.target.value)}>{CATEGORY_OPTIONS.map(([value, label]) => <option key={value || "all"} value={value}>{label}</option>)}</select></label>
          <label><span>Source</span><select aria-label="Finding source" value={filters.source} onChange={(event) => changeFilter("source", event.target.value)}>{SOURCE_OPTIONS.map(([value, label]) => <option key={value || "all"} value={value}>{label}</option>)}</select></label>
          <label><span>Asset class</span><select aria-label="Finding asset class" value={filters.assetClass} onChange={(event) => changeFilter("assetClass", event.target.value)}>{ASSET_CLASS_OPTIONS.map(([value, label]) => <option key={value || "all"} value={value}>{label}</option>)}</select></label>
        </div>

        {listStatus === "loading" && <LoadingState title="Loading evidence records" copy="Applying the selected filters." />}
        {listStatus === "ready" && !findings.length && <div className="detail-empty finding-empty">{filters.category === "FINDING" ? "No source-recorded findings match this filter." : filters.view === "signals" ? "No exposure signals match this filter." : "No records currently require attention."}</div>}
        {listStatus === "ready" && findings.length > 0 && (
          <>
            <div className="dense-table-wrap">
              <table className="dense-table findings-table">
                <thead><tr><th>Finding / observation</th><th>Affected asset</th><th>Source</th><th>Severity</th><th>Verification</th><th>Asset class</th></tr></thead>
                <tbody>{findings.map((finding) => {
                  const selected = selectedFinding?.finding_id === finding.finding_id;
                  return <tr key={finding.finding_id} className={selected ? "finding-row-selected" : ""}>
                    <td><div className="finding-name-cell"><div className="finding-name-text"><strong>{finding.title}</strong><span>{displayOptional(finding.finding_type, "Observation")}</span></div><button type="button" className="finding-details-button" aria-expanded={selected} aria-controls="finding-detail" onClick={() => setSelectedFinding(selected ? null : finding)}>{selected ? "Hide details" : "Details"}</button></div></td>
                    <td><AssetLink domain={finding.asset_domain} returnTo={routePrefix} returnQuery={pageQuery} /></td>
                    <td><span>{sourceLabel(finding.source)}</span><small>{finding.source_outcome || ""}</small></td>
                    <td>{finding.severity ? <StatusBadge value={finding.severity} /> : <span className="not-applicable">Not provided</span>}</td>
                    <td><StatusBadge value={finding.category === "FINDING" ? "Source-recorded" : categoryLabel(finding.category)} />{finding.verification_state && <small>{finding.verification_state}</small>}</td>
                    <td><StatusBadge value={finding.asset_class} /></td>
                  </tr>;
                })}</tbody>
              </table>
            </div>
            <div className="pagination-bar findings-pagination">
              <label className="risk-page-size"><span>Rows per page</span><select aria-label="Findings rows per page" value={filters.pageSize} onChange={(event) => changeFilter("pageSize", Number(event.target.value))}>{PAGE_SIZES.map((size) => <option key={size} value={size}>{size}</option>)}</select></label>
              <span>Page {filters.page} of {totalPages} · {total.toLocaleString()} matching records</span>
              <div><button type="button" className="secondary-button" disabled={filters.page <= 1} onClick={() => updateFilters({ ...filters, page: filters.page - 1 }, routePrefix, pageTab)}>Previous</button><button type="button" className="secondary-button" disabled={filters.page >= totalPages} onClick={() => updateFilters({ ...filters, page: filters.page + 1 }, routePrefix, pageTab)}>Next</button></div>
            </div>
          </>
        )}
      </Panel>

      {selectedFinding && <FindingDetail finding={selectedFinding} query={pageQuery} returnTo={routePrefix} />}
    </div>
  );
}
