import React, { useEffect, useState } from "react";
import Panel from "../components/ui/Panel";
import { ErrorState, LoadingState } from "../components/ui/AsyncState";
import { getSubdomainTakeoverEvidence } from "../services/api";

const PAGE_SIZE = 25;
const CATEGORIES = ["DNS_NEGATIVE_SIGNAL", "PROVIDER_SPECIFIC_CANDIDATE", "UNVERIFIED_PROVIDER_ASSOCIATION", "UNKNOWN"];

function readFilters(query) {
  const params = new URLSearchParams(query);
  return { scan_id: params.get("scan_id") || "", search: params.get("search") || "",
    provider: params.get("provider") || "", category: params.get("category") || "",
    verification_status: params.get("verification_status") || "", page: Math.max(1, Number(params.get("page")) || 1) };
}

function updateHash(filters) {
  const params = new URLSearchParams();
  Object.entries(filters).forEach(([key, value]) => {
    if (value && !(key === "page" && Number(value) === 1)) params.set(key, String(value));
  });
  window.location.hash = `#/risk/security-review?tab=subdomain-takeover${params.toString() ? `&${params}` : ""}`;
}

function Evidence({ value }) {
  return <pre className="dns-evidence-json">{JSON.stringify(value ?? { status: "Unavailable" }, null, 2)}</pre>;
}

export default function SubdomainTakeoverPage({ query = "" }) {
  const [filters, setFilters] = useState(() => readFilters(query));
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(null);
  const [requestVersion, setRequestVersion] = useState(0);

  useEffect(() => setFilters(readFilters(query)), [query]);
  useEffect(() => {
    let active = true;
    setLoading(true);
    const params = { page: filters.page, limit: PAGE_SIZE };
    ["scan_id", "search", "provider", "category", "verification_status"].forEach((key) => {
      if (filters[key]) params[key] = filters[key];
    });
    getSubdomainTakeoverEvidence(params).then((result) => {
      if (active) { setData(result); setError(null); }
    }).catch((requestError) => { if (active) setError(requestError); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [filters, requestVersion]);

  const change = (key, value) => {
    const next = { ...filters, [key]: value, page: 1 };
    setFilters(next);
    updateHash(next);
  };
  const rows = data?.hosts || [];
  const totalPages = Math.max(1, Math.ceil((data?.total || 0) / PAGE_SIZE));

  return <div className="dns-security-page">
    <Panel title="Subdomain Takeover" meta={data?.scan_id ? `Scan ${data.scan_id}` : null}>
      <div className="dns-summary-metrics">
        <div className="dns-summary-metric"><span>DNS-negative signals</span><strong>{data?.summary?.dns_negative_hosts ?? "—"}</strong></div>
        <div className="dns-summary-metric"><span>Unverified provider signals</span><strong>{data?.summary?.unverified_provider_hosts ?? "—"}</strong></div>
        <div className="dns-summary-metric"><span>Provider-specific candidates</span><strong>{data?.summary?.provider_candidate_hosts ?? "—"}</strong></div>
      </div>
      <div className="dns-filter-panel" style={{ marginTop: 14 }}>
        <label className="dns-filter-control"><span>Scan ID</span><input aria-label="Scan ID" inputMode="numeric" value={filters.scan_id} onChange={(event) => change("scan_id", event.target.value.replace(/\D/g, ""))} placeholder="Latest" /></label>
        <label className="dns-filter-control"><span>Hostname</span><input aria-label="Hostname" value={filters.search} onChange={(event) => change("search", event.target.value)} /></label>
        <label className="dns-filter-control"><span>Provider</span><input aria-label="Provider" value={filters.provider} onChange={(event) => change("provider", event.target.value)} /></label>
        <label className="dns-filter-control"><span>Finding</span><select aria-label="Finding" value={filters.category} onChange={(event) => change("category", event.target.value)}><option value="">Actionable evidence</option>{CATEGORIES.map((item) => <option key={item} value={item}>{item.replaceAll("_", " ")}</option>)}</select></label>
        <label className="dns-filter-control"><span>Verification</span><input aria-label="Verification status" value={filters.verification_status} onChange={(event) => change("verification_status", event.target.value)} placeholder="All" /></label>
      </div>
      {loading && <LoadingState title="Loading takeover evidence" copy="Reading takeover-related evidence from the selected scan." />}
      {error && <ErrorState title="Takeover evidence unavailable" copy="The evidence request failed. No finding state was inferred." onRetry={() => setRequestVersion((value) => value + 1)} />}
      {!loading && !error && <div className="dns-table-wrap">
        {rows.length === 0 ? <div className="dns-table-state">No matching takeover evidence.</div> : <table className="dns-findings-table">
          <thead><tr><th>Hostname</th><th>CNAME destination</th><th>Provider</th><th>Finding</th><th>Confidence</th><th>Verification</th></tr></thead>
          <tbody>{rows.map((row) => <React.Fragment key={row.domain_id}>
            <tr><td><button className="dns-domain-button" type="button" onClick={() => setExpanded(expanded === row.domain_id ? null : row.domain_id)}>{row.hostname}</button></td>
              <td>{row.cname_destination || "Unavailable"}</td><td>{row.provider || "Unknown"}</td>
              <td>{row.finding_category.replaceAll("_", " ")}</td><td>{row.confidence || "Unknown"}</td>
              <td>{row.verification_status.replaceAll("_", " ")}</td></tr>
            {expanded === row.domain_id && <tr className="dns-finding-row-expanded"><td colSpan="6"><div className="dns-evidence-details">
              <div className="dns-evidence-list">{row.observations.map((observation, index) => <details open key={`${observation.source}-${index}`}>
                <summary>{observation.source.replaceAll("_", " ")} · {observation.evidence_category.replaceAll("_", " ")}</summary>
                <p>{observation.rationale || "Evidence details"}</p><Evidence value={{ evidence: observation.evidence, verification_status: observation.verification_status, observed_at: observation.observed_at }} />
              </details>)}</div>
            </div></td></tr>}
          </React.Fragment>)}</tbody>
        </table>}
        <div className="dns-pagination"><span>{data?.total || 0} hosts · Page {filters.page} of {totalPages}</span>
          <button type="button" className="dns-secondary-action" disabled={filters.page <= 1} onClick={() => { const next = { ...filters, page: filters.page - 1 }; setFilters(next); updateHash(next); }}>Previous</button>
          <button type="button" className="dns-secondary-action" disabled={filters.page >= totalPages} onClick={() => { const next = { ...filters, page: filters.page + 1 }; setFilters(next); updateHash(next); }}>Next</button>
        </div>
      </div>}
    </Panel>
  </div>;
}
