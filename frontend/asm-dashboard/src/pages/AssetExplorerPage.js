import React, { useEffect, useMemo, useState } from "react";
import {
  Button,
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  TextField,
} from "@mui/material";
import { exportV2AssetsCsv, getV2Assets, getV2AssetsSummary } from "../services/api";
import StatusBadge from "../components/ui/StatusBadge";
import { EmptyState, ErrorState, LoadingState } from "../components/ui/AsyncState";
import { displayAssetClass, displayEvidence, displayHttpStatus, isMissingEvidence } from "../utils/presentation";
import SortableHeader from "../components/ui/SortableHeader";

const DEFAULT_LIMIT = 25;
const SORT_DEFAULTS = { domain: "asc", priority: "desc", risk_score: "desc" };
const SORT_LABELS = { domain: "Asset", priority: "Priority", risk_score: "Risk Score" };
const EXPORT_SUPPORTED_FILTERS = new Set([
  "search", "ownership", "asset_class", "priority", "provider", "http_observation_status",
]);
const HISTORY_EXPORT_SUPPORTED_FILTERS = new Set([
  ...EXPORT_SUPPORTED_FILTERS, "risk_positive", "has_ip", "http_live", "http_status",
  "http_status_group", "discovery_source", "exposure_keyword",
]);

const FILTERS = [
  ["ownership", "Ownership", ["CONFIRMED", "CANDIDATE", "EXTERNAL"]],
  ["asset_class", "Asset class", ["KNOWN", "SHADOW", "CANDIDATE", "EXTERNAL"]],
  ["priority", "Priority", ["High", "Elevated", "Review", "Low"]],
  ["http_observation_status", "HTTP observation", ["RESPONDED", "NO_RESPONSE", "FAILED", "UNKNOWN"]],
  ["http_status_group", "HTTP status group", ["2xx", "3xx", "4xx", "5xx"]],
];

function readFilters(query) {
  const params = new URLSearchParams(query);
  return {
    search: params.get("search") || "",
    ownership: params.get("ownership") || "",
    asset_class: params.get("asset_class") || "",
    priority: params.get("priority") || "",
    provider: params.get("provider") || "",
    http_observation_status: params.get("http_observation_status") || "",
    risk_positive: params.get("risk_positive") || "",
    has_ip: params.get("has_ip") || "",
    http_live: params.get("http_live") || "",
    http_status: params.get("http_status") || "",
    http_status_group: params.get("http_status_group") || "",
    discovery_source: params.get("discovery_source") || "",
    exposure_keyword: params.get("exposure_keyword") || "",
  };
}

function readScope(query) {
  return new URLSearchParams(query).get("scope") === "retained_history" ? "retained_history" : "current";
}

function filterOptionLabel(name, option) {
  return name === "asset_class" ? displayAssetClass(option) : option.replace("_", " ");
}

function activeFilterValue(name, option) {
  return name === "asset_class" ? displayAssetClass(option) : option;
}

function readSort(query) {
  const params = new URLSearchParams(query);
  const requestedSort = params.get("sort_by");
  const sortBy = SORT_DEFAULTS[requestedSort] ? requestedSort : "domain";
  const requestedDirection = params.get("sort_dir");
  const sortDir = requestedDirection === "asc" || requestedDirection === "desc"
    ? requestedDirection
    : SORT_DEFAULTS[sortBy];
  return { sortBy, sortDir };
}

function explorerHash(filters, page = 1, sortBy = "domain", sortDir = "asc", scope = "current") {
  const params = new URLSearchParams();
  Object.entries(filters).forEach(([key, value]) => {
    if (value) params.set(key, value);
  });
  if (scope === "retained_history") params.set("scope", scope);
  if (page > 1) params.set("page", String(page));
  params.set("limit", String(DEFAULT_LIMIT));
  if (!(sortBy === "domain" && sortDir === "asc")) {
    params.set("sort_by", sortBy);
    params.set("sort_dir", sortDir);
  }
  return `#/assets?${params.toString()}`;
}

function FilterSelect({ name, label, values, value, onChange }) {
  return (
    <FormControl size="small" className="asset-filter-control">
      <InputLabel>{label}</InputLabel>
      <Select name={name} label={label} value={value} onChange={onChange}>
        <MenuItem value="">All</MenuItem>
        {values.map((option) => <MenuItem value={option} key={option}>{filterOptionLabel(name, option)}</MenuItem>)}
      </Select>
    </FormControl>
  );
}

function AssetTable({ assets, returnQuery, sortBy, sortDir, onSort, historical = false }) {
  return (
    <div className="asset-table-wrap">
      <table className="asset-table">
        <thead>
          <tr>
            <SortableHeader field="domain" label={SORT_LABELS.domain} sortBy={sortBy} sortDir={sortDir} onSort={onSort} />
            <th>Class</th><th>Network</th><th>HTTP</th>
            <th>Provider / ASN</th>
            <SortableHeader field="priority" label={SORT_LABELS.priority} sortBy={sortBy} sortDir={sortDir} onSort={onSort} />
            <SortableHeader field="risk_score" label={SORT_LABELS.risk_score} sortBy={sortBy} sortDir={sortDir} onSort={onSort} />
            <th aria-label="Open asset" />
          </tr>
        </thead>
        <tbody>
          {assets.map((asset) => {
            const detailQuery = returnQuery ? `?${returnQuery}` : "";
            const detailHref = `#/assets/${encodeURIComponent(asset.domain)}${detailQuery}`;
            const httpAvailable = !historical || asset.field_availability?.http === true;
            const dnsAvailable = !historical || asset.field_availability?.dns === true;
            const asnAvailable = !historical || asset.field_availability?.asn === true;
            const providerAvailable = !historical || asset.field_availability?.provider === true;
            return (
              <tr key={asset.domain}>
                <td>
                  <a className="asset-domain-link" href={detailHref}>{asset.domain}</a>
                  {historical && <span className="asset-secondary">{asset.current_scan_member ? "Current scan member" : "Historical-only identity"}</span>}
                  {historical && <span className="asset-secondary">{asset.latest_evidence_scan_id != null ? `Evidence · scan #${asset.latest_evidence_scan_id} · ${asset.latest_evidence_scan_status || "status unavailable"}` : "Latest evidence scan unavailable"}</span>}
                  {!isMissingEvidence(asset.title) && (!historical || httpAvailable) && <span className="asset-secondary asset-title-text">{asset.title}</span>}
                </td>
                <td>
                  <StatusBadge value={displayAssetClass(asset.asset_class)} />
                  <span className="asset-secondary">{asset.ownership_status}</span>
                </td>
                <td>
                  <span className="technical-value">{dnsAvailable ? displayEvidence(asset.ip) : "Evidence unavailable"}</span>
                  <span className="asset-secondary">{asnAvailable ? asset.asn || "ASN unavailable" : "ASN unavailable"}</span>
                </td>
                <td>
                  {httpAvailable ? <>
                    <StatusBadge value={asset.http_observation_status} />
                    <span className="asset-secondary">{displayHttpStatus(asset.http_observation_status, asset.http_status)}</span>
                    <span className="asset-secondary">{asset.http_live === true ? "HTTP responding" : asset.http_live === false ? "HTTP not responding" : "HTTP state unknown"}</span>
                  </> : <span className="not-applicable">Evidence unavailable</span>}
                </td>
                <td>
                  <span>{providerAvailable ? displayEvidence(asset.provider, "Unknown") : "Provider unavailable"}</span>
                  {asset.asn && <span className="asset-secondary">{asset.asn}</span>}
                </td>
                <td>{asset.risk ? <StatusBadge value={asset.risk.priority} /> : <span className="not-applicable">{historical && asset.risk_available !== true ? "Unavailable" : "—"}</span>}</td>
                <td><span className="risk-score">{asset.risk ? asset.risk.score : historical && asset.risk_available !== true ? "Unavailable" : "—"}</span></td>
                <td><a className="row-action" href={detailHref} aria-label={`Open ${asset.domain}`}>→</a></td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export default function AssetExplorerPage({ query }) {
  const appliedFilters = useMemo(() => readFilters(query), [query]);
  const scope = useMemo(() => readScope(query), [query]);
  const { sortBy, sortDir } = useMemo(() => readSort(query), [query]);
  const urlParams = useMemo(() => new URLSearchParams(query), [query]);
  const page = Math.max(Number(urlParams.get("page")) || 1, 1);
  const limit = Math.min(Math.max(Number(urlParams.get("limit")) || DEFAULT_LIMIT, 1), 200);
  const [draft, setDraft] = useState(appliedFilters);
  const [data, setData] = useState(null);
  const [summary, setSummary] = useState(null);
  const [summaryStatus, setSummaryStatus] = useState("loading");
  const [status, setStatus] = useState("loading");
  const [requestVersion, setRequestVersion] = useState(0);
  const [exportStatus, setExportStatus] = useState("idle");

  useEffect(() => setDraft(appliedFilters), [appliedFilters]);

  useEffect(() => {
    let active = true;
    setStatus("loading");
    const params = { scope, page, limit, sort_by: sortBy, sort_dir: sortDir };
    Object.entries(appliedFilters).forEach(([key, value]) => {
      if (value) params[key] = value;
    });
    getV2Assets(params)
      .then((result) => {
        if (active) { setData(result); setStatus("ready"); }
      })
      .catch(() => { if (active) setStatus("error"); });
    return () => { active = false; };
  }, [appliedFilters, limit, page, requestVersion, scope, sortBy, sortDir]);

  useEffect(() => {
    let active = true;
    setSummaryStatus("loading");
    getV2AssetsSummary({ scope })
      .then((result) => {
        if (active) { setSummary(result); setSummaryStatus("ready"); }
      })
      .catch(() => { if (active) setSummaryStatus("error"); });
    return () => { active = false; };
  }, [requestVersion, scope]);

  const updateDraft = (event) => setDraft((current) => ({
    ...current, [event.target.name]: event.target.value,
  }));
  const applyFilters = (event) => {
    event.preventDefault();
    window.location.hash = explorerHash(draft, 1, sortBy, sortDir, scope);
  };
  const clearFilters = () => { window.location.hash = explorerHash(readFilters(""), 1, sortBy, sortDir, scope); };
  const movePage = (nextPage) => { window.location.hash = explorerHash(appliedFilters, nextPage, sortBy, sortDir, scope); };
  const changeSort = (nextSortBy) => {
    const nextSortDir = sortBy === nextSortBy
      ? (sortDir === "asc" ? "desc" : "asc")
      : SORT_DEFAULTS[nextSortBy];
    window.location.hash = explorerHash(appliedFilters, 1, nextSortBy, nextSortDir, scope);
  };
  const changeScope = (nextScope) => {
    if (nextScope !== scope) window.location.hash = explorerHash(appliedFilters, 1, sortBy, sortDir, nextScope);
  };
  const exportAssets = async () => {
    setExportStatus("loading");
    const params = {};
    Object.entries(appliedFilters).forEach(([key, value]) => {
      if (value) params[key] = value;
    });
    params.scope = scope;
    params.sort_by = sortBy;
    params.sort_dir = sortDir;

    try {
      const response = await exportV2AssetsCsv(params);
      const url = window.URL.createObjectURL(response.data);
      const link = document.createElement("a");
      link.href = url;
      const contentDisposition = response.headers?.["content-disposition"] || "";
      const filename = contentDisposition.match(/filename\*?=(?:UTF-8''|")?([^";]+)/i)?.[1];
      link.download = filename
        ? decodeURIComponent(filename.replace(/"/g, ""))
        : scope === "retained_history"
          ? "shadowrecon-assets-retained-history.csv"
          : `shadowrecon-assets-scan-${data.scan_id}.csv`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      setExportStatus("ready");
    } catch {
      setExportStatus("error");
    }
  };

  const activeFilters = Object.entries(appliedFilters).filter(([, value]) => value);
  const supportedExportFilters = scope === "retained_history" ? HISTORY_EXPORT_SUPPORTED_FILTERS : EXPORT_SUPPORTED_FILTERS;
  const exportFiltersSupported = activeFilters.every(([name]) => supportedExportFilters.has(name));
  const totalPages = Math.max(Math.ceil((data?.count || 0) / limit), 1);
  const summaryMatchesScope = summary?.scope === scope
    && typeof summary.count === "number"
    && Number.isFinite(summary.count);
  const summaryCounts = summaryMatchesScope
      && summary?.classification_counts
      && typeof summary.classification_counts === "object"
      && !Array.isArray(summary.classification_counts)
    ? summary.classification_counts : null;
  const requiredClassKeys = scope === "current"
    ? ["KNOWN", "SHADOW", "CANDIDATE"]
    : ["KNOWN", "SHADOW", "CANDIDATE", "EXTERNAL"];
  const hasMissingClassCounts = summaryCounts
    && requiredClassKeys.some((key) => typeof summaryCounts[key] !== "number" || !Number.isFinite(summaryCounts[key]));
  const hasScopeData = scope === "retained_history"
    ? data?.scope === "retained_history"
    : data?.scan_id != null;

  return (
    <div className="asset-explorer">
      <section className="inventory-scope" aria-label="Inventory scope">
        <div className="inventory-scope-controls" role="group" aria-label="Inventory scope">
          <button type="button" aria-pressed={scope === "current"} onClick={() => changeScope("current")}>Current scan</button>
          <button type="button" aria-pressed={scope === "retained_history"} onClick={() => changeScope("retained_history")}>All scans</button>
        </div>
        {scope === "retained_history" && <span className="inventory-scope-note" title="Distinct identities observed across retained scans; not exhaustive lifetime history. Risk and HTTP fields reflect the API-selected observation, not necessarily the highest historical values.">Distinct retained identities</span>}
        {summaryMatchesScope ? <div className="inventory-scope-counts" aria-label="Inventory totals">
          <strong>{summary.count.toLocaleString()} {scope === "current" ? "current scan assets" : "retained identities"}</strong>
          {summaryCounts && [["KNOWN", "Known"], ["SHADOW", "Shadow"], ["CANDIDATE", "Candidate"], ["EXTERNAL", "External"]]
            .filter(([key]) => typeof summaryCounts[key] === "number" && Number.isFinite(summaryCounts[key]))
            .map(([key, label]) => <span key={key}>{key === "CANDIDATE" ? displayAssetClass(key) : label} {summaryCounts[key].toLocaleString()}</span>)}
          {hasMissingClassCounts && <span>Some class totals unavailable</span>}
          {!summaryCounts && <span>Classification totals unavailable</span>}
        </div> : summaryStatus === "error" ? <span className="inventory-scope-error" role="status">Scope totals unavailable.</span>
          : summaryStatus === "ready" && <span className="inventory-scope-error" role="status">Inventory totals unavailable.</span>}
      </section>
      <form className="asset-filter-panel" onSubmit={applyFilters}>
        <div className="filter-primary-row">
          <TextField
            name="search"
            label="Search domain"
            size="small"
            value={draft.search}
            onChange={updateDraft}
            className="asset-search"
          />
          <TextField
            name="provider"
            label="Exact provider"
            size="small"
            value={draft.provider}
            onChange={updateDraft}
            className="provider-search"
          />
          <Button type="submit" variant="contained">Apply filters</Button>
          <Button type="button" variant="text" onClick={clearFilters} disabled={!activeFilters.length}>Clear</Button>
        </div>
        <div className="filter-secondary-row">
          {FILTERS.map(([name, label, values]) => (
            <FilterSelect key={name} name={name} label={label} values={values} value={draft[name]} onChange={updateDraft} />
          ))}
        </div>
        <div className="filter-metric-row">
          <TextField
            name="http_status"
            label="Exact HTTP status"
            type="number"
            size="small"
            value={draft.http_status}
            onChange={updateDraft}
            inputProps={{ min: 100, max: 599 }}
          />
        </div>
        {activeFilters.length > 0 && (
          <div className="active-filters" aria-label="Active filters">
            <span>Active</span>
            {activeFilters.map(([name, value]) => (
              <span className="filter-chip" key={name}>{name.replaceAll("_", " ")}: {activeFilterValue(name, value)}</span>
            ))}
          </div>
        )}
      </form>

      <div className="asset-results-bar">
        <div>
          <strong>{status === "ready" ? (data?.count ?? 0).toLocaleString() : "—"}</strong> matching {scope === "current" ? "current assets" : "retained identities"}
          {status === "ready" && scope === "current" && data?.scan_id != null && <span> · authoritative scan #{data.scan_id}</span>}
          {status === "ready" && scope === "retained_history" && summary?.retention && <span> · {summary.retention.scan_count_with_membership} retained scans</span>}
        </div>
        <div className="asset-results-actions">
          <span>Ordered by {sortBy === "domain" ? "domain" : SORT_LABELS[sortBy].toLowerCase()}</span>
          <Button
            size="small"
            variant="outlined"
            onClick={exportAssets}
            disabled={status !== "ready" || !hasScopeData || data?.count === 0 || exportStatus === "loading" || !exportFiltersSupported}
            title={!exportFiltersSupported ? "CSV export is unavailable for this metric filter" : undefined}
          >
            {exportStatus === "loading" ? "Exporting…" : "Export CSV"}
          </Button>
        </div>
      </div>
      {!exportFiltersSupported && <div className="asset-secondary" role="status">CSV export is unavailable for the selected metric filter.</div>}
      {exportStatus === "error" && <span role="alert">Export unavailable. Try again.</span>}

      {status === "loading" && <LoadingState title={scope === "current" ? "Loading current assets" : "Loading retained inventory"} copy={scope === "current" ? "Applying filters to exact authoritative scan membership." : "Applying filters to distinct identities in retained scan history."} />}
      {status === "error" && <ErrorState title="Asset inventory unavailable" copy="The selected inventory scope could not be loaded. No results have been inferred." onRetry={() => setRequestVersion((value) => value + 1)} />}
      {status === "ready" && scope === "current" && data?.scan_id == null && <EmptyState />}
      {status === "ready" && scope === "retained_history" && data?.scope !== "retained_history" && (
        <ErrorState title="Retained inventory unavailable" copy="The selected scope was not confirmed by the API." onRetry={() => setRequestVersion((value) => value + 1)} />
      )}
      {status === "ready" && hasScopeData && data.assets.length === 0 && (
        <EmptyState title="No assets match these filters" copy={scope === "current" ? "Clear or adjust the active filters to broaden the current authoritative result set." : "Clear or adjust the active filters to broaden the retained identity set."} />
      )}
      {status === "ready" && hasScopeData && data?.assets?.length > 0 && (
        <AssetTable
          assets={data.assets}
          returnQuery={query}
          sortBy={sortBy}
          sortDir={sortDir}
          onSort={changeSort}
          historical={scope === "retained_history"}
        />
      )}

      {status === "ready" && hasScopeData && data.count > 0 && (
        <div className="pagination-bar">
          <span>Page {page} of {totalPages}</span>
          <div>
            <Button size="small" variant="outlined" disabled={page <= 1} onClick={() => movePage(page - 1)}>Previous</Button>
            <Button size="small" variant="outlined" disabled={page >= totalPages} onClick={() => movePage(page + 1)}>Next</Button>
          </div>
        </div>
      )}
    </div>
  );
}
