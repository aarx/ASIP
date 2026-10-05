import React, { useEffect, useMemo, useState } from "react";
import {
  Button,
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  TextField,
} from "@mui/material";
import { exportV2AssetsCsv, getV2Assets } from "../services/api";
import StatusBadge from "../components/ui/StatusBadge";
import { EmptyState, ErrorState, LoadingState } from "../components/ui/AsyncState";
import { displayEvidence, isMissingEvidence } from "../utils/presentation";

const DEFAULT_LIMIT = 25;
const SORT_DEFAULTS = { domain: "asc", priority: "desc", risk_score: "desc" };
const SORT_LABELS = { domain: "Asset", priority: "Priority", risk_score: "Risk Score" };

const FILTERS = [
  ["ownership", "Ownership", ["CONFIRMED", "CANDIDATE", "EXTERNAL"]],
  ["asset_class", "Asset class", ["KNOWN", "SHADOW", "CANDIDATE", "EXTERNAL"]],
  ["priority", "Priority", ["High", "Elevated", "Review", "Low"]],
  ["http_observation_status", "HTTP observation", ["RESPONDED", "NO_RESPONSE", "FAILED", "UNKNOWN"]],
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
  };
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

function explorerHash(filters, page = 1, sortBy = "domain", sortDir = "asc") {
  const params = new URLSearchParams();
  Object.entries(filters).forEach(([key, value]) => {
    if (value) params.set(key, value);
  });
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
        {values.map((option) => <MenuItem value={option} key={option}>{option.replace("_", " ")}</MenuItem>)}
      </Select>
    </FormControl>
  );
}

function SortableHeader({ field, sortBy, sortDir, onSort }) {
  const active = sortBy === field;
  const direction = sortDir === "asc" ? "↑" : "↓";
  return (
    <th aria-sort={active ? (sortDir === "asc" ? "ascending" : "descending") : "none"}>
      <button
        type="button"
        className="asset-sort-button"
        onClick={() => onSort(field)}
        aria-label={`Sort by ${SORT_LABELS[field]}${active ? `, currently ${sortDir === "asc" ? "ascending" : "descending"}` : ""}`}
      >
        {SORT_LABELS[field]}{active && <span aria-hidden="true"> {direction}</span>}
      </button>
    </th>
  );
}

function AssetTable({ assets, returnQuery, sortBy, sortDir, onSort }) {
  return (
    <div className="asset-table-wrap">
      <table className="asset-table">
        <thead>
          <tr>
            <SortableHeader field="domain" sortBy={sortBy} sortDir={sortDir} onSort={onSort} />
            <th>Class</th><th>Network</th><th>HTTP</th>
            <th>Provider / ASN</th>
            <SortableHeader field="priority" sortBy={sortBy} sortDir={sortDir} onSort={onSort} />
            <SortableHeader field="risk_score" sortBy={sortBy} sortDir={sortDir} onSort={onSort} />
            <th aria-label="Open asset" />
          </tr>
        </thead>
        <tbody>
          {assets.map((asset) => {
            const detailQuery = returnQuery ? `?${returnQuery}` : "";
            const detailHref = `#/assets/${encodeURIComponent(asset.domain)}${detailQuery}`;
            return (
              <tr key={asset.domain}>
                <td>
                  <a className="asset-domain-link" href={detailHref}>{asset.domain}</a>
                  {!isMissingEvidence(asset.title) && <span className="asset-secondary asset-title-text">{asset.title}</span>}
                </td>
                <td>
                  <StatusBadge value={asset.asset_class} />
                  <span className="asset-secondary">{asset.ownership_status}</span>
                </td>
                <td>
                  <span className="technical-value">{displayEvidence(asset.ip)}</span>
                  <span className="asset-secondary">{asset.asn || "ASN unavailable"}</span>
                </td>
                <td>
                  <StatusBadge value={asset.http_observation_status} />
                  <span className="asset-secondary">{asset.http_status || "No status"}</span>
                </td>
                <td>
                  <span>{displayEvidence(asset.provider, "Unknown")}</span>
                  {asset.asn && <span className="asset-secondary">{asset.asn}</span>}
                </td>
                <td>{asset.risk ? <StatusBadge value={asset.risk.priority} /> : <span className="not-applicable">—</span>}</td>
                <td><span className="risk-score">{asset.risk ? asset.risk.score : "—"}</span></td>
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
  const { sortBy, sortDir } = useMemo(() => readSort(query), [query]);
  const urlParams = useMemo(() => new URLSearchParams(query), [query]);
  const page = Math.max(Number(urlParams.get("page")) || 1, 1);
  const limit = Math.min(Math.max(Number(urlParams.get("limit")) || DEFAULT_LIMIT, 1), 200);
  const [draft, setDraft] = useState(appliedFilters);
  const [data, setData] = useState(null);
  const [status, setStatus] = useState("loading");
  const [requestVersion, setRequestVersion] = useState(0);
  const [exportStatus, setExportStatus] = useState("idle");

  useEffect(() => setDraft(appliedFilters), [appliedFilters]);

  useEffect(() => {
    let active = true;
    setStatus("loading");
    const params = { page, limit, sort_by: sortBy, sort_dir: sortDir };
    Object.entries(appliedFilters).forEach(([key, value]) => {
      if (value) params[key] = value;
    });
    getV2Assets(params)
      .then((result) => {
        if (active) { setData(result); setStatus("ready"); }
      })
      .catch(() => { if (active) setStatus("error"); });
    return () => { active = false; };
  }, [appliedFilters, limit, page, requestVersion, sortBy, sortDir]);

  const updateDraft = (event) => setDraft((current) => ({
    ...current, [event.target.name]: event.target.value,
  }));
  const applyFilters = (event) => {
    event.preventDefault();
    window.location.hash = explorerHash(draft, 1, sortBy, sortDir);
  };
  const clearFilters = () => { window.location.hash = explorerHash(readFilters(""), 1, sortBy, sortDir); };
  const movePage = (nextPage) => { window.location.hash = explorerHash(appliedFilters, nextPage, sortBy, sortDir); };
  const changeSort = (nextSortBy) => {
    const nextSortDir = sortBy === nextSortBy
      ? (sortDir === "asc" ? "desc" : "asc")
      : SORT_DEFAULTS[nextSortBy];
    window.location.hash = explorerHash(appliedFilters, 1, nextSortBy, nextSortDir);
  };
  const exportAssets = async () => {
    setExportStatus("loading");
    const params = {};
    Object.entries(appliedFilters).forEach(([key, value]) => {
      if (value) params[key] = value;
    });
    params.sort_by = sortBy;
    params.sort_dir = sortDir;

    try {
      const response = await exportV2AssetsCsv(params);
      const url = window.URL.createObjectURL(response.data);
      const link = document.createElement("a");
      link.href = url;
      link.download = `shadowrecon-assets-scan-${data.scan_id}.csv`;
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
  const totalPages = Math.max(Math.ceil((data?.count || 0) / limit), 1);

  return (
    <div className="asset-explorer">
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
        {activeFilters.length > 0 && (
          <div className="active-filters" aria-label="Active filters">
            <span>Active</span>
            {activeFilters.map(([name, value]) => (
              <span className="filter-chip" key={name}>{name.replaceAll("_", " ")}: {value}</span>
            ))}
          </div>
        )}
      </form>

      <div className="asset-results-bar">
        <div>
          <strong>{status === "ready" ? (data?.count ?? 0) : "—"}</strong> current assets
          {status === "ready" && data?.scan_id != null && <span> · authoritative scan #{data.scan_id}</span>}
        </div>
        <div className="asset-results-actions">
          <span>Ordered by {sortBy === "domain" ? "domain" : SORT_LABELS[sortBy].toLowerCase()}</span>
          <Button
            size="small"
            variant="outlined"
            onClick={exportAssets}
            disabled={status !== "ready" || data?.scan_id == null || data?.count === 0 || exportStatus === "loading"}
          >
            {exportStatus === "loading" ? "Exporting…" : "Export CSV"}
          </Button>
        </div>
      </div>
      {exportStatus === "error" && <span role="alert">Export unavailable. Try again.</span>}

      {status === "loading" && <LoadingState title="Loading current assets" copy="Applying filters to exact authoritative scan membership." />}
      {status === "error" && <ErrorState title="Asset inventory unavailable" copy="The current asset contract could not be loaded. No results have been inferred." onRetry={() => setRequestVersion((value) => value + 1)} />}
      {status === "ready" && data?.scan_id == null && <EmptyState />}
      {status === "ready" && data?.scan_id != null && data.assets.length === 0 && (
        <EmptyState title="No assets match these filters" copy="Clear or adjust the active filters to broaden the current authoritative result set." />
      )}
      {status === "ready" && data?.assets?.length > 0 && (
        <AssetTable
          assets={data.assets}
          returnQuery={query}
          sortBy={sortBy}
          sortDir={sortDir}
          onSort={changeSort}
        />
      )}

      {status === "ready" && data?.scan_id != null && data.count > 0 && (
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
