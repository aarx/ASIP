import React, { useEffect, useMemo, useState } from "react";
import {
  Button,
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  TextField,
} from "@mui/material";
import { getV2Assets } from "../services/api";
import StatusBadge from "../components/ui/StatusBadge";
import { EmptyState, ErrorState, LoadingState } from "../components/ui/AsyncState";
import { displayEvidence, isMissingEvidence } from "../utils/presentation";

const DEFAULT_LIMIT = 25;

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

function explorerHash(filters, page = 1) {
  const params = new URLSearchParams();
  Object.entries(filters).forEach(([key, value]) => {
    if (value) params.set(key, value);
  });
  if (page > 1) params.set("page", String(page));
  params.set("limit", String(DEFAULT_LIMIT));
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

function AssetTable({ assets, returnQuery }) {
  return (
    <div className="asset-table-wrap">
      <table className="asset-table">
        <thead>
          <tr>
            <th>Asset</th><th>Class</th><th>Network</th><th>HTTP</th>
            <th>Provider / ASN</th><th>Risk</th><th aria-label="Open asset" />
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
                <td>
                  {asset.risk ? (
                    <div className="table-risk">
                      <StatusBadge value={asset.risk.priority} />
                      <span className="risk-score">{asset.risk.score}</span>
                    </div>
                  ) : <span className="not-applicable">No org. risk</span>}
                </td>
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
  const urlParams = useMemo(() => new URLSearchParams(query), [query]);
  const page = Math.max(Number(urlParams.get("page")) || 1, 1);
  const limit = Math.min(Math.max(Number(urlParams.get("limit")) || DEFAULT_LIMIT, 1), 200);
  const [draft, setDraft] = useState(appliedFilters);
  const [data, setData] = useState(null);
  const [status, setStatus] = useState("loading");
  const [requestVersion, setRequestVersion] = useState(0);

  useEffect(() => setDraft(appliedFilters), [appliedFilters]);

  useEffect(() => {
    let active = true;
    setStatus("loading");
    const params = { page, limit };
    Object.entries(appliedFilters).forEach(([key, value]) => {
      if (value) params[key] = value;
    });
    getV2Assets(params)
      .then((result) => {
        if (active) { setData(result); setStatus("ready"); }
      })
      .catch(() => { if (active) setStatus("error"); });
    return () => { active = false; };
  }, [appliedFilters, limit, page, requestVersion]);

  const updateDraft = (event) => setDraft((current) => ({
    ...current, [event.target.name]: event.target.value,
  }));
  const applyFilters = (event) => {
    event.preventDefault();
    window.location.hash = explorerHash(draft, 1);
  };
  const clearFilters = () => { window.location.hash = explorerHash(readFilters(""), 1); };
  const movePage = (nextPage) => { window.location.hash = explorerHash(appliedFilters, nextPage); };

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
        <span>Ordered by domain</span>
      </div>

      {status === "loading" && <LoadingState title="Loading current assets" copy="Applying filters to exact authoritative scan membership." />}
      {status === "error" && <ErrorState title="Asset inventory unavailable" copy="The current asset contract could not be loaded. No results have been inferred." onRetry={() => setRequestVersion((value) => value + 1)} />}
      {status === "ready" && data?.scan_id == null && <EmptyState />}
      {status === "ready" && data?.scan_id != null && data.assets.length === 0 && (
        <EmptyState title="No assets match these filters" copy="Clear or adjust the active filters to broaden the current authoritative result set." />
      )}
      {status === "ready" && data?.assets?.length > 0 && <AssetTable assets={data.assets} returnQuery={query} />}

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
