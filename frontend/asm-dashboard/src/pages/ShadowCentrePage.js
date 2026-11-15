import React, { useEffect, useMemo, useState } from "react";
import { Button, MenuItem, TextField } from "@mui/material";
import { getV2Assets } from "../services/api";
import AssetLink from "../components/ui/AssetLink";
import StatusBadge from "../components/ui/StatusBadge";
import { EmptyState, ErrorState, LoadingState } from "../components/ui/AsyncState";
import { displayHttpStatus } from "../utils/presentation";
import SortableHeader from "../components/ui/SortableHeader";

const LIMIT = 25;

function queryState(query) {
  const params = new URLSearchParams(query);
  return {
    page: Math.max(Number(params.get("page")) || 1, 1),
    search: params.get("search") || "",
    priority: params.get("priority") || "",
    sortBy: ["domain", "priority", "risk_score"].includes(params.get("sort_by")) ? params.get("sort_by") : "risk_score",
    sortDir: ["asc", "desc"].includes(params.get("sort_dir")) ? params.get("sort_dir") : "desc",
  };
}

function shadowHash({ page = 1, search = "", priority = "", sortBy = "risk_score", sortDir = "desc" }) {
  const params = new URLSearchParams();
  if (search) params.set("search", search);
  if (priority) params.set("priority", priority);
  if (page > 1) params.set("page", String(page));
  params.set("sort_by", sortBy);
  params.set("sort_dir", sortDir);
  return `#/shadow${params.toString() ? `?${params}` : ""}`;
}

export default function ShadowCentrePage({ query }) {
  const applied = useMemo(() => queryState(query), [query]);
  const [draft, setDraft] = useState({ search: applied.search, priority: applied.priority });
  const [data, setData] = useState(null);
  const [status, setStatus] = useState("loading");
  const [requestVersion, setRequestVersion] = useState(0);

  useEffect(() => setDraft({ search: applied.search, priority: applied.priority }), [applied]);
  useEffect(() => {
    let active = true;
    setStatus("loading");
    const params = { page: applied.page, limit: LIMIT, asset_class: "SHADOW", sort_by: applied.sortBy, sort_dir: applied.sortDir };
    if (applied.search) params.search = applied.search;
    if (applied.priority) params.priority = applied.priority;
    getV2Assets(params).then((result) => {
      if (active) { setData(result); setStatus("ready"); }
    }).catch(() => { if (active) setStatus("error"); });
    return () => { active = false; };
  }, [applied, requestVersion]);

  const apply = (event) => {
    event.preventDefault();
    window.location.hash = shadowHash({ ...draft, page: 1 });
  };
  const clear = () => { window.location.hash = "#/shadow"; };
  const movePage = (page) => { window.location.hash = shadowHash({ ...applied, page }); };
  const changeSort = (field) => {
    const sortDir = applied.sortBy === field ? (applied.sortDir === "asc" ? "desc" : "asc") : (field === "domain" ? "asc" : "desc");
    window.location.hash = shadowHash({ ...applied, page: 1, sortBy: field, sortDir });
  };

  if (status === "loading") return <LoadingState title="Loading Shadow inventory" copy="Retrieving confirmed current assets outside documented inventory." />;
  if (status === "error") return <ErrorState title="Shadow Centre unavailable" copy="The current Shadow inventory could not be loaded." onRetry={() => setRequestVersion((value) => value + 1)} />;
  if (data.scan_id == null) return <EmptyState />;

  const assets = (data.assets || []).filter((asset) => asset.asset_class === "SHADOW");
  const totalPages = Math.max(Math.ceil(data.count / LIMIT), 1);
  return (
    <div className="shadow-workspace">
      <section className="shadow-summary-bar">
        <div><span>Current Shadow assets</span><strong>{data.count}</strong></div>
        <div><span>Authoritative scan</span><strong>#{data.scan_id}</strong></div>
        <p>Confirmed organizational assets absent from documented Known inventory.</p>
      </section>

      <form className="shadow-filters" onSubmit={apply}>
        <TextField size="small" label="Search Shadow domains" value={draft.search} onChange={(event) => setDraft((value) => ({ ...value, search: event.target.value }))} />
        <TextField select size="small" label="Canonical priority" value={draft.priority} onChange={(event) => setDraft((value) => ({ ...value, priority: event.target.value }))}>
          <MenuItem value="">All priorities</MenuItem>
          {['High', 'Elevated', 'Review', 'Low'].map((value) => <MenuItem key={value} value={value}>{value}</MenuItem>)}
        </TextField>
        <Button type="submit" variant="contained">Apply</Button>
        <Button type="button" variant="text" onClick={clear} disabled={!applied.search && !applied.priority}>Clear</Button>
      </form>

      {assets.length ? (
        <div className="dense-table-wrap">
          <table className="dense-table shadow-table">
            <thead><tr><SortableHeader label="Shadow asset" field="domain" sortBy={applied.sortBy} sortDir={applied.sortDir} onSort={changeSort} /><th>Current context</th><th>Provider</th><th>HTTP</th><SortableHeader label="Canonical risk" field="risk_score" sortBy={applied.sortBy} sortDir={applied.sortDir} onSort={changeSort} /><th /></tr></thead>
            <tbody>{assets.map((asset) => (
              <tr key={asset.domain}>
                <td>
                  <AssetLink domain={asset.domain} returnTo="shadow" />
                  <span className="asset-secondary">Confirmed ownership · outside Known inventory</span>
                </td>
                <td>
                  {asset.first_seen_scan === data.scan_id ? <span className="new-scan-label">New in scan #{data.scan_id}</span> : <span className="asset-secondary">First seen scan #{asset.first_seen_scan}</span>}
                  <span className="asset-secondary">Provenance available in asset detail</span>
                </td>
                <td>{asset.provider || "Unknown"}<span className="asset-secondary">{asset.ip || "No current IP"}</span></td>
                <td><StatusBadge value={asset.http_observation_status} /><span className="asset-secondary">{displayHttpStatus(asset.http_observation_status, asset.http_status)}</span></td>
                <td>{asset.risk ? <><div className="table-risk"><StatusBadge value={asset.risk.priority} /><span className="risk-score">{asset.risk.score}</span></div><div className="reason-list table-reasons">{asset.risk.reasons.map((reason) => <span className="reason-token" key={reason}>{reason.replaceAll("_", " ")}</span>)}</div></> : <span className="not-applicable">Unavailable</span>}</td>
                <td><AssetLink domain={asset.domain} returnTo="shadow" className="row-action">→</AssetLink></td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      ) : <EmptyState title="No Shadow assets match" copy="No confirmed non-inventory assets match the current filters." />}

      {data.count > 0 && (
        <div className="pagination-bar"><span>Page {applied.page} of {totalPages}</span><div><Button size="small" variant="outlined" disabled={applied.page <= 1} onClick={() => movePage(applied.page - 1)}>Previous</Button><Button size="small" variant="outlined" disabled={applied.page >= totalPages} onClick={() => movePage(applied.page + 1)}>Next</Button></div></div>
      )}
    </div>
  );
}
