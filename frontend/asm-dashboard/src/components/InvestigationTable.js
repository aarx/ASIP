import React, { useEffect, useState } from "react";
import { getInvestigationAssets } from "../services/api";
import SortableHeader from "./ui/SortableHeader";

const PAGE_SIZE = 20;

export default function InvestigationTable({ filter, setFilter }) {
  const [data, setData] = useState({ assets: [], count: 0 });
  const [search, setSearch] = useState("");
  const [riskFilter, setRiskFilter] = useState("all");
  const [page, setPage] = useState(1);
  const [sortBy, setSortBy] = useState("domain");
  const [sortDir, setSortDir] = useState("asc");

  useEffect(() => { setPage(1); }, [filter?.provider, filter?.tech, search, riskFilter]);
  useEffect(() => {
    let active = true;
    getInvestigationAssets(page, PAGE_SIZE, filter?.provider, {
      search: search || undefined,
      priority: riskFilter === "all" ? undefined : riskFilter,
      tech: filter?.tech || undefined,
      sort_by: sortBy,
      sort_dir: sortDir,
    }).then((result) => {
      if (active) setData({ assets: Array.isArray(result?.assets) ? result.assets : [], count: Number.isInteger(result?.count) ? result.count : 0 });
    }).catch(() => { if (active) setData({ assets: [], count: 0 }); });
    return () => { active = false; };
  }, [page, filter?.provider, filter?.tech, search, riskFilter, sortBy, sortDir]);

  const sort = (field) => {
    setSortDir((current) => sortBy === field ? (current === "asc" ? "desc" : "asc") : (field === "domain" || field === "provider" || field === "ip" || field === "technology" ? "asc" : "desc"));
    setSortBy(field);
    setPage(1);
  };
  const providers = [...new Set(data.assets.map((asset) => asset.provider).filter((value) => value && value !== "Unknown"))];
  if (!filter) return <div className="investigation-table-empty"><h3>Investigation Console</h3><p>Choose a chart category to explore assets.</p></div>;

  const totalPages = Math.max(Math.ceil(data.count / PAGE_SIZE), 1);
  return (
    <div className="investigation-table-workspace">
      <h2>Investigation Console</h2>
      <div className="investigation-table-filters">
        <input aria-label="Search domain" placeholder="Search domain..." value={search} onChange={(event) => setSearch(event.target.value)} />
        <select aria-label="Canonical priority" value={riskFilter} onChange={(event) => setRiskFilter(event.target.value)}>
          <option value="all">All Risk</option><option value="Review">Review or higher</option><option value="Elevated">Elevated or higher</option><option value="High">High</option>
        </select>
        <select aria-label="Provider" value={filter?.provider || "all"} onChange={(event) => setFilter((previous) => ({ ...previous, provider: event.target.value === "all" ? null : event.target.value }))}>
          <option value="all">All Providers</option>{providers.map((provider) => <option key={provider} value={provider}>{provider}</option>)}
        </select>
      </div>
      <div className="dense-table-wrap"><table className="dense-table investigation-assets-table">
        <thead><tr>
          <SortableHeader label="Domain" field="domain" sortBy={sortBy} sortDir={sortDir} onSort={sort} />
          <SortableHeader label="Risk" field="risk" sortBy={sortBy} sortDir={sortDir} onSort={sort} />
          <SortableHeader label="IP" field="ip" sortBy={sortBy} sortDir={sortDir} onSort={sort} />
          <SortableHeader label="Provider" field="provider" sortBy={sortBy} sortDir={sortDir} onSort={sort} />
          <SortableHeader label="Ports" field="ports" sortBy={sortBy} sortDir={sortDir} onSort={sort} />
          <SortableHeader label="Tech" field="technology" sortBy={sortBy} sortDir={sortDir} onSort={sort} />
        </tr></thead>
        <tbody>{data.assets.map((asset) => <tr key={asset.domain}><td>{asset.domain}</td><td>{asset.risk} ({asset.priority})</td><td>{asset.ip || "Unavailable"}</td><td>{asset.provider}</td><td>{asset.ports || "—"}</td><td>{asset.tech || "—"}</td></tr>)}</tbody>
      </table></div>
      <div className="pagination-bar"><span>{data.count.toLocaleString()} assets · Page {page} of {totalPages}</span><div><button type="button" className="secondary-button" disabled={page <= 1} onClick={() => setPage((value) => value - 1)}>Previous</button><button type="button" className="secondary-button" disabled={page >= totalPages} onClick={() => setPage((value) => value + 1)}>Next</button></div></div>
    </div>
  );
}
