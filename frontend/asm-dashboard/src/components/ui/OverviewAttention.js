import React, { useMemo, useState } from "react";
import AssetLink from "./AssetLink";
import StatusBadge from "./StatusBadge";
import SortableHeader from "./SortableHeader";

function humanizeReason(reason) {
  return String(reason || "")
    .replace(":", ": ")
    .replaceAll("_", " ");
}

export function AttentionTable({ assets, returnTo = "overview", returnQuery }) {
  const [sort, setSort] = useState({ by: null, dir: "desc" });
  const rows = useMemo(() => {
    if (!sort.by) return assets;
    const rank = { Low: 0, Review: 1, Elevated: 2, High: 3 };
    const value = (asset) => sort.by === "domain" ? String(asset.domain || "").toLocaleLowerCase()
      : sort.by === "priority" ? rank[asset.priority]
        : Number.isFinite(asset.score) ? asset.score : null;
    return [...assets].sort((a, b) => {
      const av = value(a); const bv = value(b);
      if (av == null || bv == null) return av == null ? (bv == null ? String(a.domain).localeCompare(String(b.domain)) : 1) : -1;
      const compared = typeof av === "number" && typeof bv === "number" ? av - bv : String(av).localeCompare(String(bv));
      return (sort.dir === "asc" ? compared : -compared) || String(a.domain).localeCompare(String(b.domain));
    });
  }, [assets, sort]);
  const onSort = (field) => setSort((current) => ({ by: field, dir: current.by === field ? (current.dir === "asc" ? "desc" : "asc") : (field === "domain" ? "asc" : "desc") }));
  if (!assets.length) {
    return <p className="panel-subtitle">No scored assets currently require attention.</p>;
  }

  return (
    <div style={{ overflowX: "auto" }}>
      <table className="attention-table">
        <thead>
          <tr><SortableHeader label="Asset" field="domain" sortBy={sort.by} sortDir={sort.dir} onSort={onSort} /><SortableHeader label="Priority" field="priority" sortBy={sort.by} sortDir={sort.dir} onSort={onSort} /><SortableHeader label="Score" field="score" sortBy={sort.by} sortDir={sort.dir} onSort={onSort} /><th>Deterministic reasons</th></tr>
        </thead>
        <tbody>
          {rows.map((asset) => (
            <tr key={asset.domain}>
              <td><AssetLink domain={asset.domain} returnTo={returnTo} returnQuery={returnQuery} /></td>
              <td><StatusBadge value={asset.priority} /></td>
              <td><span className="risk-score">{asset.score}</span></td>
              <td>
                <div className="reason-list">
                  {(asset.reasons || []).map((reason) => (
                    <span className="reason-token" key={reason}>{humanizeReason(reason)}</span>
                  ))}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default AttentionTable;
