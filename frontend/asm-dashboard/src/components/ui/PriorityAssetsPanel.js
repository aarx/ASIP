import React, { useEffect, useState } from "react";
import AssetLink from "./AssetLink";
import Panel from "./Panel";
import StatusBadge from "./StatusBadge";
import { EmptyState, ErrorState, LoadingState } from "./AsyncState";
import { getV2Assets, getV2Overview } from "../../services/api";
import SortableHeader from "./SortableHeader";

const PAGE_SIZE = 25;

function readPage(query) {
  const value = Number.parseInt(new URLSearchParams(query).get("priority_page"), 10);
  return Number.isInteger(value) && value > 0 ? value : 1;
}

function readSort(query) {
  const params = new URLSearchParams(query);
  const sortBy = ["domain", "priority", "risk_score"].includes(params.get("priority_sort_by")) ? params.get("priority_sort_by") : "risk_score";
  const sortDir = ["asc", "desc"].includes(params.get("priority_sort_dir")) ? params.get("priority_sort_dir") : "desc";
  return { sortBy, sortDir };
}

function reasons(reasonsList) {
  return (
    <div className="reason-list">
      {(reasonsList || []).map((reason) => <span className="reason-token" key={reason}>{reason.replaceAll("_", " ")}</span>)}
    </div>
  );
}

export default function PriorityAssetsPanel({ query = "", routePrefix = "risk/security-review" }) {
  const [page, setPage] = useState(() => readPage(query));
  const [status, setStatus] = useState("loading");
  const [data, setData] = useState(null);
  const [requestVersion, setRequestVersion] = useState(0);
  const { sortBy, sortDir } = readSort(query);

  useEffect(() => {
    const requestedPage = readPage(query);
    setPage((currentPage) => currentPage === requestedPage ? currentPage : requestedPage);
  }, [query]);

  useEffect(() => {
    let active = true;
    setStatus("loading");
    getV2Overview()
      .then((overview) => {
        if (!overview || overview.current_scan_id == null) {
          if (active) { setData(null); setStatus("empty"); }
          return null;
        }
        return getV2Assets({ page, limit: PAGE_SIZE, risk_positive: true, sort_by: sortBy, sort_dir: sortDir });
      })
      .then((result) => {
        if (active && result) { setData(result); setStatus("ready"); }
      })
      .catch(() => { if (active) setStatus("error"); });
    return () => { active = false; };
  }, [page, requestVersion, sortBy, sortDir]);

  const movePage = (nextPage) => {
    const params = new URLSearchParams(query);
    params.delete("section");
    params.set("tab", "prioritized-assets");
    params.set("priority_page", String(nextPage));
    if (sortBy === "risk_score" && sortDir === "desc") {
      params.delete("priority_sort_by");
      params.delete("priority_sort_dir");
    } else {
      params.set("priority_sort_by", sortBy);
      params.set("priority_sort_dir", sortDir);
    }
    window.location.hash = `#/${routePrefix}?${params}`;
  };
  const changeSort = (field) => {
    const nextDir = sortBy === field ? (sortDir === "asc" ? "desc" : "asc") : (field === "domain" ? "asc" : "desc");
    const params = new URLSearchParams(query);
    params.set("tab", "prioritized-assets");
    params.set("priority_page", "1");
    params.set("priority_sort_by", field);
    params.set("priority_sort_dir", nextDir);
    window.location.hash = `#/${routePrefix}?${params}`;
  };

  if (status === "loading") return <LoadingState title="Loading prioritized assets" copy="Retrieving the current risk-ranked asset queue." />;
  if (status === "error") return <ErrorState title="Prioritized assets unavailable" copy="The current risk-ranked asset queue could not be loaded." onRetry={() => setRequestVersion((value) => value + 1)} />;
  if (status === "empty") return <EmptyState />;

  const assets = Array.isArray(data?.assets) ? data.assets : [];
  const total = Number.isInteger(data?.count) ? data.count : 0;
  const totalPages = Math.max(Math.ceil(total / PAGE_SIZE), 1);
  const returnParams = new URLSearchParams({ tab: "prioritized-assets", priority_page: String(page) });
  if (sortBy !== "risk_score" || sortDir !== "desc") {
    returnParams.set("priority_sort_by", sortBy);
    returnParams.set("priority_sort_dir", sortDir);
  }
  const returnQuery = returnParams.toString();

  return (
    <Panel title="Prioritized assets" subtitle="Current positive-score assets ranked by deterministic risk" meta={`${total} RANKED ASSETS`} className="operation-panel-full">
      {assets.length === 0 && <div className="detail-empty">No assets have a risk score above zero in this scan.</div>}
      {assets.length > 0 && (
        <>
          <div className="dense-table-wrap">
            <table className="dense-table risk-assets-table">
              <thead><tr>
                <SortableHeader label="Asset" field="domain" sortBy={sortBy} sortDir={sortDir} onSort={changeSort} />
                <SortableHeader label="Priority" field="priority" sortBy={sortBy} sortDir={sortDir} onSort={changeSort} />
                <SortableHeader label="Score" field="risk_score" sortBy={sortBy} sortDir={sortDir} onSort={changeSort} />
                <th>Evidence</th><th /></tr></thead>
              <tbody>{assets.map((asset) => (
                <tr key={asset.domain}>
                  <td><AssetLink domain={asset.domain} returnTo={routePrefix} returnQuery={returnQuery} /></td>
                  <td><StatusBadge value={asset.risk?.priority} /></td>
                  <td><span className="risk-score">{asset.risk?.score ?? "—"}</span></td>
                  <td>{reasons(asset.risk?.reasons)}</td>
                  <td><AssetLink domain={asset.domain} returnTo={routePrefix} returnQuery={returnQuery} className="row-action">→</AssetLink></td>
                </tr>
              ))}</tbody>
            </table>
          </div>
          <div className="pagination-bar risk-queue-pagination">
            <span>Page {page} of {totalPages} · {total} ranked assets</span>
            <div>
              <button type="button" className="secondary-button" disabled={page <= 1} onClick={() => movePage(page - 1)}>Previous</button>
              <button type="button" className="secondary-button" disabled={page >= totalPages} onClick={() => movePage(page + 1)}>Next</button>
            </div>
          </div>
        </>
      )}
    </Panel>
  );
}
