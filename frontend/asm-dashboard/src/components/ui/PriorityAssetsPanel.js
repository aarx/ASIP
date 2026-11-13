import React, { useEffect, useState } from "react";
import AssetLink from "./AssetLink";
import Panel from "./Panel";
import StatusBadge from "./StatusBadge";
import { EmptyState, ErrorState, LoadingState } from "./AsyncState";
import { getV2Assets, getV2Overview } from "../../services/api";

const PAGE_SIZE = 25;

function readPage(query) {
  const value = Number.parseInt(new URLSearchParams(query).get("priority_page"), 10);
  return Number.isInteger(value) && value > 0 ? value : 1;
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
        return getV2Assets({ page, limit: PAGE_SIZE, risk_positive: true, sort_by: "risk_score", sort_dir: "desc" });
      })
      .then((result) => {
        if (active && result) { setData(result); setStatus("ready"); }
      })
      .catch(() => { if (active) setStatus("error"); });
    return () => { active = false; };
  }, [page, requestVersion]);

  const movePage = (nextPage) => {
    const params = new URLSearchParams(query);
    params.delete("section");
    params.set("tab", "prioritized-assets");
    params.set("priority_page", String(nextPage));
    window.location.hash = `#/${routePrefix}?${params}`;
  };

  if (status === "loading") return <LoadingState title="Loading prioritized assets" copy="Retrieving the current risk-ranked asset queue." />;
  if (status === "error") return <ErrorState title="Prioritized assets unavailable" copy="The current risk-ranked asset queue could not be loaded." onRetry={() => setRequestVersion((value) => value + 1)} />;
  if (status === "empty") return <EmptyState />;

  const assets = Array.isArray(data?.assets) ? data.assets : [];
  const total = Number.isInteger(data?.count) ? data.count : 0;
  const totalPages = Math.max(Math.ceil(total / PAGE_SIZE), 1);
  const returnQuery = new URLSearchParams({ tab: "prioritized-assets", priority_page: String(page) }).toString();

  return (
    <Panel title="Prioritized assets" subtitle="Current assets with risk scores above zero" meta={`${total} RANKED ASSETS`} className="operation-panel-full">
      {assets.length === 0 && <div className="detail-empty">No assets have a risk score above zero in this scan.</div>}
      {assets.length > 0 && (
        <>
          <div className="dense-table-wrap">
            <table className="dense-table risk-assets-table">
              <thead><tr><th>Asset</th><th>Priority</th><th>Score</th><th>Evidence</th><th /></tr></thead>
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
