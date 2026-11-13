import React, { useEffect, useMemo, useState } from "react";
import { getV2Assets, getV2Overview } from "../services/api";
import Panel from "../components/ui/Panel";
import RiskDistributionChart from "../components/ui/RiskDistributionChart";
import { EmptyState, ErrorState, LoadingState } from "../components/ui/AsyncState";
import AttentionTable from "../components/ui/OverviewAttention";

const PAGE_SIZES = [10, 25, 50];

function readQueuePaging(query) {
  const params = new URLSearchParams(query);
  const requestedSize = Number(params.get("limit"));
  const pageSize = PAGE_SIZES.includes(requestedSize) ? requestedSize : 10;
  return { page: Math.max(Number(params.get("page")) || 1, 1), pageSize };
}

function queueHash({ page, pageSize }, routePrefix = "risk/needs-attention") {
  const params = new URLSearchParams({ page: String(page), limit: String(pageSize) });
  if (routePrefix === "risk/security-review") params.set("tab", "review-queue");
  return `#/${routePrefix}?${params}`;
}

function queueReturnQuery({ page, pageSize }, routePrefix = "risk/needs-attention") {
  const params = new URLSearchParams({ page: String(page), limit: String(pageSize) });
  if (routePrefix === "risk/security-review") params.set("tab", "review-queue");
  return params.toString();
}

function attentionAsset(asset) {
  return {
    domain: asset.domain,
    priority: asset.risk?.priority,
    score: asset.risk?.score,
    reasons: asset.risk?.reasons || [],
  };
}

export default function RiskNeedsAttentionPage({ query = "", embedded = false, routePrefix = "risk/needs-attention", showDistribution = true }) {
  const initialPaging = useMemo(() => readQueuePaging(query), [query]);
  const [data, setData] = useState(null);
  const [status, setStatus] = useState("loading");
  const [requestVersion, setRequestVersion] = useState(0);
  const paging = initialPaging;
  const [queueData, setQueueData] = useState(null);
  const [queueStatus, setQueueStatus] = useState("loading");
  const [queueRequestVersion, setQueueRequestVersion] = useState(0);

  useEffect(() => {
    let active = true;
    setStatus("loading");
    getV2Overview()
      .then((result) => {
        if (active) {
          setData(result);
          setStatus("ready");
        }
      })
      .catch(() => { if (active) setStatus("error"); });
    return () => { active = false; };
  }, [requestVersion]);

  useEffect(() => {
    if (status !== "ready" || data?.current_scan_id == null) return undefined;
    let active = true;
    setQueueStatus("loading");
    getV2Assets({
      page: paging.page,
      limit: paging.pageSize,
      risk_positive: true,
      sort_by: "risk_score",
      sort_dir: "desc",
    }).then((result) => {
      if (active) {
        setQueueData(result || { scan_id: null, page: paging.page, limit: paging.pageSize, count: 0, assets: [] });
        setQueueStatus("ready");
      }
    }).catch(() => { if (active) setQueueStatus("error"); });
    return () => { active = false; };
  }, [data?.current_scan_id, paging.page, paging.pageSize, queueRequestVersion, status]);

  const updatePaging = (nextPaging) => {
    window.location.hash = queueHash(nextPaging, routePrefix);
  };

  if (status === "loading") return <LoadingState title="Loading Needs Attention" copy="Retrieving the bounded deterministic risk queue." />;
  if (status === "error") return <ErrorState title="Needs Attention unavailable" copy="The current attention queue could not be loaded." onRetry={() => setRequestVersion((value) => value + 1)} />;
  if (!data || data.current_scan_id == null) return <EmptyState />;

  const totalCount = queueData?.count ?? 0;
  const totalPages = Math.max(Math.ceil(totalCount / paging.pageSize), 1);
  const queueAssets = (queueData?.assets || []).map(attentionAsset);

  return (
    <div className="operations-grid risk-needs-attention-page">
      {!embedded && <a className="overview-subpage-context operation-panel-full" href="#/scans">
        <span>Current authoritative scan</span>
        <strong>#{data.current_scan_id}</strong>
        <span aria-hidden="true">View scans →</span>
      </a>}
      {showDistribution && <Panel title="Risk distribution" subtitle="Canonical priorities across confirmed organizational assets" meta={`SCAN #${data.current_scan_id}`} className="operation-panel-full">
        <RiskDistributionChart distribution={data.risk_distribution} priorityHref={(priority) => `#/assets?priority=${encodeURIComponent(priority)}`} />
      </Panel>}
      <Panel title="Needs attention" subtitle="The same positive-score ranking, shown as a compact review queue" meta={`${totalCount} RANKED ASSETS`} className="operation-panel-full">
        {queueStatus === "loading" && <LoadingState title="Loading ranked assets" copy="Retrieving the current positive-score population." />}
        {queueStatus === "error" && <ErrorState title="Ranked assets unavailable" copy="The current positive-score asset queue could not be loaded." onRetry={() => setQueueRequestVersion((value) => value + 1)} />}
        {queueStatus === "ready" && totalCount === 0 && <EmptyState className="state-card-compact" title="No ranked assets" copy="No current assets have a positive deterministic risk score." />}
        {queueStatus === "ready" && totalCount > 0 && (
          <>
            <AttentionTable
              assets={queueAssets}
              returnTo={routePrefix}
              returnQuery={queueReturnQuery(paging, routePrefix)}
            />
            <div className="pagination-bar risk-queue-pagination">
              <label className="risk-page-size">
                <span>Rows per page</span>
                <select aria-label="Rows per page" value={paging.pageSize} onChange={(event) => updatePaging({ page: 1, pageSize: Number(event.target.value) })}>
                  {PAGE_SIZES.map((size) => <option key={size} value={size}>{size}</option>)}
                </select>
              </label>
              <span>Page {paging.page} of {totalPages} · {totalCount} ranked assets</span>
              <div>
                <button type="button" className="secondary-button" disabled={paging.page <= 1} onClick={() => updatePaging({ page: paging.page - 1, pageSize: paging.pageSize })}>Previous</button>
                <button type="button" className="secondary-button" disabled={paging.page >= totalPages} onClick={() => updatePaging({ page: paging.page + 1, pageSize: paging.pageSize })}>Next</button>
              </div>
            </div>
          </>
        )}
      </Panel>
    </div>
  );
}
