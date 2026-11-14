import React, { useEffect, useState } from "react";
import {
  getExposureSummary,
  getFindings,
  getHttpStatus,
  getRiskHistoryAssets,
  getRiskHistorySummary,
  getSensitiveExposure,
  getV2Assets,
  getV2Overview,
  getV2ReviewIndicators,
} from "../services/api";
import AssetLink from "../components/ui/AssetLink";
import MetricCard from "../components/ui/MetricCard";
import Panel from "../components/ui/Panel";
import RiskDistributionChart, { RISK_COLORS } from "../components/ui/RiskDistributionChart";
import StatusBadge from "../components/ui/StatusBadge";
import { EmptyState, ErrorState, LoadingState } from "../components/ui/AsyncState";
import { displayAssetClass } from "../utils/presentation";

const PRIORITY_LIMIT = 25;
const HISTORICAL_HIGH_LIMIT = 10;
const SENSITIVE_PORT_RESULT_LIMIT = 20;
function sensitivePortSummary(rows) {
  if (!rows.length) {
    return { value: "—", support: "Assessment coverage unavailable", meta: "NOT RECORDED" };
  }
  if (rows.length >= SENSITIVE_PORT_RESULT_LIMIT) {
    return { value: `${SENSITIVE_PORT_RESULT_LIMIT}+`, support: "Observed rows · result list capped at 20", meta: `${SENSITIVE_PORT_RESULT_LIMIT}+ OBSERVED` };
  }
  return { value: rows.length, support: "Observed current-scan rows", meta: `${rows.length} OBSERVED` };
}

function httpStatusGroups(statuses) {
  if (!statuses) return [];
  return ["2xx", "3xx", "4xx", "5xx"]
    .filter((group) => statuses[group] != null)
    .map((group) => ({ group, count: statuses[group] }));
}

function readPositivePage(query, key) {
  const value = Number.parseInt(new URLSearchParams(query).get(key), 10);
  return Number.isInteger(value) && value > 0 ? value : 1;
}

function historicalScanLabel(scanId, timestamp) {
  if (!Number.isInteger(scanId)) return "—";
  if (!timestamp) return `Scan #${scanId}`;
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime())
    ? `Scan #${scanId}`
    : `Scan #${scanId} · ${date.toLocaleDateString()}`;
}

function historicalCoverage(summary) {
  const perScan = Array.isArray(summary?.per_scan) ? summary.per_scan : [];
  return perScan.filter((scan) => scan?.coverage_complete === false && Number.isInteger(scan?.scan_id));
}

export default function RiskExposurePage({ query }) {
  const [data, setData] = useState(null);
  const [status, setStatus] = useState("loading");
  const [requestVersion, setRequestVersion] = useState(0);
  const [priorityData, setPriorityData] = useState(null);
  const [historicalSummary, setHistoricalSummary] = useState(null);
  const [historicalPage, setHistoricalPage] = useState(() => readPositivePage(query, "historical_page"));
  const [historicalData, setHistoricalData] = useState(null);
  const [historicalStatus, setHistoricalStatus] = useState("loading");

  useEffect(() => {
    const requestedPage = readPositivePage(query, "historical_page");
    setHistoricalPage((currentPage) => currentPage === requestedPage ? currentPage : requestedPage);
  }, [query]);

  useEffect(() => {
    let active = true;
    setStatus("loading");
    const httpStatusRequest = typeof getHttpStatus === "function"
      ? Promise.resolve(getHttpStatus()).catch(() => null)
      : Promise.resolve(null);
    const historicalSummaryRequest = typeof getRiskHistorySummary === "function"
      ? Promise.resolve(getRiskHistorySummary()).catch(() => ({ error: true }))
      : Promise.resolve({ error: true });
    Promise.all([
      getV2Overview(),
      getFindings(),
      getSensitiveExposure(),
      getExposureSummary(),
      Promise.resolve(getV2ReviewIndicators()).catch(() => ({ error: true, count: 0, indicators: [] })),
      httpStatusRequest,
      historicalSummaryRequest,
    ]).then(([overview, findings, sensitivePorts, exposure, reviewIndicators, httpStatuses, riskHistory]) => {
      if (active) {
        setData({ overview, findings, sensitivePorts, exposure, reviewIndicators, httpStatuses, riskHistory });
        setHistoricalSummary(riskHistory);
        setHistoricalData(null);
        setHistoricalStatus(riskHistory?.availability_state === "AVAILABLE" ? "loading" : "unavailable");
        setStatus("ready");
      }
    }).catch(() => { if (active) setStatus("error"); });
    return () => { active = false; };
  }, [requestVersion]);

  useEffect(() => {
    if (status !== "ready" || data?.overview?.current_scan_id == null) return undefined;
    let active = true;
    getV2Assets({
      page: 1,
      limit: PRIORITY_LIMIT,
      risk_positive: true,
      sort_by: "risk_score",
      sort_dir: "desc",
    }).then((result) => {
      if (active) {
        setPriorityData(result);
      }
    }).catch(() => { if (active) setPriorityData(null); });
    return () => { active = false; };
  }, [data, status]);

  useEffect(() => {
    if (status !== "ready" || historicalSummary?.availability_state !== "AVAILABLE") return undefined;
    if (!Number.isInteger(historicalSummary.historical_unique_high_assets) || historicalSummary.historical_unique_high_assets < 1) {
      setHistoricalStatus("ready");
      setHistoricalData({ page: historicalPage, limit: HISTORICAL_HIGH_LIMIT, total: 0, assets: [] });
      return undefined;
    }
    let active = true;
    setHistoricalStatus("loading");
    getRiskHistoryAssets({ page: historicalPage, limit: HISTORICAL_HIGH_LIMIT })
      .then((result) => {
        if (!active) return;
        if (result?.availability_state !== "AVAILABLE" || !Array.isArray(result.assets) || !Number.isInteger(result.total)) {
          setHistoricalStatus("unavailable");
          setHistoricalData(result || null);
          return;
        }
        setHistoricalData(result);
        setHistoricalStatus("ready");
      })
      .catch(() => { if (active) setHistoricalStatus("error"); });
    return () => { active = false; };
  }, [historicalPage, historicalSummary, status]);

  useEffect(() => {
    if (status !== "ready") return;
    const params = new URLSearchParams(query);
    const section = params.get("section") || params.get("view");
    if (!["risk-distribution", "historical-high-risk"].includes(section)) return;
    document.getElementById(section)?.scrollIntoView?.({ behavior: "smooth", block: "start" });
  }, [query, status]);

  if (status === "loading") return <LoadingState title="Loading risk and exposure" copy="Retrieving current risk and exposure evidence." />;
  if (status === "error") return <ErrorState title="Risk workspace unavailable" copy="One or more current risk or exposure contracts could not be loaded." onRetry={() => setRequestVersion((value) => value + 1)} />;
  if (data.overview.current_scan_id == null) return <EmptyState />;

  const { overview, findings, sensitivePorts, exposure, reviewIndicators, httpStatuses } = data;
  const portRows = Array.isArray(sensitivePorts) ? sensitivePorts : [];
  const portSummary = sensitivePortSummary(portRows);
  const totalHistoricalPages = Math.max(Math.ceil((historicalData?.total || historicalSummary?.historical_unique_high_assets || 0) / HISTORICAL_HIGH_LIMIT), 1);
  const groups = httpStatusGroups(httpStatuses);
  const historicalAvailable = historicalSummary?.availability_state === "AVAILABLE";
  const historicalCount = historicalAvailable && Number.isInteger(historicalSummary.historical_unique_high_assets)
    ? historicalSummary.historical_unique_high_assets
    : null;
  const incompleteHistoricalScans = historicalCoverage(historicalSummary);

  return (
    <div className="operations-grid">
      <section className="operations-kpis" aria-label="Risk and exposure metrics">
        <MetricCard label="Current High Risk" value={overview.risk_distribution?.High ?? 0} support="Current scan" accent={RISK_COLORS.High} href="#/assets?priority=High" />
        <MetricCard label="Assets with risk scores" value={priorityData?.count ?? "—"} support="Current scan" accent="#a96f1f" />
        <MetricCard label="HTTP responding" value={exposure.http_responding_domains ?? "—"} support="Current scan" accent="#2f7d5b" href="#/assets?http_live=true" />
        <MetricCard
          label="Historical High Risk"
          value={historicalCount ?? "—"}
          support={historicalAvailable ? "High in at least one successful retained scan" : "Historical data unavailable"}
          accent="#7b5bb5"
          href={historicalCount > 0 ? "#/risk?section=historical-high-risk" : undefined}
        />
      </section>

      <section className="actionable-kpis" aria-label="Actionable evidence">
        <MetricCard label="Recorded Findings" value={findings.length} support="Source-recorded observations" accent="#b43d4a" href="#/risk/security-review?tab=evidence-signals" />
        <MetricCard label="Observed sensitive-port exposures" value={portSummary.value} support={portSummary.support} accent="#a96f1f" href="#/risk/security-review?tab=sensitive-ports" />
        <MetricCard label="Review Indicators" value={reviewIndicators.count ?? "—"} support="Review only · not findings" accent="#9a79d6" href="#/risk/security-review?tab=evidence-signals&signals=review-indicators" />
      </section>

      <div className="operation-panel-full">
        <a className="context-link" href="#/risk/security-review?tab=prioritized-assets">Open Prioritized Assets in Security Review →</a>
      </div>

      {groups.length > 0 && (
        <nav className="risk-http-drilldown" aria-label="Filter assets by HTTP status group">
          <span>HTTP status groups</span>
          {groups.map(({ group, count }) => (
            <a className={`http-group-link http-group-${group[0]}`} href={`#/assets?http_status_group=${group}`} key={group}>
              <span>{group}</span><strong>{count}</strong><span aria-hidden="true">→</span>
            </a>
          ))}
        </nav>
      )}

      <Panel title="Current Risk Distribution" subtitle="Canonical priorities across confirmed organizational assets" meta={`SCAN #${overview.current_scan_id}`} className="operation-panel-full" id="risk-distribution">
        <RiskDistributionChart distribution={overview.risk_distribution} priorityHref={(priority) => `#/assets?priority=${encodeURIComponent(priority)}&limit=25`} />
      </Panel>

      <Panel title="Historical High Risk" subtitle="Distinct organizational assets with a persisted High score in a successful scan" meta={historicalCount == null ? "UNAVAILABLE" : `${historicalCount} ASSETS`} className="operation-panel-full historical-high-risk-panel" id="historical-high-risk">
        {historicalStatus === "loading" && <LoadingState title="Loading Historical High Risk" copy="Retrieving persisted High-score history." />}
        {(historicalStatus === "error" || historicalStatus === "unavailable") && (
          <div className="risk-history-unavailable" role={historicalStatus === "error" ? "alert" : "status"}>
            <strong>{historicalStatus === "error" ? "Historical High Risk unavailable" : historicalSummary?.availability_state === "UNAVAILABLE" ? "Historical High Risk unavailable" : "Historical High Risk data incomplete"}</strong>
            <span>{historicalStatus === "error" ? "The historical asset list could not be loaded." : historicalSummary?.limitations?.[0] || "The backend did not return a complete historical asset contract."}</span>
          </div>
        )}
        {historicalStatus === "ready" && historicalData?.assets?.length === 0 && <div className="detail-empty">No persisted High-score assets were recorded in successful scans.</div>}
        {historicalStatus === "ready" && historicalData?.assets?.length > 0 && (
          <>
            <div className="dense-table-wrap">
              <table className="dense-table risk-history-table">
                <thead><tr><th>Asset</th><th>Current class</th><th>Maximum High score</th><th>First High</th><th>Last High</th><th>High observations</th><th>Current score</th><th>Current membership</th><th /></tr></thead>
                <tbody>{historicalData.assets.map((asset) => (
                  <tr key={asset.domain_id || asset.domain}>
                    <td><AssetLink domain={asset.domain} returnTo="risk" returnQuery={`section=historical-high-risk&historical_page=${historicalPage}`} /></td>
                    <td><StatusBadge value={displayAssetClass(asset.asset_class)} /></td>
                    <td><span className="risk-score">{asset.maximum_persisted_historical_score ?? "—"}</span></td>
                    <td>{historicalScanLabel(asset.first_recorded_high_scan_id, asset.first_recorded_high_scan_time)}</td>
                    <td>{historicalScanLabel(asset.last_recorded_high_scan_id, asset.last_recorded_high_scan_time)}</td>
                    <td>{Number.isInteger(asset.high_score_observations) ? asset.high_score_observations : "—"}</td>
                    <td>{asset.current_risk_score ?? "—"}{asset.current_priority ? <span className="asset-secondary">{asset.current_priority}</span> : null}</td>
                    <td>{asset.current_scan_member === true ? "In current scan" : asset.current_scan_member === false ? "Not in current scan" : "—"}</td>
                    <td><AssetLink domain={asset.domain} returnTo="risk" returnQuery={`section=historical-high-risk&historical_page=${historicalPage}`} className="row-action">→</AssetLink></td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
            <div className="pagination-bar risk-history-pagination">
              <span>Page {historicalPage} of {totalHistoricalPages} · {historicalData.total} distinct assets</span>
              <div>
                <button type="button" className="secondary-button" disabled={historicalPage <= 1} onClick={() => setHistoricalPage((page) => page - 1)}>Previous</button>
                <button type="button" className="secondary-button" disabled={historicalPage >= totalHistoricalPages} onClick={() => setHistoricalPage((page) => page + 1)}>Next</button>
              </div>
            </div>
          </>
        )}
        {historicalAvailable && incompleteHistoricalScans.length > 0 && (
          <details className="risk-history-coverage">
            <summary>Historical coverage details</summary>
            <p>Missing risk observations are unknown coverage, not Low risk. Historical class-at-scan-time is not stored.</p>
            <ul>{incompleteHistoricalScans.map((scan) => <li key={scan.scan_id}>Scan #{scan.scan_id}: {scan.assets_with_risk_observation} of {scan.organizational_members} organizational assets had risk observations.</li>)}</ul>
          </details>
        )}
      </Panel>

    </div>
  );
}
