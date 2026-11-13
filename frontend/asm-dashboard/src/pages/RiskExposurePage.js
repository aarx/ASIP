import React, { useEffect, useRef, useState } from "react";
import {
  getExposureSummary,
  getFindings,
  getHttpStatus,
  getDnsSecuritySummary,
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
import { RISK_COLORS } from "../components/ui/RiskDistributionChart";
import StatusBadge from "../components/ui/StatusBadge";
import { EmptyState, ErrorState, LoadingState } from "../components/ui/AsyncState";
import { displayAssetClass, displayHttpStatus, isUsableHttpStatus } from "../utils/presentation";

const PRIORITY_LIMIT = 25;
const HISTORICAL_HIGH_LIMIT = 10;
const SENSITIVE_PORT_RESULT_LIMIT = 20;
const SECONDARY_VIEWS = [
  ["review-indicators", "Needs review"],
  ["sensitive-ports", "Sensitive ports"],
  ["dns-security", "DNS assessments"],
];

function reasons(reasonsList) {
  return (
    <div className="reason-list">
      {(reasonsList || []).map((reason) => (
        <span className="reason-token" key={reason}>{reason.replaceAll("_", " ")}</span>
      ))}
    </div>
  );
}

function readSecondaryView(query) {
  const params = new URLSearchParams(query);
  const requested = params.get("view") || params.get("section");
  return SECONDARY_VIEWS.some(([view]) => view === requested) ? requested : "review-indicators";
}

function dnsCount(value) {
  return Number.isInteger(value) && value >= 0 ? value.toLocaleString() : "—";
}

function dnsScope(summary, currentScanId) {
  if (!Number.isInteger(summary?.scan_id)) return "SCAN UNAVAILABLE";
  return summary.scan_id === currentScanId ? `SCAN #${summary.scan_id}` : `HISTORICAL SCAN #${summary.scan_id}`;
}

function dnsCoverageState(summary) {
  if (!summary || summary.error) return { title: "DNS Security unavailable", copy: "Assessment data could not be loaded." };
  if (summary.checked_assets === 0) return { title: "Not Assessed", copy: "No DNS checks have been executed for this scan." };
  if (![summary.checked_assets, summary.eligible_assets, summary.affected_assets].every((value) => Number.isInteger(value))) {
    return { title: "Assessment coverage unavailable", copy: "The summary did not include enough coverage data to classify the assessment." };
  }
  if (summary.checked_assets < summary.eligible_assets) {
    return { title: "Partial coverage", copy: `${dnsCount(summary.checked_assets)} of ${dnsCount(summary.eligible_assets)} eligible assets assessed.` };
  }
  return summary.affected_assets > 0
    ? { title: "Affected assets recorded", copy: `${dnsCount(summary.affected_assets)} assets have actionable DNS outcomes.` }
    : { title: "No actionable DNS outcomes recorded", copy: "Coverage is complete; DNS assessment details remain available." };
}

function sensitivePortSummary(rows) {
  if (!rows.length) {
    return { value: "—", support: "Assessment coverage unavailable", meta: "NOT RECORDED" };
  }
  if (rows.length >= SENSITIVE_PORT_RESULT_LIMIT) {
    return { value: `${SENSITIVE_PORT_RESULT_LIMIT}+`, support: "Observed rows · result list capped at 20", meta: `${SENSITIVE_PORT_RESULT_LIMIT}+ OBSERVED` };
  }
  return { value: rows.length, support: "Observed current-scan rows", meta: `${rows.length} OBSERVED` };
}

function DnsSecurityCoverage({ summary, currentScanId }) {
  const coverage = dnsCoverageState(summary);
  return (
    <Panel title="DNS Security" meta={dnsScope(summary, currentScanId)} className="operation-panel-full dns-risk-coverage-panel">
      {summary?.error || !summary ? (
        <div className="dns-risk-unavailable" role="alert"><strong>{coverage.title}</strong><span>{coverage.copy}</span></div>
      ) : (
        <>
          <div className="dns-risk-coverage-grid" aria-label="DNS Security coverage">
            <div><span>Eligible Assets</span><strong>{dnsCount(summary.eligible_assets)}</strong></div>
            <div><span>Assessed Assets</span><strong>{dnsCount(summary.checked_assets)}</strong></div>
            <div><span>Not Assessed</span><strong>{dnsCount(summary.unchecked_assets)}</strong></div>
            <div><span>Affected Assets</span><strong>{dnsCount(summary.affected_assets)}</strong></div>
          </div>
          <div className="dns-risk-status" role="status">
            <strong>{coverage.title}</strong>
            <span>{coverage.copy}</span>
            <span>Availability: {summary.availability_state || "Unavailable"} · Execution: {summary.execution_state || "Unavailable"} · Operation currently: {summary.operation_enabled_currently === true ? "Enabled" : summary.operation_enabled_currently === false ? "Disabled" : "Unavailable"}</span>
          </div>
          <a className="context-link dns-risk-link" href="#/risk/dns-security">Open DNS Security details →</a>
        </>
      )}
    </Panel>
  );
}

function redirectLabel(indicator) {
  return indicator.final_url_verification === "LEGACY_UNKNOWN"
    ? "Historical redirect URL — verification unavailable"
    : "Cross-host redirect observed";
}

function responseSummary(indicator) {
  const initial = isUsableHttpStatus(indicator.http_status)
    ? `Initial ${indicator.http_status}`
    : displayHttpStatus(indicator.http_observation_status, indicator.http_status);
  if (indicator.final_url_verification === "COMPLETE" && indicator.final_status != null) {
    return `${initial} · Verified terminal ${indicator.final_status}`;
  }
  return `${initial} · Terminal response unavailable`;
}

function redirectDestination(indicator) {
  if (indicator.observed_redirect_destination) return indicator.observed_redirect_destination;
  if (indicator.final_url_verification === "LEGACY_UNKNOWN") return indicator.final_url || null;
  return null;
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
  const [priorityPage, setPriorityPage] = useState(() => readPositivePage(query, "priority_page"));
  const [priorityData, setPriorityData] = useState(null);
  const [priorityStatus, setPriorityStatus] = useState("loading");
  const [priorityRequestVersion, setPriorityRequestVersion] = useState(0);
  const [historicalSummary, setHistoricalSummary] = useState(null);
  const [historicalPage, setHistoricalPage] = useState(() => readPositivePage(query, "historical_page"));
  const [historicalData, setHistoricalData] = useState(null);
  const [historicalStatus, setHistoricalStatus] = useState("loading");
  const [secondaryView, setSecondaryView] = useState(() => readSecondaryView(query));
  const secondaryTabRefs = useRef({});

  useEffect(() => {
    setSecondaryView(readSecondaryView(query));
    const requestedPriorityPage = readPositivePage(query, "priority_page");
    setPriorityPage((currentPage) => currentPage === requestedPriorityPage ? currentPage : requestedPriorityPage);
    const requestedPage = readPositivePage(query, "historical_page");
    setHistoricalPage((currentPage) => currentPage === requestedPage ? currentPage : requestedPage);
  }, [query]);

  useEffect(() => {
    let active = true;
    setStatus("loading");
    const httpStatusRequest = typeof getHttpStatus === "function"
      ? Promise.resolve(getHttpStatus()).catch(() => null)
      : Promise.resolve(null);
    const dnsSecurityRequest = typeof getDnsSecuritySummary === "function"
      ? Promise.resolve(getDnsSecuritySummary()).then((result) => result?.availability_state === "AVAILABLE" ? result : { error: true }).catch(() => ({ error: true }))
      : Promise.resolve({ error: true });
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
      dnsSecurityRequest,
      historicalSummaryRequest,
    ]).then(([overview, findings, sensitivePorts, exposure, reviewIndicators, httpStatuses, dnsSummary, riskHistory]) => {
      if (active) {
        setData({ overview, findings, sensitivePorts, exposure, reviewIndicators, httpStatuses, dnsSummary, riskHistory });
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
    setPriorityStatus("loading");
    getV2Assets({
      page: priorityPage,
      limit: PRIORITY_LIMIT,
      risk_positive: true,
      sort_by: "risk_score",
      sort_dir: "desc",
    }).then((result) => {
      if (active) {
        setPriorityData(result);
        setPriorityStatus("ready");
      }
    }).catch(() => { if (active) setPriorityStatus("error"); });
    return () => { active = false; };
  }, [data, priorityPage, priorityRequestVersion, status]);

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
    if (!["priority-assets", "sensitive-ports", "review-indicators", "dns-security", "historical-high-risk"].includes(section)) return;
    document.getElementById(section)?.scrollIntoView?.({ behavior: "smooth", block: "start" });
  }, [query, status]);

  const movePriorityPage = (page) => {
    const params = new URLSearchParams(query);
    params.set("section", "priority-assets");
    params.set("priority_page", String(page));
    window.location.hash = `#/risk?${params.toString()}`;
  };

  const moveSecondaryTab = (currentView, direction) => {
    const currentIndex = SECONDARY_VIEWS.findIndex(([view]) => view === currentView);
    const nextIndex = (currentIndex + direction + SECONDARY_VIEWS.length) % SECONDARY_VIEWS.length;
    const nextView = SECONDARY_VIEWS[nextIndex][0];
    setSecondaryView(nextView);
    secondaryTabRefs.current[nextView]?.focus();
  };

  const handleSecondaryTabKeyDown = (event, view) => {
    if (event.key === "ArrowRight" || event.key === "ArrowDown") {
      event.preventDefault();
      moveSecondaryTab(view, 1);
    } else if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
      event.preventDefault();
      moveSecondaryTab(view, -1);
    } else if (event.key === "Home") {
      event.preventDefault();
      setSecondaryView(SECONDARY_VIEWS[0][0]);
      secondaryTabRefs.current[SECONDARY_VIEWS[0][0]]?.focus();
    } else if (event.key === "End") {
      event.preventDefault();
      const lastView = SECONDARY_VIEWS[SECONDARY_VIEWS.length - 1][0];
      setSecondaryView(lastView);
      secondaryTabRefs.current[lastView]?.focus();
    }
  };

  if (status === "loading") return <LoadingState title="Loading risk and exposure" copy="Retrieving current risk and exposure evidence." />;
  if (status === "error") return <ErrorState title="Risk workspace unavailable" copy="One or more current risk or exposure contracts could not be loaded." onRetry={() => setRequestVersion((value) => value + 1)} />;
  if (data.overview.current_scan_id == null) return <EmptyState />;

  const { overview, findings, sensitivePorts, exposure, reviewIndicators, httpStatuses, dnsSummary } = data;
  const portRows = Array.isArray(sensitivePorts) ? sensitivePorts : [];
  const portSummary = sensitivePortSummary(portRows);
  const totalPriorityPages = Math.max(Math.ceil((priorityData?.count || 0) / PRIORITY_LIMIT), 1);
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
          label="Previously High Risk"
          value={historicalCount ?? "—"}
          support={historicalAvailable ? "Distinct historical assets" : "Historical data unavailable"}
          accent="#7b5bb5"
          href={historicalCount > 0 ? "#/risk?section=historical-high-risk" : undefined}
        />
      </section>

      <section className="actionable-kpis" aria-label="Actionable evidence">
        <MetricCard label="Findings" value={findings.length} support="Source-recorded observations" accent="#b43d4a" href="#/risk/findings" />
        <MetricCard label="Observed sensitive-port exposures" value={portSummary.value} support={portSummary.support} accent="#a96f1f" href="#/risk?section=sensitive-ports" />
        <MetricCard label="Review Indicators" value={reviewIndicators.count ?? "—"} support="Review only · not findings" accent="#9a79d6" href="#/risk?section=review-indicators" />
      </section>

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

      <Panel title="Priority assets" subtitle="Current assets with risk scores above zero" meta={`${priorityData?.count ?? "—"} ASSETS`} className="operation-panel-full priority-assets-panel" id="priority-assets">
        {priorityStatus === "loading" && <LoadingState title="Loading priority assets" copy="Retrieving the current risk-ranked asset queue." />}
        {priorityStatus === "error" && <ErrorState title="Priority assets unavailable" copy="The current risk-ranked asset queue could not be loaded." onRetry={() => setPriorityRequestVersion((value) => value + 1)} />}
        {priorityStatus === "ready" && priorityData.assets.length === 0 && <div className="detail-empty">No assets have a risk score above zero in this scan.</div>}
        {priorityStatus === "ready" && priorityData.assets.length > 0 && (
          <>
            <div className="dense-table-wrap">
              <table className="dense-table risk-assets-table">
                <thead><tr><th>Asset</th><th>Priority</th><th>Score</th><th>Evidence</th><th /></tr></thead>
                <tbody>{priorityData.assets.map((asset) => (
                  <tr key={asset.domain}>
                    <td><AssetLink domain={asset.domain} returnTo="risk" returnQuery={`section=priority-assets&priority_page=${priorityPage}`} /></td>
                    <td><StatusBadge value={asset.risk?.priority} /></td>
                    <td><span className="risk-score">{asset.risk?.score ?? "—"}</span></td>
                    <td>{reasons(asset.risk?.reasons)}</td>
                    <td><AssetLink domain={asset.domain} returnTo="risk" returnQuery={`section=priority-assets&priority_page=${priorityPage}`} className="row-action">→</AssetLink></td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
            {priorityData.count > 0 && (
              <div className="pagination-bar">
                <span>Page {priorityPage} of {totalPriorityPages}</span>
                <div>
                  <button type="button" className="secondary-button" disabled={priorityPage <= 1} onClick={() => movePriorityPage(priorityPage - 1)}>Previous</button>
                  <button type="button" className="secondary-button" disabled={priorityPage >= totalPriorityPages} onClick={() => movePriorityPage(priorityPage + 1)}>Next</button>
                </div>
              </div>
            )}
          </>
        )}
      </Panel>

      <Panel title="Previously High Risk" subtitle="Distinct organizational assets with a persisted High score in a successful scan" meta={historicalCount == null ? "UNAVAILABLE" : `${historicalCount} ASSETS`} className="operation-panel-full historical-high-risk-panel" id="historical-high-risk">
        {historicalStatus === "loading" && <LoadingState title="Loading historical High Risk" copy="Retrieving persisted High-score history." />}
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

      <section className="risk-secondary-workspace" aria-label="Secondary risk evidence">
        <div className="risk-secondary-header">
          <h2>Supporting evidence</h2>
          <div className="risk-view-tabs" role="tablist" aria-label="Supporting evidence views">
            {SECONDARY_VIEWS.map(([view, label]) => (
              <button
                type="button"
                role="tab"
                id={`${view}-tab`}
                aria-selected={secondaryView === view}
                aria-controls={view}
                tabIndex={secondaryView === view ? 0 : -1}
                className={secondaryView === view ? "active" : ""}
                onClick={() => setSecondaryView(view)}
                onKeyDown={(event) => handleSecondaryTabKeyDown(event, view)}
                ref={(element) => { secondaryTabRefs.current[view] = element; }}
                key={view}
              >
                {label}
              </button>
            ))}
          </div>
        </div>

        {secondaryView === "review-indicators" && (
          <div id="review-indicators" role="tabpanel" aria-labelledby="review-indicators-tab" tabIndex={0}>
          <Panel title="Review Indicators" subtitle="Observed conditions for analyst review; not findings" meta={reviewIndicators.error ? "UNAVAILABLE" : `${reviewIndicators.count} CURRENT`} className="operation-panel-full">
            {reviewIndicators.error ? (
              <div className="review-indicator-error" role="alert">Redirect review evidence could not be loaded. Other risk evidence remains available.</div>
            ) : reviewIndicators.indicators.length ? (
              <div className="dense-table-wrap">
                <table className="dense-table review-indicator-table">
                  <thead><tr><th>Source asset</th><th>Indicator</th><th>HTTP</th><th>Observed destination</th><th>Destination context</th><th /></tr></thead>
                  <tbody>{reviewIndicators.indicators.map((indicator) => {
                    const destination = redirectDestination(indicator);
                    return (
                      <tr key={`${indicator.type}-${indicator.domain}-${indicator.final_url}`}>
                        <td><AssetLink domain={indicator.domain} returnTo="risk" /><StatusBadge value={displayAssetClass(indicator.asset_class)} /></td>
                        <td><strong>{redirectLabel(indicator)}</strong><span className="asset-secondary">Review only · not a vulnerability conclusion</span></td>
                        <td><StatusBadge value={indicator.http_observation_status} /><span className="asset-secondary">{responseSummary(indicator)}</span></td>
                        <td><span className="review-destination technical-value" title={destination || undefined}>{destination || "Destination unavailable"}</span><span className="asset-secondary">{indicator.final_hostname || "Hostname unavailable"}</span></td>
                        <td>{indicator.destination_confirmed ? <><StatusBadge value={displayAssetClass(indicator.destination_asset_class)} /><span className="asset-secondary">Current scan asset match</span></> : <><span className="not-applicable">No current asset match</span><span className="asset-secondary">Redirect does not establish ownership or authorization</span></>}</td>
                        <td><AssetLink domain={indicator.domain} returnTo="risk" className="row-action">→</AssetLink></td>
                      </tr>
                    );
                  })}</tbody>
                </table>
              </div>
            ) : <div className="detail-empty">No cross-host HTTP redirects were observed in the current authoritative scan.</div>}
          </Panel>
          </div>
        )}

        {secondaryView === "sensitive-ports" && (
          <div id="sensitive-ports" role="tabpanel" aria-labelledby="sensitive-ports-tab" tabIndex={0}>
          <Panel title="Sensitive port observations" subtitle="Observed rows; assessment coverage is unavailable" meta={portSummary.meta} className="operation-panel-full">
            {portRows.length ? (
              <div className="compact-list">
                {portRows.map((item, index) => (
                  <div className="port-exposure-row" key={`${item.domain}-${item.port}-${index}`}>
                    <span className="port-number">{item.port}</span>
                    <div><AssetLink domain={item.domain} returnTo="risk" /><p>{item.service || "Service unspecified"}</p></div>
                    <span className="configured-risk">Sensitivity {item.risk}</span>
                  </div>
                ))}
              </div>
            ) : <div className="detail-empty">No port observations recorded for this scan.</div>}
          </Panel>
          </div>
        )}

        {secondaryView === "dns-security" && (
          <div id="dns-security" role="tabpanel" aria-labelledby="dns-security-tab" tabIndex={0}>
            <DnsSecurityCoverage summary={dnsSummary} currentScanId={overview.current_scan_id} />
          </div>
        )}
      </section>
    </div>
  );
}
