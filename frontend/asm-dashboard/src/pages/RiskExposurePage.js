import React, { useEffect, useRef, useState } from "react";
import {
  getExposureSummary,
  getFindings,
  getHttpStatus,
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

const PRIORITY_LIMIT = 25;
const SECONDARY_VIEWS = [
  ["review-indicators", "Needs review"],
  ["findings", "Findings"],
  ["sensitive-ports", "Sensitive ports"],
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

function redirectLabel(indicator) {
  return indicator.final_url_verification === "LEGACY_UNKNOWN"
    ? "Historical redirect URL — verification unavailable"
    : "Cross-host redirect observed";
}

function responseSummary(indicator) {
  const initial = indicator.http_status == null ? "Initial response unavailable" : `Initial ${indicator.http_status}`;
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

export default function RiskExposurePage({ query }) {
  const [data, setData] = useState(null);
  const [status, setStatus] = useState("loading");
  const [requestVersion, setRequestVersion] = useState(0);
  const [priorityPage, setPriorityPage] = useState(1);
  const [priorityData, setPriorityData] = useState(null);
  const [priorityStatus, setPriorityStatus] = useState("loading");
  const [priorityRequestVersion, setPriorityRequestVersion] = useState(0);
  const [secondaryView, setSecondaryView] = useState(() => readSecondaryView(query));
  const secondaryTabRefs = useRef({});

  useEffect(() => {
    setSecondaryView(readSecondaryView(query));
  }, [query]);

  useEffect(() => {
    let active = true;
    setStatus("loading");
    const httpStatusRequest = typeof getHttpStatus === "function"
      ? Promise.resolve(getHttpStatus()).catch(() => null)
      : Promise.resolve(null);
    Promise.all([
      getV2Overview(),
      getFindings(),
      getSensitiveExposure(),
      getExposureSummary(),
      Promise.resolve(getV2ReviewIndicators()).catch(() => ({ error: true, count: 0, indicators: [] })),
      httpStatusRequest,
    ]).then(([overview, findings, sensitivePorts, exposure, reviewIndicators, httpStatuses]) => {
      if (active) {
        setData({ overview, findings, sensitivePorts, exposure, reviewIndicators, httpStatuses });
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
    if (status !== "ready") return;
    const section = new URLSearchParams(query).get("section");
    if (!["findings", "sensitive-ports", "review-indicators"].includes(section)) return;
    document.getElementById(section)?.scrollIntoView?.({ behavior: "smooth", block: "start" });
  }, [query, status]);

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

  const { overview, findings, sensitivePorts, exposure, reviewIndicators, httpStatuses } = data;
  const totalPriorityPages = Math.max(Math.ceil((priorityData?.count || 0) / PRIORITY_LIMIT), 1);
  const groups = httpStatusGroups(httpStatuses);

  return (
    <div className="operations-grid">
      <section className="operations-kpis" aria-label="Risk and exposure metrics">
        <MetricCard label="High risk" value={overview.risk_distribution?.High ?? 0} support="Current scan" accent={RISK_COLORS.High} href="#/assets?priority=High" />
        <MetricCard label="Assets with risk scores" value={priorityData?.count ?? "—"} support="Current scan" accent="#a96f1f" />
        <MetricCard label="Assets with IP addresses" value={exposure.resolving_domains ?? "—"} support="Current scan" accent="#327d80" href="#/assets?has_ip=true" />
        <MetricCard label="HTTP responding" value={exposure.http_responding_domains ?? "—"} support="Current scan" accent="#2f7d5b" href="#/assets?http_live=true" />
      </section>

      <section className="actionable-kpis" aria-label="Actionable evidence">
        <MetricCard label="Findings" value={findings.length} support="Deterministic observations" accent="#b43d4a" href="#/risk?section=findings" />
        <MetricCard label="Sensitive port exposure" value={sensitivePorts.length} support="Configured sensitive ports" accent="#a96f1f" href="#/risk?section=sensitive-ports" />
        <MetricCard label="Review Indicators" value={reviewIndicators.count ?? "—"} support="Review only · not findings" accent="#9a79d6" href="#/risk?section=review-indicators" />
      </section>

      <Panel title="Risk distribution" meta={`SCAN #${overview.current_scan_id}`} className="operation-panel-full">
        <RiskDistributionChart distribution={overview.risk_distribution} priorityHref={(priority) => `#/assets?priority=${encodeURIComponent(priority)}`} />
      </Panel>

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
                    <td><AssetLink domain={asset.domain} returnTo="risk" /></td>
                    <td><StatusBadge value={asset.risk?.priority} /></td>
                    <td><span className="risk-score">{asset.risk?.score ?? "—"}</span></td>
                    <td>{reasons(asset.risk?.reasons)}</td>
                    <td><AssetLink domain={asset.domain} returnTo="risk" className="row-action">→</AssetLink></td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
            {priorityData.count > 0 && (
              <div className="pagination-bar">
                <span>Page {priorityPage} of {totalPriorityPages}</span>
                <div>
                  <button type="button" className="secondary-button" disabled={priorityPage <= 1} onClick={() => setPriorityPage((page) => page - 1)}>Previous</button>
                  <button type="button" className="secondary-button" disabled={priorityPage >= totalPriorityPages} onClick={() => setPriorityPage((page) => page + 1)}>Next</button>
                </div>
              </div>
            )}
          </>
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
                        <td><AssetLink domain={indicator.domain} returnTo="risk" /><StatusBadge value={indicator.asset_class} /></td>
                        <td><strong>{redirectLabel(indicator)}</strong><span className="asset-secondary">Review only · not a vulnerability conclusion</span></td>
                        <td><StatusBadge value={indicator.http_observation_status} /><span className="asset-secondary">{responseSummary(indicator)}</span></td>
                        <td><span className="review-destination technical-value" title={destination || undefined}>{destination || "Destination unavailable"}</span><span className="asset-secondary">{indicator.final_hostname || "Hostname unavailable"}</span></td>
                        <td>{indicator.destination_confirmed ? <><StatusBadge value={indicator.destination_asset_class} /><span className="asset-secondary">Current scan asset match</span></> : <><span className="not-applicable">No current asset match</span><span className="asset-secondary">Redirect does not establish ownership or authorization</span></>}</td>
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

        {secondaryView === "findings" && (
          <div id="findings" role="tabpanel" aria-labelledby="findings-tab" tabIndex={0}>
          <Panel title="Findings" subtitle="Deterministic observations" meta={`${findings.length} ROWS`} className="operation-panel-full">
            {findings.length ? (
              <div className="compact-list">
                {findings.map((finding, index) => (
                  <div className="compact-evidence-row" key={`${finding.domain}-${finding.finding}-${index}`}>
                    <StatusBadge value={finding.severity} />
                    <div><AssetLink domain={finding.domain} returnTo="risk" /><strong>{finding.finding}</strong><p>{finding.evidence || "No additional evidence recorded"}</p></div>
                  </div>
                ))}
              </div>
            ) : <div className="detail-empty">No findings were recorded for the current scan.</div>}
          </Panel>
          </div>
        )}

        {secondaryView === "sensitive-ports" && (
          <div id="sensitive-ports" role="tabpanel" aria-labelledby="sensitive-ports-tab" tabIndex={0}>
          <Panel title="Sensitive port exposure" subtitle="Configured sensitive ports observed" meta={`${sensitivePorts.length} ROWS`} className="operation-panel-full">
            {sensitivePorts.length ? (
              <div className="compact-list">
                {sensitivePorts.map((item, index) => (
                  <div className="port-exposure-row" key={`${item.domain}-${item.port}-${index}`}>
                    <span className="port-number">{item.port}</span>
                    <div><AssetLink domain={item.domain} returnTo="risk" /><p>{item.service || "Service unspecified"}</p></div>
                    <span className="configured-risk">Sensitivity {item.risk}</span>
                  </div>
                ))}
              </div>
            ) : <div className="detail-empty">No configured sensitive ports were observed in the current scan.</div>}
          </Panel>
          </div>
        )}
      </section>
    </div>
  );
}
