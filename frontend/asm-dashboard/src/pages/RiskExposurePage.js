import React, { useEffect, useState } from "react";
import {
  getExposureSummary,
  getFindings,
  getRiskyDomains,
  getSensitiveExposure,
  getV2Overview,
  getV2ReviewIndicators,
} from "../services/api";
import AssetLink from "../components/ui/AssetLink";
import MetricCard from "../components/ui/MetricCard";
import Panel from "../components/ui/Panel";
import RiskDistributionChart, { RISK_COLORS } from "../components/ui/RiskDistributionChart";
import StatusBadge from "../components/ui/StatusBadge";
import { EmptyState, ErrorState, LoadingState } from "../components/ui/AsyncState";

function reasons(reasonsList) {
  return (
    <div className="reason-list">
      {(reasonsList || []).map((reason) => (
        <span className="reason-token" key={reason}>{reason.replaceAll("_", " ")}</span>
      ))}
    </div>
  );
}

export default function RiskExposurePage({ query }) {
  const [data, setData] = useState(null);
  const [status, setStatus] = useState("loading");
  const [requestVersion, setRequestVersion] = useState(0);

  useEffect(() => {
    let active = true;
    setStatus("loading");
    Promise.all([
      getV2Overview(),
      getRiskyDomains(),
      getFindings(),
      getSensitiveExposure(),
      getExposureSummary(),
      getV2ReviewIndicators().catch(() => ({ error: true, count: 0, indicators: [] })),
    ]).then(([overview, riskyAssets, findings, sensitivePorts, exposure, reviewIndicators]) => {
      if (active) {
        setData({ overview, riskyAssets, findings, sensitivePorts, exposure, reviewIndicators });
        setStatus("ready");
      }
    }).catch(() => { if (active) setStatus("error"); });
    return () => { active = false; };
  }, [requestVersion]);

  useEffect(() => {
    if (status !== "ready") return;
    const section = new URLSearchParams(query).get("section");
    if (!["findings", "sensitive-ports", "review-indicators"].includes(section)) return;
    document.getElementById(section)?.scrollIntoView?.({ behavior: "smooth", block: "start" });
  }, [query, status]);

  if (status === "loading") return <LoadingState title="Loading risk and exposure" copy="Retrieving canonical risk and current positive exposure evidence." />;
  if (status === "error") return <ErrorState title="Risk workspace unavailable" copy="One or more current risk or exposure contracts could not be loaded." onRetry={() => setRequestVersion((value) => value + 1)} />;
  if (data.overview.current_scan_id == null) return <EmptyState />;

  const { overview, riskyAssets, findings, sensitivePorts, exposure, reviewIndicators } = data;
  return (
    <div className="operations-grid">
      <section className="operations-kpis" aria-label="Risk and exposure metrics">
        <MetricCard label="High priority" value={overview.risk_distribution?.High ?? 0} support="Canonical current risk" accent={RISK_COLORS.High} />
        <MetricCard label="Scored assets" value={riskyAssets.length} support="Positive canonical score" accent="#e7a84b" />
        <MetricCard label="Resolving assets" value={exposure.resolving_domains ?? 0} support="Positive DNS evidence" accent="#3dc4ff" />
        <MetricCard label="HTTP responses" value={exposure.http_responding_domains ?? 0} support="Observed responding assets" accent="#39cb91" />
      </section>

      <section className="actionable-kpis" aria-label="Actionable evidence">
        <MetricCard label="Findings" value={findings.length} support="Current deterministic observations" accent="#f06467" href="#/risk?section=findings" />
        <MetricCard label="Sensitive port exposure" value={sensitivePorts.length} support="Positive configured-port evidence" accent="#e7a84b" href="#/risk?section=sensitive-ports" />
        <MetricCard label="Review Indicators" value={reviewIndicators.count ?? 0} support="Context required · not findings" accent="#9a79d6" href="#/risk?section=review-indicators" />
      </section>

      <Panel id="findings" title="Findings" subtitle="Current deterministic findings; indicators are not confirmed vulnerabilities" meta={`${findings.length} ROWS`} className="operation-panel-half">
        {findings.length ? (
          <div className="compact-list">
            {findings.map((finding, index) => (
              <div className="compact-evidence-row" key={`${finding.domain}-${finding.finding}-${index}`}>
                <StatusBadge value={finding.severity} />
                <div>
                  <AssetLink domain={finding.domain} returnTo="risk" />
                  <strong>{finding.finding}</strong>
                  <p>{finding.evidence || "No additional evidence recorded"}</p>
                </div>
              </div>
            ))}
          </div>
        ) : <div className="detail-empty">No findings were recorded for the current scan.</div>}
      </Panel>

      <Panel id="sensitive-ports" title="Sensitive port exposure" subtitle="Positive observations matching configured sensitive ports" meta={`${sensitivePorts.length} ROWS`} className="operation-panel-half">
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

      <Panel id="review-indicators" title="Review Indicators" subtitle="Observed conditions requiring analyst context; indicators are not findings" meta={reviewIndicators.error ? "UNAVAILABLE" : `${reviewIndicators.count} CURRENT`} className="operation-panel-full">
        {reviewIndicators.error ? (
          <div className="review-indicator-error" role="alert">Redirect review evidence could not be loaded. Canonical risk and other exposure evidence remain available.</div>
        ) : reviewIndicators.indicators.length ? (
          <div className="dense-table-wrap">
            <table className="dense-table review-indicator-table">
              <thead><tr><th>Source asset</th><th>Indicator</th><th>HTTP</th><th>Observed destination</th><th>Destination context</th><th /></tr></thead>
              <tbody>{reviewIndicators.indicators.map((indicator) => (
                <tr key={`${indicator.type}-${indicator.domain}-${indicator.final_url}`}>
                  <td><AssetLink domain={indicator.domain} returnTo="risk" /><StatusBadge value={indicator.asset_class} /></td>
                  <td><strong>Cross-host redirect</strong><span className="asset-secondary">Review only · not a vulnerability conclusion</span></td>
                  <td><StatusBadge value={indicator.http_observation_status} /><span className="asset-secondary">{indicator.http_status} → {indicator.final_status ?? "—"}</span></td>
                  <td><span className="review-destination technical-value" title={indicator.final_url}>{indicator.final_url}</span><span className="asset-secondary">{indicator.final_hostname}</span></td>
                  <td>{indicator.destination_confirmed ? <><StatusBadge value={indicator.destination_asset_class} /><span className="asset-secondary">Independently confirmed current asset</span></> : <><span className="not-applicable">Not currently confirmed</span><span className="asset-secondary">No ownership or testing authorization by redirect</span></>}</td>
                  <td><AssetLink domain={indicator.domain} returnTo="risk" className="row-action">→</AssetLink></td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        ) : <div className="detail-empty">No cross-host HTTP redirects were observed in the current authoritative scan.</div>}
      </Panel>

      <Panel title="Canonical risk posture" subtitle="Backend-owned priorities across confirmed organizational assets" meta={`SCAN #${overview.current_scan_id}`} className="operation-panel-third">
        <RiskDistributionChart distribution={overview.risk_distribution} priorityHref={(priority) => `#/assets?priority=${encodeURIComponent(priority)}&limit=25`} />
      </Panel>

      <Panel title="Prioritized assets" subtitle="Positive canonical scores ordered by the backend" meta={`${riskyAssets.length} ASSETS`} className="operation-panel-wide">
        {riskyAssets.length ? (
          <div className="dense-table-wrap">
            <table className="dense-table risk-assets-table">
              <thead><tr><th>Asset</th><th>Priority</th><th>Score</th><th>Deterministic reasons</th><th /></tr></thead>
              <tbody>{riskyAssets.map((asset) => (
                <tr key={asset.domain}>
                  <td><AssetLink domain={asset.domain} returnTo="risk" /></td>
                  <td><StatusBadge value={asset.priority} /></td>
                  <td><span className="risk-score">{asset.risk_score}</span></td>
                  <td>{reasons(asset.reasons)}</td>
                  <td><AssetLink domain={asset.domain} returnTo="risk" className="row-action">→</AssetLink></td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        ) : <div className="detail-empty">No assets have a positive canonical score in this scan.</div>}
      </Panel>
    </div>
  );
}
