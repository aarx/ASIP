import React, { useEffect, useState } from "react";
import { getAssetGrowth, getHttpStatus, getV2Overview, getV2Scans } from "../services/api";
import MetricCard from "../components/ui/MetricCard";
import Panel from "../components/ui/Panel";
import StatusBadge from "../components/ui/StatusBadge";
import { EmptyState, ErrorState, LoadingState } from "../components/ui/AsyncState";
import RiskDistributionChart, { RISK_COLORS } from "../components/ui/RiskDistributionChart";
import AssetLink from "../components/ui/AssetLink";
import OverviewIntelligence from "../components/ui/OverviewIntelligence";

const OWNERSHIP_COLORS = {
  Known: "#4655a6",
  Shadow: "#7e91a8",
  Candidate: "#9a79d6",
  External: "#546579",
};

function humanizeReason(reason) {
  return String(reason || "")
    .replace(":", ": ")
    .replaceAll("_", " ");
}

function AttentionTable({ assets }) {
  if (!assets.length) {
    return <p className="panel-subtitle">No scored assets currently require attention.</p>;
  }

  return (
    <div style={{ overflowX: "auto" }}>
      <table className="attention-table">
        <thead>
          <tr><th>Asset</th><th>Priority</th><th>Score</th><th>Deterministic reasons</th></tr>
        </thead>
        <tbody>
          {assets.map((asset) => (
            <tr key={asset.domain}>
              <td><AssetLink domain={asset.domain} returnTo="overview" /></td>
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

function OwnershipComposition({ counts }) {
  const values = [
    ["Known", counts.known, "#/assets?asset_class=KNOWN&limit=25"],
    ["Shadow", counts.shadow, "#/shadow"],
    ["Candidate", counts.candidate, "#/brand?ownership=CANDIDATE"],
    ["External", counts.external, "#/brand?ownership=EXTERNAL"],
  ];
  const max = Math.max(...values.map(([, value]) => value), 1);

  return (
    <>
      <div className="ownership-list">
        {values.map(([name, value, href]) => (
          <a className="ownership-row ownership-row-link" href={href} key={name} aria-label={`Open ${name} assets`}>
            <span className="ownership-name">{name}</span>
            <div className="ownership-track">
              <div
                className="ownership-fill"
                style={{
                  "--ownership-color": OWNERSHIP_COLORS[name],
                  width: `${(value / max) * 100}%`,
                }}
              />
            </div>
            <span className="ownership-count">{value}</span>
            <span className="ownership-arrow" aria-hidden="true">→</span>
          </a>
        ))}
      </div>
      <hr className="ownership-divider" />
      <div className="ownership-note">
        <i className="ownership-note-marker" aria-hidden="true" />
        <span>Known and Shadow are confirmed organizational assets. Candidate and External remain in the Brand Perimeter and do not receive organizational risk.</span>
      </div>
    </>
  );
}

function relativeCompletion(value) {
  if (!value) return "completion time unavailable";
  const completed = new Date(value);
  if (Number.isNaN(completed.getTime())) return "completion time unavailable";
  const elapsed = Math.max(Date.now() - completed.getTime(), 0);
  const minutes = Math.floor(elapsed / 60000);
  if (minutes < 1) return "completed just now";
  if (minutes < 60) return `completed ${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `completed ${hours}h ago`;
  return `completed ${Math.floor(hours / 24)}d ago`;
}

export default function OverviewPage() {
  const [data, setData] = useState(null);
  const [status, setStatus] = useState("loading");
  const [requestVersion, setRequestVersion] = useState(0);

  useEffect(() => {
    let active = true;
    const optionalRequest = (request) => Promise.resolve()
      .then(request)
      .then((value) => ({ value, status: "ready" }))
      .catch(() => ({ value: null, status: "error" }));
    setStatus("loading");
    Promise.all([
      getV2Overview(),
      Promise.resolve(getV2Scans(100)).catch(() => null),
      optionalRequest(getAssetGrowth),
      optionalRequest(getHttpStatus),
    ])
      .then(([result, scans, assetGrowth, httpStatus]) => {
        if (active) {
          setData({
            ...result,
            scanHistory: scans,
            assetGrowth: assetGrowth.value,
            assetGrowthStatus: assetGrowth.status,
            httpStatus: httpStatus.value,
            httpStatusStatus: httpStatus.status,
          });
          setStatus("ready");
        }
      })
      .catch(() => {
        if (active) setStatus("error");
      });
    return () => { active = false; };
  }, [requestVersion]);

  if (status === "loading") return <LoadingState />;
  if (status === "error") return <ErrorState onRetry={() => setRequestVersion((value) => value + 1)} />;
  if (!data || data.current_scan_id == null) return <EmptyState />;

  const counts = {
    organizational: data.counts?.organizational ?? 0,
    known: data.counts?.known ?? 0,
    shadow: data.counts?.shadow ?? 0,
    candidate: data.counts?.candidate ?? 0,
    external: data.counts?.external ?? 0,
  };
  const highRisk = data.risk_distribution?.High ?? 0;
  const perimeter = counts.candidate + counts.external;
  const scanContext = data.previous_scan_id == null
    ? `scan ${data.current_scan_id} · no prior baseline`
    : `scan ${data.previous_scan_id} → ${data.current_scan_id}`;
  const authoritativeScan = data.scanHistory?.scans?.find((scan) => (
    scan.status === "SUCCEEDED"
    && (scan.is_current_authoritative || scan.scan_id === data.current_scan_id)
  ));
  const completedAt = authoritativeScan?.completed_at;
  const exactCompleted = completedAt && !Number.isNaN(new Date(completedAt).getTime())
    ? new Date(completedAt).toLocaleString()
    : "Completion timestamp unavailable";

  return (
    <div className="overview-grid">
      <a className="authoritative-freshness" href="#/scans" title={exactCompleted}>
        <span>Authoritative scan #{data.current_scan_id}</span>
        <strong>{relativeCompletion(completedAt)}</strong>
        <span aria-hidden="true">View scans →</span>
      </a>
      <section className="kpi-strip" aria-label="Overview metrics">
        <MetricCard label="Organizational assets" value={counts.organizational} support="Current confirmed surface" accent="#4655a6" href="#/assets" />
        <MetricCard label="Shadow assets" value={counts.shadow} support="Confirmed, outside inventory" accent="#7e91a8" href="#/shadow" />
        <MetricCard label="High risk" value={highRisk} support="Canonical priority" accent={RISK_COLORS.High} href="#/risk" />
        <MetricCard label="New assets" value={data.changes?.new_assets ?? 0} support="Since previous successful scan" accent="#327d80" href="#/changes?view=new" />
        <MetricCard label="Brand perimeter" value={perimeter} support={`${counts.candidate} candidate · ${counts.external} external`} accent="#9a79d6" href="#/brand" />
      </section>

      <Panel title="What changed" subtitle="Exact membership delta between successful scans" meta={scanContext} className="change-panel">
        <a className="change-row change-row-link" href="#/changes?view=new"><span className="change-label">New organizational assets</span><span className="change-value">+{data.changes?.new_assets ?? 0}</span></a>
        <a className="change-row change-row-link" href="#/changes?view=disappeared"><span className="change-label">Disappeared assets</span><span className="change-value">−{data.changes?.disappeared_assets ?? 0}</span></a>
        <div className="change-row"><span className="change-label">Current authoritative scan</span><span className="change-value">#{data.current_scan_id}</span></div>
      </Panel>

      <Panel title="Needs attention" subtitle="Highest deterministic risk scores in the current surface" meta="TOP 10" className="attention-panel">
        <AttentionTable assets={data.needs_attention || []} />
      </Panel>

      <Panel title="Risk distribution" subtitle="Canonical priorities across confirmed organizational assets" className="risk-panel">
        <RiskDistributionChart distribution={data.risk_distribution} priorityHref={(priority) => `#/assets?priority=${encodeURIComponent(priority)}&limit=25`} />
      </Panel>

      <Panel title="Ownership & asset composition" subtitle="Organizational surface and adjacent Brand Perimeter" className="ownership-panel">
        <OwnershipComposition counts={counts} />
      </Panel>

      <OverviewIntelligence
        assetGrowth={data.assetGrowth}
        assetGrowthStatus={data.assetGrowthStatus}
        httpStatus={data.httpStatus}
        httpStatusStatus={data.httpStatusStatus}
      />
    </div>
  );
}
