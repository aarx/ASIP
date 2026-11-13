import React, { useEffect, useState } from "react";
import { getAssetGrowth, getCertExpiry, getDiscoverySources, getExposureSummary, getHttpStatus, getNamingAssetExposure, getRiskHistorySummary, getSeeds, getV2Overview, getV2Scans } from "../services/api";
import MetricCard from "../components/ui/MetricCard";
import Panel from "../components/ui/Panel";
import { EmptyState, ErrorState, LoadingState } from "../components/ui/AsyncState";
import { RISK_COLORS } from "../components/ui/RiskDistributionChart";
import {
  AssetGrowthPanel,
  BrandDiscoveryPanel,
  CertificateHealthPanel,
  HttpStatusPanel,
  NamingExposurePanel,
  SeedDistributionPanel,
} from "../components/ui/OverviewIntelligence";

const OWNERSHIP_COLORS = {
  Known: "#4655a6",
  Shadow: "#7e91a8",
  "Needs Verification": "#9a79d6",
  External: "#546579",
};

const DISCOVERY_SOURCE_GROUPS = [
  { label: "Pentest Tools", keys: ["Pentest Tool", "Pentest Tools"] },
  { label: "SAN Exposure", keys: ["SAN Expansion", "SAN Exposure"] },
  { label: "Brand Exposure", keys: ["Brand Expansion", "Brand Exposure"] },
];

function discoverySourceCount(value, keys) {
  if (!value || typeof value !== "object") return null;
  const key = keys.find((candidate) => Object.prototype.hasOwnProperty.call(value, candidate));
  if (!key) return null;
  const count = Number(value[key]);
  return Number.isInteger(count) && count >= 0 ? count : null;
}

function discoverySourceGroups(value) {
  return DISCOVERY_SOURCE_GROUPS.map((group) => ({
    ...group,
    count: discoverySourceCount(value, group.keys),
  }));
}

function allTimeDiscoveryCount(value) {
  const groups = discoverySourceGroups(value);
  return groups.every((group) => group.count != null)
    ? groups.reduce((total, group) => total + group.count, 0)
    : null;
}

function DiscoverySourcesPanel({ value, status }) {
  let content;
  if (status === "loading") {
    content = <span className="discovery-source-state">Loading…</span>;
  } else if (status === "error" || !value) {
    content = <span className="discovery-source-state">Unavailable</span>;
  } else {
    content = (
      <div className="discovery-source-kpi-list" aria-label="All-time grouped discovery source domain counts">
        {discoverySourceGroups(value).map((group) => (
          <div className="discovery-source-kpi-row" key={group.label}>
            <span>{group.label}</span>
            <strong>{group.count == null ? "—" : group.count}</strong>
          </div>
        ))}
      </div>
    );
  }

  return <Panel title="Discovery Sources" meta="All-time domain counts" className="overview-discovery-sources-panel">{content}</Panel>;
}

function countValue(value) {
  return Number.isInteger(value) && value >= 0 ? value : null;
}

function OwnershipComposition({ counts }) {
  const values = [
    ["Known", counts.known, "#/assets?asset_class=KNOWN&limit=25"],
    ["Shadow", counts.shadow, "#/shadow"],
    ["Needs Verification", counts.candidate, "#/assets?asset_class=CANDIDATE&limit=25"],
    ["External", counts.external, "#/brand?asset_class=EXTERNAL"],
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
        <span>Known and Shadow are confirmed organizational assets. Needs Verification and External remain in the Brand Perimeter and do not receive organizational risk.</span>
      </div>
    </>
  );
}

function CoverageItem({ label, value, href, scope, className = "" }) {
  const Element = href ? "a" : "div";
  return (
    <Element
      className={`asset-coverage-item${href ? " asset-coverage-item-link" : ""} ${className}`.trim()}
      href={href}
      aria-label={href ? `Open ${label} (${value == null ? "unavailable" : value})` : undefined}
    >
      <span className="asset-coverage-label">{scope && <small>{scope}</small>}{label}</span>
      <strong>{value == null ? "Unavailable" : value.toLocaleString()}</strong>
    </Element>
  );
}

function AssetCoveragePanel({ allTimeDomains, currentScanAssets, organizationalCount, counts }) {
  return (
    <Panel title="Asset Coverage" className="asset-coverage-panel">
      <div className="asset-coverage-scopes">
        <div className="asset-coverage-headline">
          <CoverageItem label="All-time domains" scope="Historical" value={allTimeDomains} className="asset-coverage-historical" />
          <CoverageItem label="Current scan assets" scope="Current authoritative scan" value={currentScanAssets} href="#/assets" className="asset-coverage-current" />
        </div>
        <CoverageItem label="Organizational assets" value={organizationalCount} className="asset-coverage-organizational" />
        <div className="asset-coverage-classes" aria-label="Current authoritative scan asset classes">
          <CoverageItem label="Known" value={counts.known} href="#/assets?asset_class=KNOWN&limit=25" />
          <CoverageItem label="Shadow" value={counts.shadow} href="#/shadow" />
          <CoverageItem label="Needs Verification" value={counts.candidate} href="#/assets?asset_class=CANDIDATE&limit=25" />
          {(counts.external == null || counts.external > 0) && (
            <CoverageItem label="External" value={counts.external} href="#/brand?asset_class=EXTERNAL" />
          )}
        </div>
      </div>
    </Panel>
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
      optionalRequest(getRiskHistorySummary),
      optionalRequest(getAssetGrowth),
      optionalRequest(getSeeds),
      optionalRequest(getHttpStatus),
      optionalRequest(getCertExpiry),
      optionalRequest(getNamingAssetExposure),
      optionalRequest(getDiscoverySources),
      optionalRequest(getExposureSummary),
    ])
      .then(([result, scans, riskHistory, assetGrowth, seedDistribution, httpStatus, certificateExpiry, namingExposure, discoverySources, exposureSummary]) => {
        if (active) {
          setData({
            ...result,
            scanHistory: scans,
            riskHistory: riskHistory.value,
            riskHistoryStatus: riskHistory.status,
            assetGrowth: assetGrowth.value,
            assetGrowthStatus: assetGrowth.status,
            seedDistribution: seedDistribution.value,
            seedDistributionStatus: seedDistribution.status,
            httpStatus: httpStatus.value,
            httpStatusStatus: httpStatus.status,
            certificateExpiry: certificateExpiry.value,
            certificateExpiryStatus: certificateExpiry.status,
            brandDiscovery: result.brand_discovery,
            brandDiscoveryStatus: result.brand_discovery ? "ready" : "error",
            namingExposure: namingExposure.value,
            namingExposureStatus: namingExposure.status,
            discoverySources: discoverySources.value,
            discoverySourcesStatus: discoverySources.status,
            exposureSummary: exposureSummary.value,
            exposureSummaryStatus: exposureSummary.status,
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
    organizational: countValue(data.counts?.organizational),
    known: countValue(data.counts?.known),
    shadow: countValue(data.counts?.shadow),
    candidate: countValue(data.counts?.candidate),
    external: countValue(data.counts?.external),
  };
  const organizationalCount = counts.organizational != null
    && counts.known != null
    && counts.shadow != null
    && counts.organizational === counts.known + counts.shadow
    ? counts.organizational
    : null;
  const currentScanAssets = organizationalCount != null && counts.candidate != null && counts.external != null
    ? organizationalCount + counts.candidate + counts.external
    : null;
  const currentScanIpCount = data.exposureSummaryStatus === "ready"
    && data.exposureSummary?.scan_id === data.current_scan_id
    ? countValue(data.exposureSummary.resolving_domains)
    : null;
  const allTimeDomains = data.discoverySourcesStatus === "ready"
    ? allTimeDiscoveryCount(data.discoverySources)
    : null;
  const highRisk = countValue(data.risk_distribution?.High);
  const historicalHighRisk = data.riskHistoryStatus === "ready"
    && data.riskHistory?.availability_state === "AVAILABLE"
    && Number.isInteger(data.riskHistory.historical_unique_high_assets)
    ? data.riskHistory.historical_unique_high_assets
    : null;
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
      <section className="overview-coverage-grid" aria-label="Overview metrics">
        <AssetCoveragePanel
          allTimeDomains={allTimeDomains}
          currentScanAssets={currentScanAssets}
          organizationalCount={organizationalCount}
          counts={counts}
        />
        <DiscoverySourcesPanel value={data.discoverySources} status={data.discoverySourcesStatus} />
        <div className="overview-secondary-kpis overview-risk-kpis">
          <MetricCard label="Current High Risk" value={highRisk ?? "Unavailable"} support={`Current scan #${data.current_scan_id} · canonical priority`} accent={RISK_COLORS.High} href="#/risk?section=priority-assets" />
          <MetricCard label="Previously High Risk" value={historicalHighRisk ?? "Unavailable"} support={historicalHighRisk == null ? "Historical data unavailable" : `Historical successful scans · latest #${data.riskHistory.latest_successful_scan_id ?? data.current_scan_id}`} accent="#7b5bb5" href={historicalHighRisk == null ? undefined : "#/risk?section=historical-high-risk"} />
          <MetricCard label="New Assets" value={data.changes?.new_assets ?? 0} support="Since previous successful scan" accent="#327d80" href="#/changes?view=new" />
          <MetricCard label="Assets with IP Addresses" value={currentScanIpCount ?? "Unavailable"} support="Current scan" accent="#2f7d5b" href="#/assets?has_ip=true" />
        </div>
      </section>

      <div className="overview-chart-row">
        <AssetGrowthPanel value={data.assetGrowth} status={data.assetGrowthStatus} />
        <SeedDistributionPanel value={data.seedDistribution} status={data.seedDistributionStatus} scanId={data.current_scan_id} />
      </div>

      <Panel title="What changed" subtitle="Exact membership delta between successful scans" meta={scanContext} className="change-panel">
        <a className="change-row change-row-link" href="#/changes?view=new"><span className="change-label">New organizational assets</span><span className="change-value">+{data.changes?.new_assets ?? 0}</span></a>
        <a className="change-row change-row-link" href="#/changes?view=disappeared"><span className="change-label">Disappeared assets</span><span className="change-value">−{data.changes?.disappeared_assets ?? 0}</span></a>
        <div className="change-row"><span className="change-label">Current authoritative scan</span><span className="change-value">#{data.current_scan_id}</span></div>
      </Panel>

      <CertificateHealthPanel
        value={data.certificateExpiry}
        status={data.certificateExpiryStatus}
        scanId={data.current_scan_id}
        now={data.certificateNow}
      />

      <Panel title="Ownership & asset composition" subtitle="Organizational surface and adjacent Brand Exposure" className="ownership-panel">
        <OwnershipComposition counts={counts} />
      </Panel>

      <BrandDiscoveryPanel
        value={data.brandDiscovery}
        status={data.brandDiscoveryStatus}
        scanId={data.current_scan_id}
      />

      <HttpStatusPanel value={data.httpStatus} status={data.httpStatusStatus} />
      <NamingExposurePanel value={data.namingExposure} status={data.namingExposureStatus} scanId={data.current_scan_id} />
    </div>
  );
}
