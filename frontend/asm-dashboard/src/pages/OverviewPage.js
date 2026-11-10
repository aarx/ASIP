import React, { useEffect, useState } from "react";
import { getAssetGrowth, getCertExpiry, getDiscoverySources, getExposureSummary, getHttpStatus, getNamingAssetExposure, getV2BrandAssets, getV2Overview, getV2Scans } from "../services/api";
import MetricCard from "../components/ui/MetricCard";
import Panel from "../components/ui/Panel";
import { EmptyState, ErrorState, LoadingState } from "../components/ui/AsyncState";
import { RISK_COLORS } from "../components/ui/RiskDistributionChart";
import {
  AssetGrowthPanel,
  BrandDiscoveryPanel,
  CertificateHealthPanel,
  DiscoveryValidationPanel,
  HttpStatusPanel,
  NamingExposurePanel,
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

function DiscoverySourcesCard({ value, status }) {
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

  return <MetricCard label="Discovery Sources" value={content} support="All-time domain counts" accent="#4655a6" />;
}

function countValue(value) {
  return Number.isInteger(value) && value >= 0 ? value : null;
}

function OwnershipComposition({ counts }) {
  const values = [
    ["Known", counts.known, "#/assets?asset_class=KNOWN&limit=25"],
    ["Shadow", counts.shadow, "#/shadow"],
    ["Needs Verification", counts.candidate, "#/assets?asset_class=CANDIDATE&limit=25"],
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
        <span>Known and Shadow are confirmed organizational assets. Needs Verification and External remain in the Brand Perimeter and do not receive organizational risk.</span>
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

async function loadDiscoverySummary() {
  const [candidate, external] = await Promise.all([
    getV2BrandAssets({ page: 1, limit: 1, asset_class: "CANDIDATE" }),
    getV2BrandAssets({ page: 1, limit: 1, asset_class: "EXTERNAL" }),
  ]);
  if (!candidate || candidate.scan_id == null || candidate.scan_id !== external?.scan_id) {
    throw new Error("Discovery counts did not share one authoritative scan");
  }
  const candidateCount = Number(candidate.count);
  const externalCount = Number(external.count);
  if (!Number.isInteger(candidateCount) || candidateCount < 0 || !Number.isInteger(externalCount) || externalCount < 0) {
    throw new Error("Discovery counts were not valid unique-domain totals");
  }
  return { scan_id: candidate.scan_id, candidate: candidateCount, external: externalCount };
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
      optionalRequest(getCertExpiry),
      optionalRequest(loadDiscoverySummary),
      optionalRequest(getNamingAssetExposure),
      optionalRequest(getDiscoverySources),
      optionalRequest(getExposureSummary),
    ])
      .then(([result, scans, assetGrowth, httpStatus, certificateExpiry, discoverySummary, namingExposure, discoverySources, exposureSummary]) => {
        if (active) {
          const scopedDiscoverySummary = discoverySummary.value?.scan_id === result.current_scan_id
            ? discoverySummary
            : { value: null, status: "error" };
          setData({
            ...result,
            scanHistory: scans,
            assetGrowth: assetGrowth.value,
            assetGrowthStatus: assetGrowth.status,
            httpStatus: httpStatus.value,
            httpStatusStatus: httpStatus.status,
            certificateExpiry: certificateExpiry.value,
            certificateExpiryStatus: certificateExpiry.status,
            discoverySummary: scopedDiscoverySummary.value,
            discoverySummaryStatus: scopedDiscoverySummary.status,
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
  const currentScanSupport = counts.external == null || counts.external > 0
    ? "Organizational + Needs Verification + External"
    : "Organizational + Needs Verification";
  const currentScanIpCount = data.exposureSummaryStatus === "ready"
    && data.exposureSummary?.scan_id === data.current_scan_id
    ? countValue(data.exposureSummary.resolving_domains)
    : null;
  const allTimeDomains = data.discoverySourcesStatus === "ready"
    ? allTimeDiscoveryCount(data.discoverySources)
    : null;
  const highRisk = data.risk_distribution?.High ?? 0;
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
        <MetricCard label="Organizational assets" value={organizationalCount ?? "—"} support="Known + Shadow" accent="#4655a6" href="#/assets" />
        <MetricCard label="High risk" value={highRisk} support="Canonical priority" accent={RISK_COLORS.High} href="#/risk" />
        <MetricCard label="Shadow assets" value={counts.shadow ?? "—"} support="Confirmed, outside inventory" accent="#7e91a8" href="#/shadow" />
        <MetricCard label="New assets" value={data.changes?.new_assets ?? 0} support="Since previous successful scan" accent="#327d80" href="#/changes?view=new" />
        <MetricCard label="Current scan assets" value={currentScanAssets ?? "—"} support={currentScanSupport} accent="#546579" href="#/assets" />
        <MetricCard label="Needs Verification" value={counts.candidate ?? "—"} support="Ownership not established" accent="#9a79d6" href="#/assets?asset_class=CANDIDATE&limit=25" />
        <MetricCard label="All-time domains" value={allTimeDomains ?? "Unavailable"} support="Historical discovery inventory" accent="#327d80" />
        <MetricCard label="Assets with IP Addresses" value={currentScanIpCount ?? "Unavailable"} support="Current scan" accent="#2f7d5b" href="#/assets?has_ip=true" />
        <DiscoverySourcesCard value={data.discoverySources} status={data.discoverySourcesStatus} />
      </section>

      <AssetGrowthPanel value={data.assetGrowth} status={data.assetGrowthStatus} />

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

      <DiscoveryValidationPanel
        value={data.discoverySummary}
        status={data.discoverySummaryStatus}
        scanId={data.discoverySummary?.scan_id}
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
