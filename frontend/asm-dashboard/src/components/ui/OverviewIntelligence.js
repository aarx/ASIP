import React, { useEffect, useState } from "react";
import { Bar, BarChart, CartesianGrid, Cell, Line, LineChart, Legend, Rectangle, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import Panel from "./Panel";
import AssetLink from "./AssetLink";

const STATUS_GROUPS = [
  { key: "2xx", label: "2xx", color: "#398261" },
  { key: "3xx", label: "3xx", color: "#327d80" },
  { key: "4xx", label: "4xx", color: "#e7a84b" },
  { key: "5xx", label: "5xx", color: "#f06467" },
  { key: "no_response", label: "No HTTP response", color: "#7e91a8" },
  { key: "unknown", label: "No HTTP status recorded", color: "#a8b3c2" },
];
const DRILLDOWN_GROUPS = new Set(["2xx", "3xx", "4xx", "5xx"]);
const statusGroupHref = (group) => `#/assets?http_status_group=${group}`;
const statusGroupLinkProps = (group) => ({
  className: "http-status-drilldown",
  href: statusGroupHref(group),
  "aria-label": `Show ${group} assets`,
  tabIndex: 0,
  onClick: (event) => {
    if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    window.location.hash = statusGroupHref(group);
  },
  onKeyDown: (event) => {
    if (event.key !== "Enter") return;
    event.preventDefault();
    window.location.hash = statusGroupHref(group);
  },
});

export function HttpStatusBar({ payload, ...shape }) {
  const bar = <Rectangle {...shape} radius={[3, 3, 0, 0]} />;
  if (!DRILLDOWN_GROUPS.has(payload?.key)) return bar;
  return (
    <a {...statusGroupLinkProps(payload.key)}>
      {bar}
    </a>
  );
}

export function HttpStatusTick({ x, y, payload }) {
  const group = STATUS_GROUPS.find((item) => item.label === payload.value);
  const label = <text x={x} y={y} dy={16} textAnchor="middle" fill="#64748b" fontSize={10}>{payload.value}</text>;
  if (!DRILLDOWN_GROUPS.has(group?.key)) return <g>{label}</g>;
  return (
    <g>
      <a {...statusGroupLinkProps(group.key)}>
        <rect x={x - 22} y={y} width={44} height={20} fill="transparent" />
        {label}
      </a>
    </g>
  );
}

export function parseCertificateExpiry(value) {
  if (typeof value !== "string") return null;
  const match = value.trim().match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) return null;
  const [, year, month, day] = match.map(Number);
  const parsed = new Date(Date.UTC(year, month - 1, day));
  if (
    parsed.getUTCFullYear() !== year
    || parsed.getUTCMonth() !== month - 1
    || parsed.getUTCDate() !== day
  ) return null;
  return parsed;
}

function certificateDaysUntil(expiryDate, now) {
  const today = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  return Math.round((expiryDate.getTime() - today.getTime()) / 86400000);
}

export function classifyCertificateExpiry(value, now = new Date()) {
  const expiryDate = parseCertificateExpiry(value);
  if (!expiryDate) return { bucket: "unknown", status: "Unknown", days: null, expiryDate: null };
  const days = certificateDaysUntil(expiryDate, now);
  if (days < 0) return { bucket: "expired", status: "Expired", days, expiryDate };
  if (days <= 7) return { bucket: "within7", status: "Expiring within 7 days", days, expiryDate };
  if (days <= 30) return { bucket: "within30", status: "Expiring within 8–30 days", days, expiryDate };
  return { bucket: "healthy", status: "Beyond 30 days", days, expiryDate };
}

export function normalizeCertificateRecords(value, now = new Date()) {
  if (!Array.isArray(value)) return [];
  const byDomain = new Map();
  value.forEach((row) => {
    const domain = String(row?.domain || "").trim();
    if (!domain) return;
    const classification = classifyCertificateExpiry(row?.expiry, now);
    const record = { domain, expiry: row?.expiry || null, ...classification };
    const existing = byDomain.get(domain);
    if (
      !existing
      || (record.expiryDate && !existing.expiryDate)
      || (record.expiryDate && existing.expiryDate && record.expiryDate < existing.expiryDate)
    ) byDomain.set(domain, record);
  });
  const urgency = { expired: 0, within7: 1, within30: 2, unknown: 3, healthy: 4 };
  return [...byDomain.values()].sort((left, right) => (
    (urgency[left.bucket] - urgency[right.bucket])
    || ((left.expiryDate?.getTime() ?? Number.MAX_SAFE_INTEGER) - (right.expiryDate?.getTime() ?? Number.MAX_SAFE_INTEGER))
    || left.domain.localeCompare(right.domain)
  ));
}

const chartTooltipStyle = {
  background: "#ffffff",
  border: "1px solid #cbd5e1",
  borderRadius: 6,
  color: "#172130",
  fontSize: 11,
  boxShadow: "0 6px 18px rgba(31,45,61,.12)",
};

function asCount(value) {
  const count = Number(value);
  return Number.isFinite(count) && count >= 0 ? count : null;
}

function normalizeGrowth(value) {
  if (!Array.isArray(value)) return [];
  return value
    .map((row) => ({
      scan: row?.scan_id,
      organizational: asCount(row?.organizational_assets),
      known: asCount(row?.known_assets),
      shadow: asCount(row?.shadow_assets),
      ipPresent: asCount(row?.ip_present_assets),
      httpResponding: asCount(row?.http_responding_assets),
    }))
    .filter((row) => row.scan != null);
}

function ChartState({ title, copy, error = false }) {
  return (
    <div className="overview-chart-state" role={error ? "alert" : "status"}>
      <strong>{title}</strong>
      <span>{copy}</span>
    </div>
  );
}

export function AssetGrowthPanel({ value, status }) {
  const data = normalizeGrowth(value);
  const visibleSeries = [
    ["organizational", "Organizational Assets"],
    ["known", "Known Assets"],
    ["shadow", "Shadow Assets"],
    ["ipPresent", "IP-Present Assets"],
    ["httpResponding", "HTTP-Responding Assets"],
  ].filter(([key]) => data.some((row) => row[key] != null));
  let content;
  if (status === "loading") {
    content = <ChartState title="Loading history" copy="Reading successful-scan asset populations." />;
  } else if (status === "error") {
    content = <ChartState title="History unavailable" copy="The overview is available, but scan history could not be loaded." error />;
  } else if (data.length < 2) {
    content = <ChartState title="Insufficient scan history" copy="A trend appears after two successful scans." />;
  } else {
    content = (
      <div className="overview-chart-canvas" data-testid="overview-asset-growth-chart" aria-label={`Asset population growth chart: ${visibleSeries.map(([, label]) => label).join(", ")}`}>
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data} margin={{ top: 4, right: 12, bottom: 4, left: 0 }}>
            <CartesianGrid stroke="#e2e8f0" strokeDasharray="3 3" />
            <XAxis dataKey="scan" tick={{ fill: "#64748b", fontSize: 10 }} axisLine={false} tickLine={false} />
            <YAxis allowDecimals={false} tick={{ fill: "#64748b", fontSize: 10 }} axisLine={false} tickLine={false} width={28} />
            <Tooltip contentStyle={chartTooltipStyle} />
            <Legend wrapperStyle={{ fontSize: 10 }} />
            {visibleSeries.some(([key]) => key === "organizational") && <Line type="monotone" dataKey="organizational" name="Organizational Assets" stroke="#4655a6" strokeWidth={2} dot={{ r: 2 }} />}
            {visibleSeries.some(([key]) => key === "known") && <Line type="monotone" dataKey="known" name="Known Assets" stroke="#5c6bc0" strokeWidth={2} dot={{ r: 2 }} />}
            {visibleSeries.some(([key]) => key === "shadow") && <Line type="monotone" dataKey="shadow" name="Shadow Assets" stroke="#7e91a8" strokeWidth={2} dot={{ r: 2 }} />}
            {visibleSeries.some(([key]) => key === "ipPresent") && <Line type="monotone" dataKey="ipPresent" name="IP-Present Assets" stroke="#327d80" strokeWidth={2} dot={{ r: 2 }} />}
            {visibleSeries.some(([key]) => key === "httpResponding") && <Line type="monotone" dataKey="httpResponding" name="HTTP-Responding Assets" stroke="#d49a3a" strokeWidth={2} dot={{ r: 2 }} />}
          </LineChart>
        </ResponsiveContainer>
      </div>
    );
  }

  return (
    <Panel title="Asset growth trend" subtitle="Current effective populations across successful scans · historical classes are reconstructed" className="intelligence-panel">
      {content}
    </Panel>
  );
}

export function normalizeSeedDistribution(value, maxGroups = 8) {
  if (!Array.isArray(value)) return [];
  const grouped = new Map();
  value.forEach((row) => {
    const seed = String(row?.seed || "").trim();
    const count = Number(row?.domains_discovered);
    if (!seed || !Number.isInteger(count) || count < 0) return;
    grouped.set(seed, (grouped.get(seed) || 0) + count);
  });
  const sorted = [...grouped.entries()]
    .map(([seed, count]) => ({ seed, count }))
    .sort((left, right) => (right.count - left.count) || left.seed.localeCompare(right.seed));
  const limit = Number.isInteger(maxGroups) && maxGroups > 0 ? maxGroups : 8;
  const visible = sorted.slice(0, limit);
  if (sorted.length > limit) {
    const otherCount = sorted.slice(limit).reduce((total, row) => total + row.count, 0);
    if (otherCount > 0) visible.push({ seed: "Other", count: otherCount });
  }
  return visible;
}

export function SeedDistributionPanel({ value, status = "ready", scanId }) {
  const data = normalizeSeedDistribution(value);
  const signature = data.map((row) => `${row.seed}:${row.count}`).join("|");
  const [animatedSignature, setAnimatedSignature] = useState("");
  const reducedMotion = typeof window !== "undefined"
    && typeof window.matchMedia === "function"
    && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  useEffect(() => {
    if (signature) setAnimatedSignature(signature);
  }, [signature]);

  let content;
  if (status === "loading") {
    content = <ChartState title="Loading seed distribution" copy="Reading current-scan seed attribution." />;
  } else if (status === "error") {
    content = <ChartState title="Seed distribution unavailable" copy="Current-scan seed attribution could not be loaded." error />;
  } else if (!data.length) {
    content = <ChartState title="Seed distribution unavailable" copy="No verified current-scan seed attribution is available." />;
  } else {
    const maxCount = Math.max(...data.map((row) => row.count), 1);
    content = (
      <div className="seed-distribution-chart" data-testid="overview-seed-distribution-chart" aria-label={`Current authoritative scan ${scanId ?? ""} seed distribution`}>
        <div className="seed-distribution-bars" role="list">
          {data.map((row, index) => (
            <div className="seed-distribution-bar-item" key={row.seed} role="listitem" aria-label={`${row.seed}: ${row.count.toLocaleString()} discovered domains`}>
              <strong className="seed-distribution-bar-count">{row.count.toLocaleString()}</strong>
              <div className="seed-distribution-bar-track">
                <div
                  className={`seed-distribution-bar${animatedSignature === signature ? (reducedMotion ? " seed-distribution-bar-reduced-motion" : " seed-distribution-bar-rise") : ""}`}
                  style={{ height: `${(row.count / maxCount) * 100}%`, "--seed-delay": `${index * 60}ms` }}
                  title={`${row.seed}: ${row.count.toLocaleString()} discovered domains`}
                />
              </div>
              <span className="seed-distribution-bar-label" title={row.seed}>{row.seed}</span>
            </div>
          ))}
        </div>
      </div>
    );
  }

  return <Panel title="Seeds distribution" meta={scanId != null ? `SCAN #${scanId} · CURRENT-SCAN` : "CURRENT-SCAN"} className="intelligence-panel seed-distribution-panel">{content}</Panel>;
}

export function HttpStatusPanel({ value, status }) {
  const data = STATUS_GROUPS.map(({ key, label, color }) => ({
    key,
    label,
    color,
    count: asCount(value?.[key]) ?? 0,
  }));
  const hasResponseData = value && STATUS_GROUPS.some(({ key }) => asCount(value[key]) != null);
  let content;
  if (status === "loading") {
    content = <ChartState title="Loading HTTP observations" copy="Reading the current authoritative scan." />;
  } else if (status === "error") {
    content = <ChartState title="HTTP status unavailable" copy="The overview is available, but status observations could not be loaded." error />;
  } else if (!hasResponseData) {
    content = <ChartState title="No HTTP observations" copy="No observed status data is available for the current confirmed surface." />;
  } else {
    content = (
      <div className="overview-http-status-chart">
        <div className="overview-chart-canvas" data-testid="overview-http-status-chart" aria-label="HTTP status distribution chart: 2xx, 3xx, 4xx, 5xx, No HTTP response, No HTTP status recorded">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} margin={{ top: 4, right: 12, bottom: 4, left: 0 }}>
              <CartesianGrid stroke="#e2e8f0" strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="label" tick={<HttpStatusTick />} axisLine={false} tickLine={false} />
              <YAxis allowDecimals={false} tick={{ fill: "#64748b", fontSize: 10 }} axisLine={false} tickLine={false} width={28} />
              <Tooltip contentStyle={chartTooltipStyle} />
              <Bar dataKey="count" name="Assets" radius={[3, 3, 0, 0]} barSize={22} shape={<HttpStatusBar />}>
                {data.map((entry) => <Cell key={entry.key} fill={entry.color} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
        <p className="overview-chart-note">NO_RESPONSE is shown separately; the No HTTP status recorded bucket is the backend&apos;s aggregate UNKNOWN group.</p>
      </div>
    );
  }

  return (
    <Panel title="HTTP status distribution" subtitle="Current authoritative confirmed-organizational scan" className="intelligence-panel">
      {content}
    </Panel>
  );
}

function certificateDaysLabel(days) {
  if (days == null) return "Unavailable";
  if (days < 0) return `${Math.abs(days)}d overdue`;
  return `${days}d remaining`;
}

function CertificateStatus({ record }) {
  return <span className={`certificate-status certificate-status-${record.bucket}`}>{record.status}</span>;
}

export function CertificateHealthPanel({ value, status, scanId, now }) {
  const records = normalizeCertificateRecords(value, now);
  const counts = {
    expired: records.filter((record) => record.bucket === "expired").length,
    within7: records.filter((record) => record.bucket === "within7").length,
    within30: records.filter((record) => record.bucket === "within30").length,
    unknown: records.filter((record) => record.bucket === "unknown").length,
  };
  const urgent = records.filter((record) => ["expired", "within7", "within30"].includes(record.bucket)).slice(0, 12);
  let content;
  if (status === "loading") {
    content = <ChartState title="Loading certificate observations" copy="Reading the current confirmed-asset certificate set." />;
  } else if (status === "error") {
    content = <ChartState title="Certificate health unavailable" copy="The overview is available, but certificate observations could not be loaded." error />;
  } else if (!records.length) {
    content = <ChartState title="No certificate observations" copy="No current certificate evidence was returned." />;
  } else {
    content = (
      <>
        <div className="certificate-health-summary" aria-label="Certificate health summary">
          <div className="certificate-health-stat certificate-health-stat-expired"><span>Expired</span><strong>{counts.expired}</strong></div>
          <div className="certificate-health-stat certificate-health-stat-within7"><span>Within 7 days</span><strong>{counts.within7}</strong></div>
          <div className="certificate-health-stat certificate-health-stat-within30"><span>Within 8–30 days</span><strong>{counts.within30}</strong></div>
          <div className="certificate-health-stat certificate-health-stat-unknown"><span>Unknown expiry</span><strong>{counts.unknown}</strong></div>
        </div>
        {urgent.length ? (
          <div className="dense-table-wrap">
            <table className="dense-table certificate-health-table" aria-label="Certificate health priority observations">
              <thead><tr><th>Domain</th><th>Expiry date</th><th>Days remaining / overdue</th><th>Status</th></tr></thead>
              <tbody>{urgent.map((record) => (
                <tr key={record.domain}>
                  <td><AssetLink domain={record.domain} returnTo="overview" /></td>
                  <td><span className="technical-value">{record.expiry || "Unavailable"}</span></td>
                  <td><span className="technical-value">{certificateDaysLabel(record.days)}</span></td>
                  <td><CertificateStatus record={record} /></td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        ) : <p className="panel-subtitle">No dated certificate observations are within 30 days. Missing expiry evidence is not treated as healthy.</p>}
      </>
    );
  }

  return (
    <Panel title="Certificate health" subtitle="Current confirmed assets · up to 50 certificate observations" meta={scanId != null ? `SCAN #${scanId}` : "CURRENT"} className="intelligence-panel certificate-health-panel">
      {content}
    </Panel>
  );
}

function normalizeBrandCount(value) {
  const count = Number(value);
  return Number.isInteger(count) && count >= 0 ? count : null;
}

export function normalizeBrandDiscovery(value, scanId) {
  if (!value || (scanId != null && value.scan_id !== scanId)) return null;
  const sourceCounts = value.source_counts;
  if (!sourceCounts || typeof sourceCounts !== "object") return null;
  const normalized = {};
  for (const source of ["brand_tld", "brand_pattern", "brand_union"]) {
    const sourceValue = sourceCounts[source];
    const domains = normalizeBrandCount(sourceValue?.domains);
    const byAssetClass = sourceValue?.by_asset_class;
    if (domains == null || !byAssetClass || typeof byAssetClass !== "object") return null;
    const classes = {};
    for (const assetClass of ["candidate", "external", "known", "shadow"]) {
      const count = normalizeBrandCount(byAssetClass[assetClass]);
      if (count == null) return null;
      classes[assetClass] = count;
    }
    normalized[source] = { domains, by_asset_class: classes };
  }
  return { scan_id: value.scan_id, source_counts: normalized };
}

function brandDiscoveryHref(source, assetClass, review = false) {
  const params = new URLSearchParams({ discovery_source: source });
  if (assetClass) params.set("asset_class", assetClass);
  return `${review ? "#/brand" : "#/assets"}?${params.toString()}${review ? "" : "&limit=25"}`;
}

export function BrandDiscoveryPanel({ value, status = "ready", scanId, mode = "overview" }) {
  const summary = normalizeBrandDiscovery(value, scanId);
  let content;
  if (status === "loading") {
    content = <ChartState title="Loading brand discovery" copy="Reading current brand-source totals." />;
  } else if (status === "error" || !summary) {
    content = <ChartState title="Brand discovery unavailable" copy="No authoritative brand-source totals were returned." error />;
  } else {
    const union = summary.source_counts.brand_union;
    const metrics = mode === "brand"
      ? [
        ["Total brand matches", union.domains, brandDiscoveryHref("brand_union")],
        ["Other Domain Extensions", summary.source_counts.brand_tld.domains, brandDiscoveryHref("brand_tld")],
        ["Brand Name Variations", summary.source_counts.brand_pattern.domains, brandDiscoveryHref("brand_pattern")],
        ["Needs Verification", union.by_asset_class.candidate, brandDiscoveryHref("brand_union", "CANDIDATE", true)],
      ]
      : [
        ["Brand-related domains", union.domains, brandDiscoveryHref("brand_union")],
        ["Needs Verification", union.by_asset_class.candidate, brandDiscoveryHref("brand_union", "CANDIDATE")],
        ["Known", union.by_asset_class.known, brandDiscoveryHref("brand_union", "KNOWN")],
        ["Shadow", union.by_asset_class.shadow, brandDiscoveryHref("brand_union", "SHADOW")],
      ];
    if (mode !== "brand" && union.by_asset_class.external > 0) {
      metrics.push(["External", union.by_asset_class.external, brandDiscoveryHref("brand_union", "EXTERNAL")]);
    }
    content = (
      <div className="brand-discovery-signals" aria-label="Current brand discovery totals">
        {metrics.map(([label, count, href]) => (
          <a className="brand-discovery-signal" href={href} key={label} aria-label={`Open ${label} (${count})`}>
            <span>{label}</span>
            <strong>{count}</strong>
            <span className="brand-discovery-arrow" aria-hidden="true">→</span>
          </a>
        ))}
      </div>
    );
  }

  return (
    <Panel id={mode === "brand" ? "brand-discovery-summary" : "overview-brand-discovery"} title="Brand discovery" meta={scanId != null ? `SCAN #${scanId} · CURRENT-SCAN SUBSET` : "CURRENT-SCAN SUBSET"} className={`${mode === "brand" ? "brand-discovery-panel-page" : "intelligence-panel brand-discovery-panel"}`}>
      {content}
    </Panel>
  );
}

const NAMING_CATEGORIES = new Set([
  "DEV", "TEST", "UAT", "QA", "ADMIN", "MAIL", "TEMP", "STAGE", "STAGING",
  "SANDBOX", "PREPROD", "PRE-PROD", "NONPROD", "NON-PROD", "LAB", "DEMO",
]);

export function normalizeNamingExposure(value) {
  if (!Array.isArray(value)) return [];
  const categories = new Map();
  value.forEach((row) => {
    const keyword = String(row?.keyword || "").trim().toUpperCase();
    const count = Number(row?.count);
    if (!NAMING_CATEGORIES.has(keyword) || !Number.isInteger(count) || count < 0) return;
    categories.set(keyword, count);
  });
  return [...categories.entries()]
    .map(([keyword, count]) => ({ keyword, count }))
    .sort((left, right) => left.keyword.localeCompare(right.keyword));
}

export function NamingExposurePanel({ value, status, scanId }) {
  const categories = normalizeNamingExposure(value);
  let content;
  if (status === "loading") {
    content = <ChartState title="Loading naming exposure" copy="Reading current confirmed-asset pattern matches." />;
  } else if (status === "error") {
    content = <ChartState title="Naming exposure unavailable" copy="The overview is available, but current naming-pattern observations could not be loaded." error />;
  } else if (!categories.length) {
    content = <ChartState title="No naming matches" copy="No supported naming-pattern matches were returned for the current confirmed surface." />;
  } else {
    content = (
      <>
        <div className="naming-exposure-signals" aria-label="Naming exposure category counts">
          {categories.map(({ keyword, count }) => (
            <a className="naming-exposure-signal naming-exposure-signal-link" key={keyword} href={`#/assets?exposure_keyword=${encodeURIComponent(keyword)}&limit=25`} aria-label={`Open ${keyword} matching assets (${count})`}>
              <span>{keyword}</span>
              <strong>{count}</strong>
              <span className="naming-exposure-arrow" aria-hidden="true">→</span>
            </a>
          ))}
        </div>
        <p className="naming-exposure-note">Counts are unique organizational assets. Categories may overlap; a hostname indicator is not a verified environment or vulnerability.</p>
      </>
    );
  }

  return (
    <Panel id="overview-naming-exposure" title="Naming exposure" subtitle="Pattern matches in the current confirmed organizational surface" meta={scanId != null ? `SCAN #${scanId}` : "CURRENT"} className="intelligence-panel naming-exposure-panel">
      {content}
    </Panel>
  );
}

export default function OverviewIntelligence({ assetGrowth, assetGrowthStatus = "ready", httpStatus, httpStatusStatus = "ready", certificateExpiry, certificateExpiryStatus = "ready", certificateScanId, certificateNow, namingExposure, namingExposureStatus = "ready" }) {
  return (
    <>
      <CertificateHealthPanel value={certificateExpiry} status={certificateExpiryStatus} scanId={certificateScanId} now={certificateNow} />
      <AssetGrowthPanel value={assetGrowth} status={assetGrowthStatus} />
      <HttpStatusPanel value={httpStatus} status={httpStatusStatus} />
      <NamingExposurePanel value={namingExposure} status={namingExposureStatus} scanId={certificateScanId} />
    </>
  );
}
