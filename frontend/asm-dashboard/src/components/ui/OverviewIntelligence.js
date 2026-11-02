import React from "react";
import { Bar, BarChart, CartesianGrid, Cell, Line, LineChart, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import Panel from "./Panel";
import AssetLink from "./AssetLink";

const STATUS_GROUPS = [
  { key: "2xx", label: "2xx", color: "#398261" },
  { key: "3xx", label: "3xx", color: "#327d80" },
  { key: "4xx", label: "4xx", color: "#e7a84b" },
  { key: "5xx", label: "5xx", color: "#f06467" },
  { key: "no_response", label: "No recorded HTTP status", color: "#7e91a8" },
];

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
      total: asCount(row?.total),
      live: asCount(row?.live),
      shadow: asCount(row?.shadow),
    }))
    .filter((row) => row.scan != null && row.total != null && row.live != null && row.shadow != null);
}

function ChartState({ title, copy, error = false }) {
  return (
    <div className="overview-chart-state" role={error ? "alert" : "status"}>
      <strong>{title}</strong>
      <span>{copy}</span>
    </div>
  );
}

function AssetGrowthPanel({ value, status }) {
  const data = normalizeGrowth(value);
  let content;
  if (status === "loading") {
    content = <ChartState title="Loading history" copy="Reading successful-scan asset populations." />;
  } else if (status === "error") {
    content = <ChartState title="History unavailable" copy="The overview is available, but scan history could not be loaded." error />;
  } else if (data.length < 2) {
    content = <ChartState title="Insufficient scan history" copy="A trend appears after two successful scans." />;
  } else {
    content = (
      <div className="overview-chart-canvas" data-testid="overview-asset-growth-chart" aria-label="Confirmed asset growth chart">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data} margin={{ top: 4, right: 12, bottom: 4, left: 0 }}>
            <CartesianGrid stroke="#e2e8f0" strokeDasharray="3 3" />
            <XAxis dataKey="scan" tick={{ fill: "#64748b", fontSize: 10 }} axisLine={false} tickLine={false} />
            <YAxis allowDecimals={false} tick={{ fill: "#64748b", fontSize: 10 }} axisLine={false} tickLine={false} width={28} />
            <Tooltip contentStyle={chartTooltipStyle} />
            <Legend wrapperStyle={{ fontSize: 10 }} />
            <Line type="monotone" dataKey="total" name="Confirmed assets" stroke="#4655a6" strokeWidth={2} dot={{ r: 2 }} />
            <Line type="monotone" dataKey="live" name="Live assets" stroke="#327d80" strokeWidth={2} dot={{ r: 2 }} />
            <Line type="monotone" dataKey="shadow" name="Shadow assets" stroke="#7e91a8" strokeWidth={2} dot={{ r: 2 }} />
          </LineChart>
        </ResponsiveContainer>
      </div>
    );
  }

  return (
    <Panel title="Asset growth trend" subtitle="Confirmed organizational assets across successful scans" className="intelligence-panel">
      {content}
    </Panel>
  );
}

function HttpStatusPanel({ value, status }) {
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
      <div className="overview-chart-canvas" data-testid="overview-http-status-chart" aria-label="HTTP status distribution chart: 2xx, 3xx, 4xx, 5xx, No recorded HTTP status">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 4, right: 12, bottom: 4, left: 0 }}>
            <CartesianGrid stroke="#e2e8f0" strokeDasharray="3 3" vertical={false} />
            <XAxis dataKey="label" tick={{ fill: "#64748b", fontSize: 10 }} axisLine={false} tickLine={false} />
            <YAxis allowDecimals={false} tick={{ fill: "#64748b", fontSize: 10 }} axisLine={false} tickLine={false} width={28} />
            <Tooltip contentStyle={chartTooltipStyle} />
            <Bar dataKey="count" name="Assets" radius={[3, 3, 0, 0]} barSize={22}>
              {data.map((entry) => <Cell key={entry.key} fill={entry.color} />)}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
        <p className="overview-chart-note">Aggregate bucket for assets without a recognized numeric HTTP status; not the explicit NO_RESPONSE observation enum.</p>
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

function CertificateHealthPanel({ value, status, scanId, now }) {
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
    <Panel title="Certificate health" subtitle="Current confirmed assets · up to 50 certificate observations" meta={scanId != null ? `SCAN #${scanId}` : "CURRENT"} className="intelligence-panel">
      {content}
    </Panel>
  );
}

export default function OverviewIntelligence({ assetGrowth, assetGrowthStatus = "ready", httpStatus, httpStatusStatus = "ready", certificateExpiry, certificateExpiryStatus = "ready", certificateScanId, certificateNow }) {
  return (
    <>
      <AssetGrowthPanel value={assetGrowth} status={assetGrowthStatus} />
      <HttpStatusPanel value={httpStatus} status={httpStatusStatus} />
      <CertificateHealthPanel value={certificateExpiry} status={certificateExpiryStatus} scanId={certificateScanId} now={certificateNow} />
    </>
  );
}
