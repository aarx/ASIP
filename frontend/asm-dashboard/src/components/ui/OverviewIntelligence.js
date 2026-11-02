import React from "react";
import { Bar, BarChart, CartesianGrid, Cell, Line, LineChart, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import Panel from "./Panel";

const STATUS_GROUPS = [
  { key: "2xx", label: "2xx", color: "#398261" },
  { key: "3xx", label: "3xx", color: "#327d80" },
  { key: "4xx", label: "4xx", color: "#e7a84b" },
  { key: "5xx", label: "5xx", color: "#f06467" },
  { key: "no_response", label: "No recorded HTTP status", color: "#7e91a8" },
];

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

export default function OverviewIntelligence({ assetGrowth, assetGrowthStatus = "ready", httpStatus, httpStatusStatus = "ready" }) {
  return (
    <>
      <AssetGrowthPanel value={assetGrowth} status={assetGrowthStatus} />
      <HttpStatusPanel value={httpStatus} status={httpStatusStatus} />
    </>
  );
}
