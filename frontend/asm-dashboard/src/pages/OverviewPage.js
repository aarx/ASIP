import React, { useEffect, useMemo, useState } from "react";
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { getV2Overview } from "../services/api";
import MetricCard from "../components/ui/MetricCard";
import Panel from "../components/ui/Panel";
import StatusBadge from "../components/ui/StatusBadge";
import { EmptyState, ErrorState, LoadingState } from "../components/ui/AsyncState";

const RISK_COLORS = {
  High: "#f06467",
  Elevated: "#e7a84b",
  Review: "#d4c266",
  Low: "#4e789b",
};

const OWNERSHIP_COLORS = {
  Known: "#3dc4ff",
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
              <td>{asset.domain}</td>
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
    ["Known", counts.known],
    ["Shadow", counts.shadow],
    ["Candidate", counts.candidate],
    ["External", counts.external],
  ];
  const max = Math.max(...values.map(([, value]) => value), 1);

  return (
    <>
      <div className="ownership-list">
        {values.map(([name, value]) => (
          <div className="ownership-row" key={name}>
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
          </div>
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

export default function OverviewPage() {
  const [data, setData] = useState(null);
  const [status, setStatus] = useState("loading");
  const [requestVersion, setRequestVersion] = useState(0);

  useEffect(() => {
    let active = true;
    setStatus("loading");
    getV2Overview()
      .then((result) => {
        if (active) {
          setData(result);
          setStatus("ready");
        }
      })
      .catch(() => {
        if (active) setStatus("error");
      });
    return () => { active = false; };
  }, [requestVersion]);

  const riskData = useMemo(() => {
    if (!data) return [];
    return ["High", "Elevated", "Review", "Low"].map((priority) => ({
      priority,
      count: data.risk_distribution?.[priority] ?? 0,
    }));
  }, [data]);

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

  return (
    <div className="overview-grid">
      <section className="kpi-strip" aria-label="Overview metrics">
        <MetricCard label="Organizational assets" value={counts.organizational} support="Current confirmed surface" accent="#3dc4ff" />
        <MetricCard label="Shadow assets" value={counts.shadow} support="Confirmed, outside inventory" accent="#7e91a8" />
        <MetricCard label="High risk" value={highRisk} support="Canonical priority" accent={RISK_COLORS.High} />
        <MetricCard label="New assets" value={data.changes?.new_assets ?? 0} support="Since previous successful scan" accent="#51a8db" />
        <MetricCard label="Brand perimeter" value={perimeter} support={`${counts.candidate} candidate · ${counts.external} external`} accent="#9a79d6" />
      </section>

      <Panel title="What changed" subtitle="Exact membership delta between successful scans" meta={scanContext} className="change-panel">
        <div className="change-row"><span className="change-label">New organizational assets</span><span className="change-value">+{data.changes?.new_assets ?? 0}</span></div>
        <div className="change-row"><span className="change-label">Disappeared assets</span><span className="change-value">−{data.changes?.disappeared_assets ?? 0}</span></div>
        <div className="change-row"><span className="change-label">Current authoritative scan</span><span className="change-value">#{data.current_scan_id}</span></div>
      </Panel>

      <Panel title="Needs attention" subtitle="Highest deterministic risk scores in the current surface" meta="TOP 10" className="attention-panel">
        <AttentionTable assets={data.needs_attention || []} />
      </Panel>

      <Panel title="Risk distribution" subtitle="Canonical priorities across confirmed organizational assets" className="risk-panel">
        <div className="risk-chart-wrap" aria-label="Risk distribution chart">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={riskData} layout="vertical" margin={{ top: 2, right: 22, bottom: 2, left: 6 }}>
              <XAxis type="number" allowDecimals={false} axisLine={false} tickLine={false} tick={{ fill: "#708298", fontSize: 10 }} />
              <YAxis type="category" dataKey="priority" axisLine={false} tickLine={false} width={62} tick={{ fill: "#a9bacb", fontSize: 10 }} />
              <Tooltip cursor={{ fill: "rgba(61,196,255,.04)" }} contentStyle={{ background: "#0c1828", border: "1px solid #273b52", borderRadius: 6, fontSize: 11 }} />
              <Bar dataKey="count" radius={[0, 3, 3, 0]} barSize={15}>
                {riskData.map((entry) => <Cell key={entry.priority} fill={RISK_COLORS[entry.priority]} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </Panel>

      <Panel title="Ownership & asset composition" subtitle="Organizational surface and adjacent Brand Perimeter" className="ownership-panel">
        <OwnershipComposition counts={counts} />
      </Panel>
    </div>
  );
}
