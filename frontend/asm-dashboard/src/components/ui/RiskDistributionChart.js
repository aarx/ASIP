import React from "react";
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

export const RISK_COLORS = {
  High: "#f06467",
  Elevated: "#e7a84b",
  Review: "#6b61b1",
  Low: "#398261",
};

export default function RiskDistributionChart({ distribution, priorityHref }) {
  const data = ["High", "Elevated", "Review", "Low"].map((priority) => ({
    priority,
    count: distribution?.[priority] ?? 0,
  }));

  return (
    <div className={`risk-chart-wrap${priorityHref ? " risk-chart-actionable" : ""}`} aria-label="Risk distribution chart">
      <div className="risk-chart-canvas">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} layout="vertical" margin={{ top: 2, right: 22, bottom: 2, left: 6 }}>
            <XAxis type="number" allowDecimals={false} axisLine={false} tickLine={false} tick={{ fill: "#64748b", fontSize: 10 }} />
            <YAxis type="category" dataKey="priority" axisLine={false} tickLine={false} width={62} tick={{ fill: "#334155", fontSize: 10 }} />
            <Tooltip cursor={{ fill: "rgba(70,85,166,.06)" }} contentStyle={{ background: "#ffffff", border: "1px solid #cbd5e1", borderRadius: 6, color: "#172130", fontSize: 11, boxShadow: "0 6px 18px rgba(31,45,61,.12)" }} />
            <Bar dataKey="count" radius={[0, 3, 3, 0]} barSize={15}>
              {data.map((entry) => <Cell key={entry.priority} fill={RISK_COLORS[entry.priority]} />)}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
      {priorityHref && <nav className="risk-drilldown" aria-label="Filter assets by risk priority">{data.map((entry) => <a href={priorityHref(entry.priority)} key={entry.priority}><i style={{ background: RISK_COLORS[entry.priority] }} aria-hidden="true" /><span>{entry.priority}</span><strong>{entry.count}</strong><span aria-hidden="true">→</span></a>)}</nav>}
    </div>
  );
}
