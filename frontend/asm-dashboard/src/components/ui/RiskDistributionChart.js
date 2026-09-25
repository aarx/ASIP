import React from "react";
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

export const RISK_COLORS = {
  High: "#f06467",
  Elevated: "#e7a84b",
  Review: "#d4c266",
  Low: "#4e789b",
};

export default function RiskDistributionChart({ distribution }) {
  const data = ["High", "Elevated", "Review", "Low"].map((priority) => ({
    priority,
    count: distribution?.[priority] ?? 0,
  }));

  return (
    <div className="risk-chart-wrap" aria-label="Risk distribution chart">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ top: 2, right: 22, bottom: 2, left: 6 }}>
          <XAxis type="number" allowDecimals={false} axisLine={false} tickLine={false} tick={{ fill: "#708298", fontSize: 10 }} />
          <YAxis type="category" dataKey="priority" axisLine={false} tickLine={false} width={62} tick={{ fill: "#a9bacb", fontSize: 10 }} />
          <Tooltip cursor={{ fill: "rgba(61,196,255,.04)" }} contentStyle={{ background: "#0c1828", border: "1px solid #273b52", borderRadius: 6, fontSize: 11 }} />
          <Bar dataKey="count" radius={[0, 3, 3, 0]} barSize={15}>
            {data.map((entry) => <Cell key={entry.priority} fill={RISK_COLORS[entry.priority]} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
