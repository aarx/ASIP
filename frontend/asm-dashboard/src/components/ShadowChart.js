import React from "react";
import { BarChart, Bar, LabelList, XAxis, YAxis, Tooltip, CartesianGrid } from "recharts";

export default function ShadowChart({ data }) {

  return (
    <BarChart width={500} height={300} data={data}>
      <CartesianGrid strokeDasharray="3 3" stroke="#d8e0e8" />
      <XAxis dataKey="risk" tick={{ fill: "#526174", fontSize: 10 }} />
      <YAxis tick={{ fill: "#526174", fontSize: 10 }} />
      <Tooltip contentStyle={{ background: "#ffffff", border: "1px solid #cbd5e1", color: "#172130" }} />
      <Bar dataKey="count">
          <LabelList
              dataKey="count"
              position="top"
          />
      </Bar>
    </BarChart>
  );
}
