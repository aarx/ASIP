import React from "react";
import {
  BarChart,
  Bar,
  LabelList,
  XAxis,
  YAxis,
  Tooltip
} from "recharts";

export default function EnvironmentExposureChart({ data }) {

  if (!data) return null;

  return (
    <BarChart
      width={500}
      height={300}
      data={data}
      layout="vertical"
    >
      <XAxis
        type="number"
        domain={[0, "dataMax + 3"]}
        tick={{ fill: "#526174", fontSize: 10 }}
      />
      <YAxis
        type="category"
        dataKey="keyword"
        width={80}
        tick={{ fill: "#526174", fontSize: 10 }}
      />
      <Tooltip contentStyle={{ background: "#ffffff", border: "1px solid #cbd5e1", color: "#172130" }} />
      <Bar
          dataKey="count"
          fill="#a96f1f"
      >
          <LabelList
              dataKey="count"
              position="right"
          />
      </Bar>
    </BarChart>
  );
}
