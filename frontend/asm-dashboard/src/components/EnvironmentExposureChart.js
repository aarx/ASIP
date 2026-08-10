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
      />
      <YAxis
        type="category"
        dataKey="keyword"
        width={80}
      />
      <Tooltip />
      <Bar
          dataKey="count"
          fill="#ff9800"
      >
          <LabelList
              dataKey="count"
              position="right"
          />
      </Bar>
    </BarChart>
  );
}
