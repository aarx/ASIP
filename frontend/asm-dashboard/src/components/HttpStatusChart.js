import React from "react";
import {
  BarChart,
  Bar,
  LabelList,
  Cell,
  XAxis,
  YAxis,
  Tooltip
} from "recharts";

export default function HttpStatusChart({ data }) {

  if (!data) return null;

  const chartData = [
    {
      name: "2xx",
      value: data["2xx"] || 0,
      fill: "#398261"
    },
    {
      name: "3xx",
      value: data["3xx"] || 0,
      fill: "#4655a6"
    },
    {
      name: "4xx",
      value: data["4xx"] || 0,
      fill: "#a96f1f"
    },
    {
      name: "5xx",
      value: data["5xx"] || 0,
      fill: "#b43d4a"
    }
  ];

  return (
    <BarChart
      width={350}
      height={250}
      data={chartData}
      layout="vertical"
      margin={{ top: 10, right: 20, left: 20, bottom: 10 }}
    >
      <XAxis type="number" tick={{ fill: "#526174", fontSize: 10 }} />
      <YAxis dataKey="name" type="category" tick={{ fill: "#526174", fontSize: 10 }} />
      <Tooltip contentStyle={{ background: "#ffffff", border: "1px solid #cbd5e1", color: "#172130" }} />

      <Bar dataKey="value">
        <LabelList
          dataKey="value"
          position="right"
          style={{
            fontSize: 12,
            fontWeight: "bold",
            fill: "#334155"
          }}
        />
      
        {chartData.map((entry, index) => (
          <Cell
            key={index}
            fill={entry.fill}
          />
        ))}
      </Bar>
    </BarChart>
  );
}
