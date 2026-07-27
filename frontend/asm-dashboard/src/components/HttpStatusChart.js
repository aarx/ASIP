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
      fill: "#4caf50"
    },
    {
      name: "3xx",
      value: data["3xx"] || 0,
      fill: "#2196f3"
    },
    {
      name: "4xx",
      value: data["4xx"] || 0,
      fill: "#ff9800"
    },
    {
      name: "5xx",
      value: data["5xx"] || 0,
      fill: "#f44336"
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
      <XAxis type="number" />
      <YAxis dataKey="name" type="category" />
      <Tooltip />

      <Bar dataKey="value">
        <LabelList
          dataKey="value"
          position="right"
          style={{
            fontSize: 12,
            fontWeight: "bold"
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
