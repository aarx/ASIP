import React from "react";
import { PieChart, Pie, Cell, Tooltip } from "recharts";

const COLORS = ["#1976d2", "#ef5350", "#ffa726", "#66bb6a"];

export default function HttpStatusChart({ data }) {

  const chartData = Object.keys(data).map(key => ({
    name: key,
    value: data[key]
  }));

  return (
    <PieChart width={400} height={300}>
      <Pie
        data={chartData}
        dataKey="value"
        outerRadius={120}
        label
      >
        {chartData.map((entry, index) => (
          <Cell key={index} fill={COLORS[index % COLORS.length]} />
        ))}
      </Pie>
      <Tooltip />
    </PieChart>
  );
}
