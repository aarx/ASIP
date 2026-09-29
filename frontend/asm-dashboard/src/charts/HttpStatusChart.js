import React from "react";
import { PieChart, Pie, Cell, Tooltip } from "recharts";

const COLORS = ["#4655a6", "#b43d4a", "#a96f1f", "#398261"];

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
      <Tooltip contentStyle={{ background: "#ffffff", border: "1px solid #cbd5e1", color: "#172130" }} />
    </PieChart>
  );
}
