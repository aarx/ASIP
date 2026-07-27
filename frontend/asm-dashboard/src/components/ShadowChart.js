import React from "react";
import { BarChart, Bar, LabelList, XAxis, YAxis, Tooltip, CartesianGrid } from "recharts";

export default function ShadowChart({ data }) {

  return (
    <BarChart width={500} height={300} data={data}>
      <CartesianGrid strokeDasharray="3 3" />
      <XAxis dataKey="risk" />
      <YAxis />
      <Tooltip />
      <Bar dataKey="count">
          <LabelList
              dataKey="count"
              position="top"
          />
      </Bar>
    </BarChart>
  );
}
