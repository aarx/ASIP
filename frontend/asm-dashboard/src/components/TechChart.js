import { PieChart, Pie, Cell, Tooltip } from "recharts";

export default function TechChart({ data }) {

  if (!data) return null;

  const COLORS = ["#2196f3","#4caf50","#ff5722","#9c27b0","#ffc107"];

  return (
    <PieChart width={400} height={300}>
      <Pie
        data={data}
        dataKey="count"
        nameKey="tech"
        outerRadius={100}
        label
      >
        {data.map((entry, index) => (
          <Cell key={index} fill={COLORS[index % COLORS.length]} />
        ))}
      </Pie>
      <Tooltip/>
    </PieChart>
  );
}
