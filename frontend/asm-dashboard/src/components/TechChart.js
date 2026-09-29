import { PieChart, Pie, Cell, Tooltip } from "recharts";

export default function TechChart({ data }) {

  if (!data) return null;

  const COLORS = ["#4655a6", "#398261", "#b45b3d", "#6b61b1", "#a96f1f"];

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
      <Tooltip contentStyle={{ background: "#ffffff", border: "1px solid #cbd5e1", color: "#172130" }}/>
    </PieChart>
  );
}
