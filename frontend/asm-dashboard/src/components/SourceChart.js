import { BarChart, Bar, LabelList, XAxis, YAxis, Tooltip } from "recharts";

export default function SourceChart({ data }) {

  if (!data) return null;

  const chartData = data.map(d => ({
    name: d.source,
    value: d.count
  }));

  return (
    <BarChart width={500} height={300} data={chartData}>
      <XAxis dataKey="name" tick={{ fill: "#526174", fontSize: 10 }}/>
      <YAxis tick={{ fill: "#526174", fontSize: 10 }}/>
      <Tooltip contentStyle={{ background: "#ffffff", border: "1px solid #cbd5e1", color: "#172130" }}/>
      <Bar
          dataKey="value"
          fill="#327d80"
      >
          <LabelList
              dataKey="value"
              position="top"
          />
      </Bar>
    </BarChart>
  );
}
