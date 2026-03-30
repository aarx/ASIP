import { BarChart, Bar, XAxis, YAxis, Tooltip } from "recharts";

export default function SourceChart({ data }) {

  if (!data) return null;

  const chartData = data.map(d => ({
    name: d.source,
    value: d.count
  }));

  return (
    <BarChart width={500} height={300} data={chartData}>
      <XAxis dataKey="name"/>
      <YAxis/>
      <Tooltip/>
      <Bar dataKey="value" fill="#00bcd4"/>
    </BarChart>
  );
}
