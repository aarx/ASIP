import { BarChart, Bar, LabelList, XAxis, YAxis, Tooltip } from "recharts";

export default function HygieneChart({ data }) {

  if (!data) return null;

  const chartData = [
    { name: "New", value: data.new },
    { name: "Disappeared", value: data.disappeared }
  ];

  return (
    <BarChart width={500} height={300} data={chartData}>
      <XAxis dataKey="name" tick={{ fill: "#526174", fontSize: 10 }}/>
      <YAxis tick={{ fill: "#526174", fontSize: 10 }}/>
      <Tooltip contentStyle={{ background: "#ffffff", border: "1px solid #cbd5e1", color: "#172130" }}/>
      <Bar
          dataKey="value"
          fill="#b43d4a"
      >
          <LabelList
              dataKey="value"
              position="top"
          />
      </Bar>
    </BarChart>
  );
}
