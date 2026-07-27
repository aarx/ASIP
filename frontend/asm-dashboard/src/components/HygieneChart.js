import { BarChart, Bar, LabelList, XAxis, YAxis, Tooltip } from "recharts";

export default function HygieneChart({ data }) {

  if (!data) return null;

  const chartData = [
    { name: "New", value: data.new },
    { name: "Disappeared", value: data.disappeared }
  ];

  return (
    <BarChart width={500} height={300} data={chartData}>
      <XAxis dataKey="name"/>
      <YAxis/>
      <Tooltip/>
      <Bar
          dataKey="value"
          fill="#f44336"
      >
          <LabelList
              dataKey="value"
              position="top"
          />
      </Bar>
    </BarChart>
  );
}
