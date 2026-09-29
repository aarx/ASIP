import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  Legend
} from "recharts";

export default function AssetGrowthChart({ data }) {

  if (!data) return null;

  return (
    <LineChart width={500} height={300} data={data}>
      <XAxis dataKey="scan_id" tick={{ fill: "#526174", fontSize: 10 }} />
      <YAxis tick={{ fill: "#526174", fontSize: 10 }} />
      <Tooltip contentStyle={{ background: "#ffffff", border: "1px solid #cbd5e1", color: "#172130" }} />
      <Legend />

      <Line
        type="monotone"
        dataKey="total"
        name="Total Domains"
        stroke="#4655a6"
      />

      <Line
        type="monotone"
        dataKey="live"
        name="Live Domains"
        stroke="#398261"
      />

      <Line
        type="monotone"
        dataKey="shadow"
        name="Shadow Assets"
        stroke="#b43d4a"
      />
    </LineChart>
  );
}
