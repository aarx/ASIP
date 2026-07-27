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
      <XAxis dataKey="scan_id" />
      <YAxis />
      <Tooltip />
      <Legend />

      <Line
        type="monotone"
        dataKey="total"
        name="Total Domains"
        stroke="#1976d2"
      />

      <Line
        type="monotone"
        dataKey="live"
        name="Live Domains"
        stroke="#4caf50"
      />

      <Line
        type="monotone"
        dataKey="shadow"
        name="Shadow Assets"
        stroke="#f44336"
      />
    </LineChart>
  );
}
