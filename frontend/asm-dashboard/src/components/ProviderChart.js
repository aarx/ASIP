import { BarChart, Bar, LabelList, XAxis, YAxis, Tooltip } from "recharts";

export default function ProviderChart({ data, onProviderClick }) {

  if (!data) return null;

  return (
    <BarChart
      width={600}
      height={300}
      data={data}
      margin={{
        top: 25,
        right: 20,
        left: 10,
        bottom: 10
      }}
    >
      <XAxis dataKey="provider" tick={{ fill: "#526174", fontSize: 10 }}/>
      <YAxis tick={{ fill: "#526174", fontSize: 10 }}/>
      <Tooltip contentStyle={{ background: "#ffffff", border: "1px solid #cbd5e1", color: "#172130" }}/>
      <Bar
        dataKey="count"
        fill="#4655a6"
        onClick={(data) => {
          console.log("CLICKED:", data);
      
          if (onProviderClick) {
            onProviderClick(data.provider);
          }
        }}
      >
        <LabelList
          dataKey="count"
          position="top"
          style={{
            fontSize: 12,
            fontWeight: "bold",
            fill: "#334155"
          }}
        />
      </Bar>
    </BarChart>
  );
}
