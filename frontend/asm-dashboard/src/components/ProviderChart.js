import { BarChart, Bar, XAxis, YAxis, Tooltip } from "recharts";

export default function ProviderChart({ data, onProviderClick }) {

  if (!data) return null;

  return (
    <BarChart width={600} height={300} data={data}>
      <XAxis dataKey="provider"/>
      <YAxis/>
      <Tooltip/>
      <Bar
        dataKey="count"
        fill="#8884d8"
        onClick={(data) => {
          console.log("CLICKED:", data);
        
          if (onProviderClick) {
            onProviderClick(data.provider);
          }
        }}
      />
    </BarChart>
  );
}
