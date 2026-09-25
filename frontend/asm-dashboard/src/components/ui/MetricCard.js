import React from "react";
import { CardContent } from "@mui/material";

export default function MetricCard({ label, value, support, accent }) {
  return (
    <div className="metric-card" style={{ "--metric-accent": accent }}>
      <CardContent sx={{ p: "18px 19px !important" }}>
        <div className="metric-label">{label}</div>
        <div className="metric-value">{value}</div>
        <div className="metric-support">{support}</div>
      </CardContent>
    </div>
  );
}
