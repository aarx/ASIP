import React from "react";
import { CardContent } from "@mui/material";

export default function MetricCard({ label, value, support, accent, href }) {
  const Element = href ? "a" : "div";
  return (
    <Element className={`metric-card${href ? " metric-card-link" : ""}`} href={href} style={{ "--metric-accent": accent }}>
      <CardContent sx={{ p: "var(--asip-card-padding) !important" }}>
        <div className="metric-label">{label}</div>
        <div className="metric-value">{value}</div>
        <div className="metric-support">{support}</div>
      </CardContent>
    </Element>
  );
}
