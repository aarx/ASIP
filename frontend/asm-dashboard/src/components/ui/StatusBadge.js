import React from "react";

export default function StatusBadge({ value }) {
  const tone = String(value || "unknown").toLowerCase().replace(/\s+/g, "-");
  return <span className={`status-badge status-${tone}`}>{value || "Unknown"}</span>;
}
