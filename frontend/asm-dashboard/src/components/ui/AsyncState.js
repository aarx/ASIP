import React from "react";
import { Button } from "@mui/material";

export function LoadingState({
  title = "Loading authoritative state",
  copy = "Retrieving deterministic results from the latest successful scan.",
}) {
  return (
    <div className="state-card" role="status" aria-live="polite">
      <div>
        <div className="loading-bars" aria-hidden="true"><span /><span /><span /></div>
        <h2 className="state-title">{title}</h2>
        <p className="state-copy">{copy}</p>
      </div>
    </div>
  );
}

export function ErrorState({
  onRetry,
  title = "Overview unavailable",
  copy = "The API did not return the current authoritative state. No values have been inferred.",
}) {
  return (
    <div className="state-card" role="alert">
      <div>
        <div className="state-icon" aria-hidden="true">!</div>
        <h2 className="state-title">{title}</h2>
        <p className="state-copy">{copy}</p>
        <Button className="state-action" variant="outlined" onClick={onRetry}>Retry request</Button>
      </div>
    </div>
  );
}

export function EmptyState({
  title = "No authoritative scan yet",
  copy = "Overview data will appear after a scan completes successfully. Running or failed scans are not treated as current state.",
  className = "",
}) {
  return (
    <div className={`state-card ${className}`.trim()}>
      <div>
        <div className="state-icon" aria-hidden="true">—</div>
        <h2 className="state-title">{title}</h2>
        <p className="state-copy">{copy}</p>
      </div>
    </div>
  );
}
