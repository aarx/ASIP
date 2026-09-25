import React from "react";
import { Button } from "@mui/material";

export function LoadingState() {
  return (
    <div className="state-card" role="status" aria-live="polite">
      <div>
        <div className="loading-bars" aria-hidden="true"><span /><span /><span /></div>
        <h2 className="state-title">Loading authoritative state</h2>
        <p className="state-copy">Retrieving deterministic results from the latest successful scan.</p>
      </div>
    </div>
  );
}

export function ErrorState({ onRetry }) {
  return (
    <div className="state-card" role="alert">
      <div>
        <div className="state-icon" aria-hidden="true">!</div>
        <h2 className="state-title">Overview unavailable</h2>
        <p className="state-copy">The API did not return the current authoritative state. No values have been inferred.</p>
        <Button className="state-action" variant="outlined" onClick={onRetry}>Retry request</Button>
      </div>
    </div>
  );
}

export function EmptyState() {
  return (
    <div className="state-card">
      <div>
        <div className="state-icon" aria-hidden="true">—</div>
        <h2 className="state-title">No authoritative scan yet</h2>
        <p className="state-copy">Overview data will appear after a scan completes successfully. Running or failed scans are not treated as current state.</p>
      </div>
    </div>
  );
}
