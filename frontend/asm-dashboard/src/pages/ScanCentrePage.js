import React, { useEffect, useState } from "react";
import { getV2Overview, getV2Scans } from "../services/api";
import MetricCard from "../components/ui/MetricCard";
import Panel from "../components/ui/Panel";
import StatusBadge from "../components/ui/StatusBadge";
import { EmptyState, ErrorState, LoadingState } from "../components/ui/AsyncState";

function timestamp(value) {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString();
}

function duration(value) {
  if (value === null || value === undefined) return "—";
  const seconds = Math.max(Number(value), 0);
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const minutes = Math.floor(seconds / 60);
  const remainder = Math.round(seconds % 60);
  return `${minutes}m ${remainder}s`;
}

export default function ScanCentrePage() {
  const [data, setData] = useState(null);
  const [status, setStatus] = useState("loading");
  const [requestVersion, setRequestVersion] = useState(0);

  useEffect(() => {
    let active = true;
    setStatus("loading");
    Promise.all([getV2Scans(100), getV2Overview()])
      .then(([scans, overview]) => {
        if (active) { setData({ scans, overview }); setStatus("ready"); }
      })
      .catch(() => { if (active) setStatus("error"); });
    return () => { active = false; };
  }, [requestVersion]);

  if (status === "loading") return <LoadingState title="Loading scan history" copy="Retrieving lifecycle state and authoritative scan markers." />;
  if (status === "error") return <ErrorState title="Scan Centre unavailable" copy="Scan lifecycle history could not be loaded." onRetry={() => setRequestVersion((value) => value + 1)} />;
  if (!data.scans.scans.length) return <EmptyState title="No scan history" copy="No scans have been recorded." />;

  const { scans, overview } = data;
  return (
    <div className="scan-workspace">
      <section className="operations-kpis" aria-label="Scan status context">
        <MetricCard label="Current authoritative" value={scans.current_authoritative_scan_id ? `#${scans.current_authoritative_scan_id}` : "—"} support="Latest SUCCEEDED scan" accent="#39cb91" />
        <MetricCard label="Previous baseline" value={scans.previous_authoritative_scan_id ? `#${scans.previous_authoritative_scan_id}` : "—"} support="Previous SUCCEEDED scan" accent="#4e789b" />
        <MetricCard label="New assets" value={overview.changes?.new_assets ?? 0} support="Successful-scan comparison" accent="#3dc4ff" />
        <MetricCard label="Disappeared" value={overview.changes?.disappeared_assets ?? 0} support="Successful-scan comparison" accent="#7e91a8" />
      </section>

      <Panel title="Scan history" subtitle="Lifecycle is explicit; only SUCCEEDED scans may be authoritative" meta={`${scans.scans.length} MOST RECENT`} className="scan-history-panel">
        <div className="dense-table-wrap">
          <table className="dense-table scan-table">
            <thead><tr><th>Scan</th><th>Lifecycle</th><th>Authority</th><th>Started</th><th>Completed</th><th>Duration</th><th>Assets</th><th>Seed</th></tr></thead>
            <tbody>{scans.scans.map((scan) => (
              <tr key={scan.scan_id}>
                <td><span className="scan-id">#{scan.scan_id}</span></td>
                <td><StatusBadge value={scan.status} /></td>
                <td>
                  {scan.is_current_authoritative && <span className="authority-marker current">Current authoritative</span>}
                  {scan.is_previous_authoritative && <span className="authority-marker previous">Previous baseline</span>}
                  {!scan.is_current_authoritative && !scan.is_previous_authoritative && <span className="not-applicable">Not authoritative</span>}
                </td>
                <td>{timestamp(scan.started_at || scan.scan_time)}</td>
                <td>{timestamp(scan.completed_at)}</td>
                <td><span className="technical-value">{duration(scan.duration_seconds)}</span></td>
                <td><span className="risk-score">{scan.asset_count}</span></td>
                <td><span className="technical-value">{scan.seed || "—"}</span></td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
