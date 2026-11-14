import React, { useEffect, useState } from "react";
import { getV2Overview } from "../services/api";
import Panel from "../components/ui/Panel";
import RiskDistributionChart from "../components/ui/RiskDistributionChart";
import { EmptyState, ErrorState, LoadingState } from "../components/ui/AsyncState";

export default function OverviewRiskDistributionPage() {
  const [data, setData] = useState(null);
  const [status, setStatus] = useState("loading");
  const [requestVersion, setRequestVersion] = useState(0);

  useEffect(() => {
    let active = true;
    setStatus("loading");
    getV2Overview()
      .then((result) => {
        if (active) {
          setData(result);
          setStatus("ready");
        }
      })
      .catch(() => { if (active) setStatus("error"); });
    return () => { active = false; };
  }, [requestVersion]);

  if (status === "loading") return <LoadingState title="Loading Current Risk Distribution" copy="Retrieving canonical current-scan risk categories." />;
  if (status === "error") return <ErrorState title="Current Risk Distribution unavailable" copy="The current risk distribution could not be loaded." onRetry={() => setRequestVersion((value) => value + 1)} />;
  if (!data || data.current_scan_id == null) return <EmptyState />;

  return (
    <div className="overview-subpage">
      <a className="overview-subpage-context" href="#/scans">
        <span>Current authoritative scan</span>
        <strong>#{data.current_scan_id}</strong>
        <span aria-hidden="true">View scans →</span>
      </a>
      <Panel title="Current Risk Distribution" subtitle="Canonical priorities across confirmed organizational assets" meta={`SCAN #${data.current_scan_id}`} className="overview-subpage-panel">
        <RiskDistributionChart
          distribution={data.risk_distribution}
          priorityHref={(priority) => `#/assets?priority=${encodeURIComponent(priority)}&limit=25`}
        />
      </Panel>
    </div>
  );
}
