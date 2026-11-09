import React, { useEffect, useState } from "react";
import { getV2Overview } from "../services/api";
import Panel from "../components/ui/Panel";
import RiskDistributionChart from "../components/ui/RiskDistributionChart";
import { EmptyState, ErrorState, LoadingState } from "../components/ui/AsyncState";
import AttentionTable from "../components/ui/OverviewAttention";

export default function RiskNeedsAttentionPage() {
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

  if (status === "loading") return <LoadingState title="Loading Needs Attention" copy="Retrieving the bounded deterministic risk queue." />;
  if (status === "error") return <ErrorState title="Needs Attention unavailable" copy="The current attention queue could not be loaded." onRetry={() => setRequestVersion((value) => value + 1)} />;
  if (!data || data.current_scan_id == null) return <EmptyState />;

  return (
    <div className="operations-grid risk-needs-attention-page">
      <a className="overview-subpage-context operation-panel-full" href="#/scans">
        <span>Current authoritative scan</span>
        <strong>#{data.current_scan_id}</strong>
        <span aria-hidden="true">View scans →</span>
      </a>
      <Panel title="Needs attention" subtitle="Highest deterministic risk scores in the current surface" meta="TOP 10" className="operation-panel-full">
        <AttentionTable assets={data.needs_attention || []} returnTo="risk/needs-attention" />
      </Panel>
      <Panel title="Risk distribution" subtitle="Canonical priorities across confirmed organizational assets" meta={`SCAN #${data.current_scan_id}`} className="operation-panel-full">
        <RiskDistributionChart
          distribution={data.risk_distribution}
          priorityHref={(priority) => `#/assets?priority=${encodeURIComponent(priority)}`}
        />
      </Panel>
    </div>
  );
}
