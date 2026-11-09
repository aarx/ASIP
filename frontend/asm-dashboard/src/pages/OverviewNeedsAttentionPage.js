import React, { useEffect, useState } from "react";
import { getV2Overview } from "../services/api";
import Panel from "../components/ui/Panel";
import { EmptyState, ErrorState, LoadingState } from "../components/ui/AsyncState";
import AttentionTable from "../components/ui/OverviewAttention";

export default function OverviewNeedsAttentionPage() {
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
    <div className="overview-subpage">
      <a className="overview-subpage-context" href="#/scans">
        <span>Current authoritative scan</span>
        <strong>#{data.current_scan_id}</strong>
        <span aria-hidden="true">View scans →</span>
      </a>
      <Panel title="Needs attention" subtitle="Highest deterministic risk scores in the current surface" meta="TOP 10" className="overview-subpage-panel">
        <AttentionTable assets={data.needs_attention || []} returnTo="overview/needs-attention" />
      </Panel>
    </div>
  );
}
