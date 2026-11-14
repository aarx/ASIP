import React, { useEffect, useState } from "react";
import AssetLink from "./AssetLink";
import Panel from "./Panel";
import { ErrorState, LoadingState } from "./AsyncState";
import { getSensitiveExposure } from "../../services/api";

const RESULT_LIMIT = 20;

export default function SensitivePortsPanel() {
  const [rows, setRows] = useState(null);
  const [status, setStatus] = useState("loading");
  const [requestVersion, setRequestVersion] = useState(0);

  useEffect(() => {
    let active = true;
    setStatus("loading");
    getSensitiveExposure()
      .then((result) => { if (active) { setRows(Array.isArray(result) ? result : []); setStatus("ready"); } })
      .catch(() => { if (active) setStatus("error"); });
    return () => { active = false; };
  }, [requestVersion]);

  const count = rows?.length ?? 0;
  const meta = status !== "ready" ? "CURRENT SCAN"
    : count >= RESULT_LIMIT ? `${RESULT_LIMIT}+ OBSERVED`
      : `${count} OBSERVED`;

  return (
    <Panel title="Sensitive port observations" subtitle="Observed rows; assessment coverage is unavailable" meta={meta} className="operation-panel-full">
      {status === "loading" && <LoadingState title="Loading sensitive-port observations" copy="Retrieving recorded current-scan rows." />}
      {status === "error" && <ErrorState title="Sensitive-port observations unavailable" copy="The observed rows could not be loaded." onRetry={() => setRequestVersion((value) => value + 1)} />}
      {status === "ready" && count > 0 && (
        <div className="compact-list">
          {rows.map((item, index) => (
            <div className="port-exposure-row" key={`${item.domain}-${item.port}-${index}`}>
              <span className="port-number">{item.port}</span>
              <div><AssetLink domain={item.domain} returnTo="risk/security-review" returnQuery="tab=sensitive-ports" /><p>{item.service || "Service unspecified"}</p></div>
              <span className="configured-risk">Sensitivity {item.risk}</span>
            </div>
          ))}
        </div>
      )}
      {status === "ready" && count === 0 && <div className="detail-empty">No port observations recorded for this scan.</div>}
      {status === "ready" && count >= RESULT_LIMIT && <div className="asset-secondary">Result list capped at 20 rows.</div>}
    </Panel>
  );
}
