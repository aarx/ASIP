import React from "react";
import AssetLink from "./AssetLink";
import StatusBadge from "./StatusBadge";

function humanizeReason(reason) {
  return String(reason || "")
    .replace(":", ": ")
    .replaceAll("_", " ");
}

export function AttentionTable({ assets, returnTo = "overview" }) {
  if (!assets.length) {
    return <p className="panel-subtitle">No scored assets currently require attention.</p>;
  }

  return (
    <div style={{ overflowX: "auto" }}>
      <table className="attention-table">
        <thead>
          <tr><th>Asset</th><th>Priority</th><th>Score</th><th>Deterministic reasons</th></tr>
        </thead>
        <tbody>
          {assets.map((asset) => (
            <tr key={asset.domain}>
              <td><AssetLink domain={asset.domain} returnTo={returnTo} /></td>
              <td><StatusBadge value={asset.priority} /></td>
              <td><span className="risk-score">{asset.score}</span></td>
              <td>
                <div className="reason-list">
                  {(asset.reasons || []).map((reason) => (
                    <span className="reason-token" key={reason}>{humanizeReason(reason)}</span>
                  ))}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default AttentionTable;
