import React, { useEffect, useState } from "react";
import AssetLink from "./AssetLink";
import Panel from "./Panel";
import StatusBadge from "./StatusBadge";
import { ErrorState, LoadingState } from "./AsyncState";
import { getV2ReviewIndicators } from "../../services/api";
import { displayAssetClass, displayHttpStatus, isUsableHttpStatus } from "../../utils/presentation";

function redirectLabel(indicator) {
  return indicator.final_url_verification === "LEGACY_UNKNOWN"
    ? "Historical redirect URL — verification unavailable"
    : "Cross-host redirect observed";
}

function responseSummary(indicator) {
  const initial = isUsableHttpStatus(indicator.http_status)
    ? `Initial ${indicator.http_status}`
    : displayHttpStatus(indicator.http_observation_status, indicator.http_status);
  return indicator.final_url_verification === "COMPLETE" && indicator.final_status != null
    ? `${initial} · Verified terminal ${indicator.final_status}`
    : `${initial} · Terminal response unavailable`;
}

function redirectDestination(indicator) {
  if (indicator.observed_redirect_destination) return indicator.observed_redirect_destination;
  return indicator.final_url_verification === "LEGACY_UNKNOWN" ? indicator.final_url || null : null;
}

export default function ReviewIndicatorsPanel() {
  const [data, setData] = useState(null);
  const [status, setStatus] = useState("loading");
  const [requestVersion, setRequestVersion] = useState(0);

  useEffect(() => {
    let active = true;
    setStatus("loading");
    getV2ReviewIndicators()
      .then((result) => { if (active) { setData(result); setStatus("ready"); } })
      .catch(() => { if (active) setStatus("error"); });
    return () => { active = false; };
  }, [requestVersion]);

  const indicators = Array.isArray(data?.indicators) ? data.indicators : [];
  const returnQuery = "tab=evidence-signals&signals=review-indicators";
  return (
    <Panel title="Review Indicators" subtitle="Observed redirects for analyst review; not findings" meta={status === "ready" ? `${data?.count ?? indicators.length} CURRENT` : "CURRENT SCAN"} className="operation-panel-full">
      {status === "loading" && <LoadingState title="Loading Review Indicators" copy="Retrieving current-scan redirect observations." />}
      {status === "error" && <ErrorState title="Review Indicators unavailable" copy="Redirect review evidence could not be loaded." onRetry={() => setRequestVersion((value) => value + 1)} />}
      {status === "ready" && indicators.length > 0 && (
        <div className="dense-table-wrap">
          <table className="dense-table review-indicator-table">
            <thead><tr><th>Source asset</th><th>Indicator</th><th>HTTP</th><th>Observed destination</th><th>Destination context</th><th /></tr></thead>
            <tbody>{indicators.map((indicator) => {
              const destination = redirectDestination(indicator);
              return (
                <tr key={`${indicator.type}-${indicator.domain}-${indicator.final_url}`}>
                  <td><AssetLink domain={indicator.domain} returnTo="risk/security-review" returnQuery={returnQuery} /><StatusBadge value={displayAssetClass(indicator.asset_class)} /></td>
                  <td><strong>{redirectLabel(indicator)}</strong><span className="asset-secondary">Review only · not a vulnerability conclusion</span></td>
                  <td><StatusBadge value={indicator.http_observation_status} /><span className="asset-secondary">{responseSummary(indicator)}</span></td>
                  <td><span className="review-destination technical-value" title={destination || undefined}>{destination || "Destination unavailable"}</span><span className="asset-secondary">{indicator.final_hostname || "Hostname unavailable"}</span></td>
                  <td>{indicator.destination_confirmed ? <><StatusBadge value={displayAssetClass(indicator.destination_asset_class)} /><span className="asset-secondary">Current scan asset match</span></> : <><span className="not-applicable">No current asset match</span><span className="asset-secondary">Redirect does not establish ownership or authorization</span></>}</td>
                  <td><AssetLink domain={indicator.domain} returnTo="risk/security-review" returnQuery={returnQuery} className="row-action">→</AssetLink></td>
                </tr>
              );
            })}</tbody>
          </table>
        </div>
      )}
      {status === "ready" && indicators.length === 0 && <div className="detail-empty">No cross-host HTTP redirects were observed in the current authoritative scan.</div>}
      <a className="context-link" href="#/risk/security-review?tab=evidence-signals">Open all Evidence &amp; Signals →</a>
    </Panel>
  );
}
