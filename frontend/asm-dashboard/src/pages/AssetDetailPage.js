import React, { useEffect, useState } from "react";
import { Button } from "@mui/material";
import { getV2AssetDetail } from "../services/api";
import Panel from "../components/ui/Panel";
import StatusBadge from "../components/ui/StatusBadge";
import { ErrorState, LoadingState } from "../components/ui/AsyncState";

function valueOrDash(value) {
  return value === null || value === undefined || value === "" ? "—" : String(value);
}

function EvidenceRow({ label, value, mono = false, wide = false }) {
  return (
    <div className={`evidence-row${wide ? " evidence-wide" : ""}`}>
      <span className="evidence-label">{label}</span>
      <span className={mono ? "evidence-value technical-value" : "evidence-value"}>{valueOrDash(value)}</span>
    </div>
  );
}

function DetailEmpty({ children, compact = false }) {
  return <div className={compact ? "detail-empty compact" : "detail-empty"}>{children}</div>;
}

export default function AssetDetailPage({ domain, returnQuery }) {
  const [data, setData] = useState(null);
  const [status, setStatus] = useState("loading");
  const [requestVersion, setRequestVersion] = useState(0);

  useEffect(() => {
    let active = true;
    setStatus("loading");
    getV2AssetDetail(domain)
      .then((result) => {
        if (!active) return;
        if (result?.error) {
          setData(result);
          setStatus("not-found");
        } else {
          setData(result);
          setStatus("ready");
        }
      })
      .catch(() => { if (active) setStatus("error"); });
    return () => { active = false; };
  }, [domain, requestVersion]);

  const returnParams = new URLSearchParams(returnQuery);
  const returnTo = returnParams.get("return");
  const explicitReturnQuery = returnParams.get("return_query");
  const backRoute = ["overview", "risk", "shadow", "brand", "changes", "investigate"].includes(returnTo)
    ? returnTo
    : "assets";
  const backLabels = {
    overview: "Overview",
    risk: "Risk & Exposure",
    shadow: "Shadow",
    brand: "Brand Perimeter",
    changes: "Change Intelligence",
    investigate: "Investigate",
    assets: "Assets",
  };
  const backLabel = backLabels[backRoute];
  if (returnTo) returnParams.delete("return");
  if (explicitReturnQuery !== null) returnParams.delete("return_query");
  const backQuery = explicitReturnQuery !== null ? explicitReturnQuery : returnParams.toString();
  const backHref = `#/${backRoute}${backQuery ? `?${backQuery}` : ""}`;
  const investigationParams = new URLSearchParams({ domain });
  if (returnQuery) investigationParams.set("detail_return", returnQuery);
  const investigationHref = `#/investigate?${investigationParams}`;

  if (status === "loading") return <LoadingState title="Loading asset evidence" copy="Retrieving current scan evidence without inferring missing observations." />;
  if (status === "error") return <ErrorState title="Asset detail unavailable" copy="The current evidence contract could not be loaded." onRetry={() => setRequestVersion((value) => value + 1)} />;
  if (status === "not-found") {
    return (
      <div className="state-card">
        <div>
          <div className="state-icon" aria-hidden="true">?</div>
          <h2 className="state-title">Asset is not in the current surface</h2>
          <p className="state-copy">{data?.error || "The asset was not found in the current authoritative scan."}</p>
          <Button className="state-action" component="a" href={backHref} variant="outlined">Back to {backLabel}</Button>
        </div>
      </div>
    );
  }

  const risk = data.risk;
  return (
    <div className="asset-detail">
      <div className="detail-toolbar">
        <Button component="a" href={backHref} variant="text">← Back to {backLabel}</Button>
        <div><span>Authoritative scan #{data.scan_id}</span><Button component="a" href={investigationHref} variant="outlined" size="small">Investigate asset</Button></div>
      </div>

      <section className="asset-identity-card">
        <div className="identity-heading">
          <div>
            <span className="identity-kicker">Current asset</span>
            <h2>{data.domain}</h2>
          </div>
          <div className="identity-badges">
            <StatusBadge value={data.asset_class} />
            <StatusBadge value={data.ownership_status} />
          </div>
        </div>
        <div className="identity-meta">
          <span>First seen <strong>scan #{data.first_seen_scan} · {valueOrDash(data.first_seen_at)}</strong></span>
          <span>Last seen <strong>scan #{data.last_seen_scan} · {valueOrDash(data.last_seen_at)}</strong></span>
          <span>Seed <strong>{valueOrDash(data.seed)}</strong></span>
        </div>
        <div className="risk-posture">
          {risk ? (
            <>
              <div><span className="risk-posture-label">Canonical risk</span><strong>{risk.score}</strong></div>
              <StatusBadge value={risk.priority} />
              <div className="reason-list">
                {(risk.reasons || []).map((reason) => <span className="reason-token" key={reason}>{reason.replaceAll("_", " ")}</span>)}
              </div>
            </>
          ) : (
            <div className="non-org-risk-note">No organizational canonical risk applies to {data.ownership_status} assets.</div>
          )}
        </div>
      </section>

      <div className="detail-grid">
        <Panel title="Network" subtitle="Current DNS and infrastructure evidence" className="detail-panel">
          <div className="evidence-grid">
            <EvidenceRow label="IP address" value={data.dns?.ip} mono />
            <EvidenceRow label="Reverse DNS" value={data.dns?.reverse_dns} mono />
            <EvidenceRow label="Provider" value={data.provider} />
            <EvidenceRow label="ASN" value={data.asn?.asn} mono />
            <EvidenceRow label="Organization" value={data.asn?.organization} wide />
          </div>
          <div className="subsection-heading">Observed ports</div>
          {data.ports?.length ? (
            <div className="port-list">
              {data.ports.map((item) => (
                <div className="port-token" key={`${item.port}-${item.service}`}>
                  <strong>{item.port}</strong><span>{item.service || "service unknown"}</span>
                </div>
              ))}
            </div>
          ) : <DetailEmpty compact>No positive port evidence for this scan.</DetailEmpty>}
        </Panel>

        <Panel title="HTTP" subtitle="Observed response state and destination" className="detail-panel">
          <div className="evidence-grid">
            <div className="evidence-row"><span className="evidence-label">Observation</span><span className="evidence-value"><StatusBadge value={data.http?.observation_status} /></span></div>
            <EvidenceRow label="Initial status" value={data.http?.status} mono />
            <EvidenceRow label="Reason" value={data.http?.reason} />
            <EvidenceRow label="Final status" value={data.http?.final_status} mono />
            <EvidenceRow label="Title" value={data.http?.title} wide />
            <EvidenceRow label="Final URL" value={data.http?.final_url} mono wide />
          </div>
        </Panel>

        <Panel title="Technology" subtitle="Detected current-scan technologies" className="detail-panel">
          {data.technologies?.length ? (
            <div className="technology-list">{data.technologies.map((tech) => <span key={tech}>{tech}</span>)}</div>
          ) : <DetailEmpty>No technology evidence available.</DetailEmpty>}
        </Panel>

        <Panel title="Certificate" subtitle="Observed certificate metadata" className="detail-panel">
          {data.certificate ? (
            <div className="evidence-grid">
              <EvidenceRow label="Status" value={data.certificate.status} />
              <EvidenceRow label="Expiry" value={data.certificate.expiry_date} mono />
              <EvidenceRow label="Days remaining" value={data.certificate.days_to_expiry} mono />
            </div>
          ) : <DetailEmpty>No certificate evidence available.</DetailEmpty>}
        </Panel>

        <Panel title="Discovery & provenance" subtitle="How this asset entered the current scan" className="detail-panel detail-panel-wide">
          {data.discovery?.sources?.length ? (
            <div className="provenance-table">
              <div className="provenance-head"><span>Source</span><span>Associated seed</span></div>
              {data.discovery.sources.map((item, index) => (
                <div className="provenance-row" key={`${item.source}-${item.seed}-${index}`}>
                  <span className="technical-value">{valueOrDash(item.source)}</span>
                  <span className="technical-value">{valueOrDash(item.seed)}</span>
                </div>
              ))}
            </div>
          ) : <DetailEmpty>No current-scan provenance rows are available.</DetailEmpty>}
        </Panel>

        <Panel title="Findings" subtitle="Deterministic observations requiring investigation" className="detail-panel detail-panel-wide">
          {data.findings?.length ? (
            <div className="finding-list">
              {data.findings.map((finding, index) => (
                <div className="finding-row" key={`${finding.finding}-${index}`}>
                  <StatusBadge value={finding.severity} />
                  <div><strong>{finding.finding}</strong><p>{valueOrDash(finding.evidence)}</p></div>
                </div>
              ))}
            </div>
          ) : <DetailEmpty>No findings were recorded for this asset in the current scan.</DetailEmpty>}
        </Panel>
      </div>
    </div>
  );
}
