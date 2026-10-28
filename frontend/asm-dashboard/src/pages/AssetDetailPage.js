import React, { useEffect, useState } from "react";
import { Button } from "@mui/material";
import { getV2AssetDetail, updateV2AssetOwnership } from "../services/api";
import Panel from "../components/ui/Panel";
import StatusBadge from "../components/ui/StatusBadge";
import { ErrorState, LoadingState } from "../components/ui/AsyncState";
import { brandAcceptanceDetail, isBrandAcceptanceFixture } from "../fixtures/brandAcceptance";
import { displayEvidence } from "../utils/presentation";

function EvidenceRow({ label, value, mono = false, wide = false }) {
  return (
    <div className={`evidence-row${wide ? " evidence-wide" : ""}`}>
      <span className="evidence-label">{label}</span>
      <span className={mono ? "evidence-value technical-value" : "evidence-value"}>{displayEvidence(value)}</span>
    </div>
  );
}

function DetailEmpty({ children, compact = false }) {
  return <div className={compact ? "detail-empty compact" : "detail-empty"}>{children}</div>;
}

function humanizeStatus(value, fallback = "Unknown") {
  if (value === null || value === undefined || value === "") return fallback;
  return String(value)
    .replaceAll("_", " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

function statusTone(value) {
  return String(value || "unknown").toLowerCase().replaceAll("_", "-");
}

function TechnologyStatus({ value, tone }) {
  return <span className={`technology-status technology-status-${tone || statusTone(value)}`}>{value}</span>;
}

function technologyRows(technologies, observations) {
  const structured = Array.isArray(observations)
    ? observations.filter((observation) => observation && observation.technology)
    : [];
  const structuredNames = new Set(
    structured.map((observation) => String(observation.technology).trim().toLowerCase())
  );
  const legacy = Array.isArray(technologies)
    ? technologies.filter(Boolean).filter((technology, index, values) => (
      values.findIndex((item) => String(item).trim().toLowerCase() === String(technology).trim().toLowerCase()) === index
      && !structuredNames.has(String(technology).trim().toLowerCase())
    ))
    : [];

  return [
    ...structured.map((observation, index) => ({
      key: `structured-${index}`,
      technology: observation.technology,
      observation,
    })),
    ...legacy.map((technology, index) => ({
      key: `legacy-${index}-${technology}`,
      technology,
      observation: null,
    })),
  ];
}

function lifecycleSummary(observation) {
  if (!observation) return { label: "Not assessed", tone: "not-assessed" };
  const status = observation.lifecycle?.status;
  const labels = {
    active_support: "Active support",
    security_support: "Security support",
    end_of_life: "End of life",
    unknown: "Unknown",
  };
  return status && labels[status]
    ? { label: labels[status], tone: statusTone(status) }
    : { label: "Not assessed", tone: "not-assessed" };
}

function cveSummary(observation) {
  const intelligence = observation?.cve_intelligence;
  if (!intelligence) return { label: "Not assessed", tone: "not-assessed" };
  const candidates = Array.isArray(intelligence.candidates) ? intelligence.candidates : [];
  const potentialCount = candidates.filter((candidate) => candidate?.applicability_status === "potentially_affected").length;
  if (potentialCount) {
    return {
      label: `${potentialCount} Potential CVE${potentialCount === 1 ? "" : "s"}`,
      tone: "potential-cve",
    };
  }
  if (candidates.some((candidate) => candidate?.applicability_status === "insufficient_evidence")) {
    return { label: "Insufficient evidence", tone: "insufficient-evidence" };
  }
  return { label: "No local candidates", tone: "no-candidates" };
}

function applicabilityLabel(status) {
  if (status === "potentially_affected") return "Potential CVE";
  if (status === "insufficient_evidence") return "Insufficient evidence";
  if (status === "not_affected_by_version") return "Not affected by reported version";
  return humanizeStatus(status);
}

function TechnologyDetails({ observation }) {
  const lifecycle = observation.lifecycle;
  const intelligence = observation.cve_intelligence;
  const candidates = Array.isArray(intelligence?.candidates) ? intelligence.candidates : [];

  return (
    <details className="technology-details">
      <summary>Technical details</summary>
      <div className="technology-details-body">
        <div className="technology-detail-grid">
          <EvidenceRow label="Detection confidence" value={observation.confidence} />
          <EvidenceRow label="Evidence type" value={observation.evidence_type} />
          <EvidenceRow label="Sanitized evidence" value={observation.sanitized_evidence} mono wide />
          <EvidenceRow label="Observed URL" value={observation.observed_url} mono wide />
          <EvidenceRow label="Detector version" value={observation.detector_version} mono />
        </div>

        {lifecycle && (
          <div className="technology-subsection">
            <div className="subsection-heading">Support lifecycle</div>
            <div className="technology-detail-grid">
              <EvidenceRow label="Status" value={lifecycleSummary(observation).label} />
              <EvidenceRow label="Release branch" value={lifecycle.matched_release_branch} mono />
              <EvidenceRow label="Active support until" value={lifecycle.active_support_until} mono />
              <EvidenceRow label="Security support until" value={lifecycle.security_support_until} mono />
              <EvidenceRow label="End of life" value={lifecycle.end_of_life} mono />
              <EvidenceRow label="Assessment date" value={lifecycle.assessment_date} mono />
              <EvidenceRow label="Source" value={lifecycle.source_url} mono wide />
            </div>
          </div>
        )}

        {intelligence && (
          <div className="technology-subsection">
            <div className="subsection-heading">Potential CVE intelligence</div>
            <div className="technology-detail-grid">
              <EvidenceRow label="Coverage" value={humanizeStatus(intelligence.coverage)} />
              <EvidenceRow label="Assessment date" value={intelligence.assessment_date} mono />
              <EvidenceRow label="Dataset revision" value={intelligence.dataset_revision} mono />
            </div>
            {candidates.length ? (
              <div className="technology-cve-list">
                {candidates.map((candidate, index) => (
                  <div className="technology-cve-row" key={`${candidate.cve_id || "candidate"}-${index}`}>
                    <div className="technology-cve-heading">
                      <strong>{candidate.cve_id || "Unidentified advisory"}</strong>
                      <TechnologyStatus
                        value={applicabilityLabel(candidate.applicability_status)}
                        tone={statusTone(candidate.applicability_status)}
                      />
                    </div>
                    <div className="technology-detail-grid">
                      <EvidenceRow label="Reported version" value={candidate.reported_version} mono />
                      <EvidenceRow label="Affected range" value={candidate.affected_version_range} mono />
                      <EvidenceRow label="Fixed version" value={candidate.fixed_version} mono />
                      <EvidenceRow label="Evidence confidence" value={humanizeStatus(candidate.evidence_confidence)} />
                      <EvidenceRow label="Patch status" value={humanizeStatus(candidate.patch_status)} />
                      <EvidenceRow label="Explanation" value={humanizeStatus(candidate.explanation_code)} />
                      {candidate.source_url && (
                        <div className="evidence-row evidence-wide">
                          <span className="evidence-label">Advisory source</span>
                          <a className="technology-source-link technical-value" href={candidate.source_url} target="_blank" rel="noreferrer">
                            {candidate.source_url}
                          </a>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <DetailEmpty compact>No local CVE candidates were returned. This does not establish that no vulnerabilities exist.</DetailEmpty>
            )}
          </div>
        )}

        <p className="technology-boundary-note">Reported technology and version evidence do not verify the installed runtime, patch state, configuration, or exploitability.</p>
      </div>
    </details>
  );
}

function TechnologyIntelligence({ technologies, observations }) {
  const rows = technologyRows(technologies, observations);
  const hasPartialCoverage = rows.some(({ observation }) => observation?.cve_intelligence?.coverage === "partial");

  return (
    <Panel title="Technology Intelligence" subtitle="Reported current-scan technology and advisory context; not verification" className="detail-panel detail-panel-wide">
      {hasPartialCoverage && (
        <div className="technology-coverage-note" role="note">
          Local CVE advisory coverage is partial. No local candidate does not mean no vulnerabilities exist.
        </div>
      )}
      {rows.length ? (
        <div className="technology-table-wrap">
          <table className="technology-table">
            <thead>
              <tr><th>Technology</th><th>Version</th><th>Support</th><th>Potential CVEs</th><th aria-label="Details" /></tr>
            </thead>
            <tbody>
              {rows.map(({ key, technology, observation }) => {
                const lifecycle = lifecycleSummary(observation);
                const cves = cveSummary(observation);
                return (
                  <tr key={key}>
                    <td data-label="Technology"><strong>{displayEvidence(technology)}</strong></td>
                    <td data-label="Version" className="technical-value">{observation ? displayEvidence(observation.version, "Version unavailable") : "—"}</td>
                    <td data-label="Support"><TechnologyStatus value={lifecycle.label} tone={lifecycle.tone} /></td>
                    <td data-label="Potential CVEs"><TechnologyStatus value={cves.label} tone={cves.tone} /></td>
                    <td data-label="Details">
                      {observation ? <TechnologyDetails observation={observation} /> : <span className="technology-legacy-note">No structured observation</span>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : <DetailEmpty>No technology evidence available.</DetailEmpty>}
    </Panel>
  );
}

function redirectBoundary(domain, finalUrl) {
  if (!finalUrl) return null;
  try {
    const finalHostname = new URL(finalUrl).hostname.toLowerCase().replace(/\.$/, "");
    const reviewedHostname = String(domain || "").toLowerCase().replace(/\.$/, "");
    return finalHostname && finalHostname !== reviewedHostname
      ? { finalHostname, finalUrl }
      : null;
  } catch {
    return null;
  }
}

function OwnershipReview({ asset, onChanged, fixtureMode = false }) {
  const [pending, setPending] = useState("");
  const [status, setStatus] = useState("idle");
  const [message, setMessage] = useState("");

  const leaveCandidate = () => {
    setPending("");
    setStatus("idle");
    setMessage("Candidate retained. No ownership decision was persisted.");
  };

  const persist = async () => {
    setStatus("loading");
    setMessage("");
    try {
      if (!fixtureMode) await updateV2AssetOwnership(asset.domain, pending);
      setStatus("success");
      setMessage(fixtureMode ? `Fixture preview only: ${pending} was not persisted.` : `Ownership updated to ${pending}.`);
      setPending("");
      if (!fixtureMode) onChanged(pending);
    } catch (error) {
      setStatus("error");
      setMessage(error?.response?.data?.detail || "Ownership decision could not be saved.");
    }
  };

  const canMarkExternal = !asset.is_known && asset.ownership_status !== "EXTERNAL";
  const canConfirm = asset.ownership_status !== "CONFIRMED";

  return (
    <Panel title="Ownership Review" subtitle="Analyst decision for this domain only" meta={fixtureMode ? "DEVELOPMENT FIXTURE · NO PERSISTENCE" : "OWNERSHIP · NOT AUTHORIZATION"} className="ownership-review-panel">
      <div className="ownership-review-summary">
        <div><span>Current ownership</span><StatusBadge value={asset.ownership_status} /></div>
        <p>Confirming ownership does not grant active-scanning authorization. Redirect destinations are never confirmed or authorized by association.</p>
      </div>
      {fixtureMode && <div className="ownership-review-note">Acceptance fixture decisions remain in this browser view only and never reach ShadowRecon APIs or data.</div>}
      <div className="ownership-review-actions">
        {canConfirm && <Button variant="contained" onClick={() => { setPending("CONFIRMED"); setMessage(""); }}>Confirm Organizational Asset</Button>}
        {canMarkExternal && <Button variant="outlined" color="warning" onClick={() => { setPending("EXTERNAL"); setMessage(""); }}>Mark External / Not Ours</Button>}
        {asset.ownership_status === "CANDIDATE" && <Button variant="text" onClick={leaveCandidate}>Leave Candidate</Button>}
      </div>
      {asset.is_known && <div className="ownership-review-note">Approved inventory membership keeps this asset CONFIRMED and Known.</div>}
      {pending && (
        <div className="ownership-confirmation" role="alertdialog" aria-label="Confirm ownership decision">
          <strong>{pending === "CONFIRMED" ? "Confirm this organizational asset?" : "Mark this asset External / Not Ours?"}</strong>
          <p>This decision applies only to <span className="technical-value">{asset.domain}</span>. It does not change any redirect destination.</p>
          <div><Button variant="text" disabled={status === "loading"} onClick={() => setPending("")}>Cancel</Button><Button variant="contained" disabled={status === "loading"} onClick={persist}>{status === "loading" ? "Saving…" : "Confirm decision"}</Button></div>
        </div>
      )}
      {message && <div className={`ownership-review-message ${status}`} role={status === "error" ? "alert" : "status"}>{message}</div>}
    </Panel>
  );
}

export default function AssetDetailPage({ domain, returnQuery }) {
  const fixtureMode = isBrandAcceptanceFixture(returnQuery);
  const [data, setData] = useState(null);
  const [status, setStatus] = useState("loading");
  const [requestVersion, setRequestVersion] = useState(0);

  useEffect(() => {
    let active = true;
    setStatus("loading");
    const request = fixtureMode ? Promise.resolve(brandAcceptanceDetail(domain)) : getV2AssetDetail(domain);
    request
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
  }, [domain, fixtureMode, requestVersion]);

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
  const redirect = redirectBoundary(data.domain, data.http?.final_url);
  const classificationContext = data.asset_class === "SHADOW"
    ? { href: "#/shadow", label: "Open Shadow workflow" }
    : ["CANDIDATE", "EXTERNAL"].includes(data.ownership_status)
      ? { href: `#/brand?ownership=${data.ownership_status}`, label: "Open Brand Perimeter" }
      : null;
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
            {classificationContext && <a className="context-link" href={classificationContext.href}>{classificationContext.label}</a>}
          </div>
        </div>
        <div className="identity-meta">
          <span>First seen <strong>scan #{data.first_seen_scan} · {displayEvidence(data.first_seen_at)}</strong></span>
          <span>Last seen <strong>scan #{data.last_seen_scan} · {displayEvidence(data.last_seen_at)}</strong></span>
          <span>Seed <strong>{displayEvidence(data.seed)}</strong></span>
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

      <OwnershipReview
        asset={data}
        fixtureMode={fixtureMode}
        onChanged={() => {
          getV2AssetDetail(domain).then((result) => { if (!result?.error) setData(result); });
        }}
      />

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
          {redirect && (
            <div className="redirect-boundary" role="note">
              <strong>Final destination is outside the reviewed hostname.</strong>
              <div><span className="technical-value">{data.domain}</span><span aria-hidden="true">↓</span><span className="technical-value">{redirect.finalUrl}</span></div>
              <p>The redirect destination is observational evidence only and is not authorized for active testing by association. A different hostname does not establish external ownership, malicious activity, or a vulnerability.</p>
            </div>
          )}
        </Panel>

        <TechnologyIntelligence
          technologies={data.technologies}
          observations={data.technology_observations}
        />

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
                  <span className="technical-value">{displayEvidence(item.source)}</span>
                  <span className="technical-value">{displayEvidence(item.seed)}</span>
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
                  <div><strong>{finding.finding}</strong><p>{displayEvidence(finding.evidence)}</p></div>
                </div>
              ))}
            </div>
          ) : <DetailEmpty>No findings were recorded for this asset in the current scan.</DetailEmpty>}
        </Panel>
      </div>
    </div>
  );
}
