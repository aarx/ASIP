import React, { useEffect, useMemo, useState } from "react";
import { Button } from "@mui/material";
import { getPhpRceCheck, getV2Scans } from "../services/api";
import MetricCard from "../components/ui/MetricCard";
import Panel from "../components/ui/Panel";
import { EmptyState, ErrorState, LoadingState } from "../components/ui/AsyncState";

const RESULT_LIMIT = 25;
const FILTERS = [
  ["classification", "Classification", [
    "Potential CVE",
    "Not affected by reported version",
    "Insufficient evidence",
    "Not evaluated",
    "Unknown",
    "No PHP observation",
  ]],
  ["lifecycle", "Lifecycle", ["active_support", "security_support", "end_of_life", "unknown"]],
  ["cve_status", "CVE status", ["potentially_affected", "not_affected_by_version", "insufficient_evidence", "none"]],
];
const STATUS_LABELS = {
  active_support: "Active support",
  security_support: "Security support",
  end_of_life: "End of life",
  potentially_affected: "Potential CVE",
  not_affected_by_version: "Not affected by reported version",
  insufficient_evidence: "Insufficient evidence",
  none: "No CVE candidates",
  unknown: "Unknown",
};

function timestamp(value) {
  if (!value) return "Unavailable";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString();
}

function readable(value) {
  return String(value || "")
    .replaceAll("_", " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

function displayStatus(value) {
  return STATUS_LABELS[value] || readable(value);
}

function statusClass(value) {
  return String(value || "unknown").toLowerCase().replaceAll("_", "-").replaceAll(" ", "-");
}

function unique(values) {
  return [...new Set(values.filter((value) => value !== null && value !== undefined && value !== ""))];
}

function lifecycleStatuses(observations) {
  return unique(observations.map((observation) => observation.lifecycle?.status)).map(displayStatus);
}

function versions(observations) {
  return unique(observations.map((observation) => observation.version));
}

function candidateLabel(candidate) {
  return displayStatus(candidate.applicability_status);
}

function DetailValue({ label, value }) {
  if (value === null || value === undefined || value === "") return null;
  return (
    <div className="adhoc-evidence-item">
      <span>{label}</span>
      <strong>{String(value)}</strong>
    </div>
  );
}

function CandidateDetails({ intelligence }) {
  const candidates = intelligence?.candidates || [];
  return (
    <div className="adhoc-cve-details">
      <div className="adhoc-detail-heading">CVE intelligence</div>
      <div className="adhoc-coverage-note">
        Coverage: {intelligence?.coverage ? readable(intelligence.coverage) : "Unavailable"}
        {intelligence?.dataset_revision && ` · dataset ${intelligence.dataset_revision}`}
      </div>
      {!candidates.length && <p className="adhoc-detail-empty">No local CVE candidates returned. This does not establish that no vulnerabilities exist.</p>}
      {candidates.map((candidate) => (
        <div className="adhoc-candidate" key={candidate.cve_id}>
          <div className="adhoc-candidate-heading">
            <strong>{candidate.cve_id}</strong>
            <span className={`technology-status technology-status-${statusClass(candidateLabel(candidate))}`}>
              {candidateLabel(candidate)}
            </span>
          </div>
          <div className="adhoc-evidence-grid">
            <DetailValue label="Affected range" value={candidate.affected_version_range} />
            <DetailValue label="Fixed version" value={candidate.fixed_version} />
            <DetailValue label="Evidence confidence" value={readable(candidate.evidence_confidence)} />
            <DetailValue label="Patch status" value={readable(candidate.patch_status)} />
            <DetailValue label="Explanation" value={readable(candidate.explanation_code)} />
            {candidate.source_url && (
              <div className="adhoc-evidence-item adhoc-evidence-wide">
                <span>Advisory source</span>
                <a href={candidate.source_url} target="_blank" rel="noreferrer">{candidate.source_url}</a>
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

function ObservationDetails({ observation }) {
  const lifecycle = observation.lifecycle || {};
  const intelligence = observation.cve_intelligence || {};
  return (
    <details className="adhoc-observation-details">
      <summary>Technical evidence</summary>
      <div className="adhoc-details-body">
        <div className="adhoc-detail-heading">Fingerprint</div>
        <div className="adhoc-evidence-grid">
          <DetailValue label="Reported PHP version" value={observation.version || "Version unavailable"} />
          <DetailValue label="Fingerprint confidence" value={readable(observation.confidence)} />
          <DetailValue label="Evidence type" value={observation.evidence_type} />
          <DetailValue label="Sanitized evidence" value={observation.sanitized_evidence} />
          <DetailValue label="Observed URL" value={observation.observed_url} />
          <DetailValue label="Detector version" value={observation.detector_version} />
          <DetailValue label="Persisted at" value={`${timestamp(observation.persisted_at)} (persistence time; not HTTP observation time)`} />
        </div>

        <div className="adhoc-detail-heading">Lifecycle</div>
        <div className="adhoc-evidence-grid">
          <DetailValue label="Support status" value={displayStatus(lifecycle.status)} />
          <DetailValue label="Assessment date" value={lifecycle.assessment_date} />
          <DetailValue label="Release branch" value={lifecycle.matched_release_branch} />
          <DetailValue label="Active support until" value={lifecycle.active_support_until} />
          <DetailValue label="Security support until" value={lifecycle.security_support_until} />
          <DetailValue label="End of life" value={lifecycle.end_of_life} />
          {lifecycle.source_url && (
            <div className="adhoc-evidence-item adhoc-evidence-wide">
              <span>Lifecycle source</span>
              <a href={lifecycle.source_url} target="_blank" rel="noreferrer">{lifecycle.source_url}</a>
            </div>
          )}
        </div>

        <CandidateDetails intelligence={intelligence} />
      </div>
    </details>
  );
}

function ResultTable({ results, authoritative }) {
  return (
    <div className="adhoc-table-wrap">
      <table className="adhoc-table">
        <thead>
          <tr><th>Asset</th><th>PHP version</th><th>Lifecycle</th><th>CVE status</th><th>Evidence</th></tr>
        </thead>
        <tbody>
          {results.map((result) => {
            const observations = result.observations || [];
            const versionValues = versions(observations);
            const lifecycleValues = lifecycleStatuses(observations);
            const asset = authoritative
              ? <a className="asset-domain-link" href={`#/assets/${encodeURIComponent(result.domain)}`}>{result.domain}</a>
              : <span className="technical-value">{result.domain}</span>;
            return (
              <tr key={`${result.scan_id}-${result.domain}`}>
                <td data-label="Asset">
                  {asset}
                  {result.legacy_php_lead && <span className="adhoc-legacy-indicator">Legacy evidence</span>}
                  <span className="asset-secondary">{authoritative ? "Current authoritative scan" : "Historical scan · current detail not linked"}</span>
                </td>
                <td data-label="PHP version" className="technical-value">
                  {versionValues.length ? versionValues.join(" / ") : "Version unavailable"}
                </td>
                <td data-label="Lifecycle">
                  {lifecycleValues.length ? lifecycleValues.join(" / ") : "Not assessed"}
                </td>
                <td data-label="CVE status">
                  <span className={`technology-status technology-status-${statusClass(result.classification)}`}>
                    {result.classification}
                  </span>
                </td>
                <td data-label="Evidence">
                  <span className="asset-secondary adhoc-evidence-summary">
                    {observations.length ? `${observations.length} structured observation${observations.length === 1 ? "" : "s"}` : "No structured observation"}
                  </span>
                  {observations.map((observation, index) => (
                    <ObservationDetails key={`${observation.detector_version || "detector"}-${observation.persisted_at || index}`} observation={observation} />
                  ))}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function FilterControl({ name, label, values, value, onChange }) {
  return (
    <label className="adhoc-filter-control">
      <span>{label}</span>
      <select aria-label={label} name={name} value={value} onChange={onChange}>
        <option value="">All</option>
        {values.map((option) => (
          <option value={option} key={option}>{name === "classification" ? option : displayStatus(option)}</option>
        ))}
      </select>
    </label>
  );
}

export default function AdhocChecksPage() {
  const [scanState, setScanState] = useState("loading");
  const [scanData, setScanData] = useState(null);
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [scanRequestVersion, setScanRequestVersion] = useState(0);
  const [checkState, setCheckState] = useState("idle");
  const [checkData, setCheckData] = useState(null);
  const [checkRequestVersion, setCheckRequestVersion] = useState(0);
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState({ classification: "", lifecycle: "", cve_status: "" });

  useEffect(() => {
    let active = true;
    setScanState("loading");
    getV2Scans(100)
      .then((result) => {
        if (!active) return;
        setScanData(result);
        const successful = (result.scans || []).filter((scan) => scan.status === "SUCCEEDED");
        const current = successful.find((scan) => scan.scan_id === result.current_authoritative_scan_id);
        setSelectedScanId(current?.scan_id ?? successful[0]?.scan_id ?? null);
        setScanState("ready");
      })
      .catch(() => { if (active) setScanState("error"); });
    return () => { active = false; };
  }, [scanRequestVersion]);

  useEffect(() => {
    if (selectedScanId == null) return undefined;
    let active = true;
    setCheckState("loading");
    setCheckData(null);
    const params = { scan_id: selectedScanId, page, limit: RESULT_LIMIT };
    Object.entries(filters).forEach(([key, value]) => {
      if (value) params[key] = value;
    });
    getPhpRceCheck(params)
      .then((result) => { if (active) { setCheckData(result); setCheckState("ready"); } })
      .catch(() => { if (active) setCheckState("error"); });
    return () => { active = false; };
  }, [checkRequestVersion, filters, page, selectedScanId]);

  const successfulScans = useMemo(
    () => (scanData?.scans || []).filter((scan) => scan.status === "SUCCEEDED"),
    [scanData],
  );
  const selectedScan = successfulScans.find((scan) => scan.scan_id === selectedScanId);
  const resultRows = checkData?.results || [];
  const totalPages = Math.max(Math.ceil((checkData?.count || 0) / RESULT_LIMIT), 1);

  const updateFilter = (event) => {
    setFilters((current) => ({ ...current, [event.target.name]: event.target.value }));
    setPage(1);
  };
  const changeScan = (event) => {
    setSelectedScanId(Number(event.target.value));
    setPage(1);
  };
  const retryCheck = () => setCheckRequestVersion((value) => value + 1);

  if (scanState === "loading") return <LoadingState title="Loading Adhoc Checks" copy="Retrieving successful scan history before loading the PHP review." />;
  if (scanState === "error") return <ErrorState title="Adhoc Checks unavailable" copy="Successful scan history could not be loaded. No review population has been inferred." onRetry={() => setScanRequestVersion((value) => value + 1)} />;
  if (!successfulScans.length) return <EmptyState title="No successful scans" copy="PHP RCE review is available only for completed successful scans." />;

  const selectedAuthoritative = checkData?.scan?.authoritative ?? selectedScanId === scanData?.current_authoritative_scan_id;
  const scope = checkData?.scope;
  const hasAuthorizedAssets = scope?.authorized_assets > 0;
  const hasEvaluatedAssets = scope?.evaluated_assets > 0;
  const noFilteredResults = checkState === "ready" && checkData?.count === 0;

  return (
    <div className="adhoc-workspace">
      <section className="adhoc-scan-toolbar">
        <div>
          <div className="adhoc-kicker">PHP Remote Code Execution</div>
          <h2>Targeted vulnerability review</h2>
          <p>Offline intelligence from authorized scan observations. This workspace does not execute probes or confirm exploitability.</p>
        </div>
        <label className="adhoc-scan-select">
          <span>Successful scan</span>
          <select aria-label="Successful scan" value={selectedScanId || ""} onChange={changeScan}>
            {successfulScans.map((scan) => (
              <option value={scan.scan_id} key={scan.scan_id}>
                #{scan.scan_id} · {scan.scan_id === scanData.current_authoritative_scan_id ? "Current authoritative" : "Historical successful"}
              </option>
            ))}
          </select>
        </label>
      </section>

      <section className="adhoc-scan-context">
        <div><span>Selected scan</span><strong>#{checkData?.scan?.scan_id || selectedScanId}</strong></div>
        <div><span>Completion</span><strong>{timestamp(checkData?.scan?.completed_at || selectedScan?.completed_at)}</strong></div>
        <div><span>Authority</span><strong>{selectedAuthoritative ? "Current authoritative" : "Historical successful"}</strong></div>
        <p>Historical results remain tied to their selected scan. Asset Detail links are available only for the current authoritative scan.</p>
      </section>

      <section className="operations-kpis" aria-label="PHP review scope">
        <MetricCard label="Scan members" value={scope?.scan_members ?? "—"} support="Selected successful scan" accent="#64748b" />
        <MetricCard label="Authorized assets" value={scope?.authorized_assets ?? "—"} support="Confirmed · scannable · manual" accent="#4655a6" />
        <MetricCard label="Evaluated assets" value={scope?.evaluated_assets ?? "—"} support="Structured PHP observations" accent="#2f7d5b" />
        <MetricCard label="Not evaluated" value={scope?.not_evaluated_assets ?? "—"} support="No structured PHP observation" accent="#a96f1f" />
      </section>

      <div className="adhoc-boundary-note">
        Potential CVE is a reported-version candidate from the local advisory dataset. It is not a confirmed vulnerability, installed-runtime verification, or exploitability result. Partial coverage and unknown patch status remain explicit.
      </div>

      <form className="adhoc-filter-panel" onSubmit={(event) => event.preventDefault()}>
        <div className="adhoc-filter-grid">
          {FILTERS.map(([name, label, values]) => (
            <FilterControl key={name} name={name} label={label} values={values} value={filters[name]} onChange={updateFilter} />
          ))}
        </div>
        <div className="adhoc-filter-meta">
          <span>Server-side filters · page {page} of {totalPages}</span>
          {(filters.classification || filters.lifecycle || filters.cve_status) && <Button type="button" size="small" variant="text" onClick={() => { setFilters({ classification: "", lifecycle: "", cve_status: "" }); setPage(1); }}>Clear filters</Button>}
        </div>
      </form>

      {checkState === "loading" && <LoadingState title="Loading PHP review" copy="Applying the selected scan and server-side filters." />}
      {checkState === "error" && <ErrorState title="PHP RCE review unavailable" copy="The selected scan review could not be loaded. No values have been inferred." onRetry={retryCheck} />}
      {checkState === "ready" && !hasAuthorizedAssets && (
        <Panel title="No authorized assets in selected scan" subtitle="The review population is empty because the exact authorization predicate returned no assets.">
          <div className="adhoc-empty-copy"><strong>{scope?.scan_members ?? 0} scan members</strong><span>0 authorized assets · 0 structured observations evaluated</span><p>Candidate and External assets are excluded. Zero authorized assets is not evidence of safety or of no PHP exposure.</p></div>
        </Panel>
      )}
      {checkState === "ready" && hasAuthorizedAssets && !hasEvaluatedAssets && (
        <Panel title="No structured PHP observations" subtitle="Authorized assets exist, but this selected scan has no persisted structured PHP observations.">
          <div className="adhoc-empty-copy"><strong>{scope.authorized_assets} authorized assets</strong><span>No structured observations were returned for this scan.</span><p>Legacy PHP labels remain visible in the results table as evidence-only leads without version or CVE applicability.</p></div>
        </Panel>
      )}
      {checkState === "ready" && hasAuthorizedAssets && hasEvaluatedAssets && noFilteredResults && (
        <EmptyState title="No matching filtered results" copy="No authorized results matched the selected classification, lifecycle, and CVE status filters. This does not establish that no vulnerabilities exist." />
      )}
      {checkState === "ready" && resultRows.length > 0 && (
        <Panel title="PHP review results" subtitle="Evidence remains observation-based; statuses do not confirm installation or exploitability." meta={`${checkData.count} MATCHING RESULTS`}>
          <ResultTable results={resultRows} authoritative={selectedAuthoritative} />
        </Panel>
      )}

      {checkState === "ready" && checkData?.count > 0 && (
        <div className="pagination-bar">
          <span>Page {page} of {totalPages} · {checkData.count} server-filtered results</span>
          <div>
            <Button size="small" variant="outlined" disabled={page <= 1} onClick={() => setPage((value) => value - 1)}>Previous</Button>
            <Button size="small" variant="outlined" disabled={page >= totalPages} onClick={() => setPage((value) => value + 1)}>Next</Button>
          </div>
        </div>
      )}
    </div>
  );
}
