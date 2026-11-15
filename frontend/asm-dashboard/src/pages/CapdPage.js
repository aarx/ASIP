import React, { useEffect, useMemo, useState } from "react";
import { getCapdChecks, getCapdRun, getCapdRunResults, getCapdRuns } from "../services/api";
import AssetLink from "../components/ui/AssetLink";
import Panel from "../components/ui/Panel";
import StatusBadge from "../components/ui/StatusBadge";
import SortableHeader from "../components/ui/SortableHeader";

const PAGE_SIZE = 20;
const RESULT_STATUSES = ["POTENTIAL_MATCH", "INSUFFICIENT_EVIDENCE", "NOT_APPLICABLE", "UNSUPPORTED", "ERROR"];

function paramsFrom(query) {
  return new URLSearchParams(query || "");
}

function href(values = {}) {
  const query = new URLSearchParams();
  Object.entries(values).forEach(([key, value]) => {
    if (value !== null && value !== undefined && value !== "") query.set(key, value);
  });
  return `#/capd${query.toString() ? `?${query}` : ""}`;
}

function pageHref(current, key, value) {
  const next = Object.fromEntries(current.entries());
  next[key] = value;
  if (key === "run_page" || key === "result_status") next.result_page = 1;
  if (key === "result_page") next.result_page = value;
  return href(next);
}

function dateLabel(value) {
  if (!value) return "Unavailable";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

function human(value) {
  if (value === null || value === undefined || value === "") return "Not recorded";
  return String(value).replaceAll("_", " ").toLowerCase().replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function errorText(error) {
  return error?.response?.data?.detail || error?.message || "The CAPD request failed.";
}

function safeAdvisoryUrl(value) {
  try { return new URL(value).protocol === "https:" ? value : null; } catch (_) { return null; }
}

function Loading() { return <div className="capd-state" role="status">Loading CAPD evidence…</div>; }
function Failure({ error, retry }) {
  return <div className="capd-state capd-error" role="alert"><span>{errorText(error)}</span><button type="button" onClick={retry}>Retry</button></div>;
}

function DefinitionDetails({ check }) {
  if (!check) return null;
  return (
    <div className="capd-definition-grid">
      <div><span>Product</span><strong>{[check.vendor, check.product].filter(Boolean).join(" · ") || "Not recorded"}</strong></div>
      <div><span>Platform / category</span><strong>{[check.platform, check.category].filter(Boolean).join(" · ") || "Not recorded"}</strong></div>
      <div><span>Signature revision</span><strong>{check.check_revision || "Not recorded"}</strong></div>
      <div><span>Version scheme</span><strong>{check.version_scheme || "Not recorded"}</strong></div>
      <div className="capd-wide"><span>Affected version ranges</span>
        {Array.isArray(check.affected_ranges) && check.affected_ranges.length ? (
          <ul>{check.affected_ranges.map((range, index) => (
            <li key={`${range.branch || "range"}-${index}`}>{range.branch || "Branch unknown"}{range.introduced ? ` from ${range.introduced}` : ""}{range.fixed ? ` until fixed in ${range.fixed}` : " · range details unavailable"}</li>
          ))}</ul>
        ) : <strong>Not recorded</strong>}
      </div>
      <div className="capd-wide"><span>Evidence requirements</span>
        <div className="capd-chip-list">
          {(check.required_evidence?.technology_labels || []).map((item) => <span key={`tech-${item}`}>{item}</span>)}
          {(check.required_evidence?.evidence_types || []).map((item) => <span key={`evidence-${item}`}>{human(item)}</span>)}
          {check.required_evidence?.minimum_detection_confidence && <span>Minimum confidence: {human(check.required_evidence.minimum_detection_confidence)}</span>}
          {!check.required_evidence && <strong>Not recorded</strong>}
        </div>
      </div>
      <div><span>Detection method</span><strong>{human(check.verification_method)}</strong></div>
      <div><span>Last reviewed</span><strong>{check.last_reviewed_at || "Not recorded"}</strong></div>
      {safeAdvisoryUrl(check.advisory_reference) && <div className="capd-wide"><span>Advisory reference</span><a href={safeAdvisoryUrl(check.advisory_reference)} target="_blank" rel="noreferrer">{check.advisory_reference}</a></div>}
      {Array.isArray(check.limitations) && check.limitations.length > 0 && <div className="capd-wide"><span>Limitations</span><ul>{check.limitations.map((item, i) => <li key={i}>{item}</li>)}</ul></div>}
    </div>
  );
}

function RunsTable({ runs, query, total, page, onPage, sortBy, sortDir, onSort }) {
  if (!runs.length) return <div className="capd-empty"><strong>No CAPD assessments yet.</strong><p>Assessment runs are created by an operator through the local CLI. The web interface is read-only.</p></div>;
  return <>
    <div className="capd-table-wrap"><table className="capd-table">
      <thead><tr><SortableHeader label="Run" field="run_id" sortBy={sortBy} sortDir={sortDir} onSort={onSort} /><SortableHeader label="Check" field="check_id" sortBy={sortBy} sortDir={sortDir} onSort={onSort} /><SortableHeader label="Inventory scan" field="source_scan_id" sortBy={sortBy} sortDir={sortDir} onSort={onSort} /><th>Mode</th><SortableHeader label="Status" field="status" sortBy={sortBy} sortDir={sortDir} onSort={onSort} /><SortableHeader label="Started" field="started_at" sortBy={sortBy} sortDir={sortDir} onSort={onSort} /><th>Targets / results</th></tr></thead>
      <tbody>{runs.map((run) => <tr key={run.run_id}>
        <td data-label="Run"><a href={href({ check_id: run.check_id, run_id: run.run_id })} className="capd-run-link">{String(run.run_id).slice(0, 8)}…</a><span className="capd-secondary">{run.run_id}</span></td>
        <td data-label="Check">{run.cve_id || run.check_id}<span className="capd-secondary">Revision {run.check_revision || "not recorded"}</span></td>
        <td data-label="Inventory scan">{run.source_scan_id ? `Scan #${run.source_scan_id}` : "Not recorded"}</td>
        <td data-label="Mode">{human(run.execution_mode)}</td>
        <td data-label="Status"><StatusBadge value={human(run.status)} /></td>
        <td data-label="Started">{dateLabel(run.started_at)}</td>
        <td data-label="Targets / results">{run.selected_target_count ?? "—"} selected · {Object.values(run.counts || {}).reduce((a, b) => a + (Number(b) || 0), 0)} results</td>
      </tr>)}</tbody>
    </table></div>
    <Pagination total={total} page={page} pageSize={PAGE_SIZE} onPage={onPage} label="assessment runs" />
  </>;
}

function Pagination({ total, page, pageSize, onPage, label }) {
  const pages = Math.max(1, Math.ceil((total || 0) / pageSize));
  return <div className="capd-pagination"><span>{total} {label} · page {page} of {pages}</span><div>
    <button type="button" disabled={page <= 1} onClick={() => onPage(page - 1)}>Previous</button>
    <button type="button" disabled={page >= pages} onClick={() => onPage(page + 1)}>Next</button>
  </div></div>;
}

function Evidence({ evidence }) {
  const items = Array.isArray(evidence) ? evidence : evidence && typeof evidence === "object" ? Object.entries(evidence).map(([key, value]) => ({ label: key, value })) : [];
  if (!items.length) return <span className="capd-secondary">No evidence details recorded</span>;
  return <details className="capd-evidence"><summary>View evidence ({items.length})</summary><dl>
    {items.map((item, index) => {
      const entries = item && typeof item === "object" && !Array.isArray(item) ? Object.entries(item) : [[`Evidence ${index + 1}`, item]];
      return entries.map(([key, value]) => <React.Fragment key={`${index}-${key}`}><dt>{human(key)}</dt><dd>{value === null || value === undefined ? "Not recorded" : typeof value === "object" ? Array.isArray(value) ? value.join(", ") : "Structured evidence available" : String(value)}</dd></React.Fragment>);
    })}
  </dl></details>;
}

function ResultsTable({ results, query, run, total, page, onPage, sortBy, sortDir, onSort }) {
  return <>
    <div className="capd-table-wrap"><table className="capd-table capd-results-table">
      <thead><tr><SortableHeader label="Asset" field="domain" sortBy={sortBy} sortDir={sortDir} onSort={onSort} /><SortableHeader label="Observed product / version" field="product" sortBy={sortBy} sortDir={sortDir} onSort={onSort} /><SortableHeader label="Assessment result" field="result_status" sortBy={sortBy} sortDir={sortDir} onSort={onSort} /><SortableHeader label="Confidence" field="confidence" sortBy={sortBy} sortDir={sortDir} onSort={onSort} /><th>Evidence</th></tr></thead>
      <tbody>{results.map((item) => <tr key={item.result_id}>
        <td data-label="Asset"><AssetLink domain={item.domain} returnTo="capd" returnQuery={query.toString()} /> <span className="capd-secondary">{item.asset_class || "Class unavailable"}</span><span className="capd-secondary">{run?.cve_id || run?.check_id || "Check unavailable"} · revision {run?.check_revision || "not recorded"} · {run?.source_scan_id ? `Scan #${run.source_scan_id}` : "source scan unavailable"}</span></td>
        <td data-label="Product / version">{item.product || "Product not established"}<span className="capd-secondary">{item.version || "Version unknown"}</span></td>
        <td data-label="Assessment result"><StatusBadge value={human(item.result_status)} /><span className="capd-secondary">{human(item.candidate_classification)}</span></td>
        <td data-label="Confidence">Detection: {human(item.detection_confidence)}<span className="capd-secondary">Match: {human(item.match_confidence)}</span></td>
        <td data-label="Evidence"><Evidence evidence={item.evidence} />{item.explanation && <p className="capd-explanation">{item.explanation}</p>}{item.limitations?.length > 0 && <details className="capd-evidence"><summary>Limitations</summary><ul>{item.limitations.map((limitation, index) => <li key={index}>{limitation}</li>)}</ul></details>}</td>
      </tr>)}</tbody>
    </table></div>
    {!results.length && <div className="capd-empty"><strong>No results in this status.</strong><p>An empty result set is not evidence that the selected inventory is free of vulnerabilities.</p></div>}
    {total > 0 && <Pagination total={total} page={page} pageSize={PAGE_SIZE} onPage={onPage} label="assessment results" />}
  </>;
}

function RelevanceSummary({ selection }) {
  const relevance = selection?.relevance;
  if (!relevance) return null;
  const metrics = [
    ["Eligible inventory", relevance.eligible_inventory_assets],
    ["Selected inventory", relevance.selected_inventory_assets],
    ["Product-matched", relevance.product_matched_candidate_assets],
    ["Service candidates", relevance.service_candidate_assets],
    ["Version-matched", relevance.version_matched_candidate_assets],
    ["Potential CVE matches", relevance.potential_cve_match_assets],
    ["No relevant product/service evidence", relevance.assets_without_relevant_product_or_service_evidence],
  ].filter(([, value]) => value !== null && value !== undefined);
  if (!metrics.length) return null;
  return <div className="capd-relevance"><h3>Target relevance breakdown</h3><div>{metrics.map(([label, value]) => <div key={label}><span>{label}</span><strong>{Number(value).toLocaleString()}</strong></div>)}</div><p>Counts are the run’s stored selection summary. Eligible inventory is not the same as CVE-relevant candidates.</p></div>;
}

export default function CapdPage({ query = "" }) {
  const params = useMemo(() => paramsFrom(query), [query]);
  const checkId = params.get("check_id");
  const runId = params.get("run_id");
  const runPage = Number(params.get("run_page") || 1);
  const resultPage = Number(params.get("result_page") || 1);
  const resultStatus = params.get("result_status") || "";
  const runSortBy = ["run_id", "check_id", "source_scan_id", "status", "started_at", "completed_at"].includes(params.get("run_sort_by")) ? params.get("run_sort_by") : "started_at";
  const runSortDir = ["asc", "desc"].includes(params.get("run_sort_dir")) ? params.get("run_sort_dir") : "desc";
  const resultSortBy = ["domain", "result_status", "product", "version", "confidence", "assessed_at"].includes(params.get("result_sort_by")) ? params.get("result_sort_by") : "domain";
  const resultSortDir = ["asc", "desc"].includes(params.get("result_sort_dir")) ? params.get("result_sort_dir") : "asc";
  const [checks, setChecks] = useState(null);
  const [checkError, setCheckError] = useState(null);
  const [runsData, setRunsData] = useState(null);
  const [runsError, setRunsError] = useState(null);
  const [runData, setRunData] = useState(null);
  const [runError, setRunError] = useState(null);
  const [resultsData, setResultsData] = useState(null);
  const [resultsError, setResultsError] = useState(null);
  const [reload, setReload] = useState(0);
  const retry = () => setReload((value) => value + 1);

  useEffect(() => {
    let live = true;
    setChecks(null); setCheckError(null);
    getCapdChecks().then((data) => { if (live) setChecks(data.checks || []); }).catch((error) => { if (live) setCheckError(error); });
    return () => { live = false; };
  }, [reload]);

  useEffect(() => {
    let live = true;
    setRunsData(null); setRunsError(null);
    const runSort = runSortBy === "started_at" && runSortDir === "desc" ? {} : { sort_by: runSortBy, sort_dir: runSortDir };
    getCapdRuns({ page: runPage, limit: PAGE_SIZE, ...runSort, ...(checkId ? { check_id: checkId } : {}) })
      .then((data) => { if (live) setRunsData(data); }).catch((error) => { if (live) setRunsError(error); });
    return () => { live = false; };
  }, [checkId, runPage, runSortBy, runSortDir, reload]);

  useEffect(() => {
    if (!runId) { setRunData(null); setRunError(null); setResultsData(null); setResultsError(null); return undefined; }
    let live = true;
    setRunData(null); setRunError(null); setResultsData(null); setResultsError(null);
    getCapdRun(runId).then((data) => { if (live) setRunData(data); }).catch((error) => { if (live) setRunError(error); });
    const resultSort = resultSortBy === "domain" && resultSortDir === "asc" ? {} : { sort_by: resultSortBy, sort_dir: resultSortDir };
    getCapdRunResults(runId, { page: resultPage, limit: PAGE_SIZE, ...resultSort, ...(resultStatus ? { result_status: resultStatus } : {}) })
      .then((data) => { if (live) setResultsData(data); }).catch((error) => { if (live) setResultsError(error); });
    return () => { live = false; };
  }, [runId, resultPage, resultStatus, resultSortBy, resultSortDir, reload]);

  const changeSort = (key, field, active, direction) => {
    const next = new URLSearchParams(params);
    next.set(`${key}_sort_by`, field);
    next.set(`${key}_sort_dir`, active ? (direction === "asc" ? "desc" : "asc") : (field === "domain" || field === "check_id" || field === "source_scan_id" ? "asc" : "desc"));
    next.set(key === "run" ? "run_page" : "result_page", "1");
    window.location.hash = href(Object.fromEntries(next.entries()));
  };

  const selectedCheck = checks?.find((item) => item.check_id === checkId);
  const potentialCount = resultsData?.results?.filter((item) => item.result_status === "POTENTIAL_MATCH").length || 0;
  const tableResults = resultsData?.results || [];
  const statusChange = (event) => { window.location.hash = pageHref(params, "result_status", event.target.value); };

  return <main className="capd-workspace">
    <div className="capd-boundary"><strong>Passive inventory assessment</strong><span>CAPD is separate from routine discovery. A potential version match is not a confirmed vulnerability. This workspace does not launch checks.</span></div>
    {checkError ? <Failure error={checkError} retry={retry} /> : checks === null ? <Loading /> : (
      <>
        <div className="capd-toolbar">
          <div><span className="capd-kicker">CVE check catalog</span><h2>{selectedCheck ? selectedCheck.cve_id : "Available checks"}</h2><p>{selectedCheck ? "Versioned detection definition and its assessment history." : `${checks.length} catalog check${checks.length === 1 ? "" : "s"} available.`}</p></div>
          {checkId && <a className="capd-back-link" href={href({})}>All CVE checks</a>}
        </div>
        {!selectedCheck && checkId && <div className="capd-state" role="alert">This check is not present in the current catalog.</div>}
        {!checkId && <Panel title="CVE Checks" subtitle="Catalog metadata describes detection scope; it does not establish an affected system." className="capd-panel">
          {checks.length ? <div className="capd-check-grid">{checks.map((check) => <a className="capd-check-card" href={href({ check_id: check.check_id })} key={check.check_id}>
            <div className="capd-check-top"><strong>{check.cve_id}</strong><StatusBadge value={check.enabled ? "Enabled" : "Disabled"} /></div>
            <span>{[check.vendor, check.product].filter(Boolean).join(" · ") || "Product unavailable"}</span>
            <small>Revision {check.check_revision || "not recorded"} · {human(check.category)}</small>
            <small>{check.affected_ranges?.length || 0} affected version branches · {human(check.verification_method)}</small>
          </a>)}</div> : <div className="capd-empty">No check definitions are available.</div>}
        </Panel>}
        {selectedCheck && <Panel title="Check definition" subtitle="A signature match is an indicator for review, not proof of vulnerability." className="capd-panel">
          <div className="capd-definition-head"><div><strong>{selectedCheck.cve_id}</strong><span>{selectedCheck.enabled ? "Enabled definition" : "Disabled definition"} · revision {selectedCheck.check_revision}</span></div><StatusBadge value={selectedCheck.coverage || "Coverage unavailable"} /></div>
          <DefinitionDetails check={selectedCheck} />
          {selectedCheck.coverage && <p className="capd-coverage-note">Catalog coverage: {human(selectedCheck.coverage)}. {selectedCheck.source_updated_at ? `Source updated ${selectedCheck.source_updated_at}.` : ""}</p>}
        </Panel>}
        {runsError ? <Failure error={runsError} retry={retry} /> : runsData === null ? <Loading /> : (
          <Panel title={selectedCheck ? "Assessment history" : "Recent assessment runs"} subtitle={selectedCheck ? `Runs for ${selectedCheck.cve_id}; inventory eligibility and CVE relevance are separate populations.` : "Persisted local CLI runs. No run history is synthesized from the check catalog."} className="capd-panel">
            {runsData.total === 0 && !runId ? <div className="capd-empty"><strong>No CAPD assessments yet.</strong><p>Assessments currently run from the local CLI. This interface is read-only.</p></div> : <RunsTable runs={runsData.runs || []} query={params} total={runsData.total || 0} page={runsData.page || runPage} onPage={(page) => { window.location.hash = pageHref(params, "run_page", page); }} sortBy={runSortBy} sortDir={runSortDir} onSort={(field) => changeSort("run", field, runSortBy === field, runSortDir)} />}
          </Panel>
        )}
        {runId && <>
          {runError ? <Failure error={runError} retry={retry} /> : runData === null ? <Loading /> : <Panel title="Assessment run" subtitle="Run provenance and target selection counts from the persisted run record." className="capd-panel">
            <div className="capd-definition-grid capd-run-context">
              <div><span>Run ID</span><strong>{runData.run_id}</strong></div><div><span>Check</span><strong>{runData.cve_id} · revision {runData.check_revision}</strong></div>
              <div><span>Source inventory scan</span><strong>{runData.source_scan_id ? `Scan #${runData.source_scan_id}` : "Not recorded"}</strong></div><div><span>Mode / status</span><strong>{human(runData.execution_mode)} · {human(runData.status)}</strong></div>
              <div><span>Started</span><strong>{dateLabel(runData.started_at)}</strong></div><div><span>Completed</span><strong>{dateLabel(runData.completed_at)}</strong></div>
              <div><span>Eligible / selected / skipped</span><strong>{runData.eligible_target_count ?? "—"} / {runData.selected_target_count ?? "—"} / {runData.skipped_target_count ?? "—"}</strong></div>
              <div><span>Result counts</span><strong>{Object.entries(runData.counts || {}).map(([key, value]) => `${human(key)} ${value}`).join(" · ") || "Not recorded"}</strong></div>
            </div>
            <RelevanceSummary selection={runData.selection_summary} />
          </Panel>}
          {resultsError ? <Failure error={resultsError} retry={retry} /> : resultsData === null ? <Loading /> : <Panel title="Assessment results" subtitle={`${potentialCount} potential match${potentialCount === 1 ? "" : "es"} on this returned page; ${resultsData.total} total matching results. A passive match requires independent validation.`} className="capd-panel">
            <div className="capd-result-toolbar"><label><span>Result view</span><select aria-label="Assessment result filter" value={resultStatus} onChange={statusChange}><option value="">All assessment results</option><option value="POTENTIAL_MATCH">Potential hosts only</option>{RESULT_STATUSES.filter((status) => status !== "POTENTIAL_MATCH").map((status) => <option value={status} key={status}>{human(status)}</option>)}</select></label><span>{resultsData.total} matching results</span></div>
            <ResultsTable results={tableResults} query={params} run={resultsData.run} total={resultsData.total || 0} page={resultsData.page || resultPage} onPage={(page) => { window.location.hash = pageHref(params, "result_page", page); }} sortBy={resultSortBy} sortDir={resultSortDir} onSort={(field) => changeSort("result", field, resultSortBy === field, resultSortDir)} />
          </Panel>}
        </>}
      </>
    )}
  </main>;
}
