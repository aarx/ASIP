import React, { useEffect, useState } from "react";
import { exportV2ScanReport, getV2Overview, getV2ScanDetail, getV2Scans } from "../services/api";
import MetricCard from "../components/ui/MetricCard";
import Panel from "../components/ui/Panel";
import StatusBadge from "../components/ui/StatusBadge";
import { EmptyState, ErrorState, LoadingState } from "../components/ui/AsyncState";
import { downloadBlobResponse, downloadErrorKind } from "../utils/download";

function timestamp(value) {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString();
}

function duration(value) {
  if (value === null || value === undefined || !Number.isFinite(Number(value))) return "—";
  const seconds = Math.max(Number(value), 0);
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const minutes = Math.floor(seconds / 60);
  const remainder = Math.round(seconds % 60);
  return `${minutes}m ${remainder}s`;
}

function detailValue(value) {
  return value === null || value === undefined || value === "" ? "Unavailable" : value;
}

function reportFeedback(status) {
  if (status === "loading") return { text: "Downloading…", role: "status" };
  if (status === "ready") return { text: "Download started", role: "status" };
  if (status === "not-found") return { text: "Scan report not found.", role: "alert" };
  if (status === "unavailable") return { text: "Report unavailable for this scan.", role: "alert" };
  if (status === "error") return { text: "Report download failed.", role: "alert" };
  return null;
}

const STAGE_STATUSES = new Set(["RUNNING", "SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELLED"]);

function stageAttemptsState(value) {
  if (!Array.isArray(value)) return { attempts: [], usable: false };
  const attempts = value.filter((attempt) => attempt && typeof attempt === "object");
  const usable = attempts.length === value.length && attempts.every((attempt) => (
    typeof attempt.stage === "string"
    && attempt.stage.trim() !== ""
    && Number.isInteger(attempt.order)
    && Number.isInteger(attempt.attempt)
    && STAGE_STATUSES.has(attempt.status)
  ));
  return { attempts, usable };
}

function stageBreakdown(attempts) {
  const counts = { SUCCEEDED: 0, FAILED: 0, TIMED_OUT: 0, CANCELLED: 0, RUNNING: 0 };
  attempts.forEach((attempt) => {
    if (Object.prototype.hasOwnProperty.call(counts, attempt.status)) counts[attempt.status] += 1;
  });
  return counts;
}

function stageOutcomeSummary(attempts) {
  const finalStages = new Map();
  for (const attempt of attempts) {
    const key = `${attempt.order}:${attempt.stage}`;
    const previous = finalStages.get(key);
    if (previous && previous.attempt === attempt.attempt) return null;
    if (!previous || attempt.attempt > previous.attempt) finalStages.set(key, attempt);
  }
  return {
    label: "stages",
    counts: stageBreakdown([...finalStages.values()]),
  };
}

function retryCount(attempts) {
  if (!attempts.every((attempt) => Number.isInteger(attempt.attempt))) return null;
  return attempts.filter((attempt) => attempt.attempt > 1).length;
}

function workerSummaryRows(attempts) {
  return attempts.flatMap((attempt, index) => Object.entries(attempt.worker_summary || {}).map(([key, value]) => ({
    key,
    value,
    stage: attempt.stage || `Attempt ${index + 1}`,
    attempt: attempt.attempt,
  })));
}

function workerSummaryValue(value) {
  if (value === null || value === undefined || value === "") return "Unavailable";
  if (typeof value === "string" || typeof value === "number") return String(value);
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (Array.isArray(value)) {
    if (!value.length) return "No observations";
    return (
      <ul className="scan-worker-observations">
        {value.map((item, index) => (
          <li key={index}>{workerSummaryValue(item)}</li>
        ))}
      </ul>
    );
  }
  if (typeof value === "object") {
    if (Number.isInteger(value.domain_id) && typeof value.status === "string") {
      return (
        <span>
          Domain #{value.domain_id} · {value.status}
          {typeof value.destination_ip === "string" ? ` · ${value.destination_ip}` : ""}
        </span>
      );
    }
    const entries = Object.entries(value);
    if (!entries.length) return "No details";
    return (
      <span className="scan-worker-object">
        {entries.map(([key, item]) => (
          <span key={key}>{key}: {workerSummaryValue(item)}</span>
        ))}
      </span>
    );
  }
  return "Unavailable";
}

function DiagnosticStat({ label, value }) {
  return (
    <div className="scan-diagnostic-stat">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function ScanDiagnostics({ detail }) {
  if (!detail.diagnostics_available) {
    return (
      <div className="scan-diagnostics-unavailable">
        <strong>Diagnostics unavailable</strong>
        <span>This scan has no persistent stage diagnostics.</span>
      </div>
    );
  }

  const attemptsState = stageAttemptsState(detail.stage_attempts);
  const attempts = attemptsState.attempts;
  const stageOutcomes = attemptsState.usable ? stageOutcomeSummary(attempts) : null;
  const breakdown = stageOutcomes?.counts;
  const retries = retryCount(attempts);
  const workerRows = workerSummaryRows(attempts);
  const eventRows = attempts.filter((attempt) => (
    ["FAILED", "TIMED_OUT", "CANCELLED"].includes(attempt.status) || attempt.error_category
  ));
  const retryRows = attempts.filter((attempt) => (
    (Number.isInteger(attempt.attempt) && attempt.attempt > 1) || attempt.status === "CANCELLED"
  ));
  const currentStage = detail.status === "RUNNING" ? detail.current_stage : null;
  const scopeKeys = ["authorization_skips", "failed_incomplete", "no_permitted_destinations", "no_permitted_destination"];
  const scopeRows = workerRows.filter((row) => scopeKeys.includes(row.key));

  return (
    <div className="scan-diagnostics">
      <div className="scan-detail-grid" aria-label="Scan diagnostics summary">
        <DiagnosticStat label="Status" value={<StatusBadge value={detail.status} />} />
        <DiagnosticStat label="Started" value={timestamp(detail.started_at || detail.scan_time)} />
        <DiagnosticStat label="Completed" value={timestamp(detail.completed_at)} />
        <DiagnosticStat label="Total duration" value={duration(detail.duration_seconds)} />
        <DiagnosticStat label="Assets" value={detailValue(detail.asset_count)} />
        <DiagnosticStat
          label="Current stage"
          value={currentStage ? detailValue(currentStage.stage) : detail.status === "RUNNING" ? "Unavailable" : "—"}
        />
        {stageOutcomes ? (
          <>
            <DiagnosticStat label="Completed stages" value={breakdown.SUCCEEDED} />
            <DiagnosticStat label="Failed stages" value={breakdown.FAILED + breakdown.TIMED_OUT + breakdown.CANCELLED} />
          </>
        ) : (
          <div className="scan-diagnostic-incomplete" role="status">
            <strong>Stage outcomes incomplete</strong>
            <span>Completed and failed stage counts are unavailable.</span>
          </div>
        )}
        <DiagnosticStat label="Retry attempts" value={retries === null ? "Unavailable" : retries} />
        {detail.status === "FAILED" && detail.failure_category && (
          <DiagnosticStat label="Failure category" value={detail.failure_category} />
        )}
      </div>

      <section className="scan-diagnostics-section" aria-labelledby={`scan-stage-heading-${detail.scan_id}`}>
        <h3 id={`scan-stage-heading-${detail.scan_id}`}>Stage breakdown</h3>
        {stageOutcomes ? (
          <div className="scan-stage-summary" aria-label={`Final ${stageOutcomes.label} outcome counts`}>
            <span>Completed {breakdown.SUCCEEDED}</span>
            <span>Failed {breakdown.FAILED}</span>
            <span>Timed out {breakdown.TIMED_OUT}</span>
            <span>Cancelled {breakdown.CANCELLED}</span>
            {breakdown.RUNNING > 0 && <span>Running {breakdown.RUNNING}</span>}
          </div>
        ) : (
          <p className="scan-diagnostics-empty">Stage outcome data is incomplete; no outcome counts are shown.</p>
        )}
        {attempts.length ? (
          <div className="dense-table-wrap">
            <table className="dense-table scan-stage-table">
              <thead><tr><th>Stage</th><th>Status</th><th>Attempt</th><th>Started</th><th>Completed</th><th>Duration</th><th>Result</th></tr></thead>
              <tbody>{attempts.map((attempt, index) => (
                <tr key={`${attempt.stage}-${attempt.order}-${attempt.attempt}-${index}`}>
                  <td><span className="technical-value">{detailValue(attempt.stage)}</span></td>
                  <td><StatusBadge value={attempt.status} /></td>
                  <td>{detailValue(attempt.attempt)}</td>
                  <td>{timestamp(attempt.started_at)}</td>
                  <td>{timestamp(attempt.completed_at)}</td>
                  <td>{duration(attempt.duration_seconds)}</td>
                  <td><span className="technical-value">{detailValue(attempt.error_category)}</span></td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        ) : <p className="scan-diagnostics-empty">No stage attempts returned.</p>}
      </section>

      <details className="scan-advanced-diagnostics">
        <summary>Advanced Diagnostics</summary>
        <div className="scan-advanced-body">
          <section className="scan-diagnostics-section">
            <h3>Worker summary counts</h3>
            {workerRows.length ? (
              <div className="scan-worker-summary">
                {workerRows.map((row, index) => (
                  <div className="scan-worker-row" key={`${row.stage}-${row.key}-${index}`}>
                    <span>{row.stage}{row.attempt ? ` · attempt ${row.attempt}` : ""}</span>
                    <strong>{row.key}</strong>
                    <b>{workerSummaryValue(row.value)}</b>
                  </div>
                ))}
              </div>
            ) : <p className="scan-diagnostics-empty">No worker summary counts returned.</p>}
          </section>

          <section className="scan-diagnostics-section">
            <h3>Timeouts and failures</h3>
            {eventRows.length ? (
              <div className="scan-event-list">
                {eventRows.map((attempt, index) => (
                  <div className="scan-event-row" key={`${attempt.stage}-${attempt.attempt}-${index}`}>
                    <StatusBadge value={attempt.status} />
                    <span>{detailValue(attempt.stage)} · attempt {detailValue(attempt.attempt)}</span>
                    <strong>{detailValue(attempt.error_category)}</strong>
                  </div>
                ))}
              </div>
            ) : <p className="scan-diagnostics-empty">No timeout or failure records returned.</p>}
          </section>

          <section className="scan-diagnostics-section">
            <h3>Authorization skips and partial work</h3>
            {scopeRows.length ? (
              <div className="scan-worker-summary">
                {scopeRows.map((row, index) => (
                  <div className="scan-worker-row" key={`${row.stage}-${row.key}-scope-${index}`}>
                    <span>{row.stage}</span>
                    <strong>{row.key}</strong>
                    <b>{row.value}</b>
                  </div>
                ))}
              </div>
            ) : <p className="scan-diagnostics-empty">No authorization skips or partial-work counters returned.</p>}
          </section>

          <section className="scan-diagnostics-section">
            <h3>Retry and cancellation details</h3>
            {retryRows.length ? (
              <div className="scan-event-list">
                {retryRows.map((attempt, index) => (
                  <div className="scan-event-row" key={`${attempt.stage}-retry-${attempt.attempt}-${index}`}>
                    <span>{detailValue(attempt.stage)} · attempt {detailValue(attempt.attempt)}</span>
                    <StatusBadge value={attempt.status} />
                    <strong>{detailValue(attempt.error_category)}</strong>
                  </div>
                ))}
              </div>
            ) : <p className="scan-diagnostics-empty">No retry or cancellation records returned.</p>}
          </section>

          {detail.scan_outcome && (
            <div className="scan-outcome">
              <span>Scan outcome</span>
              <StatusBadge value={detail.scan_outcome.status} />
              {detail.scan_outcome.error_category !== detail.failure_category && (
                <strong>{detailValue(detail.scan_outcome.error_category)}</strong>
              )}
              <span>{timestamp(detail.scan_outcome.completed_at)}</span>
            </div>
          )}
          {detail.diagnostics_last_updated_at && (
            <p className="scan-diagnostics-updated">Last updated {timestamp(detail.diagnostics_last_updated_at)}</p>
          )}
        </div>
      </details>
    </div>
  );
}

function ScanDetail({ detail, status, onRetry }) {
  if (status === "loading") return <div className="scan-detail-state" role="status">Loading diagnostics…</div>;
  if (status === "error") {
    return (
      <div className="scan-detail-state" role="alert">
        <span>Diagnostics could not be loaded.</span>
        <button type="button" className="scan-detail-retry" onClick={onRetry}>Retry</button>
      </div>
    );
  }
  return <ScanDiagnostics detail={detail} />;
}

export default function ScanCentrePage() {
  const [data, setData] = useState(null);
  const [status, setStatus] = useState("loading");
  const [requestVersion, setRequestVersion] = useState(0);
  const [expandedScanId, setExpandedScanId] = useState(null);
  const [details, setDetails] = useState({});
  const [detailStatuses, setDetailStatuses] = useState({});
  const [reportDownloads, setReportDownloads] = useState({});

  useEffect(() => {
    let active = true;
    setStatus("loading");
    Promise.all([getV2Scans(100), getV2Overview()])
      .then(([scans, overview]) => {
        if (active) { setData({ scans, overview }); setStatus("ready"); }
      })
      .catch(() => { if (active) setStatus("error"); });
    return () => { active = false; };
  }, [requestVersion]);

  const loadDetail = (scanId) => {
    setDetailStatuses((current) => ({ ...current, [scanId]: "loading" }));
    getV2ScanDetail(scanId)
      .then((detail) => {
        setDetails((current) => ({ ...current, [scanId]: detail }));
        setDetailStatuses((current) => ({ ...current, [scanId]: "ready" }));
      })
      .catch(() => setDetailStatuses((current) => ({ ...current, [scanId]: "error" })));
  };

  const toggleDetail = (scanId) => {
    if (expandedScanId === scanId) {
      setExpandedScanId(null);
      return;
    }
    setExpandedScanId(scanId);
    if (!details[scanId] && detailStatuses[scanId] !== "loading") loadDetail(scanId);
  };

  const downloadReport = async (scanId) => {
    if (reportDownloads[scanId]?.status === "loading") return;
    setReportDownloads((current) => ({ ...current, [scanId]: { status: "loading" } }));
    try {
      const response = await exportV2ScanReport(scanId);
      downloadBlobResponse(response, `asip_scan_${scanId}_report.zip`);
      setReportDownloads((current) => ({ ...current, [scanId]: { status: "ready" } }));
    } catch (error) {
      setReportDownloads((current) => ({ ...current, [scanId]: { status: downloadErrorKind(error) } }));
    }
  };

  if (status === "loading") return <LoadingState title="Loading scan history" copy="Retrieving lifecycle state and authoritative scan markers." />;
  if (status === "error") return <ErrorState title="Scan Centre unavailable" copy="Scan lifecycle history could not be loaded." onRetry={() => setRequestVersion((value) => value + 1)} />;
  if (!data.scans.scans.length) return <EmptyState title="No scan history" copy="No scans have been recorded." />;

  const { scans, overview } = data;
  return (
    <div className="scan-workspace">
      <section className="operations-kpis" aria-label="Scan status context">
        <MetricCard label="Current authoritative" value={scans.current_authoritative_scan_id ? `#${scans.current_authoritative_scan_id}` : "—"} support="Latest SUCCEEDED scan" accent="#2f7d5b" />
        <MetricCard label="Previous baseline" value={scans.previous_authoritative_scan_id ? `#${scans.previous_authoritative_scan_id}` : "—"} support="Previous SUCCEEDED scan" accent="#64748b" />
        <MetricCard label="New assets" value={overview.changes?.new_assets ?? 0} support="Successful-scan comparison" accent="#4655a6" href="#/changes?view=new" />
        <MetricCard label="Disappeared" value={overview.changes?.disappeared_assets ?? 0} support="Successful-scan comparison" accent="#7e91a8" href="#/changes?view=disappeared" />
      </section>

      <Panel title="Scan history" subtitle="Lifecycle is explicit; only SUCCEEDED scans may be authoritative" meta={`${scans.scans.length} MOST RECENT`} className="scan-history-panel">
        <div className="dense-table-wrap">
          <table className="dense-table scan-table">
            <thead><tr><th>Scan</th><th>Lifecycle</th><th>Authority</th><th>Started</th><th>Completed</th><th>Duration</th><th>Assets</th><th>Seed</th><th>Report</th></tr></thead>
            <tbody>{scans.scans.map((scan) => {
              const isExpanded = expandedScanId === scan.scan_id;
              return (
                <React.Fragment key={scan.scan_id}>
                  <tr className={isExpanded ? "scan-row-expanded" : ""}>
                    <td>
                      <button
                        type="button"
                        className="scan-expand-button"
                        aria-label={`${isExpanded ? "Collapse" : "Expand"} scan ${scan.scan_id}`}
                        aria-expanded={isExpanded}
                        aria-controls={`scan-detail-${scan.scan_id}`}
                        onClick={() => toggleDetail(scan.scan_id)}
                      >
                        <span className="scan-expand-icon" aria-hidden="true">{isExpanded ? "−" : "+"}</span>
                        <span className="scan-id">#{scan.scan_id}</span>
                      </button>
                    </td>
                    <td><StatusBadge value={scan.status} /></td>
                    <td>
                      {scan.is_current_authoritative && <span className="authority-marker current">Current authoritative</span>}
                      {scan.is_previous_authoritative && <span className="authority-marker previous">Previous baseline</span>}
                      {!scan.is_current_authoritative && !scan.is_previous_authoritative && <span className="not-applicable">Not authoritative</span>}
                    </td>
                    <td>{timestamp(scan.started_at || scan.scan_time)}</td>
                    <td>{timestamp(scan.completed_at)}</td>
                    <td><span className="technical-value">{duration(scan.duration_seconds)}</span></td>
                    <td><span className="risk-score">{detailValue(scan.asset_count)}</span></td>
                      <td><span className="technical-value">{scan.seed || "—"}</span></td>
                      <td>
                        {scan.status === "SUCCEEDED" ? (
                          <>
                            <button
                              type="button"
                              className="download-report-button"
                              aria-label={`Download report for scan ${scan.scan_id}`}
                              disabled={reportDownloads[scan.scan_id]?.status === "loading"}
                              onClick={() => downloadReport(scan.scan_id)}
                            >
                              {reportDownloads[scan.scan_id]?.status === "loading" ? "Downloading…" : "Download Report"}
                            </button>
                            {(() => {
                              const feedback = reportFeedback(reportDownloads[scan.scan_id]?.status);
                              return feedback ? <span className="download-feedback" role={feedback.role}>{feedback.text}</span> : null;
                            })()}
                          </>
                        ) : <span className="not-applicable">—</span>}
                      </td>
                  </tr>
                  {isExpanded && (
                    <tr className="scan-detail-row">
                      <td colSpan="9" id={`scan-detail-${scan.scan_id}`}>
                        <ScanDetail
                          detail={details[scan.scan_id]}
                          status={detailStatuses[scan.scan_id] || "loading"}
                          onRetry={() => loadDetail(scan.scan_id)}
                        />
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}</tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
