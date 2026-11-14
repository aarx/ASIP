import React, { useEffect, useRef, useState } from "react";
import AssetLink from "./AssetLink";
import Panel from "./Panel";
import { ErrorState, LoadingState } from "./AsyncState";
import { getSensitivePortHosts } from "../../services/api";

const PAGE_SIZE = 25;

function normalizeHostname(value) {
  return String(value || "").trim().toLowerCase().replace(/\.+$/, "");
}

function uniquePortEvidence(ports) {
  const seen = new Set();
  return (Array.isArray(ports) ? ports : []).filter((item) => {
    if (item?.port == null) return false;
    const key = JSON.stringify([item.port, item.service ?? null, item.source_risk ?? null, item.description ?? null, item.scan_id ?? null]);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function distinctPorts(ports) {
  return [...new Set(ports.map((item) => String(item.port)))].sort((left, right) => Number(left) - Number(right));
}

function highestSensitivity(ports) {
  const values = ports.map((item) => item.source_risk).filter((value) => Number.isFinite(Number(value)) && value !== null && value !== "");
  return values.length ? Math.max(...values.map(Number)) : null;
}

export default function SensitivePortsPanel() {
  const [data, setData] = useState(null);
  const [status, setStatus] = useState("loading");
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(PAGE_SIZE);
  const [expandedHost, setExpandedHost] = useState(null);
  const [requestVersion, setRequestVersion] = useState(0);
  const scanIdRef = useRef(null);

  useEffect(() => {
    let active = true;
    setStatus("loading");
    setData(null);
    setExpandedHost(null);
    getSensitivePortHosts({ page, limit, ...(scanIdRef.current ? { scan_id: scanIdRef.current } : {}) })
      .then((result) => {
        if (!active) return;
        if (!result || !Array.isArray(result.hosts) || !Number.isInteger(result.total) || !Number.isInteger(result.page) || !Number.isInteger(result.limit)
          || result.total < 0 || result.page !== page || result.limit !== limit || result.hosts.length > limit
          || result.hosts.some((host) => !host || host.domain_id == null || !normalizeHostname(host.hostname || host.domain) || !Array.isArray(host.ports))) {
          throw new Error("Invalid sensitive-port host response");
        }
        if (scanIdRef.current && result.scan_id !== scanIdRef.current) throw new Error("Sensitive-port scan changed during pagination");
        if (result.scan_id != null) scanIdRef.current = result.scan_id;
        setData(result);
        setStatus("ready");
      })
      .catch(() => { if (active) setStatus("error"); });
    return () => { active = false; };
  }, [page, limit, requestVersion]);

  const hosts = status === "ready" ? data.hosts : [];
  const total = status === "ready" ? data.total : null;
  const pageCount = total == null ? 1 : Math.max(1, Math.ceil(total / data.limit));
  const meta = status === "ready"
    ? `${total.toLocaleString()} HOSTS${data.scan_id ? ` · SCAN #${data.scan_id}` : ""}`
    : "HOSTS · COVERAGE UNKNOWN";

  return (
    <Panel title="Sensitive port observations" subtitle="Observed hosts · assessment coverage unknown" meta={meta} className="operation-panel-full">
      {status === "loading" && <LoadingState title="Loading sensitive-port hosts" copy="Retrieving recorded host observations." />}
      {status === "error" && <ErrorState title="Sensitive-port observations unavailable" copy="Host observations could not be loaded." onRetry={() => setRequestVersion((value) => value + 1)} />}
      {status === "ready" && hosts.length > 0 && (
        <>
          <div className="sensitive-host-list">
            {hosts.map((host) => {
              const hostname = normalizeHostname(host.hostname || host.domain);
              const evidence = uniquePortEvidence(host.ports);
              const ports = distinctPorts(evidence);
              const maximum = highestSensitivity(evidence);
              const expanded = expandedHost === host.domain_id;
              const detailId = `sensitive-port-evidence-${host.domain_id}`;
              return (
                <article className="sensitive-host-item" key={host.domain_id ?? hostname}>
                  <div className="sensitive-host-row">
                    <AssetLink domain={host.hostname || host.domain} returnTo="risk/security-review" returnQuery="tab=sensitive-ports" className="sensitive-host-link">
                      {hostname}
                    </AssetLink>
                    <div className="sensitive-port-chips" aria-label={`${ports.length} distinct ports`}>
                      {ports.map((port) => <span className="sensitive-port-chip" key={port}>{port}</span>)}
                      <span className="sensitive-port-count">{ports.length} {ports.length === 1 ? "port" : "ports"}</span>
                    </div>
                    <span className="sensitive-host-maximum">{maximum == null ? "Sensitivity unavailable" : `Highest sensitivity ${maximum}`}</span>
                    <button
                      type="button"
                      className="sensitive-port-expand"
                      aria-label={`${expanded ? "Collapse" : "Expand"} port evidence for ${hostname}`}
                      aria-expanded={expanded}
                      aria-controls={detailId}
                      onClick={() => setExpandedHost((current) => current === host.domain_id ? null : host.domain_id)}
                    >
                      {expanded ? "Hide details" : "Port details"}
                    </button>
                  </div>
                  {expanded && (
                    <div className="sensitive-port-evidence" id={detailId}>
                      <div className="sensitive-port-evidence-head" aria-hidden="true">
                        <span>Port</span><span>Service</span><span>Description</span><span>Sensitivity</span><span>Evidence scan</span>
                      </div>
                      {evidence.map((item, index) => (
                        <div className="sensitive-port-evidence-row" key={`${item.port}-${index}`}>
                          <strong>{item.port}</strong>
                          <span>{item.service || "Not recorded"}</span>
                          <span>{item.description || "Not recorded"}</span>
                          <span>{item.source_risk == null ? "Not recorded" : item.source_risk}</span>
                          <span>{item.scan_id == null ? "Not recorded" : `#${item.scan_id}`}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </article>
              );
            })}
          </div>
          {total > 0 && (
            <div className="pagination-bar sensitive-host-pagination">
              <span>Page {data.page} of {pageCount} · {total.toLocaleString()} observed hosts</span>
              <div>
                <label className="sensitive-host-page-size">Rows
                  <select aria-label="Sensitive-port hosts per page" value={limit} onChange={(event) => { setLimit(Number(event.target.value)); setPage(1); }}>
                    <option value={25}>25</option><option value={50}>50</option>
                  </select>
                </label>
                <button type="button" className="secondary-button" disabled={data.page <= 1} onClick={() => setPage((value) => value - 1)}>Previous</button>
                <button type="button" className="secondary-button" disabled={data.page >= pageCount} onClick={() => setPage((value) => value + 1)}>Next</button>
              </div>
            </div>
          )}
        </>
      )}
      {status === "ready" && hosts.length === 0 && (
        <div className="detail-empty">No positive port observations recorded · assessment coverage unknown.</div>
      )}
    </Panel>
  );
}
