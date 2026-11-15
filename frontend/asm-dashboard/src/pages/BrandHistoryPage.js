import React, { useEffect, useState } from "react";
import { Button, MenuItem, TextField } from "@mui/material";
import { getBrandHistoryAssets, getBrandHistoryDetail } from "../services/api";
import { EmptyState, ErrorState, LoadingState } from "../components/ui/AsyncState";
import StatusBadge from "../components/ui/StatusBadge";
import SortableHeader from "../components/ui/SortableHeader";

const LIMIT = 25;
const CLASSES = ["NEEDS_VERIFICATION", "KNOWN", "SHADOW", "UNKNOWN"];
const LABELS = { NEEDS_VERIFICATION: "Needs Verification", KNOWN: "Known", SHADOW: "Shadow", UNKNOWN: "Unknown" };

function readQuery(query) {
  const params = new URLSearchParams(query);
  return {
    from: params.get("from") === "overview" ? "overview" : "brand",
    classification: CLASSES.includes(params.get("classification")) ? params.get("classification") : "",
    search: params.get("search") || "",
    page: Math.max(Number(params.get("page")) || 1, 1),
    sort_by: ["domain", "first_seen", "last_seen"].includes(params.get("sort_by")) ? params.get("sort_by") : "domain",
    sort_dir: params.get("sort_dir") === "desc" ? "desc" : "asc",
  };
}

function listHref(values) {
  const params = new URLSearchParams({ from: values.from });
  if (values.classification) params.set("classification", values.classification);
  if (values.search) params.set("search", values.search);
  if (values.page > 1) params.set("page", String(values.page));
  if (values.sort_by !== "domain") params.set("sort_by", values.sort_by);
  if (values.sort_dir !== "asc") params.set("sort_dir", values.sort_dir);
  return `#/brand/history?${params}`;
}

function HistoryDetail({ domain, query }) {
  const [data, setData] = useState(null);
  const [status, setStatus] = useState("loading");
  const [retry, setRetry] = useState(0);
  const returnQuery = new URLSearchParams(query).get("return_query") || query;
  const backHref = listHref(readQuery(returnQuery));
  useEffect(() => {
    let active = true;
    setStatus("loading");
    getBrandHistoryDetail(domain).then((result) => {
      if (active) { setData(result); setStatus("ready"); }
    }).catch(() => { if (active) setStatus("error"); });
    return () => { active = false; };
  }, [domain, retry]);
  if (status === "loading") return <LoadingState title="Loading historical asset" />;
  if (status === "error") return <ErrorState title="Historical asset unavailable" onRetry={() => setRetry((value) => value + 1)} />;
  const evidence = data.detail_availability === "AVAILABLE" ? data.detail : null;
  return <div className="brand-history-page">
    <Button component="a" href={backHref} variant="text">← Back to Brand discovery</Button>
    <section className="panel"><header className="panel-header"><div><h2 className="panel-title">{data.domain}</h2></div><div className="scan-context">Retained history</div></header>
      <div className="panel-body brand-history-detail">
        <div><span>Review class</span><StatusBadge value={LABELS[data.review_class] || data.review_class} /></div>
        <div><span>First brand evidence</span><strong>Scan #{data.first_evidence_scan_id}</strong></div>
        <div><span>Last brand evidence</span><strong>Scan #{data.last_evidence_scan_id}</strong></div>
        <div><span>Retained scans</span><strong>{data.retained_scan_count}</strong></div>
        <div><span>Discovery sources</span><strong>{Array.isArray(data.discovery_sources) ? data.discovery_sources.join(", ") : "Unavailable"}</strong></div>
        <div><span>Asset evidence</span><strong>{evidence ? `Scan #${data.detail_evidence_scan_id} · ${data.detail_evidence_scan_status}` : "Unavailable"}</strong></div>
        {evidence?.dns?.ip && <div><span>Observed IP</span><strong>{evidence.dns.ip}</strong></div>}
        {evidence?.http?.observation_status && <div><span>HTTP observation</span><strong>{evidence.http.observation_status}{evidence.http.status != null ? ` · ${evidence.http.status}` : ""}</strong></div>}
      </div>
    </section>
    {data.current_scan_member && <Button component="a" href={`#/assets/${encodeURIComponent(data.domain)}?${new URLSearchParams({ return: "brand/history", return_query: returnQuery })}`} variant="outlined">Open current asset detail</Button>}
    <p className="brand-history-limitation">{data.limitation}</p>
  </div>;
}

export default function BrandHistoryPage({ query = "", domain = null }) {
  const applied = readQuery(query);
  const [draft, setDraft] = useState(applied.search);
  const [data, setData] = useState(null);
  const [status, setStatus] = useState("loading");
  const [retry, setRetry] = useState(0);
  useEffect(() => setDraft(applied.search), [applied.search]);
  useEffect(() => {
    if (domain) return undefined;
    let active = true;
    setStatus("loading");
    getBrandHistoryAssets({ page: applied.page, limit: LIMIT, classification: applied.classification || undefined,
      search: applied.search || undefined, sort_by: applied.sort_by, sort_dir: applied.sort_dir }).then((result) => {
      if (active) { setData(result); setStatus("ready"); }
    }).catch(() => { if (active) setStatus("error"); });
    return () => { active = false; };
  }, [domain, applied.classification, applied.page, applied.search, applied.sort_by, applied.sort_dir, retry]);
  if (domain) return <HistoryDetail domain={domain} query={query} />;
  const change = (next) => { window.location.hash = listHref({ ...applied, ...next }); };
  const totalPages = Math.max(Math.ceil((data?.count || 0) / LIMIT), 1);
  return <div className="brand-history-page">
    <Button component="a" href={`#/${applied.from}`} variant="text">← Back to {applied.from === "overview" ? "Overview" : "Brand Exposure"}</Button>
    <section className="panel"><header className="panel-header"><div><h2 className="panel-title">Brand discovery history</h2></div><div className="scan-context" title="Earlier or deleted source evidence cannot be reconstructed.">Retained history</div></header>
      <div className="panel-body">
        <form className="brand-history-filters" onSubmit={(event) => { event.preventDefault(); change({ search: draft, page: 1 }); }}>
          <TextField size="small" label="Search domain" value={draft} onChange={(event) => setDraft(event.target.value)} />
          <TextField size="small" select label="Review class" value={applied.classification} onChange={(event) => change({ classification: event.target.value, page: 1 })}>
            <MenuItem value="">All classes</MenuItem>{CLASSES.map((key) => <MenuItem value={key} key={key}>{LABELS[key]}</MenuItem>)}
          </TextField>
          <Button size="small" type="submit" variant="contained">Search</Button>
          <Button size="small" type="button" disabled={!applied.classification && !applied.search} onClick={() => { setDraft(""); change({ classification: "", search: "", page: 1 }); }}>Clear filter</Button>
        </form>
        {status === "loading" ? <LoadingState title="Loading historical brand assets" /> : status === "error" ? <ErrorState title="Historical brand assets unavailable" onRetry={() => setRetry((value) => value + 1)} /> : data?.assets?.length ? <>
          <div className="dense-table-wrap"><table className="dense-table"><thead><tr>
            <SortableHeader label="Domain" field="domain" sortBy={applied.sort_by} sortDir={applied.sort_dir} onSort={(field) => change({ sort_by: field, sort_dir: applied.sort_by === field ? (applied.sort_dir === "asc" ? "desc" : "asc") : "asc", page: 1 })} />
            <th>Review class</th>
            <SortableHeader label="First evidence" field="first_seen" sortBy={applied.sort_by} sortDir={applied.sort_dir} onSort={(field) => change({ sort_by: field, sort_dir: applied.sort_by === field ? (applied.sort_dir === "asc" ? "desc" : "asc") : "asc", page: 1 })} />
            <SortableHeader label="Last evidence" field="last_seen" sortBy={applied.sort_by} sortDir={applied.sort_dir} onSort={(field) => change({ sort_by: field, sort_dir: applied.sort_by === field ? (applied.sort_dir === "asc" ? "desc" : "asc") : "desc", page: 1 })} />
            <th /></tr></thead><tbody>{data.assets.map((asset) => {
            const params = new URLSearchParams({ return_query: new URLSearchParams(query).toString() || `from=${applied.from}` });
            const href = `#/brand/history/${encodeURIComponent(asset.identity)}?${params}`;
            return <tr key={asset.identity}><td><a href={href}>{asset.domain}</a></td><td><StatusBadge value={LABELS[asset.review_class] || asset.review_class} /></td><td>Scan #{asset.first_evidence_scan_id}</td><td>Scan #{asset.last_evidence_scan_id}</td><td><a className="row-action" href={href} aria-label={`Open historical ${asset.domain}`}>→</a></td></tr>;
          })}</tbody></table></div>
          <div className="pagination-bar"><span>Page {applied.page} of {totalPages} · {data.count} matching</span><div><Button size="small" variant="outlined" disabled={applied.page <= 1} onClick={() => change({ page: applied.page - 1 })}>Previous</Button><Button size="small" variant="outlined" disabled={applied.page >= totalPages} onClick={() => change({ page: applied.page + 1 })}>Next</Button></div></div>
        </> : <EmptyState title="No historical brand assets match" />}
      </div>
    </section>
  </div>;
}
