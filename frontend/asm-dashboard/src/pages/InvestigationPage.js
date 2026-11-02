import React, { useEffect, useMemo, useRef, useState } from "react";
import { Button, TextField } from "@mui/material";
import { getInvestigationAssets, getV2AssetAssistant, getV2AssetDetail } from "../services/api";
import Panel from "../components/ui/Panel";
import StatusBadge from "../components/ui/StatusBadge";
import { EmptyState, ErrorState, LoadingState } from "../components/ui/AsyncState";
import { displayEvidence } from "../utils/presentation";

const LIMIT = 20;
const ACTIONS = [
  ["explain_risk", "Explain Risk"],
  ["investigation_plan", "Investigation Plan"],
  ["summarize_asset", "Summarize Asset"],
];

function selectedFromQuery(query) {
  return new URLSearchParams(query).get("domain") || "";
}

function detailReturnFromQuery(query) {
  return new URLSearchParams(query).get("detail_return") || "";
}

function investigationHash(domain) {
  return domain ? `#/investigate?domain=${encodeURIComponent(domain)}` : "#/investigate";
}

function cleanAIResponse(response) {
  return String(response || "")
    .replace(/\*\*(.*?)\*\*/g, "$1")
    .replace(/__(.*?)__/g, "$1")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/^#{1,6}\s+/gm, "")
    .trim();
}

function EvidenceItem({ label, children, mono = false }) {
  return <div className="investigation-evidence-item"><span>{label}</span><strong className={mono ? "technical-value" : ""}>{children}</strong></div>;
}

function AssetEvidence({ asset, detailHref }) {
  const risk = asset.risk;
  return (
    <div className="investigation-evidence">
      <section className="investigation-identity">
        <div><span className="identity-kicker">Authoritative ShadowRecon evidence</span><h2>{asset.domain}</h2></div>
        <div className="identity-badges"><StatusBadge value={asset.asset_class} /><StatusBadge value={asset.ownership_status} /><a className="context-link" href={detailHref}>Full Asset Detail</a></div>
        <div className="investigation-risk">
          {risk ? <><StatusBadge value={risk.priority} /><strong>{risk.score}</strong><div className="reason-list">{risk.reasons.map((reason) => <span className="reason-token" key={reason}>{reason.replaceAll("_", " ")}</span>)}</div></> : <span>No organizational canonical risk applies to {asset.ownership_status} assets.</span>}
        </div>
      </section>

      <div className="investigation-evidence-grid">
        <Panel title="Network & HTTP">
          <div className="investigation-facts">
            <EvidenceItem label="IP" mono>{displayEvidence(asset.dns?.ip, "No current IP evidence")}</EvidenceItem>
            <EvidenceItem label="Reverse DNS" mono>{displayEvidence(asset.dns?.reverse_dns, "Unknown")}</EvidenceItem>
            <EvidenceItem label="Provider">{displayEvidence(asset.provider, "Unknown")}</EvidenceItem>
            <EvidenceItem label="ASN" mono>{displayEvidence(asset.asn?.asn, "Unknown")}</EvidenceItem>
            <EvidenceItem label="HTTP observation"><StatusBadge value={asset.http?.observation_status} /></EvidenceItem>
            <EvidenceItem label="HTTP status" mono>{displayEvidence(asset.http?.status, "No status")}</EvidenceItem>
            <EvidenceItem label="Final destination" mono>{displayEvidence(asset.http?.final_url, "Not observed")}</EvidenceItem>
            <EvidenceItem label="Title">{displayEvidence(asset.http?.title, "Not observed")}</EvidenceItem>
          </div>
        </Panel>

        <Panel title="Exposure & technology">
          <span className="evidence-label">Observed ports</span>
          {asset.ports?.length ? <div className="port-list">{asset.ports.map((item) => <div className="port-token" key={`${item.port}-${item.service}`}><strong>{item.port}</strong><span>{item.service || "service unknown"}</span></div>)}</div> : <div className="detail-empty compact">No positive port evidence.</div>}
          <span className="evidence-label investigation-subheading">Technologies</span>
          {asset.technologies?.length ? <div className="technology-list">{asset.technologies.map((tech) => <span key={tech}>{tech}</span>)}</div> : <div className="detail-empty compact">No technology evidence.</div>}
          <span className="evidence-label investigation-subheading">Certificate</span>
          <div className="technical-value investigation-inline-fact">{asset.certificate ? `${displayEvidence(asset.certificate.status)} · expires ${displayEvidence(asset.certificate.expiry_date)}` : "No certificate evidence"}</div>
        </Panel>

        <Panel title="Findings">
          {asset.findings?.length ? <div className="finding-list">{asset.findings.map((finding, index) => <div className="finding-row" key={`${finding.finding}-${index}`}><StatusBadge value={finding.severity} /><div><strong>{finding.finding}</strong><p>{displayEvidence(finding.evidence, "No supporting text recorded")}</p></div></div>)}</div> : <div className="detail-empty compact">No findings recorded for this scan.</div>}
        </Panel>

        <Panel title="Discovery provenance">
          {asset.discovery?.sources?.length ? <div className="provenance-table">{asset.discovery.sources.map((item, index) => <div className="provenance-row" key={`${item.source}-${item.seed}-${index}`}><span className="technical-value">{displayEvidence(item.source)}</span><span className="technical-value">{displayEvidence(item.seed)}</span></div>)}</div> : <div className="detail-empty compact">No current-scan provenance rows.</div>}
        </Panel>
      </div>
    </div>
  );
}

export default function InvestigationPage({ query }) {
  const queryDomain = useMemo(() => selectedFromQuery(query), [query]);
  const detailReturn = useMemo(() => detailReturnFromQuery(query), [query]);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [list, setList] = useState(null);
  const [listStatus, setListStatus] = useState("loading");
  const [listVersion, setListVersion] = useState(0);
  const autoSelectionRef = useRef(false);
  const [asset, setAsset] = useState(null);
  const [assetStatus, setAssetStatus] = useState(queryDomain ? "loading" : "idle");
  const [assetVersion, setAssetVersion] = useState(0);
  const [assistant, setAssistant] = useState(null);
  const [assistantStatus, setAssistantStatus] = useState("idle");

  useEffect(() => {
    let active = true;
    setListStatus("loading");
    getInvestigationAssets(page, LIMIT, null)
      .then((result) => { if (active) { setList(result); setListStatus("ready"); } })
      .catch(() => { if (active) setListStatus("error"); });
    return () => { active = false; };
  }, [page, listVersion]);

  useEffect(() => {
    if (listStatus !== "ready" || queryDomain || autoSelectionRef.current) return;
    const firstAsset = (list?.assets || []).find((item) => item?.domain);
    if (!firstAsset) return;

    const currentQuery = window.location.hash.replace(/^#\/?/, "").split("?")[1] || "";
    if (selectedFromQuery(currentQuery)) return;

    autoSelectionRef.current = true;
    window.history.replaceState(window.history.state, "", investigationHash(firstAsset.domain));
    window.dispatchEvent(new HashChangeEvent("hashchange"));
  }, [listStatus, list, queryDomain]);

  useEffect(() => {
    let active = true;
    setAssistant(null);
    setAssistantStatus("idle");
    if (!queryDomain) {
      setAsset(null);
      setAssetStatus("idle");
      return () => { active = false; };
    }
    setAssetStatus("loading");
    getV2AssetDetail(queryDomain)
      .then((result) => {
        if (!active) return;
        if (result?.error) { setAsset(result); setAssetStatus("not-found"); }
        else { setAsset(result); setAssetStatus("ready"); }
      })
      .catch(() => { if (active) setAssetStatus("error"); });
    return () => { active = false; };
  }, [queryDomain, assetVersion]);

  const runAction = (action) => {
    setAssistant(null);
    setAssistantStatus("loading");
    getV2AssetAssistant(asset.domain, action)
      .then((result) => { setAssistant(result); setAssistantStatus("ready"); })
      .catch(() => { setAssistantStatus("error"); });
  };

  const filtered = (list?.assets || []).filter((item) => item.domain.toLowerCase().includes(search.trim().toLowerCase()));
  const pages = Math.max(Math.ceil((list?.count || 0) / LIMIT), 1);
  const defaultDetailReturn = new URLSearchParams({
    return: "investigate",
    return_query: `domain=${encodeURIComponent(queryDomain)}`,
  }).toString();
  const assetDetailHref = queryDomain
    ? `#/assets/${encodeURIComponent(queryDomain)}?${detailReturn || defaultDetailReturn}`
    : "#/assets";
  const openExact = (event) => {
    event.preventDefault();
    const domain = search.trim();
    if (domain) window.location.hash = investigationHash(domain);
  };

  return (
    <div className="investigation-workspace">
      <Panel title="Investigation queue" meta={list?.count != null ? `${list.count} ASSETS` : "CURRENT"} className="investigation-queue">
        <form className="investigation-search" onSubmit={openExact}>
          <TextField size="small" label="Search assets" value={search} onChange={(event) => setSearch(event.target.value)} />
          <Button type="submit" variant="outlined" disabled={!search.trim()}>Load exact</Button>
        </form>
        {listStatus === "loading" && <LoadingState title="Loading investigation assets" copy="Retrieving current authoritative organizational assets." />}
        {listStatus === "error" && <ErrorState title="Investigation queue unavailable" copy="The current investigation population could not be loaded." onRetry={() => setListVersion((value) => value + 1)} />}
        {listStatus === "ready" && list.count === 0 && <EmptyState className="state-card-compact" title="No investigation assets" copy="No confirmed resolving assets are available in the current authoritative scan." />}
        {listStatus === "ready" && list.count > 0 && (
          <div className="investigation-asset-list">
            {filtered.map((item) => <button className={`investigation-asset-option${queryDomain === item.domain ? " selected" : ""}`} type="button" key={item.domain} onClick={() => { window.location.hash = investigationHash(item.domain); }}><span>{item.domain}</span><small>{item.priority} · score {item.risk}</small></button>)}
            {!filtered.length && <div className="detail-empty">No domains on this page match the local search.</div>}
          </div>
        )}
        {listStatus === "ready" && list.count > 0 && <div className="pagination-bar"><span>Page {page} of {pages}</span><div><Button size="small" variant="outlined" disabled={page <= 1} onClick={() => setPage((value) => value - 1)}>Previous</Button><Button size="small" variant="outlined" disabled={page >= pages} onClick={() => setPage((value) => value + 1)}>Next</Button></div></div>}
      </Panel>

      <div className="investigation-main">
        {assetStatus === "idle" && <EmptyState className="state-card-compact" title="Select an asset to investigate" copy="Choose a current asset or load an exact current domain to review authoritative evidence and request grounded assistance." />}
        {assetStatus === "loading" && <LoadingState title="Loading authoritative evidence" copy="Retrieving the selected asset from the latest successful scan." />}
        {assetStatus === "error" && <ErrorState title="Asset evidence unavailable" copy="The selected asset evidence could not be loaded." onRetry={() => setAssetVersion((value) => value + 1)} />}
        {assetStatus === "not-found" && <EmptyState className="state-card-compact" title="Asset is not current" copy={asset?.error || "The domain is not in the latest authoritative scan."} />}
        {assetStatus === "ready" && <AssetEvidence asset={asset} detailHref={assetDetailHref} />}

        {assetStatus === "ready" && (
          <Panel title="Grounded AI Assistance" meta="AI · NOT EVIDENCE" className="investigation-assistant">
            <div className="assistant-actions">{ACTIONS.map(([action, label]) => <Button key={action} variant={assistant?.action === action ? "contained" : "outlined"} disabled={assistantStatus === "loading"} onClick={() => runAction(action)}>{label}</Button>)}</div>
            {assistantStatus === "loading" && <div className="assistant-progress" role="status">AI is reviewing supplied ShadowRecon evidence…</div>}
            {assistantStatus === "error" && <div className="assistant-error" role="alert">Grounded assistance is unavailable. Authoritative ShadowRecon evidence remains unchanged.</div>}
            {assistantStatus === "ready" && <div className="assistant-response"><div><span>Source</span><strong>Grounded AI · authoritative ShadowRecon context</strong></div><pre>{cleanAIResponse(assistant.response)}</pre></div>}
          </Panel>
        )}
      </div>
    </div>
  );
}
