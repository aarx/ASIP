import React, { useEffect, useMemo, useRef, useState } from "react";
import { Button, TextField } from "@mui/material";
import { askShadowRecon, getInvestigationAssets, getV2AssetAssistant, getV2AssetDetail } from "../services/api";
import Panel from "../components/ui/Panel";
import StatusBadge from "../components/ui/StatusBadge";
import { EmptyState, ErrorState, LoadingState } from "../components/ui/AsyncState";
import { displayAssetClass, displayEvidence, displayHttpStatus } from "../utils/presentation";

const LIMIT = 20;
const ACTIONS = [
  ["explain_risk", "Explain Risk"],
  ["investigation_plan", "Investigation Plan"],
  ["summarize_asset", "Summarize Asset"],
];
const GLOBAL_QUESTIONS = [
  "What is our current attack surface?",
  "Which assets need attention?",
  "Are there DNS Security concerns?",
  "Which certificates need attention?",
  "Which technologies were detected?",
  "Compare the last two successful scans",
];
const ASSET_QUESTIONS = [
  "Tell me about this asset",
  "Why is this domain risky?",
  "What should I investigate next?",
];
const MAX_QUESTION_LENGTH = 500;

function selectedFromQuery(query) {
  return new URLSearchParams(query).get("domain") || "";
}

function detailReturnFromQuery(query) {
  return new URLSearchParams(query).get("detail_return") || "";
}

function investigationHash(domain) {
  return domain ? `#/investigate?domain=${encodeURIComponent(domain)}` : "#/investigate";
}

function cleanResponse(response) {
  return String(response || "")
    .replace(/\*\*(.*?)\*\*/g, "$1")
    .replace(/__(.*?)__/g, "$1")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/^#{1,6}\s+/gm, "")
    .trim();
}

function assistantValue(value) {
  if (value === null || value === undefined || value === "") return "";
  if (Array.isArray(value)) return value.map(assistantValue).join(" · ");
  if (typeof value === "object") {
    return Object.entries(value).map(([key, item]) => `${key.replaceAll("_", " ")}: ${assistantValue(item)}`).join(" · ");
  }
  return String(value);
}

function AssistantDetails({ assistant }) {
  const details = [
    ["Mode", assistant.mode],
    ["Source", assistant.source],
    ["Context", assistant.context],
    ["Coverage", assistant.coverage],
    ["Limitations", assistant.limitations],
    ["Next actions", assistant.next_actions],
    ["Model metadata", assistant.model],
  ].filter(([, value]) => assistantValue(value));

  if (!details.length) return null;

  return (
    <details className="assistant-details">
      <summary>Evidence details</summary>
      <div className="assistant-details-grid">
        {details.map(([label, value]) => <div key={label}><span>{label}</span><p>{assistantValue(value)}</p></div>)}
      </div>
    </details>
  );
}

function questionUsesAssetContext(question) {
  const normalized = question.toLowerCase();
  return normalized.includes("this asset")
    || normalized.includes("this domain")
    || normalized.includes("investigate next")
    || normalized.includes("check on this");
}

function displayLabel(value) {
  return String(value || "").replaceAll("_", " ");
}

function evidenceItemTitle(item) {
  return item?.domain || item?.target || item?.technology || item?.check_key || "Observation";
}

function evidenceItemSummary(item) {
  if (!item || typeof item !== "object") return String(item || "");
  const parts = [];
  if (item.priority) parts.push(`${item.priority}${item.score !== undefined ? ` · score ${item.score}` : ""}`);
  if (item.outcome) parts.push(item.outcome);
  if (item.severity) parts.push(item.severity);
  if (item.status) parts.push(item.status);
  if (item.technology && item.version) parts.push(`version ${item.version}`);
  else if (item.version) parts.push(item.version);
  if (item.ip) parts.push(item.ip);
  if (item.before || item.after) parts.push(`before: ${item.before || "not recorded"} · after: ${item.after || "not recorded"}`);
  if (item.expiry_date) parts.push(`expires ${item.expiry_date}`);
  if (item.record_type) parts.push(item.record_type);
  return parts.join(" · ") || "Evidence recorded";
}

function EvidenceList({ title, items, total }) {
  if (!Array.isArray(items) || !items.length) return null;
  const bounded = items.slice(0, 25);
  return (
    <section className="assistant-evidence-block">
      <div className="assistant-evidence-block-head"><strong>{title}</strong><small>{total != null ? `Showing ${bounded.length} of ${total}` : `${bounded.length} returned`}</small></div>
      <div className="assistant-evidence-list">
        {bounded.map((item, index) => <div className="assistant-evidence-row" key={`${evidenceItemTitle(item)}-${index}`}><strong>{evidenceItemTitle(item)}</strong><span>{evidenceItemSummary(item)}</span></div>)}
      </div>
    </section>
  );
}

function StructuredEvidence({ data, coverage }) {
  if (!data || typeof data !== "object") return null;
  const sections = [];
  const nested = data.data && typeof data.data === "object" && !Array.isArray(data.data) ? data.data : null;
  const scalarEntries = Object.entries(data).filter(([key, value]) => (
    !["answer", "data", "risk_distribution", "next_tier_assets", "assets", "checks", "added", "removed", "http_dns_state_changes"].includes(key)
    && ["string", "number", "boolean"].includes(typeof value)
  ));

  if (scalarEntries.length) {
    sections.push(
      <div className="assistant-metric-grid" key="metrics">
        {scalarEntries.map(([key, value]) => <div key={key}><span>{displayLabel(key)}</span><strong>{String(value)}</strong></div>)}
      </div>
    );
  }
  if (data.risk_distribution && typeof data.risk_distribution === "object") {
    sections.push(
      <div className="assistant-metric-grid" key="risk-distribution">
        {Object.entries(data.risk_distribution).map(([key, value]) => <div key={key}><span>{key}</span><strong>{String(value)}</strong></div>)}
      </div>
    );
  }
  if (nested?.items) sections.push(<EvidenceList key="items" title={`${displayLabel(nested.category || "Evidence")} observations`} items={nested.items} total={nested.total} />);
  if (data.next_tier_assets) sections.push(<EvidenceList key="priority" title={`${data.next_priority_tier || "Ranked"} examples`} items={data.next_tier_assets} />);
  if (data.assets) sections.push(<EvidenceList key="assets" title="Shadow assets with IP evidence" items={data.assets} total={data.total_shadow_assets} />);
  if (data.checks) sections.push(<EvidenceList key="checks" title="DNS assessment records" items={data.checks} total={data.check_records} />);
  if (data.added) sections.push(<EvidenceList key="added" title="Assets added" items={data.added} total={coverage?.membership_additions_total} />);
  if (data.removed) sections.push(<EvidenceList key="removed" title="Assets removed" items={data.removed} total={coverage?.membership_removals_total} />);
  if (data.http_dns_state_changes) sections.push(<EvidenceList key="changes" title="HTTP/DNS state changes" items={data.http_dns_state_changes} total={coverage?.state_changes_total} />);
  if (!sections.length) return null;
  return <div className="assistant-structured-evidence" aria-label="Supporting evidence">{sections}</div>;
}

function SuggestedQuestions({ questions, onSelect, label }) {
  return (
    <div className="assistant-suggestions">
      <span>{label}</span>
      <div>{questions.map((item) => <button type="button" key={item} onClick={() => onSelect(item)}>{item}</button>)}</div>
    </div>
  );
}

function QuestionResponse({ result, onSelect }) {
  return (
    <div className="question-response" role="region" aria-label="Ask ShadowRecon response">
      <div className="question-asked"><span>Question</span><strong>{result.question}</strong></div>
      <pre>{cleanResponse(result.answer)}</pre>
      <StructuredEvidence data={result.data} coverage={result.coverage} />
      {result.next_actions?.length > 0 && <div className="assistant-next-actions"><span>Next actions</span><ul>{result.next_actions.map((item) => <li key={item}>{item}</li>)}</ul></div>}
      {result.suggested_questions?.length > 0 && <SuggestedQuestions questions={result.suggested_questions} onSelect={onSelect} label="Try a supported question" />}
      <AssistantDetails assistant={result} />
    </div>
  );
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
        <div className="identity-badges"><StatusBadge value={displayAssetClass(asset.asset_class)} /><StatusBadge value={asset.ownership_status} /><a className="context-link" href={detailHref}>Full Asset Detail</a></div>
        <div className="investigation-risk">
          {risk ? <><StatusBadge value={risk.priority} /><strong>{risk.score}</strong><div className="reason-list">{risk.reasons.map((reason) => <span className="reason-token" key={reason}>{reason.replaceAll("_", " ")}</span>)}</div></> : <span>No organizational canonical risk applies to {displayAssetClass(asset.asset_class)} assets.</span>}
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
            <EvidenceItem label="HTTP status" mono>{displayHttpStatus(asset.http?.observation_status, asset.http?.status)}</EvidenceItem>
            <EvidenceItem label="Observed redirect destination" mono>{displayEvidence(asset.http?.redirect_evidence?.first_hop_destination, "Not observed")}</EvidenceItem>
            <EvidenceItem label={asset.http?.redirect_evidence?.completion_status === "COMPLETE" ? "Verified final URL" : "Final URL unresolved"} mono>{displayEvidence(asset.http?.redirect_evidence?.completion_status === "COMPLETE" ? asset.http.redirect_evidence.verified_terminal_url : null, "Unresolved or unavailable")}</EvidenceItem>
            {asset.http?.redirect_evidence?.completion_status === "LEGACY_UNKNOWN" && asset.http?.final_url && <EvidenceItem label="Historical URL (unverified)" mono>{asset.http.final_url}</EvidenceItem>}
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
  const [question, setQuestion] = useState("");
  const [questionResult, setQuestionResult] = useState(null);
  const [questionStatus, setQuestionStatus] = useState("idle");
  const [questionError, setQuestionError] = useState("");
  const assistantRequestRef = useRef(0);
  const questionRequestRef = useRef(0);

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
    assistantRequestRef.current += 1;
    questionRequestRef.current += 1;
    setAssistant(null);
    setAssistantStatus("idle");
    setQuestionResult(null);
    setQuestionStatus("idle");
    setQuestionError("");
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
    const selectedDomain = asset.domain;
    const requestId = ++assistantRequestRef.current;
    questionRequestRef.current += 1;
    setAssistant(null);
    setAssistantStatus("loading");
    setQuestionResult(null);
    setQuestionStatus("idle");
    getV2AssetAssistant(selectedDomain, action)
      .then((result) => {
        if (requestId !== assistantRequestRef.current || selectedDomain !== queryDomain) return;
        setAssistant(result);
        setAssistantStatus("ready");
      })
      .catch(() => {
        if (requestId === assistantRequestRef.current && selectedDomain === queryDomain) setAssistantStatus("error");
      });
  };

  const selectQuestion = (value) => {
    setQuestion(value);
    setQuestionError("");
  };

  const submitQuestion = (event) => {
    event.preventDefault();
    if (questionStatus === "loading") return;
    const value = question.trim();
    if (!value) {
      setQuestionError("Enter a question to ask ShadowRecon.");
      return;
    }
    if (value.length > MAX_QUESTION_LENGTH) {
      setQuestionError(`Questions must be ${MAX_QUESTION_LENGTH} characters or fewer.`);
      return;
    }
    const selectedDomain = asset?.domain && questionUsesAssetContext(value) ? asset.domain : null;
    const requestId = ++questionRequestRef.current;
    assistantRequestRef.current += 1;
    setQuestionError("");
    setQuestionResult(null);
    setQuestionStatus("loading");
    setAssistant(null);
    setAssistantStatus("idle");
    askShadowRecon(value, selectedDomain)
      .then((result) => {
        if (requestId !== questionRequestRef.current || selectedDomain !== (questionUsesAssetContext(value) ? queryDomain : null)) return;
        setQuestionResult(result);
        setQuestionStatus("ready");
      })
      .catch(() => {
        if (requestId === questionRequestRef.current) {
          setQuestionStatus("error");
          setQuestionError("ShadowRecon questions are unavailable. Try again.");
        }
      });
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
          <Panel title="Investigation Assistant" meta="EVIDENCE-BASED" className="investigation-assistant">
            <div className="ask-shadowrecon">
              <strong>ASK SHADOWRECON</strong>
              <form className="assistant-question-form" onSubmit={submitQuestion}>
                <TextField
                  size="small"
                  fullWidth
                  label="Ask ShadowRecon"
                  placeholder="Ask ShadowRecon a security question..."
                  value={question}
                  inputProps={{ maxLength: MAX_QUESTION_LENGTH, "aria-label": "Ask ShadowRecon a security question" }}
                  onChange={(event) => { setQuestion(event.target.value); setQuestionError(""); }}
                />
                <Button type="submit" variant="contained" disabled={questionStatus === "loading"}>{questionStatus === "loading" ? "Asking…" : "Ask"}</Button>
              </form>
              {questionError && <div className="assistant-error" role="alert">{questionError}</div>}
              <SuggestedQuestions questions={GLOBAL_QUESTIONS} onSelect={selectQuestion} label="Suggested questions" />
              <SuggestedQuestions questions={ASSET_QUESTIONS} onSelect={selectQuestion} label={`Selected asset: ${asset.domain}`} />
            </div>
            <div className="assistant-actions">{ACTIONS.map(([action, label]) => <Button key={action} variant={assistant?.action === action ? "contained" : "outlined"} disabled={assistantStatus === "loading"} onClick={() => runAction(action)}>{label}</Button>)}</div>
            {assistantStatus === "loading" && <div className="assistant-progress" role="status">Preparing an evidence-based response…</div>}
            {assistantStatus === "error" && <div className="assistant-error" role="alert">Investigation Assistant is unavailable. Authoritative ShadowRecon evidence remains unchanged.</div>}
            {questionStatus === "loading" && <div className="assistant-progress" role="status">Reading current ShadowRecon evidence…</div>}
            {questionStatus === "ready" && questionResult && <QuestionResponse result={questionResult} onSelect={selectQuestion} />}
            {assistantStatus === "ready" && <div className="assistant-response"><pre>{cleanResponse(assistant.response)}</pre><AssistantDetails assistant={assistant} /></div>}
          </Panel>
        )}
      </div>
    </div>
  );
}
