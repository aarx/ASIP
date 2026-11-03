import React, { useEffect, useMemo, useState } from "react";
import { Button, MenuItem, TextField } from "@mui/material";
import { getV2BrandAssets } from "../services/api";
import AssetLink from "../components/ui/AssetLink";
import StatusBadge from "../components/ui/StatusBadge";
import { EmptyState, ErrorState, LoadingState } from "../components/ui/AsyncState";
import { brandAcceptanceInventory, isBrandAcceptanceFixture } from "../fixtures/brandAcceptance";
import { displayEvidence } from "../utils/presentation";

const LIMIT = 25;

function readQuery(query) {
  const params = new URLSearchParams(query);
  return {
    page: Math.max(Number(params.get("page")) || 1, 1),
    search: params.get("search") || "",
    ownership: params.get("ownership") || "",
    fixture: params.get("fixture") || "",
  };
}

function brandHash({ page = 1, search = "", ownership = "", fixture = "" }) {
  const params = new URLSearchParams();
  if (search) params.set("search", search);
  if (ownership) params.set("ownership", ownership);
  if (page > 1) params.set("page", String(page));
  if (fixture) params.set("fixture", fixture);
  return `#/brand${params.toString() ? `?${params}` : ""}`;
}

function EvidenceTokens({ values, empty }) {
  return values?.length ? (
    <div className="brand-token-list">
      {values.map((value) => <span className="reason-token" key={value}>{value}</span>)}
    </div>
  ) : <span className="not-applicable">{empty}</span>;
}

export default function BrandPerimeterPage({ query }) {
  const applied = useMemo(() => readQuery(query), [query]);
  const fixtureMode = isBrandAcceptanceFixture(query);
  const [draft, setDraft] = useState({ search: applied.search, ownership: applied.ownership });
  const [data, setData] = useState(null);
  const [status, setStatus] = useState("loading");
  const [requestVersion, setRequestVersion] = useState(0);

  useEffect(() => setDraft({ search: applied.search, ownership: applied.ownership }), [applied]);
  useEffect(() => {
    let active = true;
    setStatus("loading");
    const inventoryParams = { page: applied.page, limit: LIMIT };
    if (applied.search) inventoryParams.search = applied.search;
    if (applied.ownership) inventoryParams.ownership = applied.ownership;
    const load = fixtureMode
      ? (params) => Promise.resolve(brandAcceptanceInventory(params))
      : getV2BrandAssets;
    Promise.all([
      load(inventoryParams),
      load({ page: 1, limit: 1 }),
      load({ page: 1, limit: 1, ownership: "CANDIDATE" }),
      load({ page: 1, limit: 1, ownership: "EXTERNAL" }),
    ]).then(([inventory, all, candidate, external]) => {
      if (active) {
        setData({ inventory, total: all.count, candidate: candidate.count, external: external.count });
        setStatus("ready");
      }
    }).catch(() => { if (active) setStatus("error"); });
    return () => { active = false; };
  }, [applied, fixtureMode, requestVersion]);

  const apply = (event) => {
    event.preventDefault();
    window.location.hash = brandHash({ ...draft, page: 1 });
  };
  const clear = () => { window.location.hash = fixtureMode ? "#/brand?fixture=ownership-review" : "#/brand"; };
  const movePage = (page) => { window.location.hash = brandHash({ ...applied, page }); };

  if (status === "loading") return <LoadingState title="Loading Brand Perimeter" copy="Retrieving current Candidate and External evidence without assuming ownership." />;
  if (status === "error") return <ErrorState title="Brand Perimeter unavailable" copy="The current ownership-investigation inventory could not be loaded." onRetry={() => setRequestVersion((value) => value + 1)} />;
  if (data.inventory.scan_id == null) return <EmptyState />;

  const totalPages = Math.max(Math.ceil(data.inventory.count / LIMIT), 1);
  return (
    <div className="brand-workspace">
      <section className="brand-command-bar" aria-label="Brand Perimeter context">
        <div><span>Current perimeter</span><strong>{data.total}</strong></div>
        <div><span>Candidate</span><strong>{data.candidate}</strong></div>
        <div><span>External</span><strong>{data.external}</strong></div>
        <div><span>Authoritative scan</span><strong>#{data.inventory.scan_id}</strong></div>
      </section>

      <div className="brand-boundary-notice">
        <strong>{fixtureMode ? "Development acceptance fixture" : "Ownership unconfirmed or external"}</strong>
        <p>{fixtureMode ? "Synthetic .invalid assets are held entirely in the frontend. No database, scan history, worker, risk, or authorization state is used or changed." : "These assets are excluded from the organizational attack surface and canonical risk unless ownership is confirmed."}</p>
      </div>

      <form className="brand-filters" onSubmit={apply}>
        <TextField name="search" size="small" label="Search perimeter domains" value={draft.search} onChange={(event) => setDraft((value) => ({ ...value, search: event.target.value }))} />
        <TextField name="ownership" select size="small" label="Ownership classification" value={draft.ownership} onChange={(event) => setDraft((value) => ({ ...value, ownership: event.target.value }))}>
          <MenuItem value="">Candidate and External</MenuItem>
          <MenuItem value="CANDIDATE">Candidate</MenuItem>
          <MenuItem value="EXTERNAL">External</MenuItem>
        </TextField>
        <Button type="submit" variant="contained">Apply</Button>
        <Button type="button" variant="text" onClick={clear} disabled={!applied.search && !applied.ownership}>Clear</Button>
      </form>

      {data.inventory.assets.length ? (
        <div className="dense-table-wrap brand-table-wrap">
          <table className="dense-table brand-table">
            <thead><tr><th>Domain / classification</th><th>Why discovered</th><th>DNS / IP</th><th>HTTP evidence</th><th>Destination / title</th><th>Risk boundary</th><th /></tr></thead>
            <tbody>{data.inventory.assets.map((asset) => (
              <tr key={asset.domain}>
                <td><AssetLink domain={asset.domain} returnTo="brand" returnQuery={fixtureMode ? "fixture=ownership-review" : ""} /><StatusBadge value={asset.ownership_status} /></td>
                <td><span className="evidence-label">Sources</span><EvidenceTokens values={asset.discovery_sources} empty="No source recorded" /><span className="evidence-label brand-seed-label">Associated seeds</span><EvidenceTokens values={asset.seeds} empty="No seed recorded" /></td>
                <td><span className="technical-value">{displayEvidence(asset.ip)}</span><span className="asset-secondary">{asset.has_ip ? "Resolution observed" : "No current IP evidence"}</span></td>
                <td><StatusBadge value={asset.http_observation_status} /><span className="asset-secondary">{asset.http_status ?? "No status"}</span></td>
                <td><span className="evidence-label">{asset.final_url_verification === "LEGACY_UNKNOWN" ? "Legacy URL (verification unknown)" : asset.redirect_evidence?.first_hop_destination ? "Observed redirect destination" : asset.final_url_verification === "COMPLETE" ? "Verified final URL" : "Final URL unresolved"}</span><span className="brand-destination technical-value" title={displayEvidence(asset.redirect_evidence?.first_hop_destination || (asset.final_url_verification === "LEGACY_UNKNOWN" ? asset.final_url : asset.redirect_evidence?.verified_terminal_url), "")}>{displayEvidence(asset.redirect_evidence?.first_hop_destination || (asset.final_url_verification === "LEGACY_UNKNOWN" ? asset.final_url : asset.redirect_evidence?.verified_terminal_url), "No URL observed")}</span><span className="asset-secondary">{asset.final_url_verification === "UNRESOLVED" || asset.final_url_verification === "UNKNOWN" ? `Final URL unresolved · ${asset.redirect_evidence?.stop_reason || "unknown reason"}` : asset.final_url_verification === "LEGACY_UNKNOWN" ? `Legacy status (verification unknown): ${displayEvidence(asset.final_status, "not recorded")}` : displayEvidence(asset.final_status, "No verified final status")} · {displayEvidence(asset.title, "No title")}</span></td>
                <td><span className="not-applicable">No org. risk</span><span className="asset-secondary">Outside confirmed surface</span></td>
                <td><AssetLink domain={asset.domain} returnTo="brand" returnQuery={fixtureMode ? "fixture=ownership-review" : ""} className="row-action">→</AssetLink></td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      ) : <EmptyState title="No Brand Perimeter assets match" copy="No current Candidate or External assets match the selected search and ownership classification." />}

      {data.inventory.count > 0 && (
        <div className="pagination-bar"><span>Page {applied.page} of {totalPages} · {data.inventory.count} matching</span><div><Button size="small" variant="outlined" disabled={applied.page <= 1} onClick={() => movePage(applied.page - 1)}>Previous</Button><Button size="small" variant="outlined" disabled={applied.page >= totalPages} onClick={() => movePage(applied.page + 1)}>Next</Button></div></div>
      )}
    </div>
  );
}
