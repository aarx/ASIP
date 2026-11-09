import React, { useEffect, useMemo, useState } from "react";
import { Button, MenuItem, TextField } from "@mui/material";
import { getV2BrandAssets, getV2Overview } from "../services/api";
import AssetLink from "../components/ui/AssetLink";
import StatusBadge from "../components/ui/StatusBadge";
import { EmptyState, ErrorState, LoadingState } from "../components/ui/AsyncState";
import { BrandDiscoveryPanel } from "../components/ui/OverviewIntelligence";
import { brandAcceptanceInventory, isBrandAcceptanceFixture } from "../fixtures/brandAcceptance";
import { displayAssetClass, displayEvidence } from "../utils/presentation";

const LIMIT = 25;

function readQuery(query) {
  const params = new URLSearchParams(query);
  return {
    page: Math.max(Number(params.get("page")) || 1, 1),
    search: params.get("search") || "",
    ownership: params.get("ownership") || "",
    asset_class: params.get("asset_class") || "",
    discovery_source: params.get("discovery_source") || "",
    fixture: params.get("fixture") || "",
  };
}

function brandHash({ page = 1, search = "", ownership = "", asset_class: assetClass = "", discovery_source: discoverySource = "", fixture = "" }) {
  const params = new URLSearchParams();
  if (search) params.set("search", search);
  if (assetClass) params.set("asset_class", assetClass);
  else if (ownership) params.set("ownership", ownership);
  if (discoverySource) params.set("discovery_source", discoverySource);
  if (page > 1) params.set("page", String(page));
  if (fixture) params.set("fixture", fixture);
  return `#/brand${params.toString() ? `?${params}` : ""}`;
}

function httpStatusValue(value) {
  return value === null || value === undefined || value === "" || value === 0 || value === "0" || Number.isNaN(value)
    ? "Unknown"
    : value;
}

function destinationEvidence(asset) {
  const evidence = asset.redirect_evidence || {};
  if (evidence.first_hop_destination) {
    return { label: "Observed destination", value: evidence.first_hop_destination };
  }
  if (asset.final_url_verification === "COMPLETE" && evidence.verified_terminal_url) {
    return { label: "Verified final URL", value: evidence.verified_terminal_url };
  }
  if (asset.final_url_verification === "LEGACY_UNKNOWN" && asset.final_url) {
    return { label: "Historical URL (unverified)", value: asset.final_url };
  }
  return null;
}

function queryForReturn(query) {
  const params = new URLSearchParams(query);
  const returnParams = new URLSearchParams();
  ["search", "ownership", "asset_class", "discovery_source", "page", "fixture"].forEach((key) => {
    const value = params.get(key);
    if (value) returnParams.set(key, value);
  });
  return returnParams.toString();
}

export default function BrandPerimeterPage({ query }) {
  const applied = useMemo(() => readQuery(query), [query]);
  const fixtureMode = isBrandAcceptanceFixture(query);
  const [draft, setDraft] = useState({ search: applied.search, ownership: applied.ownership });
  const [data, setData] = useState(null);
  const [status, setStatus] = useState("loading");
  const [requestVersion, setRequestVersion] = useState(0);

  useEffect(() => setDraft({
    search: applied.search,
    ownership: applied.asset_class || applied.ownership,
    discovery_source: applied.discovery_source,
  }), [applied]);
  useEffect(() => {
    let active = true;
    setStatus("loading");
    const inventoryParams = { page: applied.page, limit: LIMIT };
    if (applied.search) inventoryParams.search = applied.search;
    if (applied.asset_class || applied.ownership) inventoryParams.asset_class = applied.asset_class || applied.ownership;
    if (applied.discovery_source) inventoryParams.discovery_source = applied.discovery_source;
    const load = fixtureMode
      ? (params) => Promise.resolve(brandAcceptanceInventory(params))
      : getV2BrandAssets;
    const overview = fixtureMode
      ? Promise.resolve(null)
      : Promise.resolve().then(() => getV2Overview()).catch(() => null);
    Promise.all([
      load(inventoryParams),
      load({ page: 1, limit: 1 }),
      load({ page: 1, limit: 1, asset_class: "CANDIDATE" }),
      load({ page: 1, limit: 1, asset_class: "EXTERNAL" }),
      overview,
    ]).then(([inventory, all, candidate, external, overviewData]) => {
      if (active) {
        const brandDiscovery = overviewData?.current_scan_id === inventory.scan_id
          ? overviewData.brand_discovery
          : null;
        setData({
          inventory,
          total: all.count,
          candidate: candidate.count,
          external: external.count,
          brandDiscovery,
          brandDiscoveryStatus: brandDiscovery ? "ready" : "error",
        });
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

  if (status === "loading") return <LoadingState title="Loading Brand Perimeter" copy="Retrieving current Needs Verification and External evidence without assuming ownership." />;
  if (status === "error") return <ErrorState title="Brand Perimeter unavailable" copy="The current ownership-investigation inventory could not be loaded." onRetry={() => setRequestVersion((value) => value + 1)} />;
  if (data.inventory.scan_id == null) return <EmptyState />;

  const totalPages = Math.max(Math.ceil(data.inventory.count / LIMIT), 1);
  return (
    <div className="brand-workspace">
      <section className="brand-command-bar" aria-label="Brand Perimeter context">
        <div><span>Current perimeter</span><strong>{data.total}</strong></div>
        <div><span>Needs Verification</span><strong>{data.candidate}</strong></div>
        <div><span>External</span><strong>{data.external}</strong></div>
        <div><span>Authoritative scan</span><strong>#{data.inventory.scan_id}</strong></div>
      </section>

      <div className="brand-boundary-notice">
        <strong>{fixtureMode ? "Development acceptance fixture" : "Outside confirmed surface"}</strong>
        <p>Potential brand misuse or lookalike domains</p>
      </div>

      <BrandDiscoveryPanel
        value={data.brandDiscovery}
        status={data.brandDiscoveryStatus}
        scanId={data.inventory.scan_id}
        mode="brand"
      />

      <form className="brand-filters" onSubmit={apply}>
        <TextField name="search" size="small" label="Search perimeter domains" value={draft.search} onChange={(event) => setDraft((value) => ({ ...value, search: event.target.value }))} />
        <TextField name="ownership" select size="small" label="Asset classification" value={draft.ownership} onChange={(event) => setDraft((value) => ({ ...value, ownership: event.target.value }))}>
          <MenuItem value="">Needs Verification and External</MenuItem>
          <MenuItem value="CANDIDATE">Needs Verification</MenuItem>
          <MenuItem value="EXTERNAL">External</MenuItem>
        </TextField>
        <Button type="submit" variant="contained">Apply</Button>
        <Button type="button" variant="text" onClick={clear} disabled={!applied.search && !applied.ownership && !applied.asset_class && !applied.discovery_source}>Clear</Button>
      </form>

      {data.inventory.assets.length ? (
        <div className="dense-table-wrap brand-table-wrap">
          <table className="dense-table brand-table">
            <thead><tr><th>Domain / current class</th><th>DNS / IP</th><th>HTTP evidence</th><th>Observed destination / title</th><th /></tr></thead>
            <tbody>{data.inventory.assets.map((asset) => {
              const destination = destinationEvidence(asset);
              return (
              <tr key={asset.domain}>
                <td><AssetLink domain={asset.domain} returnTo="brand" returnQuery={queryForReturn(query)} /><StatusBadge value={displayAssetClass(asset.asset_class)} /></td>
                <td><span className="technical-value">{displayEvidence(asset.ip)}</span><span className="asset-secondary">{asset.has_ip ? "Resolution observed" : "No current IP evidence"}</span></td>
                <td><StatusBadge value={asset.http_observation_status} /><span className="asset-secondary">{httpStatusValue(asset.http_status)}</span></td>
                <td>{destination ? <><span className="evidence-label">{destination.label}</span><span className="brand-destination technical-value" title={destination.value}>{destination.value}</span></> : <span className="not-applicable">—</span>}{asset.title && <span className="asset-secondary">Title: {asset.title}</span>}</td>
                <td><AssetLink domain={asset.domain} returnTo="brand" returnQuery={queryForReturn(query)} className="row-action">→</AssetLink></td>
              </tr>
              );
            })}</tbody>
          </table>
        </div>
      ) : <EmptyState title="No Brand Perimeter assets match" copy="No current Needs Verification or External assets match the selected search and classification." />}

      {data.inventory.count > 0 && (
        <div className="pagination-bar"><span>Page {applied.page} of {totalPages} · {data.inventory.count} matching</span><div><Button size="small" variant="outlined" disabled={applied.page <= 1} onClick={() => movePage(applied.page - 1)}>Previous</Button><Button size="small" variant="outlined" disabled={applied.page >= totalPages} onClick={() => movePage(applied.page + 1)}>Next</Button></div></div>
      )}
    </div>
  );
}
