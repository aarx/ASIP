import React, { useEffect, useMemo, useState } from "react";
import { Button, MenuItem, TextField } from "@mui/material";
import { getV2BrandAssets, getV2Overview } from "../services/api";
import AssetLink from "../components/ui/AssetLink";
import StatusBadge from "../components/ui/StatusBadge";
import { EmptyState, ErrorState, LoadingState } from "../components/ui/AsyncState";
import { BrandDiscoveryPanel } from "../components/ui/OverviewIntelligence";
import { brandAcceptanceInventory, isBrandAcceptanceFixture } from "../fixtures/brandAcceptance";
import { displayAssetClass, displayEvidence, displayHttpStatus } from "../utils/presentation";
import SortableHeader from "../components/ui/SortableHeader";

const LIMIT = 25;

function readQuery(query) {
  const params = new URLSearchParams(query);
  return {
    page: Math.max(Number(params.get("page")) || 1, 1),
    search: params.get("search") || "",
    ownership: params.get("ownership") || "",
    asset_class: params.get("asset_class") || "",
    discovery_source: params.get("discovery_source") || "",
    brand_scope: params.get("brand_scope") || "",
    fixture: params.get("fixture") || "",
    sortBy: ["domain", "asset_class", "ip", "http_status", "final_status", "destination", "title"].includes(params.get("sort_by")) ? params.get("sort_by") : "domain",
    sortDir: ["asc", "desc"].includes(params.get("sort_dir")) ? params.get("sort_dir") : "asc",
  };
}

function brandHash({ page = 1, search = "", ownership = "", asset_class: assetClass = "", discovery_source: discoverySource = "", brand_scope: brandScope = "", fixture = "", sortBy = "domain", sortDir = "asc" }) {
  const params = new URLSearchParams();
  if (search) params.set("search", search);
  if (assetClass) params.set("asset_class", assetClass);
  else if (ownership) params.set("ownership", ownership);
  if (discoverySource) params.set("discovery_source", discoverySource);
  if (brandScope) params.set("brand_scope", brandScope);
  if (page > 1) params.set("page", String(page));
  if (fixture) params.set("fixture", fixture);
  if (sortBy !== "domain") params.set("sort_by", sortBy);
  if (sortDir !== "asc") params.set("sort_dir", sortDir);
  return `#/brand${params.toString() ? `?${params}` : ""}`;
}

function destinationEvidence(asset) {
  const observation = observationFor(asset);
  if (!observation) return null;
  if (observation.verified_final_url) return { label: "Verified final URL", value: observation.verified_final_url };
  if (observation.reported_destination_url || observation.last_reported_destination_url) {
    return { label: "Reported destination", value: observation.reported_destination_url || observation.last_reported_destination_url };
  }
  if (observation.historical_url_unverified) return { label: "Historical URL (unverified)", value: observation.historical_url_unverified };
  return null;
}

function observationFor(asset) {
  const stored = asset.brand_redirect_observation;
  if (stored?.evidence_scope === "CURRENT") return stored;
  const currentStatus = String(asset.http_observation_status || "UNKNOWN").toUpperCase();
  const currentHttpExists = currentStatus !== "UNKNOWN"
    || Number(asset.http_status) > 0
    || Boolean(asset.title)
    || Boolean(asset.final_url);
  if (currentHttpExists) {
    const redirect = asset.redirect_evidence || {};
    const legacy = asset.final_url_verification === "LEGACY_UNKNOWN";
    return {
      evidence_scope: "CURRENT",
      evidence_source: "HTTP_TLS_OBSERVATION",
      scan_id: asset.scan_id,
      initial_http_status: asset.http_status,
      reported_destination_url: legacy ? null : redirect.first_hop_destination,
      last_reported_destination_url: legacy ? null : redirect.last_observed_destination,
      redirect_location: legacy ? null : redirect.first_hop_location,
      observed_hops: legacy ? [] : (redirect.observed_hops || []),
      verified_final_url: redirect.completion_status === "COMPLETE" ? redirect.verified_terminal_url : null,
      historical_url_unverified: legacy ? asset.final_url : null,
      final_status: redirect.completion_status === "COMPLETE" ? asset.final_status : null,
      page_title: asset.title,
      completeness: redirect.completion_status || "LEGACY_UNKNOWN",
    };
  }
  return stored || null;
}

function observationTimestamp(observation) {
  if (!observation?.observed_at) return "Timestamp unavailable";
  const date = new Date(observation.observed_at);
  if (Number.isNaN(date.getTime())) return String(observation.observed_at);
  return observation.timestamp_basis === "SCAN_COMPLETION"
    ? `Scan completed ${date.toLocaleString()}`
    : date.toLocaleString();
}

function queryForReturn(query) {
  const params = new URLSearchParams(query);
  const returnParams = new URLSearchParams();
  ["search", "ownership", "asset_class", "discovery_source", "brand_scope", "page", "fixture", "sort_by", "sort_dir"].forEach((key) => {
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
  const [expandedDomain, setExpandedDomain] = useState(null);

  useEffect(() => setDraft({
    search: applied.search,
    ownership: applied.asset_class || applied.ownership,
    discovery_source: applied.discovery_source,
  }), [applied]);
  useEffect(() => {
    let active = true;
    setStatus("loading");
    const inventoryParams = { page: applied.page, limit: LIMIT };
    if (applied.sortBy !== "domain" || applied.sortDir !== "asc") {
      inventoryParams.sort_by = applied.sortBy;
      inventoryParams.sort_dir = applied.sortDir;
    }
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
    window.location.hash = brandHash({ ...draft, brand_scope: applied.brand_scope, page: 1 });
  };
  const clear = () => { window.location.hash = brandHash({ brand_scope: applied.brand_scope, fixture: fixtureMode ? "ownership-review" : "" }); };
  const movePage = (page) => { window.location.hash = brandHash({ ...applied, page }); };
  const changeSort = (field) => {
    const sortDir = applied.sortBy === field ? (applied.sortDir === "asc" ? "desc" : "asc") : (field === "http_status" || field === "final_status" ? "desc" : "asc");
    window.location.hash = brandHash({ ...applied, page: 1, sortBy: field, sortDir });
  };

  if (status === "loading") return <LoadingState title="Loading Brand Exposure" copy="Retrieving current Needs Verification and External evidence without assuming ownership." />;
  if (status === "error") return <ErrorState title="Brand Exposure unavailable" copy="The current ownership-investigation inventory could not be loaded." onRetry={() => setRequestVersion((value) => value + 1)} />;
  if (data.inventory.scan_id == null) return <EmptyState />;

  const totalPages = Math.max(Math.ceil(data.inventory.count / LIMIT), 1);
  return (
    <div className="brand-workspace">
      <section className="brand-command-bar" aria-label="Brand Exposure context">
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
        query={query}
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
            <thead><tr>
              <SortableHeader label="Domain / current class" field="domain" sortBy={applied.sortBy} sortDir={applied.sortDir} onSort={changeSort} />
              <SortableHeader label="DNS / IP" field="ip" sortBy={applied.sortBy} sortDir={applied.sortDir} onSort={changeSort} />
              <SortableHeader label="HTTP evidence" field="http_status" sortBy={applied.sortBy} sortDir={applied.sortDir} onSort={changeSort} />
              <SortableHeader label="Observed destination / title" field="destination" sortBy={applied.sortBy} sortDir={applied.sortDir} onSort={changeSort} />
              <th /></tr></thead>
            <tbody>{data.inventory.assets.map((asset) => {
              const observation = observationFor(asset);
              const destination = destinationEvidence(asset);
              const httpStatus = observation?.initial_http_status ?? asset.http_status;
              const assessed = Boolean(observation && (
                Number(observation.requests_attempted) > 0
                || Number(observation.initial_http_status) > 0
                || observation.http_observation_status === "RESPONDED"
                || observation.http_observation_status === "NO_RESPONSE"
                || (observation.evidence_scope === "HISTORICAL" && (
                  observation.historical_url_unverified || observation.page_title
                ))
              ));
              const httpState = observation?.http_observation_status
                || (Number(httpStatus) > 0 ? "RESPONDED" : (assessed ? "NO_RESPONSE" : "UNKNOWN"));
              const expanded = expandedDomain === asset.domain;
              return (
              <React.Fragment key={asset.domain}>
              <tr>
                <td><AssetLink domain={asset.domain} returnTo="brand" returnQuery={queryForReturn(query)} /><StatusBadge value={displayAssetClass(asset.asset_class)} /></td>
                <td><span className="technical-value">{displayEvidence(asset.ip)}</span><span className="asset-secondary">{asset.has_ip ? "Resolution observed" : "No current IP evidence"}</span></td>
                <td>{assessed ? <><StatusBadge value={observation.evidence_scope === "HISTORICAL" ? "HISTORICAL" : "ASSESSED"} /><span className="asset-secondary">{displayHttpStatus(httpState, httpStatus)}</span></> : <><StatusBadge value="NOT ASSESSED" /><span className="asset-secondary">No HTTP evidence</span></>}</td>
                <td>{destination ? <><span className="evidence-label">{destination.label}</span><span className="brand-destination technical-value" title={destination.value}>→ {destination.value}</span></> : <span className="not-applicable">{assessed ? "No redirect observed" : "Not assessed"}</span>}{observation?.page_title && <span className="asset-secondary">Title: {observation.page_title}</span>}{assessed && <button type="button" className="brand-evidence-toggle" aria-expanded={expanded} onClick={() => setExpandedDomain(expanded ? null : asset.domain)}>{expanded ? "Hide HTTP details" : "HTTP details"}</button>}</td>
                <td><AssetLink domain={asset.domain} returnTo="brand" returnQuery={queryForReturn(query)} className="row-action">→</AssetLink></td>
              </tr>
              {expanded && <tr className="brand-evidence-details"><td colSpan={5}><div><strong>{observation.evidence_scope} · {observation.evidence_source}</strong><span>Scan #{observation.scan_id ?? data.inventory.scan_id} · {observationTimestamp(observation)}</span><span>Initial status: {displayEvidence(observation.initial_http_status, "Not recorded")}</span>{observation.observed_hops?.map((hop, index) => <span key={`${hop.source_url}-${index}`}>Hop {index + 1}: {hop.status} · {hop.reported_location || "No Location header"}{hop.reported_destination_url ? ` · Reported destination ${hop.reported_destination_url}` : ""}{hop.followed ? " · followed" : " · not followed"}</span>)}{observation.final_status != null && <span>Verified final status: {observation.final_status}</span>}<span>Completeness: {observation.completeness || "UNKNOWN"}</span>{observation.operation_id && <span>Operation: {observation.operation_id}</span>}</div></td></tr>}
              </React.Fragment>
              );
            })}</tbody>
          </table>
        </div>
      ) : <EmptyState title="No Brand Exposure assets match" copy="No current Needs Verification or External assets match the selected search and classification." />}

      {data.inventory.count > 0 && (
        <div className="pagination-bar"><span>Page {applied.page} of {totalPages} · {data.inventory.count} matching</span><div><Button size="small" variant="outlined" disabled={applied.page <= 1} onClick={() => movePage(applied.page - 1)}>Previous</Button><Button size="small" variant="outlined" disabled={applied.page >= totalPages} onClick={() => movePage(applied.page + 1)}>Next</Button></div></div>
      )}
    </div>
  );
}
