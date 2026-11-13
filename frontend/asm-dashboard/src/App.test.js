import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import App from "./App";
import { getAssetGrowth, getCertExpiry, getDiscoverySources, getExposureSummary, getFindings, getHttpStatus, getNamingAssetExposure, getRiskHistorySummary, getSecurityFindings, getSecurityFindingsSummary, getSeeds, getSensitiveExposure, getV2Assets, getV2Overview, getV2ReviewIndicators, getV2Scans } from "./services/api";

jest.mock("./services/api", () => ({
  getV2Overview: jest.fn(),
  getAssetGrowth: jest.fn(),
  getCertExpiry: jest.fn(),
  getDiscoverySources: jest.fn(),
  getExposureSummary: jest.fn(),
  getHttpStatus: jest.fn(),
  getV2Assets: jest.fn(),
  getV2AssetDetail: jest.fn(),
  updateV2AssetOwnership: jest.fn(),
  getV2Scans: jest.fn(),
  getNamingAssetExposure: jest.fn(),
  getSeeds: jest.fn(),
  getRiskHistorySummary: jest.fn(),
  getV2ReviewIndicators: jest.fn(),
  getSecurityFindings: jest.fn(),
  getSecurityFindingsSummary: jest.fn(),
  getV2AssetAssistant: jest.fn(),
  getInvestigationAssets: jest.fn(),
  getNewDomainsDelta: jest.fn(),
  getDisappearedDomains: jest.fn(),
  getRiskyDomains: jest.fn(),
  getFindings: jest.fn(),
  getSensitiveExposure: jest.fn(),
  getExposureSummary: jest.fn(),
}));
jest.mock("recharts", () => {
  const actual = jest.requireActual("recharts");
  return {
    ...actual,
    ResponsiveContainer: ({ children }) => <div>{children}</div>,
  };
});

const overview = {
  current_scan_id: 42,
  previous_scan_id: 41,
  counts: { organizational: 18, known: 11, shadow: 7, candidate: 3, external: 2 },
  brand_discovery: {
    scan_id: 42,
    source_counts: {
      brand_tld: { domains: 20, by_asset_class: { candidate: 7, external: 2, known: 6, shadow: 5 } },
      brand_pattern: { domains: 15, by_asset_class: { candidate: 6, external: 1, known: 5, shadow: 3 } },
      brand_union: { domains: 32, by_asset_class: { candidate: 10, external: 2, known: 12, shadow: 8 } },
    },
  },
  risk_distribution: { High: 1, Elevated: 2, Review: 4, Low: 11 },
  changes: { new_assets: 3, disappeared_assets: 1 },
  needs_attention: [{
    domain: "alpha.example",
    score: 9,
    priority: "High",
    reasons: ["finding", "shadow_asset"],
  }],
};

const rankedAssetPage = {
  scan_id: 42,
  page: 1,
  limit: 10,
  sort_by: "risk_score",
  sort_dir: "desc",
  count: 1,
  assets: [{
    domain: "alpha.example",
    asset_class: "SHADOW",
    risk: { score: 9, priority: "High", reasons: ["finding", "shadow_asset"] },
  }],
};

beforeEach(() => {
  window.location.hash = "#/overview";
  getV2Overview.mockReset();
  getV2Assets.mockReset();
  getAssetGrowth.mockReset();
  getV2Scans.mockReset();
  getHttpStatus.mockReset();
  getNamingAssetExposure.mockReset();
  getSeeds.mockReset();
  getCertExpiry.mockReset();
  getDiscoverySources.mockReset();
  getExposureSummary.mockReset();
  getRiskHistorySummary.mockReset();
  getSecurityFindings.mockReset();
  getSecurityFindingsSummary.mockReset();
  getFindings.mockReset();
  getSensitiveExposure.mockReset();
  getV2ReviewIndicators.mockReset();
});

test("renders the permanent shell and authoritative overview", async () => {
  getV2Overview.mockResolvedValue(overview);
  jest.spyOn(Date, "now").mockReturnValue(new Date("2026-09-26T12:00:00Z").getTime());
  getV2Scans.mockResolvedValue({
    current_authoritative_scan_id: 42,
    scans: [
      { scan_id: 43, status: "RUNNING", completed_at: null, is_current_authoritative: false },
      { scan_id: 42, status: "SUCCEEDED", completed_at: "2026-09-26T10:00:00Z", is_current_authoritative: true },
    ],
  });
  getNamingAssetExposure.mockResolvedValue([
    { keyword: "DEV", count: 2 },
    { keyword: "STAGE", count: 1 },
  ]);
  getCertExpiry.mockResolvedValue([]);
  getSeeds.mockResolvedValue([
    { seed: "abc.com", domains_discovered: 18 },
    { seed: "other.example", domains_discovered: 5 },
  ]);
  getDiscoverySources.mockResolvedValue({ "Pentest Tool": 617, "SAN Expansion": 427, "Brand Expansion": 1241 });
  getExposureSummary.mockResolvedValue({ scan_id: 42, resolving_domains: 14, http_responding_domains: 9 });
  render(<App />);

  expect(screen.getByText("Loading authoritative state")).toBeInTheDocument();
  expect(await screen.findByText("Brand discovery")).toBeInTheDocument();
  expect(screen.getByText("ShadowRecon")).toBeInTheDocument();
  const pageHeaderContent = document.querySelector(".page-context-inner");
  const pageBodyContent = document.querySelector(".page-content-overview");
  expect(pageHeaderContent).toHaveClass("page-layout-container");
  expect(pageBodyContent).toHaveClass("page-layout-container");
  expect(pageHeaderContent.parentElement).toHaveClass("page-context-overview");
  const overviewMetrics = screen.getByRole("region", { name: "Overview metrics" });
  const coveragePanel = screen.getByRole("heading", { name: "Asset Coverage" }).closest("section");
  expect(overviewMetrics.querySelectorAll(".panel")).toHaveLength(2);
  expect(overviewMetrics.querySelectorAll(".metric-card")).toHaveLength(4);
  expect(coveragePanel).toHaveClass("asset-coverage-panel");
  expect(overviewMetrics.querySelector(".overview-discovery-sources-panel")).toBeInTheDocument();
  expect(within(coveragePanel).getByText("Historical")).toBeInTheDocument();
  expect(within(coveragePanel).getByText("Current authoritative scan")).toBeInTheDocument();
  expect(within(coveragePanel).getByText("All-time domains")).toBeInTheDocument();
  expect(within(coveragePanel).getByText("2,285")).toBeInTheDocument();
  expect(within(coveragePanel).getByText("Current scan assets")).toBeInTheDocument();
  expect(within(coveragePanel).getByText("23")).toBeInTheDocument();
  expect(within(coveragePanel).getByText("Organizational assets")).toBeInTheDocument();
  expect(within(coveragePanel).getByText("18")).toBeInTheDocument();
  expect(within(coveragePanel).getByText("Known")).toBeInTheDocument();
  expect(within(coveragePanel).getByText("11")).toBeInTheDocument();
  expect(within(coveragePanel).getByText("Shadow")).toBeInTheDocument();
  expect(within(coveragePanel).getByText("7")).toBeInTheDocument();
  expect(within(coveragePanel).getByText("Needs Verification")).toBeInTheDocument();
  expect(within(coveragePanel).getByText("3")).toBeInTheDocument();
  expect(within(coveragePanel).getByText("External")).toBeInTheDocument();
  expect(within(coveragePanel).getByText("2")).toBeInTheDocument();
  expect(coveragePanel.querySelector(".asset-coverage-current")).toHaveAttribute("aria-label", "Open Current scan assets (23)");
  expect(coveragePanel.querySelector(".asset-coverage-organizational")).not.toHaveAttribute("href");
  expect(coveragePanel.querySelector(".asset-coverage-organizational")).toHaveTextContent("Organizational assets");
  expect(coveragePanel.querySelector('a[href="#/assets?asset_class=KNOWN&limit=25"]')).toBeInTheDocument();
  expect(coveragePanel.querySelector('a[href="#/shadow"]')).toBeInTheDocument();
  expect(coveragePanel.querySelector('a[href="#/assets?asset_class=CANDIDATE&limit=25"]')).toBeInTheDocument();
  expect(coveragePanel.querySelector('a[href="#/brand?asset_class=EXTERNAL"]')).toBeInTheDocument();
  expect(within(overviewMetrics).getByRole("link", { name: /Current High Risk/ })).toHaveAttribute("href", "#/risk/security-review?tab=prioritized-assets");
  expect(within(overviewMetrics).getByRole("link", { name: /New Assets/ })).toHaveAttribute("href", "#/changes?view=new");
  expect(within(overviewMetrics).getByRole("link", { name: /Assets with IP Addresses/ })).toHaveAttribute("href", "#/assets?has_ip=true");
  expect(within(overviewMetrics).getByText("14")).toBeInTheDocument();
  const kpiAssetGrowthPanel = screen.getByText("Asset growth trend").closest("section");
  expect(overviewMetrics.compareDocumentPosition(kpiAssetGrowthPanel) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  const chartRow = document.querySelector(".overview-chart-row");
  expect(chartRow).toBeInTheDocument();
  expect([...chartRow.querySelectorAll(":scope > .panel .panel-title")].map((node) => node.textContent)).toEqual([
    "Asset growth trend", "Seeds distribution",
  ]);
  expect(within(chartRow).getByTestId("overview-seed-distribution-chart")).toHaveAttribute(
    "aria-label", "Current authoritative scan 42 seed distribution"
  );
  const discoverySourcesPanel = screen.getByRole("heading", { name: "Discovery Sources" }).closest("section");
  expect(discoverySourcesPanel).toHaveTextContent("All-time domain counts");
  expect(within(discoverySourcesPanel).getByText("Pentest Tools").parentElement).toHaveTextContent("617");
  expect(within(discoverySourcesPanel).getByText("SAN Exposure").parentElement).toHaveTextContent("427");
  expect(within(discoverySourcesPanel).getByText("Brand Exposure").parentElement).toHaveTextContent("1241");
  expect(overviewMetrics.querySelectorAll(".metric-card")).toHaveLength(4);
  expect(screen.getByText("scan 41 → 42")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Overview" })).toHaveAttribute("aria-current", "page");
  expect(screen.getByRole("link", { name: "Overview" })).toHaveAttribute("href", "#/overview");
  expect(screen.getByRole("link", { name: "Asset Inventory" })).toHaveAttribute("href", "#/assets");
  expect(screen.getByRole("link", { name: "Shadow Assets" })).toHaveAttribute("href", "#/shadow");
  expect(screen.getByRole("link", { name: "Risk Overview" })).toHaveAttribute("href", "#/risk");
  expect(screen.getByRole("link", { name: "Security Review" })).toHaveAttribute("href", "#/risk/security-review");
  expect(screen.getByRole("link", { name: "Brand Exposure" })).toHaveAttribute("href", "#/brand");
  expect(screen.getByRole("link", { name: "Asset Analysis" })).toHaveAttribute("href", "#/investigate");
  expect(screen.getByRole("link", { name: "DNS Security" })).toHaveAttribute("href", "#/risk/dns-security");
  expect(screen.getByRole("link", { name: "Brand Exposure" })).toHaveAttribute("href", "#/brand");
  expect(screen.getByRole("link", { name: "Scan Centre" })).toHaveAttribute("href", "#/scans");
  expect(screen.getByRole("link", { name: "CVE Checks" })).toHaveAttribute("href", "#/capd");
  expect(screen.getByRole("link", { name: "Adhoc Checks" })).toHaveAttribute("href", "#/adhoc/php-rce");
  expect(screen.getByRole("link", { name: "Change Intelligence" })).toHaveAttribute("href", "#/changes");
  const primaryNavigation = screen.getByLabelText("Primary navigation").querySelector("nav");
  expect([...primaryNavigation.children]
    .filter((item) => item.matches("a, details"))
    .map((item) => item.querySelector(".nav-label").textContent.trim()))
    .toEqual(["Overview", "Assets", "Risk & Exposure", "Analytics", "Scans", "CAPD"]);
  expect(screen.queryByText("Asset Discovery")).not.toBeInTheDocument();
  expect(screen.queryByRole("link", { name: "Dashboard" })).not.toBeInTheDocument();
  expect(screen.queryByRole("link", { name: "Risk Distribution" })).not.toBeInTheDocument();
  expect(document.querySelectorAll(".nav-group")).toHaveLength(5);
  const riskGroup = [...document.querySelectorAll(".nav-group")].find((group) => group.querySelector(".nav-group-summary")?.textContent.includes("Risk & Exposure"));
  expect(riskGroup).toHaveAttribute("open");
  const riskSummary = riskGroup.querySelector(".nav-group-summary");
  fireEvent.click(riskSummary);
  await waitFor(() => {
    expect(riskGroup).not.toHaveAttribute("open");
    expect(riskSummary).toHaveAttribute("aria-expanded", "false");
  });
  fireEvent.click(riskSummary);
  await waitFor(() => expect(riskGroup).toHaveAttribute("open"));
  expect(screen.queryByRole("link", { name: "Settings" })).not.toBeInTheDocument();
  expect(screen.getByRole("link", { name: /Authoritative scan #42 completed 2h ago/i })).toHaveAttribute("href", "#/scans");
  expect(screen.queryByText(/Authoritative scan #43/)).not.toBeInTheDocument();
  expect(screen.getByRole("link", { name: /Authoritative scan #42/i })).toHaveAttribute("title", expect.stringContaining("2026"));
  expect(screen.getAllByRole("link", { name: /Open Known/ }).some((link) => link.getAttribute("href") === "#/assets?asset_class=KNOWN&limit=25")).toBe(true);
  expect(screen.getByRole("link", { name: "Open Shadow assets" })).toHaveAttribute("href", "#/shadow");
  expect(screen.getAllByRole("link", { name: /Open Needs Verification/ }).some((link) => link.getAttribute("href") === "#/assets?asset_class=CANDIDATE&limit=25")).toBe(true);
  expect(screen.getByRole("link", { name: "Open External assets" })).toHaveAttribute("href", "#/brand?asset_class=EXTERNAL");
  const overviewContent = document.querySelector(".page-content-overview");
  expect(within(overviewContent).queryByText("Needs attention")).not.toBeInTheDocument();
  expect(within(overviewContent).queryByText("Risk distribution")).not.toBeInTheDocument();
  expect(within(overviewContent).getByText("Asset growth trend")).toBeInTheDocument();
  const certificatePanel = screen.getByText("Certificate health").closest("section");
  const changedPanel = screen.getByText("What changed").closest("section");
  expect(certificatePanel).toHaveClass("certificate-health-panel");
  expect(changedPanel).toHaveClass("change-panel");
  const assetGrowthPanel = screen.getByText("Asset growth trend").closest("section");
  expect(assetGrowthPanel.compareDocumentPosition(changedPanel) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expect(changedPanel.compareDocumentPosition(certificatePanel) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expect(getCertExpiry).toHaveBeenCalledTimes(1);
  expect(screen.queryByText("Discovery & validation")).not.toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Open Brand-related domains (32)" })).toHaveAttribute(
    "href", "#/assets?discovery_source=brand_union&limit=25"
  );
  const brandPanel = screen.getByText("Brand discovery").closest("section");
  expect(within(brandPanel).getByRole("link", { name: "Open External (2)" })).toHaveAttribute(
    "href", "#/assets?discovery_source=brand_union&asset_class=EXTERNAL&limit=25"
  );
  expect(screen.getByText("Naming exposure")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Open DEV matching assets (2)" })).toBeInTheDocument();
  expect(getNamingAssetExposure).toHaveBeenCalledTimes(1);
  expect(getSeeds).toHaveBeenCalledTimes(1);

  expect(screen.queryByTestId("supporting-intelligence")).not.toBeInTheDocument();
  expect(within(overviewContent).getByText("Ownership & asset composition")).toBeInTheDocument();
  expect(within(overviewContent).getByText("Brand discovery")).toBeInTheDocument();
  expect(within(overviewContent).getByRole("link", { name: "Open Needs Verification (10)" })).toHaveAttribute(
    "href", "#/assets?discovery_source=brand_union&asset_class=CANDIDATE&limit=25"
  );
  expect(within(overviewContent).getByText("HTTP status distribution")).toBeInTheDocument();
  expect(within(overviewContent).getByText("Naming exposure")).toBeInTheDocument();
  Date.now.mockRestore();
});

test("main Overview separates current and previously High Risk with scan context and correct destinations", async () => {
  getV2Overview.mockResolvedValue(overview);
  getV2Scans.mockResolvedValue({ scans: [{ scan_id: 42, status: "SUCCEEDED", completed_at: "2026-09-26T10:00:00Z", is_current_authoritative: true }] });
  getRiskHistorySummary.mockResolvedValue({ availability_state: "AVAILABLE", latest_successful_scan_id: 42, current_high_assets: 1, historical_unique_high_assets: 19 });
  getCertExpiry.mockResolvedValue([]);
  getSeeds.mockResolvedValue([]);
  getDiscoverySources.mockResolvedValue({ "Pentest Tool": 1, "SAN Expansion": 0, "Brand Expansion": 0 });
  getExposureSummary.mockResolvedValue({ scan_id: 42, resolving_domains: 0 });
  render(<App />);

  const current = await screen.findByRole("link", { name: /Current High Risk/ });
  const historical = screen.getByRole("link", { name: /Previously High Risk/ });
  expect(current).toHaveTextContent("1");
  expect(current).toHaveTextContent("Current scan #42");
  expect(current).toHaveAttribute("href", "#/risk/security-review?tab=prioritized-assets");
  expect(historical).toHaveTextContent("19");
  expect(historical).toHaveTextContent("latest #42");
  expect(historical).toHaveAttribute("href", "#/risk?section=historical-high-risk");
});

test("keeps historical and current coverage unavailable when their source contracts are incomplete", async () => {
  getV2Overview.mockResolvedValue({
    ...overview,
    counts: { organizational: 6, known: 4, shadow: 2, candidate: 3, external: 0 },
  });
  getDiscoverySources.mockResolvedValue({ "Pentest Tool": 10, "SAN Expansion": 5 });
  getExposureSummary.mockResolvedValue({ scan_id: 41, resolving_domains: 99 });
  render(<App />);

  expect(await screen.findByText("Asset Coverage")).toBeInTheDocument();
  const coveragePanel = screen.getByRole("heading", { name: "Asset Coverage" }).closest("section");
  expect(within(coveragePanel).getByText("9")).toBeInTheDocument();
  expect(within(coveragePanel).getByText("6")).toBeInTheDocument();
  expect(within(coveragePanel).getByText("All-time domains").parentElement).toHaveTextContent("Unavailable");
  expect(within(coveragePanel).queryByText("External")).not.toBeInTheDocument();
  expect(screen.getByRole("link", { name: /Assets with IP Addresses/ })).toHaveTextContent("Unavailable");
  const discoveryPanel = screen.getByRole("heading", { name: "Discovery Sources" }).closest("section");
  expect(within(discoveryPanel).getByText("Brand Exposure").parentElement).toHaveTextContent("—");
  expect(getV2Overview).toHaveBeenCalledTimes(1);
  expect(getDiscoverySources).toHaveBeenCalledTimes(1);
  expect(getExposureSummary).toHaveBeenCalledTimes(1);
});

test("marks reconciled current totals unavailable when effective classes do not add up", async () => {
  getV2Overview.mockResolvedValue({
    ...overview,
    counts: { organizational: 9, known: 4, shadow: 3, candidate: 2, external: 1 },
  });
  getDiscoverySources.mockResolvedValue({ "Pentest Tool": 10, "SAN Expansion": 5, "Brand Expansion": 2 });
  getExposureSummary.mockResolvedValue({ scan_id: 42, resolving_domains: 14 });
  render(<App />);

  const coveragePanel = (await screen.findByRole("heading", { name: "Asset Coverage" })).closest("section");
  expect(await within(coveragePanel).findByText("Organizational assets")).toBeInTheDocument();
  expect(within(coveragePanel).getAllByText("Unavailable")).toHaveLength(2);
  expect(within(coveragePanel).getByText("Known")).toBeInTheDocument();
  expect(within(coveragePanel).getByText("Shadow")).toBeInTheDocument();
  expect(within(coveragePanel).getByText("Needs Verification")).toBeInTheDocument();
  expect(within(coveragePanel).getByText("External")).toBeInTheDocument();
});

test("shows no-authoritative-scan state without fabricating values", async () => {
  getV2Overview.mockResolvedValue({
    ...overview,
    current_scan_id: null,
    previous_scan_id: null,
    counts: { organizational: 0, known: 0, shadow: 0, candidate: 0, external: 0 },
    risk_distribution: { High: 0, Elevated: 0, Review: 0, Low: 0 },
    changes: { new_assets: 0, disappeared_assets: 0 },
    needs_attention: [],
  });
  render(<App />);

  expect(await screen.findByText("No authoritative scan yet")).toBeInTheDocument();
  expect(screen.queryByText("alpha.example")).not.toBeInTheDocument();
});

test("redirects the legacy Needs Attention overview route to Prioritized Assets", async () => {
  window.location.hash = "#/overview/needs-attention";
  getV2Overview.mockResolvedValue(overview);
  getV2Assets.mockResolvedValue(rankedAssetPage);
  render(<App />);

  expect(await screen.findByText("alpha.example")).toBeInTheDocument();
  expect(screen.getByText("Current positive-score assets ranked by deterministic risk")).toBeInTheDocument();
  expect(screen.getByText("1 RANKED ASSETS")).toBeInTheDocument();
  expect(screen.getByText("alpha.example").closest("a")).toHaveAttribute(
    "href", "#/assets/alpha.example?return=risk%2Fsecurity-review&return_query=tab%3Dprioritized-assets%26priority_page%3D1"
  );
  expect(window.location.hash).toBe("#/risk/security-review?tab=prioritized-assets");
  expect(screen.getByRole("tab", { name: "Prioritized Assets" })).toHaveAttribute("aria-selected", "true");
  expect(getV2Overview).toHaveBeenCalledTimes(1);
});

test("redirects the legacy Risk Distribution route to Risk Overview", async () => {
  window.location.hash = "#/overview/risk-distribution";
  getV2Overview.mockResolvedValue(overview);
  getV2Assets.mockResolvedValue(rankedAssetPage);
  getFindings.mockResolvedValue([]);
  getSensitiveExposure.mockResolvedValue([]);
  getExposureSummary.mockResolvedValue({ resolving_domains: 8, http_responding_domains: 6 });
  getV2ReviewIndicators.mockResolvedValue({ scan_id: 42, count: 0, indicators: [] });
  getHttpStatus.mockResolvedValue(null);
  getRiskHistorySummary.mockResolvedValue({ availability_state: "UNAVAILABLE" });
  render(<App />);

  expect(await screen.findByRole("heading", { name: "Risk distribution" })).toBeInTheDocument();
  expect(screen.getByRole("tab", { name: "Risk distribution" })).toHaveAttribute("aria-selected", "true");
  expect(screen.getByRole("link", { name: /High 1/ })).toHaveAttribute("href", "#/assets?priority=High&limit=25");
  expect(window.location.hash).toBe("#/risk?section=risk-distribution");
  expect(getV2Overview).toHaveBeenCalledTimes(1);
});

test("redirects the direct legacy Needs Attention route to Prioritized Assets", async () => {
  window.location.hash = "#/risk/needs-attention";
  getV2Overview.mockResolvedValue(overview);
  getV2Assets.mockResolvedValue(rankedAssetPage);
  render(<App />);

  expect(await screen.findByText("Prioritized assets")).toBeInTheDocument();
  expect(window.location.hash).toBe("#/risk/security-review?tab=prioritized-assets");
  expect(screen.getByRole("tab", { name: "Prioritized Assets" })).toHaveAttribute("aria-selected", "true");
});

test("redirects the legacy Review Queue URL to Prioritized Assets with compatible pagination", async () => {
  window.location.hash = "#/risk/security-review?tab=review-queue&page=2&limit=25";
  getV2Overview.mockResolvedValue(overview);
  getV2Assets.mockResolvedValue({ ...rankedAssetPage, page: 2, limit: 25, count: 51 });
  render(<App />);

  expect(await screen.findByText("51 RANKED ASSETS")).toBeInTheDocument();
  expect(getV2Assets).toHaveBeenCalledWith({
    page: 2,
    limit: 25,
    risk_positive: true,
    sort_by: "risk_score",
    sort_dir: "desc",
  });
  expect(window.location.hash).toBe("#/risk/security-review?tab=prioritized-assets&priority_page=2");
  expect(screen.getByRole("tab", { name: "Prioritized Assets" })).toHaveAttribute("aria-selected", "true");
});

test("Security Review keeps stable accessible tabs and preserves tab navigation", async () => {
  window.location.hash = "#/risk/security-review";
  getV2Overview.mockResolvedValue(overview);
  getV2Assets.mockResolvedValue(rankedAssetPage);
  getSecurityFindingsSummary.mockResolvedValue({ availability_state: "AVAILABLE", scan_id: 42, counts_by_category: {} });
  getSecurityFindings.mockResolvedValue({ availability_state: "AVAILABLE", scan_id: 42, findings: [], total: 0 });
  render(<App />);

  const prioritized = await screen.findByRole("tab", { name: "Prioritized Assets" });
  const evidence = screen.getByRole("tab", { name: "Evidence & Signals" });
  expect(prioritized).toHaveAttribute("aria-selected", "true");
  expect(evidence).toHaveAttribute("aria-selected", "false");
  expect(screen.queryByRole("tab", { name: "Review Queue" })).not.toBeInTheDocument();
  expect(screen.getByText("alpha.example")).toBeInTheDocument();
  expect(getV2Assets).toHaveBeenLastCalledWith({
    page: 1, limit: 25, risk_positive: true, sort_by: "risk_score", sort_dir: "desc",
  });

  fireEvent.click(evidence);
  expect(window.location.hash).toBe("#/risk/security-review?tab=evidence-signals");
  expect(await screen.findByText("Evidence records")).toBeInTheDocument();
  expect(evidence).toHaveAttribute("aria-selected", "true");

  fireEvent.keyDown(evidence, { key: "ArrowRight" });
  expect(window.location.hash).toBe("#/risk/security-review?tab=prioritized-assets");
  expect(await screen.findByText("Prioritized assets")).toBeInTheDocument();
  expect(prioritized).toHaveAttribute("aria-selected", "true");
  expect(getV2Assets).toHaveBeenLastCalledWith({
    page: 1, limit: 25, risk_positive: true, sort_by: "risk_score", sort_dir: "desc",
  });
});

test("redirects the legacy Settings route to Overview without placeholder content", async () => {
  window.location.hash = "#/settings";
  getV2Overview.mockResolvedValue(overview);
  render(<App />);

  expect(window.location.hash).toBe("#/overview");
  expect(await screen.findByText("Brand discovery")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Overview" })).toHaveAttribute("aria-current", "page");
  expect(screen.queryByRole("link", { name: "Settings" })).not.toBeInTheDocument();
  expect(screen.queryByText("FUTURE")).not.toBeInTheDocument();
  expect(screen.queryByText(/Scheduled for a later Frontend V2 phase|This navigation destination is reserved/)).not.toBeInTheDocument();
});

test("shows an API error and retries the overview request", async () => {
  getV2Overview.mockRejectedValueOnce(new Error("offline")).mockResolvedValueOnce(overview);
  render(<App />);

  expect(await screen.findByText("Overview unavailable")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Retry request" }));

  expect(await screen.findByText("Brand discovery")).toBeInTheDocument();
  await waitFor(() => expect(getV2Overview).toHaveBeenCalledTimes(2));
});
