import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import App from "./App";
import { getAssetGrowth, getCertExpiry, getHttpStatus, getNamingAssetExposure, getV2BrandAssets, getV2Overview, getV2Scans } from "./services/api";

jest.mock("./services/api", () => ({
  getV2Overview: jest.fn(),
  getAssetGrowth: jest.fn(),
  getCertExpiry: jest.fn(),
  getHttpStatus: jest.fn(),
  getV2Assets: jest.fn(),
  getV2AssetDetail: jest.fn(),
  updateV2AssetOwnership: jest.fn(),
  getV2Scans: jest.fn(),
  getV2BrandAssets: jest.fn(),
  getNamingAssetExposure: jest.fn(),
  getV2ReviewIndicators: jest.fn(),
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

beforeEach(() => {
  window.location.hash = "#/overview";
  getV2Overview.mockReset();
  getAssetGrowth.mockReset();
  getV2Scans.mockReset();
  getV2BrandAssets.mockReset();
  getHttpStatus.mockReset();
  getNamingAssetExposure.mockReset();
  getCertExpiry.mockReset();
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
  getV2BrandAssets.mockImplementation(({ asset_class: assetClass }) => Promise.resolve({
    scan_id: 42,
    page: 1,
    limit: 1,
    count: assetClass === "CANDIDATE" ? 3 : 2,
    assets: [],
  }));
  getNamingAssetExposure.mockResolvedValue([
    { keyword: "DEV", count: 2 },
    { keyword: "STAGE", count: 1 },
  ]);
  getCertExpiry.mockResolvedValue([]);
  render(<App />);

  expect(screen.getByText("Loading authoritative state")).toBeInTheDocument();
  expect(await screen.findByText("Brand discovery")).toBeInTheDocument();
  expect(screen.getByText("ShadowRecon")).toBeInTheDocument();
  const kpiStrip = screen.getByRole("region", { name: "Overview metrics" });
  expect([...kpiStrip.querySelectorAll(".metric-label")].map((node) => node.textContent)).toEqual([
    "Organizational assets",
    "High risk",
    "Shadow assets",
    "New assets",
  ]);
  expect(within(kpiStrip).queryByText("Brand perimeter")).not.toBeInTheDocument();
  expect(screen.getByText("scan 41 → 42")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Overview" })).toHaveAttribute("aria-current", "page");
  expect(screen.getByRole("link", { name: "Overview" })).toHaveAttribute("href", "#/overview");
  expect(screen.getByRole("link", { name: "Asset Inventory" })).toHaveAttribute("href", "#/assets");
  expect(screen.getByRole("link", { name: "Shadow Assets" })).toHaveAttribute("href", "#/shadow");
  expect(screen.getByRole("link", { name: "Risk & Exposure" })).toHaveAttribute("href", "#/risk");
  expect(screen.getByRole("link", { name: "Needs Attention" })).toHaveAttribute("href", "#/risk/needs-attention");
  expect(screen.getByRole("link", { name: "Brand Exposure" })).toHaveAttribute("href", "#/brand");
  expect(screen.getByRole("link", { name: "Scan Centre" })).toHaveAttribute("href", "#/scans");
  expect(screen.getByRole("link", { name: "Adhoc Checks" })).toHaveAttribute("href", "#/adhoc/php-rce");
  expect(screen.getByRole("link", { name: "Investigate" })).toHaveAttribute("href", "#/investigate");
  expect(screen.queryByText("Asset Discovery")).not.toBeInTheDocument();
  expect(screen.queryByRole("link", { name: "Dashboard" })).not.toBeInTheDocument();
  expect(screen.queryByRole("link", { name: "Risk Distribution" })).not.toBeInTheDocument();
  expect(document.querySelectorAll(".nav-group")).toHaveLength(3);
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
  expect(screen.getByRole("link", { name: "Open Known assets" })).toHaveAttribute("href", "#/assets?asset_class=KNOWN&limit=25");
  expect(screen.getByRole("link", { name: "Open Shadow assets" })).toHaveAttribute("href", "#/shadow");
  expect(screen.getByRole("link", { name: "Open Needs Verification assets" })).toHaveAttribute("href", "#/assets?asset_class=CANDIDATE&limit=25");
  expect(screen.getByRole("link", { name: "Open External assets" })).toHaveAttribute("href", "#/brand?ownership=EXTERNAL");
  const overviewContent = document.querySelector(".page-content-overview");
  expect(within(overviewContent).queryByText("Needs attention")).not.toBeInTheDocument();
  expect(within(overviewContent).queryByText("Risk distribution")).not.toBeInTheDocument();
  expect(within(overviewContent).getByText("Asset growth trend")).toBeInTheDocument();
  const certificatePanel = screen.getByText("Certificate health").closest("section");
  const changedPanel = screen.getByText("What changed").closest("section");
  const discoveryPanel = screen.getByText("Discovery & validation").closest("section");
  expect(certificatePanel).toHaveClass("certificate-health-panel");
  expect(changedPanel).toHaveClass("change-panel");
  expect(discoveryPanel).toHaveClass("discovery-validation-panel");
  const assetGrowthPanel = screen.getByText("Asset growth trend").closest("section");
  expect(assetGrowthPanel.compareDocumentPosition(changedPanel) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expect(changedPanel.compareDocumentPosition(certificatePanel) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expect(changedPanel.compareDocumentPosition(discoveryPanel) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expect(getCertExpiry).toHaveBeenCalledTimes(1);
  expect(screen.getByText("Discovery & validation")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Open Brand Exposure Needs Verification assets (3)" })).toHaveAttribute(
    "href",
    "#/brand?ownership=CANDIDATE"
  );
  expect(screen.getByText("Naming exposure")).toBeInTheDocument();
  expect(screen.getByLabelText("DEV: 2 matching confirmed assets")).toBeInTheDocument();
  expect(getNamingAssetExposure).toHaveBeenCalledTimes(1);

  expect(screen.queryByTestId("supporting-intelligence")).not.toBeInTheDocument();
  expect(within(overviewContent).getByText("Ownership & asset composition")).toBeInTheDocument();
  expect(within(overviewContent).getByText("Brand discovery")).toBeInTheDocument();
  expect(within(overviewContent).getByRole("link", { name: "Open Brand-related domains (32)" })).toHaveAttribute(
    "href", "#/assets?discovery_source=brand_union&limit=25"
  );
  expect(within(overviewContent).getByRole("link", { name: "Open Needs Verification (10)" })).toHaveAttribute(
    "href", "#/assets?discovery_source=brand_union&asset_class=CANDIDATE&limit=25"
  );
  expect(within(overviewContent).getByText("HTTP status distribution")).toBeInTheDocument();
  expect(within(overviewContent).getByText("Naming exposure")).toBeInTheDocument();
  Date.now.mockRestore();
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

test("redirects the legacy Needs Attention overview route to the consolidated risk page", async () => {
  window.location.hash = "#/overview/needs-attention";
  getV2Overview.mockResolvedValue(overview);
  render(<App />);

  expect(await screen.findByText("alpha.example")).toBeInTheDocument();
  expect(screen.getByText("Highest deterministic risk scores in the current surface")).toBeInTheDocument();
  expect(screen.getByText("TOP 10")).toBeInTheDocument();
  expect(screen.getByText("alpha.example").closest("a")).toHaveAttribute(
    "href", "#/assets/alpha.example?return=risk%2Fneeds-attention"
  );
  expect(window.location.hash).toBe("#/risk/needs-attention");
  expect(screen.getByRole("link", { name: "Needs Attention" })).toHaveAttribute("aria-current", "page");
  expect(getV2Overview).toHaveBeenCalledTimes(1);
});

test("renders the consolidated Risk Distribution section after Needs Attention", async () => {
  window.location.hash = "#/overview/risk-distribution";
  getV2Overview.mockResolvedValue(overview);
  render(<App />);

  expect(await screen.findByText("Risk distribution")).toBeInTheDocument();
  expect(screen.getByText("Needs attention").compareDocumentPosition(screen.getByText("Risk distribution")) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expect(screen.getByText("Canonical priorities across confirmed organizational assets")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: /High 1/ })).toHaveAttribute("href", "#/assets?priority=High");
  expect(screen.getByRole("link", { name: /Low 11/ })).toHaveAttribute("href", "#/assets?priority=Low");
  expect(window.location.hash).toBe("#/risk/needs-attention");
  expect(screen.getByRole("link", { name: "Needs Attention" })).toHaveAttribute("aria-current", "page");
  expect(getV2Overview).toHaveBeenCalledTimes(1);
});

test("renders the direct consolidated Needs Attention route", async () => {
  window.location.hash = "#/risk/needs-attention";
  getV2Overview.mockResolvedValue(overview);
  render(<App />);

  expect(await screen.findByText("Needs attention")).toBeInTheDocument();
  expect(screen.getByText("Risk distribution")).toBeInTheDocument();
  expect(window.location.hash).toBe("#/risk/needs-attention");
  expect(screen.getByRole("link", { name: "Needs Attention" })).toHaveAttribute("aria-current", "page");
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
