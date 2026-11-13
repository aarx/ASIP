import { fireEvent, render, screen, within } from "@testing-library/react";
import App from "./App";
import {
  getExposureSummary,
  getFindings,
  getDnsSecuritySummary,
  getHttpStatus,
  getRiskHistoryAssets,
  getRiskHistorySummary,
  getSensitiveExposure,
  getV2Assets,
  getV2Overview,
  getV2ReviewIndicators,
  getV2ScanDetail,
  getV2Scans,
  exportV2ScanReport,
} from "./services/api";

jest.mock("./services/api", () => ({
  getV2Overview: jest.fn(),
  getV2Assets: jest.fn(),
  getV2AssetDetail: jest.fn(),
  updateV2AssetOwnership: jest.fn(),
  getV2ScanDetail: jest.fn(),
  getV2Scans: jest.fn(),
  exportV2ScanReport: jest.fn(),
  getV2BrandAssets: jest.fn(),
  getV2ReviewIndicators: jest.fn(),
  getHttpStatus: jest.fn(),
  getV2AssetAssistant: jest.fn(),
  getInvestigationAssets: jest.fn(),
  getNewDomainsDelta: jest.fn(),
  getDisappearedDomains: jest.fn(),
  getFindings: jest.fn(),
  getSensitiveExposure: jest.fn(),
  getExposureSummary: jest.fn(),
  getDnsSecuritySummary: jest.fn(),
  getRiskHistoryAssets: jest.fn(),
  getRiskHistorySummary: jest.fn(),
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
  counts: { organizational: 10, known: 6, shadow: 4, candidate: 2, external: 1 },
  risk_distribution: { High: 1, Elevated: 2, Review: 3, Low: 4 },
  changes: { new_assets: 2, disappeared_assets: 1 },
  needs_attention: [],
};

beforeEach(() => {
  [
    getExposureSummary,
    getDnsSecuritySummary,
    getFindings,
    getHttpStatus,
    getRiskHistoryAssets,
    getRiskHistorySummary,
    getSensitiveExposure,
    getV2Assets,
    getV2Overview,
    getV2ReviewIndicators,
    getV2ScanDetail,
    getV2Scans,
    exportV2ScanReport,
  ].forEach((mockFunction) => mockFunction.mockReset());
});

test("risk workspace presents exact metrics and separate review evidence", async () => {
  window.location.hash = "#/risk?section=review-indicators";
  const scrollIntoView = jest.fn();
  Element.prototype.scrollIntoView = scrollIntoView;
  getV2Overview.mockResolvedValue(overview);
  getV2Assets.mockResolvedValue({
    scan_id: 42,
    page: 1,
    limit: 25,
    count: 1,
    assets: [{
      domain: "critical.example.com",
      risk: { score: 9, priority: "High", reasons: ["finding", "sensitive_ports"] },
    }],
  });
  getFindings.mockResolvedValue([{
    domain: "critical.example.com",
    finding: "takeover_indicator",
    severity: "HIGH",
    evidence: "deterministic fingerprint match",
  }]);
  getSensitiveExposure.mockResolvedValue([{
    domain: "critical.example.com", port: 22, risk: 4, service: "SSH administration",
  }]);
  getExposureSummary.mockResolvedValue({
    scan_id: 42, total_domains: 10, resolving_domains: 8, http_responding_domains: 6,
  });
  getHttpStatus.mockResolvedValue({ "2xx": 4, "3xx": 2, "4xx": 1, "5xx": 0 });
  getV2ReviewIndicators.mockResolvedValue({
    scan_id: 42,
    count: 2,
    indicators: [
      {
        type: "CROSS_HOST_HTTP_REDIRECT",
        domain: "critical.example.com",
        ownership_status: "CONFIRMED",
        asset_class: "SHADOW",
        http_observation_status: "RESPONDED",
        http_status: 302,
        final_url: "https://external.example/login",
        observed_redirect_destination: "https://external.example/login",
        final_url_verification: "UNRESOLVED",
        final_status: 200,
        final_hostname: "external.example",
        destination_confirmed: false,
        destination_asset_class: null,
      },
      {
        type: "CROSS_HOST_HTTP_REDIRECT",
        domain: "known.example.com",
        ownership_status: "CONFIRMED",
        asset_class: "KNOWN",
        http_observation_status: "RESPONDED",
        http_status: 301,
        final_url: "https://portal.example.com/home",
        observed_redirect_destination: "https://portal.example.com/home",
        final_url_verification: "COMPLETE",
        final_status: 200,
        final_hostname: "portal.example.com",
        destination_confirmed: true,
        destination_asset_class: "KNOWN",
      },
    ],
  });

  render(<App />);

  expect(screen.getByRole("heading", { name: "Risk Overview" })).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Risk Overview" })).toHaveAttribute("href", "#/risk");
  expect((await screen.findAllByText("critical.example.com"))[0]).toBeInTheDocument();
  const primaryKpis = screen.getByRole("region", { name: "Risk and exposure metrics" });
  expect([...primaryKpis.querySelectorAll(".metric-label")].map((node) => node.textContent)).toEqual([
    "Current High Risk", "Assets with risk scores", "HTTP responding", "Previously High Risk",
  ]);
  const actionableKpis = screen.getByRole("region", { name: "Actionable evidence" });
  expect([...actionableKpis.querySelectorAll(".metric-label")].map((node) => node.textContent)).toEqual([
    "Findings", "Observed sensitive-port exposures", "Review Indicators",
  ]);
  expect(screen.queryByText("Discovery Sources")).not.toBeInTheDocument();
  expect(screen.queryByText("Risk distribution")).not.toBeInTheDocument();
  expect(screen.queryByRole("link", { name: /Assets with IP addresses/ })).not.toBeInTheDocument();
  expect(screen.getByRole("link", { name: /HTTP responding/ })).toHaveAttribute("href", "#/assets?http_live=true");
  expect(screen.queryByRole("link", { name: "High 1" })).not.toBeInTheDocument();
  expect(screen.getByRole("link", { name: "2xx 4" })).toHaveAttribute("href", "#/assets?http_status_group=2xx");
  expect(screen.getByRole("link", { name: "3xx 2" })).toHaveAttribute("href", "#/assets?http_status_group=3xx");
  expect(screen.getByRole("link", { name: "4xx 1" })).toHaveAttribute("href", "#/assets?http_status_group=4xx");
  expect(screen.getByRole("link", { name: "5xx 0" })).toHaveAttribute("href", "#/assets?http_status_group=5xx");
  expect(screen.getByRole("heading", { name: "Supporting evidence" })).toBeInTheDocument();
  expect(screen.queryByText("Secondary evidence")).not.toBeInTheDocument();
  expect(screen.queryByText("Review observations separately from ranked risk.")).not.toBeInTheDocument();
  expect(screen.getAllByText("Review Indicators")).toHaveLength(2);
  const needsReviewTab = screen.getByRole("tab", { name: "Needs review" });
  expect(needsReviewTab).toHaveAttribute("aria-selected", "true");
  expect(needsReviewTab).toHaveAttribute("aria-controls", "review-indicators");
  expect(document.getElementById("review-indicators")).toHaveAttribute("aria-labelledby", "review-indicators-tab");
  expect(screen.getByText("https://external.example/login")).toBeInTheDocument();
  expect(screen.getByText("No current asset match")).toBeInTheDocument();
  expect(screen.getByText("Current scan asset match")).toBeInTheDocument();
  expect(screen.getAllByText("Review only · not a vulnerability conclusion")).toHaveLength(2);
  expect(screen.getByText("Redirect does not establish ownership or authorization")).toBeInTheDocument();
  const actionable = screen.getByRole("region", { name: "Actionable evidence" });
  expect(actionable.querySelector('a[href="#/risk/security-review?tab=evidence-signals"]')).toBeInTheDocument();
  expect(actionable.querySelector('a[href="#/risk?section=sensitive-ports"]')).toBeInTheDocument();
  expect(actionable.querySelector('a[href="#/risk?section=review-indicators"]')).toBeInTheDocument();
  expect(document.getElementById("review-indicators")).toBeInTheDocument();
  expect(screen.queryByRole("tab", { name: "Findings" })).not.toBeInTheDocument();
  const sensitivePortsTab = screen.getByRole("tab", { name: "Sensitive ports" });
  fireEvent.keyDown(needsReviewTab, { key: "ArrowRight" });
  expect(sensitivePortsTab).toHaveAttribute("aria-selected", "true");
  expect(document.getElementById("sensitive-ports")).toBeInTheDocument();
  expect(screen.getByText("SSH administration")).toBeInTheDocument();
  expect(screen.getByText("Sensitivity 4")).toBeInTheDocument();
  fireEvent.keyDown(sensitivePortsTab, { key: "Home" });
  expect(needsReviewTab).toHaveAttribute("aria-selected", "true");
  expect(screen.getByText("https://external.example/login")).toBeInTheDocument();
  expect(scrollIntoView).toHaveBeenCalled();
  const criticalAssetLinks = screen.getAllByRole("link", { name: "Open critical.example.com" });
  expect(criticalAssetLinks.some((link) => link.getAttribute("href") === "#/assets/critical.example.com?return=risk")).toBe(true);
  expect(screen.getByRole("link", { name: /Open Prioritized Assets/ })).toHaveAttribute(
    "href", "#/risk/security-review?tab=prioritized-assets"
  );
});

test("Risk Overview exposes DNS coverage without treating partial evidence as a vulnerability verdict", async () => {
  window.location.hash = "#/risk?view=dns-security";
  getV2Overview.mockResolvedValue(overview);
  getV2Assets.mockResolvedValue({ scan_id: 42, page: 1, limit: 25, count: 0, assets: [] });
  getFindings.mockResolvedValue([]);
  getSensitiveExposure.mockResolvedValue([]);
  getExposureSummary.mockResolvedValue({ scan_id: 42, resolving_domains: 8, http_responding_domains: 6 });
  getV2ReviewIndicators.mockResolvedValue({ scan_id: 42, count: 0, indicators: [] });
  getHttpStatus.mockResolvedValue(null);
  getDnsSecuritySummary.mockResolvedValue({
    scan_id: 42,
    availability_state: "AVAILABLE",
    execution_state: "SUCCEEDED",
    operation_enabled_currently: false,
    eligible_assets: 10,
    checked_assets: 4,
    unchecked_assets: 6,
    affected_assets: 2,
  });

  render(<App />);

  expect(await screen.findByRole("tab", { name: "DNS assessments" })).toHaveAttribute("aria-selected", "true");
  expect(screen.getByText("Partial coverage")).toBeInTheDocument();
  expect(screen.getByText("4 of 10 eligible assets assessed.")).toBeInTheDocument();
  expect(screen.queryByText("HISTORICAL SCAN #42")).not.toBeInTheDocument();
  expect(screen.getByText("SCAN #42")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Open DNS Security details →" })).toHaveAttribute("href", "#/risk/dns-security");
  expect(screen.queryByText(/confirmed vulnerability/i)).not.toBeInTheDocument();
  expect(getDnsSecuritySummary).toHaveBeenCalledTimes(1);
});

test("reports capped sensitive-port observations without presenting an exact total", async () => {
  window.location.hash = "#/risk?view=sensitive-ports";
  getV2Overview.mockResolvedValue(overview);
  getV2Assets.mockResolvedValue({ scan_id: 42, page: 1, limit: 25, count: 0, assets: [] });
  getFindings.mockResolvedValue([]);
  getSensitiveExposure.mockResolvedValue(Array.from({ length: 20 }, (_, index) => ({
    domain: `port-${index}.example.com`, port: 20 + index, risk: 3, service: "Observed service",
  })));
  getExposureSummary.mockResolvedValue({ scan_id: 42, resolving_domains: 8, http_responding_domains: 6 });
  getV2ReviewIndicators.mockResolvedValue({ scan_id: 42, count: 0, indicators: [] });
  getHttpStatus.mockResolvedValue(null);
  getDnsSecuritySummary.mockResolvedValue(null);

  render(<App />);

  expect(await screen.findByText("20+ OBSERVED")).toBeInTheDocument();
  expect(screen.getByText("Observed rows · result list capped at 20")).toBeInTheDocument();
  expect(screen.getByText("20+")).toBeInTheDocument();
  expect(screen.queryByText("20 ROWS")).not.toBeInTheDocument();
});

test("does not describe an empty sensitive-port result as a clean assessment", async () => {
  window.location.hash = "#/risk?view=sensitive-ports";
  getV2Overview.mockResolvedValue(overview);
  getV2Assets.mockResolvedValue({ scan_id: 42, page: 1, limit: 25, count: 0, assets: [] });
  getFindings.mockResolvedValue([]);
  getSensitiveExposure.mockResolvedValue([]);
  getExposureSummary.mockResolvedValue({ scan_id: 42, resolving_domains: 8, http_responding_domains: 6 });
  getV2ReviewIndicators.mockResolvedValue({ scan_id: 42, count: 0, indicators: [] });
  getHttpStatus.mockResolvedValue(null);
  getDnsSecuritySummary.mockResolvedValue(null);

  render(<App />);

  expect(await screen.findByText("No port observations recorded for this scan.")).toBeInTheDocument();
  expect(screen.getByText("Assessment coverage unavailable")).toBeInTheDocument();
  expect(screen.queryByText(/clean assessment/i)).not.toBeInTheDocument();
});

test("Risk Overview labels DNS evidence from a non-authoritative scan as historical", async () => {
  window.location.hash = "#/risk?view=dns-security";
  getV2Overview.mockResolvedValue(overview);
  getV2Assets.mockResolvedValue({ scan_id: 42, page: 1, limit: 25, count: 0, assets: [] });
  getFindings.mockResolvedValue([]);
  getSensitiveExposure.mockResolvedValue([]);
  getExposureSummary.mockResolvedValue({ scan_id: 42, resolving_domains: 8, http_responding_domains: 6 });
  getV2ReviewIndicators.mockResolvedValue({ scan_id: 42, count: 0, indicators: [] });
  getHttpStatus.mockResolvedValue(null);
  getDnsSecuritySummary.mockResolvedValue({
    scan_id: 41,
    availability_state: "AVAILABLE",
    execution_state: "SUCCEEDED",
    operation_enabled_currently: false,
    eligible_assets: 3,
    checked_assets: 0,
    unchecked_assets: 3,
    affected_assets: 0,
  });

  render(<App />);

  expect(await screen.findByText("HISTORICAL SCAN #41")).toBeInTheDocument();
  expect(screen.getAllByText("Not Assessed").length).toBeGreaterThan(0);
});

test("Security Review prioritizes the exact positive-risk count and paginates the ranked queue", async () => {
  window.location.hash = "#/risk/security-review?tab=prioritized-assets";
  getV2Overview.mockResolvedValue(overview);
  getFindings.mockResolvedValue([]);
  getSensitiveExposure.mockResolvedValue([]);
  getExposureSummary.mockResolvedValue({ resolving_domains: 8, http_responding_domains: 6 });
  getV2ReviewIndicators.mockResolvedValue({ scan_id: 42, count: 0, indicators: [] });
  getHttpStatus.mockResolvedValue(null);
  getV2Assets
    .mockResolvedValueOnce({
      scan_id: 42, page: 1, limit: 25, count: 51,
      assets: [{ domain: "first.example.com", risk: { score: 9, priority: "High", reasons: ["finding"] } }],
    })
    .mockResolvedValueOnce({
      scan_id: 42, page: 2, limit: 25, count: 51,
      assets: [{ domain: "second.example.com", risk: { score: 4, priority: "Review", reasons: ["http_exposed"] } }],
    });

  render(<App />);

  expect(await screen.findByText("51 RANKED ASSETS")).toBeInTheDocument();
  expect(getV2Assets).toHaveBeenCalledWith({
    page: 1, limit: 25, risk_positive: true, sort_by: "risk_score", sort_dir: "desc",
  });
  fireEvent.click(screen.getByRole("button", { name: "Next" }));
  await screen.findByText("second.example.com");
  expect(getV2Assets).toHaveBeenLastCalledWith({
    page: 2, limit: 25, risk_positive: true, sort_by: "risk_score", sort_dir: "desc",
  });
});

test("Risk Overview keeps current High Risk separate from paginated historical High assets", async () => {
  window.location.hash = "#/risk?section=historical-high-risk";
  getV2Overview.mockResolvedValue(overview);
  getV2Assets.mockResolvedValue({ scan_id: 42, page: 1, limit: 25, count: 0, assets: [] });
  getFindings.mockResolvedValue([]);
  getSensitiveExposure.mockResolvedValue([]);
  getExposureSummary.mockResolvedValue({ scan_id: 42, resolving_domains: 8, http_responding_domains: 6 });
  getV2ReviewIndicators.mockResolvedValue({ scan_id: 42, count: 0, indicators: [] });
  getHttpStatus.mockResolvedValue(null);
  getDnsSecuritySummary.mockResolvedValue(null);
  getRiskHistorySummary.mockResolvedValue({
    availability_state: "AVAILABLE",
    latest_successful_scan_id: 19,
    current_high_assets: 0,
    historical_unique_high_assets: 19,
    formerly_high_scoring_assets: 19,
    current_risk_data_coverage: { organizational_members: 829, assets_with_risk_observation: 829, assets_missing_risk_observation: 0, complete: true },
    per_scan: [{ scan_id: 12, organizational_members: 197, assets_with_risk_observation: 91, coverage_complete: false }],
    limitations: ["Missing risk rows are unknown coverage, not Low priority."],
  });
  getRiskHistoryAssets.mockResolvedValue({
    availability_state: "AVAILABLE", latest_successful_scan_id: 19, page: 1, limit: 10, total: 19,
    assets: [{
      domain_id: 101, domain: "historical.example.com", asset_class: "SHADOW",
      first_recorded_high_scan_id: 17, first_recorded_high_scan_time: "2026-11-03T13:00:10.995099",
      last_recorded_high_scan_id: 17, last_recorded_high_scan_time: "2026-11-03T13:00:10.995099",
      maximum_persisted_historical_score: 10, high_score_observations: 1,
      current_scan_member: true, current_risk_score: 3, current_priority: "Low",
    }],
  });

  render(<App />);

  expect(await screen.findByRole("link", { name: /Current High Risk/ })).toHaveTextContent("1");
  const historicalMetric = screen.getByRole("link", { name: /Previously High Risk/ });
  expect(historicalMetric).toHaveTextContent("19");
  expect(historicalMetric).toHaveAttribute("href", "#/risk?section=historical-high-risk");
  expect(await screen.findByText("historical.example.com")).toBeInTheDocument();
  expect(screen.getByText(/19 distinct assets/)).toBeInTheDocument();
  expect(screen.getByText("In current scan")).toBeInTheDocument();
  expect(screen.getByText(/Scan #12: 91 of 197/)).toBeInTheDocument();
  expect(getRiskHistoryAssets).toHaveBeenCalledWith({ page: 1, limit: 10 });
  expect(screen.getByRole("link", { name: "Open historical.example.com" })).toHaveAttribute(
    "href",
    "#/assets/historical.example.com?return=risk&return_query=section%3Dhistorical-high-risk%26historical_page%3D1"
  );
});

test("Security Review priority asset page survives detail navigation and restores from the URL", async () => {
  window.location.hash = "#/risk/security-review?tab=prioritized-assets&priority_page=2";
  getV2Overview.mockResolvedValue(overview);
  getV2Assets
    .mockResolvedValueOnce({ scan_id: 42, page: 2, limit: 25, count: 51, assets: [{ domain: "page-two.example.com", risk: { score: 5, priority: "Elevated", reasons: ["http_exposed"] } }] })
    .mockResolvedValueOnce({ scan_id: 42, page: 3, limit: 25, count: 51, assets: [{ domain: "page-three.example.com", risk: { score: 4, priority: "Review", reasons: ["shadow_asset"] } }] });
  getFindings.mockResolvedValue([]);
  getSensitiveExposure.mockResolvedValue([]);
  getExposureSummary.mockResolvedValue({ scan_id: 42, resolving_domains: 8, http_responding_domains: 6 });
  getV2ReviewIndicators.mockResolvedValue({ scan_id: 42, count: 0, indicators: [] });
  getHttpStatus.mockResolvedValue(null);
  getDnsSecuritySummary.mockResolvedValue(null);
  getRiskHistorySummary.mockResolvedValue({ availability_state: "UNAVAILABLE", per_scan: [] });

  render(<App />);

  expect(await screen.findByText("page-two.example.com")).toBeInTheDocument();
  expect(getV2Assets).toHaveBeenCalledWith({ page: 2, limit: 25, risk_positive: true, sort_by: "risk_score", sort_dir: "desc" });
  expect(screen.getByRole("link", { name: "Open page-two.example.com" })).toHaveAttribute(
    "href",
    "#/assets/page-two.example.com?return=risk%2Fsecurity-review&return_query=tab%3Dprioritized-assets%26priority_page%3D2"
  );

  fireEvent.click(screen.getByRole("button", { name: "Next" }));
  expect(window.location.hash).toBe("#/risk/security-review?tab=prioritized-assets&priority_page=3");
  expect(await screen.findByText("page-three.example.com")).toBeInTheDocument();
  expect(getV2Assets).toHaveBeenLastCalledWith({ page: 3, limit: 25, risk_positive: true, sort_by: "risk_score", sort_dir: "desc" });
  expect(screen.getByRole("link", { name: "Open page-three.example.com" })).toHaveAttribute(
    "href",
    "#/assets/page-three.example.com?return=risk%2Fsecurity-review&return_query=tab%3Dprioritized-assets%26priority_page%3D3"
  );
});

test("historical High pagination preserves the exact total and page context", async () => {
  window.location.hash = "#/risk";
  getV2Overview.mockResolvedValue(overview);
  getV2Assets.mockResolvedValue({ scan_id: 42, page: 1, limit: 25, count: 0, assets: [] });
  getFindings.mockResolvedValue([]);
  getSensitiveExposure.mockResolvedValue([]);
  getExposureSummary.mockResolvedValue({ scan_id: 42, resolving_domains: 8, http_responding_domains: 6 });
  getV2ReviewIndicators.mockResolvedValue({ scan_id: 42, count: 0, indicators: [] });
  getHttpStatus.mockResolvedValue(null);
  getDnsSecuritySummary.mockResolvedValue(null);
  getRiskHistorySummary.mockResolvedValue({ availability_state: "AVAILABLE", historical_unique_high_assets: 19, per_scan: [] });
  getRiskHistoryAssets
    .mockResolvedValueOnce({ availability_state: "AVAILABLE", page: 1, limit: 10, total: 19, assets: [{ domain_id: 1, domain: "first.example.com", asset_class: "KNOWN", maximum_persisted_historical_score: 9, high_score_observations: 2 }] })
    .mockResolvedValueOnce({ availability_state: "AVAILABLE", page: 2, limit: 10, total: 19, assets: [{ domain_id: 2, domain: "last.example.com", asset_class: "SHADOW", maximum_persisted_historical_score: 8, high_score_observations: 1 }] });

  render(<App />);

  expect(await screen.findByText("first.example.com")).toBeInTheDocument();
  expect(screen.getByText("Page 1 of 2 · 19 distinct assets")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Next" }));
  expect(await screen.findByText("last.example.com")).toBeInTheDocument();
  expect(getRiskHistoryAssets).toHaveBeenLastCalledWith({ page: 2, limit: 10 });
  expect(screen.getByText("Page 2 of 2 · 19 distinct assets")).toBeInTheDocument();
});

test("historical High assets remain unavailable when the response is incomplete", async () => {
  window.location.hash = "#/risk";
  getV2Overview.mockResolvedValue(overview);
  getV2Assets.mockResolvedValue({ scan_id: 42, page: 1, limit: 25, count: 0, assets: [] });
  getFindings.mockResolvedValue([]);
  getSensitiveExposure.mockResolvedValue([]);
  getExposureSummary.mockResolvedValue({ scan_id: 42, resolving_domains: 8, http_responding_domains: 6 });
  getV2ReviewIndicators.mockResolvedValue({ scan_id: 42, count: 0, indicators: [] });
  getHttpStatus.mockResolvedValue(null);
  getDnsSecuritySummary.mockResolvedValue(null);
  getRiskHistorySummary.mockResolvedValue({ availability_state: "AVAILABLE", historical_unique_high_assets: 19 });
  getRiskHistoryAssets.mockResolvedValue({ availability_state: "AVAILABLE", page: 1, limit: 10, total: 19, assets: null });

  render(<App />);

  expect(await screen.findByText("Historical High Risk data incomplete")).toBeInTheDocument();
  expect(screen.queryByText("19 distinct assets")).not.toBeInTheDocument();
  expect(screen.queryByText("No persisted High-score assets were recorded in successful scans.")).not.toBeInTheDocument();
});

test("historical High Risk shows unavailable instead of zero when no successful scan exists", async () => {
  window.location.hash = "#/risk";
  getV2Overview.mockResolvedValue(overview);
  getV2Assets.mockResolvedValue({ scan_id: 42, page: 1, limit: 25, count: 0, assets: [] });
  getFindings.mockResolvedValue([]);
  getSensitiveExposure.mockResolvedValue([]);
  getExposureSummary.mockResolvedValue({ scan_id: 42, resolving_domains: 8, http_responding_domains: 6 });
  getV2ReviewIndicators.mockResolvedValue({ scan_id: 42, count: 0, indicators: [] });
  getHttpStatus.mockResolvedValue(null);
  getDnsSecuritySummary.mockResolvedValue(null);
  getRiskHistorySummary.mockResolvedValue({ availability_state: "UNAVAILABLE", historical_unique_high_assets: 0, limitations: ["No successful scans are available."] });

  render(<App />);

  expect(await screen.findByText("Historical High Risk unavailable")).toBeInTheDocument();
  expect(screen.queryByRole("link", { name: /Previously High Risk/ })).not.toBeInTheDocument();
  expect(getRiskHistoryAssets).not.toHaveBeenCalled();
});

test("review indicators have truthful empty and isolated failure states", async () => {
  const baseContracts = () => {
    getV2Overview.mockResolvedValue(overview);
    getV2Assets.mockResolvedValue({ scan_id: 42, page: 1, limit: 25, count: 0, assets: [] });
    getFindings.mockResolvedValue([]);
    getSensitiveExposure.mockResolvedValue([]);
    getExposureSummary.mockResolvedValue({
      scan_id: 42, total_domains: 10, resolving_domains: 8, http_responding_domains: 6,
    });
    getHttpStatus.mockResolvedValue({ "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0 });
  };

  window.location.hash = "#/risk";
  baseContracts();
  getV2ReviewIndicators.mockResolvedValue({ scan_id: 42, count: 0, indicators: [] });
  const empty = render(<App />);
  expect(await screen.findByText("No cross-host HTTP redirects were observed in the current authoritative scan.")).toBeInTheDocument();
  empty.unmount();

  baseContracts();
  getV2ReviewIndicators.mockRejectedValue(new Error("offline"));
  render(<App />);
  expect(await screen.findByRole("alert")).toHaveTextContent("Redirect review evidence could not be loaded");
  expect(screen.queryByText("Risk distribution")).not.toBeInTheDocument();
});

test("review indicators label historical and incomplete redirect evidence without implying a verified chain", async () => {
  window.location.hash = "#/risk?view=review-indicators";
  getV2Overview.mockResolvedValue(overview);
  getV2Assets.mockResolvedValue({ scan_id: 42, page: 1, limit: 25, count: 0, assets: [] });
  getFindings.mockResolvedValue([]);
  getSensitiveExposure.mockResolvedValue([]);
  getExposureSummary.mockResolvedValue({ resolving_domains: 8, http_responding_domains: 6 });
  getHttpStatus.mockResolvedValue(null);
  getV2ReviewIndicators.mockResolvedValue({
    scan_id: 42,
    count: 1,
    indicators: [{
      type: "CROSS_HOST_HTTP_REDIRECT",
      domain: "historical.example.com",
      asset_class: "KNOWN",
      http_observation_status: "RESPONDED",
      http_status: 302,
      final_url: "https://old.example.com/login",
      final_status: 302,
      final_url_verification: "LEGACY_UNKNOWN",
      final_hostname: null,
      destination_confirmed: false,
    }],
  });

  render(<App />);

  expect(await screen.findByText("Historical redirect URL — verification unavailable")).toBeInTheDocument();
  expect(screen.getByText("Initial 302 · Terminal response unavailable")).toBeInTheDocument();
  expect(screen.queryByText("302 → 302")).not.toBeInTheDocument();
  expect(screen.getByText("Hostname unavailable")).toBeInTheDocument();
});

test("Shadow Centre uses effective asset class rather than stored ownership status", async () => {
  window.location.hash = "#/shadow";
  getV2Assets.mockResolvedValue({
    scan_id: 42,
    page: 1,
    limit: 25,
    count: 1,
    assets: [
      {
        domain: "shadow.example.com",
        ownership_status: "CONFIRMED",
        asset_class: "SHADOW",
        first_seen_scan: 42,
        ip: "192.0.2.10",
        http_observation_status: "UNKNOWN",
        http_status: 0,
        provider: null,
        risk: { score: 8, priority: "High", reasons: ["shadow_asset"] },
      },
      {
        domain: "candidate.example.net",
        ownership_status: "CANDIDATE",
        asset_class: "CANDIDATE",
        first_seen_scan: 42,
        risk: null,
      },
      {
        domain: "legacy-outside.example.net",
        ownership_status: "CONFIRMED",
        asset_class: "CANDIDATE",
        first_seen_scan: 5,
        risk: null,
      },
    ],
  });

  render(<App />);

  expect(await screen.findByText("shadow.example.com")).toBeInTheDocument();
  expect(getV2Assets).toHaveBeenCalledWith({ page: 1, limit: 25, asset_class: "SHADOW" });
  expect(screen.getByText("New in scan #42")).toBeInTheDocument();
  expect(screen.getByText("UNKNOWN")).toBeInTheDocument();
  expect(screen.queryByText("candidate.example.net")).not.toBeInTheDocument();
  expect(screen.queryByText("legacy-outside.example.net")).not.toBeInTheDocument();
  expect(screen.queryByText("Mark as Known")).not.toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Open shadow.example.com" })).toHaveAttribute(
    "href", "#/assets/shadow.example.com?return=shadow"
  );
});

test("Scan Centre marks only successful authoritative scans as authoritative", async () => {
  window.location.hash = "#/scans";
  getV2Overview.mockResolvedValue(overview);
  getV2Scans.mockResolvedValue({
    current_authoritative_scan_id: 42,
    previous_authoritative_scan_id: 41,
    scans: [
      { scan_id: 43, status: "RUNNING", started_at: "2026-09-25T13:00:00Z", completed_at: null, duration_seconds: null, asset_count: 2, seed: "example.com", is_current_authoritative: false, is_previous_authoritative: false },
      { scan_id: 42, status: "SUCCEEDED", started_at: "2026-09-25T12:00:00Z", completed_at: "2026-09-25T12:01:00Z", duration_seconds: 60, asset_count: 10, seed: "example.com", is_current_authoritative: true, is_previous_authoritative: false },
      { scan_id: 41, status: "SUCCEEDED", started_at: "2026-09-24T12:00:00Z", completed_at: "2026-09-24T12:00:30Z", duration_seconds: 30, asset_count: 9, seed: "example.com", is_current_authoritative: false, is_previous_authoritative: true },
      { scan_id: 40, status: "FAILED", started_at: "2026-09-23T12:00:00Z", completed_at: "2026-09-23T12:00:10Z", duration_seconds: 10, asset_count: 1, seed: "example.com", is_current_authoritative: false, is_previous_authoritative: false },
      { scan_id: 39, status: "UNKNOWN", started_at: null, completed_at: null, duration_seconds: null, asset_count: 0, seed: "example.com", is_current_authoritative: false, is_previous_authoritative: false },
    ],
  });

  render(<App />);

  expect(await screen.findByText("Scan history")).toBeInTheDocument();
  expect(getV2Scans).toHaveBeenCalledWith(100);
  const historyTable = screen.getByRole("table");
  expect(within(within(historyTable).getByText("#42").closest("tr")).getByText("Current authoritative")).toBeInTheDocument();
  expect(within(within(historyTable).getByText("#41").closest("tr")).getByText("Previous baseline")).toBeInTheDocument();
  ["#43", "#40", "#39"].forEach((scanId) => {
    expect(within(within(historyTable).getByText(scanId).closest("tr")).getByText("Not authoritative")).toBeInTheDocument();
  });
});

test("downloads a historical scan report with the row scan ID and backend filename", async () => {
  window.location.hash = "#/scans";
  getV2Overview.mockResolvedValue(overview);
  getV2Scans.mockResolvedValue({
    current_authoritative_scan_id: 16,
    previous_authoritative_scan_id: 15,
    scans: [
      { scan_id: 16, status: "SUCCEEDED", completed_at: "done", asset_count: 2, is_current_authoritative: true, is_previous_authoritative: false },
      { scan_id: 15, status: "SUCCEEDED", completed_at: "done", asset_count: 2, is_current_authoritative: false, is_previous_authoritative: true },
      { scan_id: 14, status: "FAILED", completed_at: "failed", asset_count: 0, is_current_authoritative: false, is_previous_authoritative: false },
    ],
  });
  const payload = new Blob(["zip"], { type: "application/zip" });
  exportV2ScanReport.mockResolvedValue({
    data: payload,
    headers: { "content-disposition": 'attachment; filename="asip_scan_15_report.zip"' },
  });
  const createObjectURL = jest.fn(() => "blob:scan-report");
  const revokeObjectURL = jest.fn();
  Object.defineProperty(window.URL, "createObjectURL", { configurable: true, value: createObjectURL });
  Object.defineProperty(window.URL, "revokeObjectURL", { configurable: true, value: revokeObjectURL });
  const originalCreateElement = document.createElement.bind(document);
  let downloadLink;
  const createElement = jest.spyOn(document, "createElement").mockImplementation((tagName) => {
    const element = originalCreateElement(tagName);
    if (tagName === "a") downloadLink = element;
    return element;
  });
  const anchorClick = jest.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});

  render(<App />);

  const historicalRow = (await screen.findByRole("button", { name: "Expand scan 15" })).closest("tr");
  expect(within(historicalRow).getByRole("button", { name: "Download report for scan 15" })).toBeInTheDocument();
  expect(within((await screen.findByRole("button", { name: "Expand scan 14" })).closest("tr")).queryByRole("button", { name: "Download report for scan 14" })).not.toBeInTheDocument();
  fireEvent.click(within(historicalRow).getByRole("button", { name: "Download report for scan 15" }));

  expect(await screen.findByText("Download started")).toBeInTheDocument();
  expect(exportV2ScanReport).toHaveBeenCalledWith(15);
  expect(downloadLink.download).toBe("asip_scan_15_report.zip");
  expect(createObjectURL).toHaveBeenCalledWith(payload);
  expect(revokeObjectURL).toHaveBeenCalledWith("blob:scan-report");
  createElement.mockRestore();
  anchorClick.mockRestore();
});

test("prevents duplicate scan report clicks and distinguishes 404 from 409", async () => {
  window.location.hash = "#/scans";
  getV2Overview.mockResolvedValue(overview);
  getV2Scans.mockResolvedValue({
    current_authoritative_scan_id: null,
    previous_authoritative_scan_id: null,
    scans: [{ scan_id: 15, status: "SUCCEEDED", asset_count: 2, is_current_authoritative: false, is_previous_authoritative: false }],
  });
  let resolveDownload;
  exportV2ScanReport.mockReturnValue(new Promise((resolve) => { resolveDownload = resolve; }));
  const anchorClick = jest.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});

  const { unmount } = render(<App />);
  const button = await screen.findByRole("button", { name: "Download report for scan 15" });
  fireEvent.click(button);
  fireEvent.click(button);
  expect(exportV2ScanReport).toHaveBeenCalledTimes(1);
  expect(button).toBeDisabled();
  resolveDownload({ data: new Blob(["zip"]), headers: {} });
  expect(await screen.findByText("Download started")).toBeInTheDocument();
  unmount();
  anchorClick.mockRestore();

  exportV2ScanReport.mockRejectedValueOnce({ response: { status: 409 } });
  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "Download report for scan 15" }));
  expect(await screen.findByText("Report unavailable for this scan.")).toBeInTheDocument();

  exportV2ScanReport.mockRejectedValueOnce({ response: { status: 404 } });
  fireEvent.click(screen.getByRole("button", { name: "Download report for scan 15" }));
  expect(await screen.findByText("Scan report not found.")).toBeInTheDocument();
});

test("Scan Centre loads persistent stage diagnostics on demand", async () => {
  window.location.hash = "#/scans";
  getV2Overview.mockResolvedValue(overview);
  getV2Scans.mockResolvedValue({
    current_authoritative_scan_id: 42,
    previous_authoritative_scan_id: null,
    scans: [{
      scan_id: 42, status: "SUCCEEDED", started_at: "2026-11-01T12:00:00Z",
      completed_at: "2026-11-01T12:01:00Z", duration_seconds: 60,
      asset_count: 10, seed: "example.com", is_current_authoritative: true,
      is_previous_authoritative: false,
    }],
  });
  getV2ScanDetail.mockResolvedValue({
    scan_id: 42,
    status: "SUCCEEDED",
    scan_time: "2026-11-01T12:00:00Z",
    started_at: "2026-11-01T12:00:00Z",
    completed_at: "2026-11-01T12:01:00Z",
    seed: "example.com",
    asset_count: 10,
    duration_seconds: 60,
    diagnostics_available: true,
    current_stage: null,
    stage_attempts: [
      {
        stage: "Recon", order: 0, attempt: 1, status: "FAILED",
        started_at: "2026-11-01T12:00:00Z", completed_at: "2026-11-01T12:00:02Z",
        duration_seconds: 2, error_category: "RETRYABLE_INCOMPLETE",
        worker_summary: { authorization_skips: 2, failed_incomplete: 1 },
      },
      {
        stage: "Recon", order: 0, attempt: 2, status: "SUCCEEDED",
        started_at: "2026-11-01T12:00:03Z", completed_at: "2026-11-01T12:00:12Z",
        duration_seconds: 9, error_category: null,
        worker_summary: { completed_observations: 4 },
      },
    ],
    failure_category: null,
    scan_outcome: { status: "SUCCEEDED", completed_at: "2026-11-01T12:01:00Z", error_category: null },
    diagnostics_last_updated_at: "2026-11-01T12:01:00Z",
  });

  render(<App />);
  expect(await screen.findByText("Scan history")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Expand scan 42" }));
  expect(getV2ScanDetail).toHaveBeenCalledWith(42);
  expect(await screen.findByText("Stage breakdown")).toBeInTheDocument();
  expect(screen.getByText("Completed stages").nextSibling).toHaveTextContent("1");
  expect(screen.getByText("Failed stages").nextSibling).toHaveTextContent("0");
  expect(screen.getByText("Retry attempts").nextSibling).toHaveTextContent("1");
  expect(screen.getByText("Advanced Diagnostics").closest("details")).not.toHaveAttribute("open");
  fireEvent.click(screen.getByText("Advanced Diagnostics"));
  expect(screen.getAllByText("authorization_skips").length).toBe(2);
  expect(screen.getAllByText("RETRYABLE_INCOMPLETE").length).toBe(2);
});

test("Scan Centre shows the current stage for a running scan", async () => {
  window.location.hash = "#/scans";
  getV2Overview.mockResolvedValue(overview);
  getV2Scans.mockResolvedValue({
    current_authoritative_scan_id: null,
    previous_authoritative_scan_id: null,
    scans: [{
      scan_id: 43, status: "RUNNING", started_at: "2026-11-01T12:00:00Z",
      completed_at: null, duration_seconds: null, asset_count: 3,
      seed: "example.com", is_current_authoritative: false, is_previous_authoritative: false,
    }],
  });
  getV2ScanDetail.mockResolvedValue({
    scan_id: 43, status: "RUNNING", scan_time: "2026-11-01T12:00:00Z",
    started_at: "2026-11-01T12:00:00Z", completed_at: null, seed: "example.com",
    asset_count: 3, duration_seconds: 12, diagnostics_available: true,
    current_stage: { stage: "DNS Resolution", order: 6, attempt: 1, started_at: "2026-11-01T12:00:10Z" },
    stage_attempts: [], failure_category: null, scan_outcome: null,
    diagnostics_last_updated_at: "2026-11-01T12:00:12Z",
  });

  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "Expand scan 43" }));
  expect(await screen.findByText("DNS Resolution")).toBeInTheDocument();
  expect(screen.getByText("Current stage").nextSibling).toHaveTextContent("DNS Resolution");
});

test("Scan Centre does not fabricate diagnostics for historical scans", async () => {
  window.location.hash = "#/scans";
  getV2Overview.mockResolvedValue(overview);
  getV2Scans.mockResolvedValue({
    current_authoritative_scan_id: 42,
    previous_authoritative_scan_id: 41,
    scans: [{
      scan_id: 41, status: "SUCCEEDED", started_at: "2026-10-01T12:00:00Z",
      completed_at: "2026-10-01T12:01:00Z", duration_seconds: 60,
      asset_count: 9, seed: "example.com", is_current_authoritative: false,
      is_previous_authoritative: true,
    }],
  });
  getV2ScanDetail.mockResolvedValue({
    scan_id: 41, status: "SUCCEEDED", scan_time: "2026-10-01T12:00:00Z",
    started_at: "2026-10-01T12:00:00Z", completed_at: "2026-10-01T12:01:00Z",
    seed: "example.com", asset_count: 9, duration_seconds: 60,
    diagnostics_available: false, current_stage: null, stage_attempts: null,
    failure_category: null, scan_outcome: null, diagnostics_last_updated_at: null,
  });

  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "Expand scan 41" }));
  expect(await screen.findByText("Diagnostics unavailable")).toBeInTheDocument();
  expect(screen.queryByText("Stage breakdown")).not.toBeInTheDocument();
  expect(screen.queryByText("Completed stages")).not.toBeInTheDocument();
});

test("Scan Centre renders failure categories and final stage outcomes", async () => {
  window.location.hash = "#/scans";
  getV2Overview.mockResolvedValue(overview);
  getV2Scans.mockResolvedValue({
    current_authoritative_scan_id: null,
    previous_authoritative_scan_id: null,
    scans: [{
      scan_id: 44, status: "FAILED", started_at: "2026-11-02T12:00:00Z",
      completed_at: "2026-11-02T12:02:00Z", duration_seconds: 120,
      asset_count: 4, seed: "example.com", is_current_authoritative: false,
      is_previous_authoritative: false,
    }],
  });
  getV2ScanDetail.mockResolvedValue({
    scan_id: 44, status: "FAILED", scan_time: "2026-11-02T12:00:00Z",
    started_at: "2026-11-02T12:00:00Z", completed_at: "2026-11-02T12:02:00Z",
    seed: "example.com", asset_count: 4, duration_seconds: 120,
    diagnostics_available: true, current_stage: null,
    stage_attempts: [
      { stage: "Recon", order: 0, attempt: 1, status: "FAILED", started_at: "start", completed_at: "failed", duration_seconds: 2, error_category: "RETRYABLE_INCOMPLETE", worker_summary: null },
      { stage: "Recon", order: 0, attempt: 2, status: "SUCCEEDED", started_at: "retry", completed_at: "done", duration_seconds: 4, error_category: null, worker_summary: null },
      { stage: "HTTP", order: 7, attempt: 1, status: "TIMED_OUT", started_at: "start", completed_at: "timeout", duration_seconds: 8, error_category: "STAGE_TIMEOUT", worker_summary: null },
      { stage: "Port Scan", order: 9, attempt: 1, status: "CANCELLED", started_at: "start", completed_at: "cancelled", duration_seconds: 1, error_category: "INTERRUPTED", worker_summary: null },
    ],
    failure_category: "SCAN_FAILED",
    scan_outcome: { status: "FAILED", completed_at: "2026-11-02T12:02:00Z", error_category: "SCAN_FAILED" },
    diagnostics_last_updated_at: "2026-11-02T12:02:00Z",
  });

  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "Expand scan 44" }));
  expect(await screen.findByText("Failure category")).toBeInTheDocument();
  expect(screen.getAllByText("SCAN_FAILED")).toHaveLength(1);
  expect(screen.getByText("Completed stages").nextSibling).toHaveTextContent("1");
  expect(screen.getByText("Failed stages").nextSibling).toHaveTextContent("2");
  expect(screen.getByText("Retry attempts").nextSibling).toHaveTextContent("1");
  expect(screen.getByText("Advanced Diagnostics").closest("details")).not.toHaveAttribute("open");
});

test("Scan Centre does not convert missing or malformed stage attempts into zero counts", async () => {
  window.location.hash = "#/scans";
  getV2Overview.mockResolvedValue(overview);
  getV2Scans.mockResolvedValue({
    current_authoritative_scan_id: null,
    previous_authoritative_scan_id: null,
    scans: [{
      scan_id: 45, status: "RUNNING", started_at: "2026-11-02T12:00:00Z",
      completed_at: null, duration_seconds: null, asset_count: 1,
      seed: "example.com", is_current_authoritative: false, is_previous_authoritative: false,
    }],
  });
  const baseDetail = {
    scan_id: 45, status: "RUNNING", scan_time: "2026-11-02T12:00:00Z",
    started_at: "2026-11-02T12:00:00Z", completed_at: null, seed: "example.com",
    asset_count: 1, duration_seconds: 4, diagnostics_available: true,
    current_stage: { stage: "DNS", order: 6, attempt: 1, started_at: "start" },
    failure_category: null, scan_outcome: null, diagnostics_last_updated_at: "updated",
  };
  getV2ScanDetail.mockResolvedValueOnce({ ...baseDetail, stage_attempts: null });

  const first = render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "Expand scan 45" }));
  expect(await screen.findByText("Stage outcomes incomplete")).toBeInTheDocument();
  expect(screen.queryByText("Completed stages")).not.toBeInTheDocument();
  first.unmount();

  getV2ScanDetail.mockResolvedValueOnce({
    ...baseDetail,
    stage_attempts: [{
      stage: "DNS", order: null, attempt: null, status: "SUCCEEDED",
      started_at: "start", completed_at: "done", duration_seconds: 1,
      error_category: null, worker_summary: null,
    }],
  });
  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "Expand scan 45" }));
  expect(await screen.findByText("Stage outcomes incomplete")).toBeInTheDocument();
  expect(screen.queryByText("Completed stages")).not.toBeInTheDocument();
});

test("Scan Centre lazily loads, caches, and isolates rapidly switched rows", async () => {
  window.location.hash = "#/scans";
  getV2Overview.mockResolvedValue(overview);
  getV2Scans.mockResolvedValue({
    current_authoritative_scan_id: null,
    previous_authoritative_scan_id: null,
    scans: [
      { scan_id: 42, status: "SUCCEEDED", started_at: "start", completed_at: "done", duration_seconds: 1, asset_count: 1, seed: "a.example", is_current_authoritative: false, is_previous_authoritative: false },
      { scan_id: 43, status: "RUNNING", started_at: "start", completed_at: null, duration_seconds: null, asset_count: 1, seed: "b.example", is_current_authoritative: false, is_previous_authoritative: false },
    ],
  });
  const pending = {};
  getV2ScanDetail.mockImplementation((scanId) => new Promise((resolve) => { pending[scanId] = resolve; }));

  render(<App />);
  expect(getV2ScanDetail).not.toHaveBeenCalled();
  fireEvent.click(await screen.findByRole("button", { name: "Expand scan 42" }));
  expect(getV2ScanDetail).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByRole("button", { name: "Expand scan 43" }));
  expect(getV2ScanDetail).toHaveBeenCalledTimes(2);
  pending[42]({ ...overview, scan_id: 42, status: "SUCCEEDED", diagnostics_available: true, stage_attempts: [{ stage: "Recon", order: 0, attempt: 1, status: "SUCCEEDED", started_at: "start", completed_at: "done", duration_seconds: 1, error_category: null, worker_summary: null }], current_stage: null, failure_category: null, scan_outcome: null });
  pending[43]({ ...overview, scan_id: 43, status: "RUNNING", diagnostics_available: true, stage_attempts: [], current_stage: { stage: "DNS Resolution", order: 6, attempt: 1, started_at: "start" }, failure_category: null, scan_outcome: null });
  expect(await screen.findByText("DNS Resolution")).toBeInTheDocument();
  expect(screen.queryByText("Recon")).not.toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "Collapse scan 43" }));
  fireEvent.click(screen.getByRole("button", { name: "Expand scan 43" }));
  expect(getV2ScanDetail).toHaveBeenCalledTimes(2);
});

test("Scan Centre exposes detail request errors and retries them", async () => {
  window.location.hash = "#/scans";
  getV2Overview.mockResolvedValue(overview);
  getV2Scans.mockResolvedValue({
    current_authoritative_scan_id: null,
    previous_authoritative_scan_id: null,
    scans: [{ scan_id: 46, status: "SUCCEEDED", started_at: "start", completed_at: "done", duration_seconds: 1, asset_count: 1, seed: "example.com", is_current_authoritative: false, is_previous_authoritative: false }],
  });
  getV2ScanDetail
    .mockRejectedValueOnce(new Error("offline"))
    .mockResolvedValueOnce({
      scan_id: 46, status: "SUCCEEDED", diagnostics_available: true,
      stage_attempts: [], current_stage: null, failure_category: null,
      scan_outcome: null, diagnostics_last_updated_at: null,
    });

  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: "Expand scan 46" }));
  expect(await screen.findByText("Diagnostics could not be loaded.")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Retry" }));
  expect(await screen.findByText("Stage breakdown")).toBeInTheDocument();
  expect(getV2ScanDetail).toHaveBeenCalledTimes(2);
});

test("new workflows expose honest error and empty states", async () => {
  window.location.hash = "#/risk";
  getV2Overview.mockRejectedValue(new Error("offline"));
  getV2Assets.mockResolvedValue({ scan_id: 42, page: 1, limit: 25, count: 0, assets: [] });
  getFindings.mockResolvedValue([]);
  getSensitiveExposure.mockResolvedValue([]);
  getExposureSummary.mockResolvedValue({});
  getV2ReviewIndicators.mockResolvedValue({ scan_id: 42, count: 0, indicators: [] });
  const risk = render(<App />);
  expect(await screen.findByText("Risk workspace unavailable")).toBeInTheDocument();
  risk.unmount();

  window.location.hash = "#/shadow";
  getV2Assets.mockResolvedValue({ scan_id: 42, page: 1, limit: 25, count: 0, assets: [] });
  const shadow = render(<App />);
  expect(await screen.findByText("No Shadow assets match")).toBeInTheDocument();
  shadow.unmount();

  window.location.hash = "#/scans";
  getV2Scans.mockResolvedValue({ current_authoritative_scan_id: null, previous_authoritative_scan_id: null, scans: [] });
  getV2Overview.mockResolvedValue({ ...overview, current_scan_id: null });
  render(<App />);
  expect(await screen.findByText("No scan history")).toBeInTheDocument();
});
