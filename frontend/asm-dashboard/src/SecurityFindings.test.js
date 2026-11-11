import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import App from "./App";
import { getSecurityFindings, getSecurityFindingsSummary } from "./services/api";

jest.mock("./services/api", () => ({
  getSecurityFindings: jest.fn(),
  getSecurityFindingsSummary: jest.fn(),
  getV2Overview: jest.fn(),
  getV2Assets: jest.fn(),
  getV2AssetDetail: jest.fn(),
  getV2AssetAssistant: jest.fn(),
  askShadowRecon: jest.fn(),
  getFindings: jest.fn(),
  getSensitiveExposure: jest.fn(),
  getExposureSummary: jest.fn(),
  getHttpStatus: jest.fn(),
  getDnsSecuritySummary: jest.fn(),
  getV2ReviewIndicators: jest.fn(),
  getV2Scans: jest.fn(),
  getV2ScanDetail: jest.fn(),
  exportV2ScanReport: jest.fn(),
  getV2BrandAssets: jest.fn(),
  getNewDomainsDelta: jest.fn(),
  getDisappearedDomains: jest.fn(),
  getInvestigationAssets: jest.fn(),
  getAssetGrowth: jest.fn(),
  getCertExpiry: jest.fn(),
  getDiscoverySources: jest.fn(),
  getNamingAssetExposure: jest.fn(),
  getSeeds: jest.fn(),
  getRiskyDomains: jest.fn(),
}));

const summary = {
  scan_id: 19,
  availability_state: "AVAILABLE",
  total_records: 924,
  affected_assets: 775,
  counts_by_category: {
    NEEDS_VERIFICATION: { records: 32, distinct_assets: 26 },
    EXPOSURE_SIGNAL: { records: 892, distinct_assets: 773 },
  },
  coverage: {
    dns_security: { eligible_assets: 829, assessed_assets: 2, unassessed_assets: 827 },
    certificates: { observed_assets: 37 },
    sensitive_ports: { positive_observations: 0, assessed_assets: null, assessment_state: "UNKNOWN" },
  },
};

const attentionPage = {
  scan_id: 19,
  availability_state: "AVAILABLE",
  page: 1,
  limit: 25,
  total: 32,
  view: "attention",
  findings: [{
    finding_id: "dns_security_checks:19",
    asset_domain: "admin-dev.example.com",
    asset_class: "SHADOW",
    category: "NEEDS_VERIFICATION",
    title: "spf_policy — WARNING",
    finding_type: "spf_policy",
    source: "dns_security_checks",
    source_outcome: "WARNING",
    severity: null,
    confidence: null,
    verification_state: "WARNING",
    evidence: { record_type: "TXT", details: { observed: "softfail" } },
    why_it_matters: "The recorded DNS assessment outcome may warrant validation.",
    recommended_action: "Review the recorded policy.",
    environment_indicators: ["DEV"],
    role_indicators: ["ADMIN"],
    indicators_inferred: true,
    limitations: ["Does not establish exploitability."],
    scan_id: 19,
  }],
};

beforeEach(() => {
  window.location.hash = "#/risk/findings";
  getSecurityFindings.mockReset();
  getSecurityFindingsSummary.mockReset();
  getSecurityFindingsSummary.mockResolvedValue(summary);
  getSecurityFindings.mockResolvedValue(attentionPage);
});

test("renders live category counts, separate coverage, and the default attention view", async () => {
  render(<App />);

  expect(await screen.findByRole("heading", { name: "Security Findings" })).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Findings" })).toHaveAttribute("href", "#/risk/findings");
  expect(screen.getByText("0")).toBeInTheDocument();
  expect(screen.getByText("32")).toBeInTheDocument();
  expect(screen.getByText("892")).toBeInTheDocument();
  expect(screen.getByText("2 assessed / 829 eligible")).toBeInTheDocument();
  expect(screen.getByText("827 unassessed")).toBeInTheDocument();
  expect(screen.getByText("37 observed assets")).toBeInTheDocument();
  expect(screen.getByText("Assessment coverage unknown.")).toBeInTheDocument();
  expect(screen.getByRole("combobox", { name: "Finding view" })).toHaveValue("attention");
  expect(getSecurityFindings).toHaveBeenCalledWith({ page: 1, limit: 25, view: "attention" });
  expect(screen.queryByText("Candidate")).not.toBeInTheDocument();
});

test("maps source labels, null severity, inferred environment, and nested evidence in details", async () => {
  render(<App />);

  const title = await screen.findByRole("button", { name: /spf_policy/ });
  expect(screen.getAllByText("DNS Security").length).toBeGreaterThan(0);
  expect(screen.getByText("Not provided")).toBeInTheDocument();
  fireEvent.click(title);

  expect(screen.getByText("Finding details")).toBeInTheDocument();
  expect(screen.getByText("The recorded DNS assessment outcome may warrant validation.")).toBeInTheDocument();
  expect(screen.getByText("record type")).toBeInTheDocument();
  expect(screen.getByText("softfail")).toBeInTheDocument();
  expect(screen.getByText(/inferred from hostname text/i)).toBeInTheDocument();
  expect(screen.getByText("Inferred environment indicators: DEV")).toBeInTheDocument();
  expect(screen.getAllByRole("link", { name: "admin-dev.example.com" }).every((link) => link.getAttribute("href") === "#/assets/admin-dev.example.com?return=risk%2Ffindings")).toBe(true);
  expect(screen.queryByText("[object Object]")).not.toBeInTheDocument();
});

test("filters by source and asset class and keeps exact pagination totals", async () => {
  getSecurityFindings.mockImplementation((params) => Promise.resolve({ ...attentionPage, ...params, total: 51 }));
  render(<App />);

  await screen.findByRole("button", { name: /spf_policy/ });
  fireEvent.change(screen.getByRole("combobox", { name: "Finding source" }), { target: { value: "domain_cert" } });
  fireEvent.change(screen.getByRole("combobox", { name: "Finding asset class" }), { target: { value: "KNOWN" } });

  await waitFor(() => expect(getSecurityFindings).toHaveBeenLastCalledWith({
    page: 1, limit: 25, view: "attention", source: "domain_cert", asset_class: "KNOWN",
  }));
  expect(await screen.findByText(/51 matching records/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Next" }));
  await waitFor(() => expect(getSecurityFindings).toHaveBeenLastCalledWith({
    page: 2, limit: 25, view: "attention", source: "domain_cert", asset_class: "KNOWN",
  }));
});

test("supports exposure signals and truthful empty and unavailable states", async () => {
  getSecurityFindings.mockResolvedValue({ ...attentionPage, findings: [], total: 0, view: "signals" });
  render(<App />);
  fireEvent.change(await screen.findByRole("combobox", { name: "Finding view" }), { target: { value: "signals" } });
  expect(await screen.findByText("No exposure signals match this filter.")).toBeInTheDocument();

  getSecurityFindings.mockRejectedValueOnce(new Error("offline"));
  fireEvent.change(screen.getByRole("combobox", { name: "Finding source" }), { target: { value: "domain_cert" } });
  expect(await screen.findByRole("alert")).toHaveTextContent("Security Findings unavailable");
});

test("renders no successful scan without fabricating zero findings", async () => {
  getSecurityFindingsSummary.mockResolvedValue({ scan_id: null, availability_state: "UNAVAILABLE", total_records: 0 });
  getSecurityFindings.mockResolvedValue({ scan_id: null, availability_state: "UNAVAILABLE", findings: [], total: 0 });
  render(<App />);
  expect(await screen.findByRole("heading", { name: "No successful scan available" })).toBeInTheDocument();
  expect(screen.queryByText("No security issues found")).not.toBeInTheDocument();
});
