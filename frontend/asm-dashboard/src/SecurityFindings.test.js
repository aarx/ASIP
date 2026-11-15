import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import App from "./App";
import { getCertificateHosts, getDnsSecurityHosts, getSecurityFindings, getSecurityFindingsSummary, getSensitivePortHosts } from "./services/api";

jest.mock("./services/api", () => ({
  getSecurityFindings: jest.fn(),
  getSecurityFindingsSummary: jest.fn(),
  getDnsSecurityHosts: jest.fn(),
  getCertificateHosts: jest.fn(),
  getSensitivePortHosts: jest.fn(),
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
  window.location.hash = "#/risk/security-review?tab=evidence-signals";
  getSecurityFindings.mockReset();
  getSecurityFindingsSummary.mockReset();
  getDnsSecurityHosts.mockReset();
  getCertificateHosts.mockReset();
  getSensitivePortHosts.mockReset();
  getSecurityFindingsSummary.mockResolvedValue(summary);
  getSecurityFindings.mockResolvedValue(attentionPage);
});

test("renders live category counts, separate coverage, and the default attention view", async () => {
  render(<App />);

  expect(await screen.findByRole("heading", { name: "Security Review" })).toBeInTheDocument();
  expect(screen.getByRole("tab", { name: "Evidence & Signals" })).toHaveAttribute("aria-selected", "true");
  const findingSummary = screen.getByRole("region", { name: "Security findings summary" });
  expect(within(findingSummary).getByText("Recorded Findings")).toBeInTheDocument();
  expect(screen.getByRole("combobox", { name: "Finding category" })).toHaveDisplayValue("All categories");
  expect(within(screen.getByRole("combobox", { name: "Finding category" })).getByRole("option", { name: "Recorded Findings" })).toHaveValue("FINDING");
  expect(screen.getByText("0")).toBeInTheDocument();
  expect(screen.getByText("32")).toBeInTheDocument();
  expect(screen.getByText("892")).toBeInTheDocument();
  expect(screen.getByText("2 assessed / 829 eligible")).toBeInTheDocument();
  expect(screen.getByText("827 unassessed")).toBeInTheDocument();
  expect(screen.getByText("37 observed assets")).toBeInTheDocument();
  expect(screen.getAllByText("Assessment coverage unknown.").length).toBeGreaterThan(0);
  expect(screen.getByRole("combobox", { name: "Finding view" })).toHaveValue("attention");
  expect(getSecurityFindings).toHaveBeenCalledWith({ page: 1, limit: 25, view: "attention" });
  expect(screen.queryByText("Candidate")).not.toBeInTheDocument();
});

test("finding name is selectable plain text and its separate Details control opens evidence", async () => {
  render(<App />);

  const name = await screen.findByText("spf_policy — WARNING");
  expect(name.closest("button")).toBeNull();
  expect(name.closest(".finding-name-text")).toHaveClass("finding-name-text");
  expect(screen.getAllByText("WARNING").length).toBeGreaterThan(0);
  fireEvent.click(screen.getByRole("button", { name: "Details" }));
  expect(await screen.findByText("The recorded DNS assessment outcome may warrant validation.")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Hide details" })).toHaveAttribute("aria-expanded", "true");
});

test("uses the evidence-list scan ID while summary metadata is pending", async () => {
  let resolveSummary;
  getSecurityFindingsSummary.mockReturnValue(new Promise((resolve) => { resolveSummary = resolve; }));
  render(<App />);

  expect(await screen.findByText("admin-dev.example.com")).toBeInTheDocument();
  const context = screen.getByRole("region", { name: "Security findings scan context" });
  expect(within(context).getByText("CURRENT SCAN #19")).toBeInTheDocument();
  expect(within(context).queryByText("SCAN UNAVAILABLE")).not.toBeInTheDocument();

  await act(async () => resolveSummary(summary));
  expect(within(context).getByText("CURRENT SCAN #19")).toBeInTheDocument();
});

test("keeps evidence scan context when the independent summary request fails", async () => {
  getSecurityFindingsSummary.mockRejectedValue(new Error("summary unavailable"));
  render(<App />);

  expect(await screen.findByText("admin-dev.example.com")).toBeInTheDocument();
  const context = screen.getByRole("region", { name: "Security findings scan context" });
  expect(within(context).getByText("CURRENT SCAN #19")).toBeInTheDocument();
  expect(screen.getByText("32 MATCHING")).toBeInTheDocument();
  expect(within(screen.getByRole("region", { name: "Security findings summary" })).getAllByText("—")).toHaveLength(3);
  expect(screen.queryByText("SCAN UNAVAILABLE")).not.toBeInTheDocument();
});

test("does not fabricate a scan ID when the evidence-list response omits it", async () => {
  getSecurityFindings.mockResolvedValueOnce({ ...attentionPage, scan_id: null });
  render(<App />);

  expect(await screen.findByText("admin-dev.example.com")).toBeInTheDocument();
  const context = screen.getByRole("region", { name: "Security findings scan context" });
  expect(within(context).getByText("Scan metadata unavailable")).toBeInTheDocument();
  expect(within(context).queryByText(/CURRENT SCAN #/)).not.toBeInTheDocument();
});

test("does not mix summary counts from a different scan than the evidence list", async () => {
  getSecurityFindingsSummary.mockResolvedValue({ ...summary, scan_id: 18 });
  render(<App />);

  expect(await screen.findByText("admin-dev.example.com")).toBeInTheDocument();
  const context = screen.getByRole("region", { name: "Security findings scan context" });
  expect(within(context).getByText("CURRENT SCAN #19")).toBeInTheDocument();
  expect(within(screen.getByRole("region", { name: "Security findings summary" })).getAllByText("—")).toHaveLength(3);
});

test("assessment cards select one inline panel and use server-side domain search and pagination", async () => {
  getDnsSecurityHosts
    .mockResolvedValueOnce({ scan_id: 19, page: 1, limit: 25, total: 30, hosts: [{ domain_id: 8, domain: "app.example.com", asset_class: "SHADOW", scan_id: 19, check_count: 1, outcome_distribution: { WARNING: 1 }, assessment_state: "ASSESSED", checks: [{ check_id: 3, check_key: "spf_policy", outcome: "WARNING", evidence: { observed: "softfail" }, remediation: "Review DNS policy", scan_id: 19 }] }] })
    .mockResolvedValueOnce({ scan_id: 19, page: 1, limit: 25, total: 30, hosts: [{ domain_id: 8, domain: "app.example.com", asset_class: "SHADOW", scan_id: 19, check_count: 1, outcome_distribution: { WARNING: 1 }, assessment_state: "ASSESSED", checks: [{ check_id: 3, check_key: "spf_policy", outcome: "WARNING", evidence: { observed: "softfail" }, remediation: "Review DNS policy", scan_id: 19 }] }] })
    .mockResolvedValueOnce({ scan_id: 19, page: 2, limit: 25, total: 30, hosts: [{ domain_id: 9, domain: "mail.example.com", asset_class: "KNOWN", scan_id: 19, assessment_state: "ASSESSED", checks: [] }] })
    .mockResolvedValue({ scan_id: 19, page: 2, limit: 25, total: 30, hosts: [{ domain_id: 9, domain: "mail.example.com", asset_class: "KNOWN", scan_id: 19, assessment_state: "ASSESSED", checks: [] }] });
  render(<App />);

  fireEvent.click(await screen.findByRole("button", { name: /DNS Security/ }));
  expect(await screen.findByRole("heading", { name: "DNS Security hosts" })).toBeInTheDocument();
  expect(getDnsSecurityHosts).toHaveBeenLastCalledWith({ page: 1, limit: 25 });
  fireEvent.change(screen.getByRole("textbox", { name: "Search hostname or domain" }), { target: { value: "example.com" } });
  fireEvent.change(screen.getByRole("combobox", { name: "Search mode" }), { target: { value: "domain" } });
  fireEvent.click(screen.getByRole("button", { name: "Search" }));
  await waitFor(() => expect(getDnsSecurityHosts).toHaveBeenLastCalledWith({ page: 1, limit: 25, search: "example.com", search_mode: "domain" }));
  expect(await screen.findByRole("link", { name: "app.example.com" })).toHaveAttribute("href", "#/assets/app.example.com?return=risk%2Fsecurity-review&return_query=tab%3Devidence-signals%26coverage%3Ddns%26coverage_search%3Dexample.com%26coverage_mode%3Ddomain");
  fireEvent.click(screen.getByText("Recorded checks and evidence"));
  expect(screen.getByText("softfail")).toBeInTheDocument();
  expect(screen.getByText("Review DNS policy")).toBeInTheDocument();
  fireEvent.click(within(screen.getByRole("heading", { name: "DNS Security hosts" }).closest("section")).getByRole("button", { name: "Next" }));
  await waitFor(() => expect(getDnsSecurityHosts).toHaveBeenLastCalledWith({ page: 2, limit: 25, search: "example.com", search_mode: "domain" }));
  expect(await screen.findByRole("link", { name: "mail.example.com" })).toBeInTheDocument();
  expect(window.location.hash).toContain("coverage_page=2");
});

test("unassessed DNS and unobserved certificates remain distinct from completed assessment", async () => {
  getDnsSecurityHosts.mockResolvedValue({ scan_id: 19, page: 1, limit: 25, total: 1, hosts: [{ domain_id: 10, domain: "unknown.example.com", asset_class: "KNOWN", scan_id: 19, assessment_state: "NOT_ASSESSED", checks: [] }] });
  getCertificateHosts.mockResolvedValue({ scan_id: 19, page: 1, limit: 25, total: 1, hosts: [{ domain_id: 11, domain: "missing.example.com", asset_class: "SHADOW", scan_id: 19, assessment_state: "NO_PERSISTED_OBSERVATION", certificates: [] }] });
  render(<App />);

  fireEvent.click(await screen.findByRole("button", { name: /DNS Security/ }));
  fireEvent.click(await screen.findByLabelText("Show unassessed hosts"));
  expect(await screen.findByText("UNASSESSED · NO CHECKS")).toBeInTheDocument();
  expect(getDnsSecurityHosts).toHaveBeenLastCalledWith({ page: 1, limit: 25, include_unassessed: true });
  fireEvent.click(screen.getByRole("button", { name: /Certificates/ }));
  fireEvent.click(await screen.findByLabelText("Show hosts without observations"));
  expect(await screen.findByText("NO OBSERVATION")).toBeInTheDocument();
  expect(getCertificateHosts).toHaveBeenLastCalledWith({ page: 1, limit: 25, include_unobserved: true });
  expect(screen.getByText(/not a successful TLS assessment/i)).toBeInTheDocument();
});

test("sensitive-port empty results preserve unknown coverage semantics", async () => {
  getSensitivePortHosts.mockResolvedValue({ scan_id: 19, page: 1, limit: 25, total: 0, assessment_coverage: "UNKNOWN", hosts: [] });
  render(<App />);
  fireEvent.click(await screen.findByRole("button", { name: /Sensitive ports/ }));
  expect(await screen.findByText("No positive observations recorded. Assessment coverage unknown.")).toBeInTheDocument();
  expect(screen.getByText(/No matching sensitive-port observation hosts/)).toBeInTheDocument();
  expect(getSensitivePortHosts).toHaveBeenCalledWith({ page: 1, limit: 25 });
});

test("certificate and positive port evidence display recorded fields without inventing freshness", async () => {
  getCertificateHosts.mockResolvedValue({ scan_id: 19, page: 1, limit: 25, total: 1, hosts: [{ domain_id: 12, domain: "cert.example.com", asset_class: "KNOWN", scan_id: 19, assessment_state: "OBSERVATION_RECORDED", certificates: [{ status: "EXPIRED", expiry: "2026-10-30", days_to_expiry_at_scan: -14, observed_at: null, scan_id: 19 }] }] });
  getSensitivePortHosts.mockResolvedValue({ scan_id: 19, page: 1, limit: 25, total: 1, assessment_coverage: "UNKNOWN", hosts: [{ domain_id: 13, domain: "service.example.com", asset_class: "SHADOW", scan_id: 19, assessment_state: "OBSERVATION_RECORDED", ports: [{ port: 22, service: "SSH", source_risk: 4, description: "Remote administration service", scan_id: 19 }] }] });
  render(<App />);

  fireEvent.click(await screen.findByRole("button", { name: /Certificates/ }));
  expect(await screen.findByText("EXPIRED")).toBeInTheDocument();
  expect(screen.getByText("Expiry: 2026-10-30")).toBeInTheDocument();
  expect(screen.getByText("Days to expiry at scan: -14")).toBeInTheDocument();
  expect(screen.queryByText(/observed at/i)).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: /Sensitive ports/ }));
  expect(await screen.findByText("SSH · port 22")).toBeInTheDocument();
  expect(screen.getByText("Remote administration service")).toBeInTheDocument();
  expect(screen.getByText("Source risk 4 · scan #19")).toBeInTheDocument();
  expect(screen.getAllByText("Assessment coverage unknown.").length).toBeGreaterThan(0);
});

test("maps source labels, null severity, inferred environment, and nested evidence in details", async () => {
  render(<App />);

  const title = await screen.findByRole("button", { name: "Details" });
  expect(screen.getAllByText("DNS Security").length).toBeGreaterThan(0);
  expect(screen.getByText("Not provided")).toBeInTheDocument();
  fireEvent.click(title);

  expect(screen.getByText("Finding details")).toBeInTheDocument();
  expect(screen.getByText("The recorded DNS assessment outcome may warrant validation.")).toBeInTheDocument();
  expect(screen.getByText("record type")).toBeInTheDocument();
  expect(screen.getByText("softfail")).toBeInTheDocument();
  expect(screen.getByText(/inferred from hostname text/i)).toBeInTheDocument();
  expect(screen.getByText("Inferred environment indicators: DEV")).toBeInTheDocument();
  expect(screen.getAllByRole("link", { name: "admin-dev.example.com" }).every((link) => link.getAttribute("href") === "#/assets/admin-dev.example.com?return=risk%2Fsecurity-review&return_query=tab%3Devidence-signals")).toBe(true);
  expect(screen.queryByText("[object Object]")).not.toBeInTheDocument();
});

test("filters by source and asset class and keeps exact pagination totals", async () => {
  getSecurityFindings.mockImplementation((params) => Promise.resolve({ ...attentionPage, ...params, total: 51 }));
  render(<App />);

  await screen.findByRole("button", { name: "Details" });
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
