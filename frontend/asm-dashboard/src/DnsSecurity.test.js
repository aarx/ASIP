import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import App from "./App";
import { getDnsSecurityDomainEvidence, getDnsSecurityFindings, getDnsSecuritySummary } from "./services/api";

jest.mock("./services/api", () => ({
  getDnsSecuritySummary: jest.fn(),
  getDnsSecurityFindings: jest.fn(),
  getDnsSecurityDomainEvidence: jest.fn(),
}));

const summary = {
  scan_id: 17,
  availability_state: "AVAILABLE",
  execution_state: "UNKNOWN",
  operation_enabled_currently: false,
  eligible_assets: 570,
  checked_assets: 0,
  unchecked_assets: 570,
  affected_assets: 0,
  counts_by_outcome: {},
  counts_by_severity: {},
  counts_by_category: {},
};

const emptyFindings = {
  scan_id: 17,
  availability_state: "AVAILABLE",
  page: 1,
  limit: 25,
  total: 0,
  findings: [],
};

const finding = {
  check_id: 101,
  domain_id: 42,
  domain: "mail.example.com",
  asset_class: "KNOWN",
  category: "spf_configuration",
  outcome: "INCONCLUSIVE",
  severity: "UNKNOWN",
  confidence: "LOW",
  record_type: "TXT",
  target: "v=spf1 ?all",
  evidence: "Basic SPF parsing could not establish a clear result.",
  remediation: "Review the SPF record.",
  checked_at: "2026-11-10T12:00:00Z",
};

const loadedSummary = {
  ...summary,
  eligible_assets: 4,
  checked_assets: 2,
  unchecked_assets: 2,
  affected_assets: 1,
  counts_by_outcome: { INCONCLUSIVE: 1, NOT_CHECKED: 1, POTENTIAL_EXPOSURE: 1 },
};

beforeEach(() => {
  window.location.hash = "#/risk/dns-security";
  getDnsSecuritySummary.mockReset();
  getDnsSecurityFindings.mockReset();
  getDnsSecurityDomainEvidence.mockReset();
});

test("renders the current scan summary without implying DNS is secure when nothing was assessed", async () => {
  getDnsSecuritySummary.mockResolvedValue(summary);
  getDnsSecurityFindings.mockResolvedValue(emptyFindings);

  render(<App />);

  expect(await screen.findByRole("heading", { name: "DNS Security" })).toBeInTheDocument();
  expect(screen.getByRole("heading", { name: "DNS assessment summary" })).toBeInTheDocument();
  expect(screen.getByRole("heading", { name: "DNS check results" })).toBeInTheDocument();
  expect(screen.getAllByText("Not Assessed")).toHaveLength(3);
  expect(screen.getAllByText("570", { selector: ".dns-summary-metric strong" })).toHaveLength(2);
  expect(screen.getByText("No DNS checks have been executed for this scan.")).toBeInTheDocument();
  expect(screen.queryByText("No actionable findings recorded for the assessed assets")).not.toBeInTheDocument();
  expect(screen.getByRole("link", { name: "DNS Security" })).toHaveAttribute("href", "#/risk/dns-security");
  await waitFor(() => expect(getDnsSecurityFindings).toHaveBeenCalledWith({ scan_id: 17, page: 1, limit: 25 }));
  expect(getDnsSecuritySummary).toHaveBeenCalledTimes(1);
  expect(getDnsSecurityFindings).toHaveBeenCalledTimes(1);
});

test("shows partial coverage, distinct outcomes, exact filters, and server pagination", async () => {
  getDnsSecuritySummary.mockResolvedValue(loadedSummary);
  getDnsSecurityFindings.mockImplementation(({ page, limit, outcome }) => Promise.resolve({
    ...emptyFindings,
    page,
    limit,
    total: outcome ? 1 : limit === 50 ? 101 : 51,
    findings: outcome
      ? [{ ...finding, outcome: "POTENTIAL_EXPOSURE" }]
      : page === 2
        ? [{ ...finding, check_id: 102, domain: "dns.example.com", outcome: "NOT_CHECKED" }]
        : [finding],
  }));

  render(<App />);

  expect(await screen.findByText("Partial assessment coverage")).toBeInTheDocument();
  expect(screen.getByText("2 of 4 eligible assets assessed.")).toBeInTheDocument();
  expect(screen.getAllByText("INCONCLUSIVE").length).toBeGreaterThan(0);
  expect(screen.getAllByText("UNKNOWN").length).toBeGreaterThan(0);
  expect(screen.getByText("Page 1 of 3 · 51 matching")).toBeInTheDocument();

  fireEvent.change(screen.getByLabelText("Page size"), { target: { value: "50" } });
  await waitFor(() => expect(getDnsSecurityFindings).toHaveBeenLastCalledWith({ scan_id: 17, page: 1, limit: 50 }));

  const nextButton = screen.getByRole("button", { name: "Next" });
  fireEvent.click(nextButton);
  await waitFor(() => expect(getDnsSecurityFindings).toHaveBeenLastCalledWith({ scan_id: 17, page: 2, limit: 50 }));
  expect(await screen.findByText("dns.example.com")).toBeInTheDocument();
  expect(screen.getAllByText("NOT_CHECKED").length).toBeGreaterThan(0);

  fireEvent.change(screen.getByLabelText("Outcome"), { target: { value: "POTENTIAL_EXPOSURE" } });
  fireEvent.click(screen.getByRole("button", { name: "Apply" }));
  await waitFor(() => expect(getDnsSecurityFindings).toHaveBeenLastCalledWith({ scan_id: 17, page: 1, limit: 50, outcome: "POTENTIAL_EXPOSURE" }));
  expect(window.location.hash).toContain("outcome=POTENTIAL_EXPOSURE");
});

test("loads domain evidence only after an accessible finding control is activated", async () => {
  getDnsSecuritySummary.mockResolvedValue({ ...summary, eligible_assets: 1, checked_assets: 1, unchecked_assets: 0 });
  getDnsSecurityFindings.mockResolvedValue({ ...emptyFindings, total: 1, findings: [finding] });
  getDnsSecurityDomainEvidence.mockResolvedValue({
    scan_id: 17,
    domain_id: 42,
    domain: "mail.example.com",
    asset_class: "KNOWN",
    availability_state: "AVAILABLE",
    execution_state: "SUCCEEDED",
    checks: [{ ...finding, category: "dmarc_configuration", outcome: "CLEAR", severity: "INFO", confidence: "HIGH", record_type: "TXT", target: "v=DMARC1; p=none" }],
  });

  render(<App />);

  const evidenceButton = await screen.findByRole("button", { name: "Show DNS evidence for mail.example.com" });
  expect(getDnsSecurityDomainEvidence).not.toHaveBeenCalled();
  expect(evidenceButton).toHaveAttribute("aria-expanded", "false");

  fireEvent.click(evidenceButton);
  expect(evidenceButton).toHaveAttribute("aria-expanded", "true");
  await waitFor(() => expect(getDnsSecurityDomainEvidence).toHaveBeenCalledWith(42, 17));
  expect(screen.getAllByText("DMARC configuration").length).toBeGreaterThan(0);
  expect(screen.getByText("v=DMARC1; p=none")).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "Hide DNS evidence for mail.example.com" }));
  expect(screen.queryByText("v=DMARC1; p=none")).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Show DNS evidence for mail.example.com" }));
  expect(getDnsSecurityDomainEvidence).toHaveBeenCalledTimes(1);
});

test("distinguishes filtered empty results", async () => {
  getDnsSecuritySummary.mockResolvedValue(summary);
  getDnsSecurityFindings.mockResolvedValue(emptyFindings);
  window.location.hash = "#/risk/dns-security?outcome=WARNING";
  render(<App />);

  expect(await screen.findByText("No matching results")).toBeInTheDocument();
  expect(getDnsSecurityFindings).toHaveBeenCalledWith({ scan_id: 17, page: 1, limit: 25, outcome: "WARNING" });
});

test("shows a retryable state for summary request failures", async () => {
  getDnsSecuritySummary.mockRejectedValueOnce(new Error("request failed")).mockResolvedValueOnce(summary);
  getDnsSecurityFindings.mockResolvedValue(emptyFindings);
  render(<App />);

  expect(await screen.findByRole("heading", { name: "DNS Security unavailable" })).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Retry request" }));
  expect(await screen.findByText("No DNS checks have been executed for this scan.")).toBeInTheDocument();
});
