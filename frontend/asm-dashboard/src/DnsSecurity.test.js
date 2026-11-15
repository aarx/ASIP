import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import App from "./App";
import { getDnsSecurityHosts, getDnsSecuritySummary } from "./services/api";

jest.mock("./services/api", () => ({
  getDnsSecuritySummary: jest.fn(),
  getDnsSecurityHosts: jest.fn(),
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

const emptyHosts = {
  scan_id: 17,
  availability_state: "AVAILABLE",
  page: 1,
  limit: 25,
  total: 0,
  hosts: [],
};

const host = {
  domain_id: 42,
  domain: "mail.example.com",
  asset_class: "KNOWN",
  scan_id: 17,
  check_count: 2,
  assessment_state: "ASSESSED",
  outcome_distribution: { INCONCLUSIVE: 1, CLEAR: 1 },
  checks: [
    {
      check_id: 101,
      check_key: "spf_configuration",
      outcome: "INCONCLUSIVE",
      severity: "UNKNOWN",
      confidence: "LOW",
      record_type: "TXT",
      target: "v=spf1 ?all",
      evidence: { resolver_outcome: "NXDOMAIN", notes: ["No authoritative answer"] },
      remediation: "Review the SPF record.",
      checked_at: "2026-11-10T12:00:00Z",
      scan_id: 17,
    },
    {
      check_id: 102,
      check_key: "dmarc_configuration",
      outcome: "CLEAR",
      severity: "INFO",
      confidence: "HIGH",
      record_type: "TXT",
      target: "v=DMARC1; p=none",
      evidence: "Policy is present.",
      remediation: null,
      checked_at: "2026-11-10T12:00:01Z",
      scan_id: 17,
    },
  ],
};

const loadedSummary = {
  ...summary,
  eligible_assets: 4,
  checked_assets: 2,
  unchecked_assets: 2,
  affected_assets: 1,
  counts_by_outcome: { INCONCLUSIVE: 1, NOT_CHECKED: 1, WARNING: 1 },
};

beforeEach(() => {
  window.location.hash = "#/risk/dns-security";
  getDnsSecuritySummary.mockReset();
  getDnsSecurityHosts.mockReset();
});

test("renders coverage without implying DNS is secure when nothing was assessed", async () => {
  getDnsSecuritySummary.mockResolvedValue(summary);
  getDnsSecurityHosts.mockResolvedValue(emptyHosts);

  render(<App />);

  expect(await screen.findByRole("heading", { name: "DNS Security" })).toBeInTheDocument();
  expect(screen.getByRole("heading", { name: "DNS assessment summary" })).toBeInTheDocument();
  expect(screen.getByRole("heading", { name: "DNS assessments by host" })).toBeInTheDocument();
  expect(screen.getAllByText("Not Assessed")).toHaveLength(3);
  expect(screen.getAllByText("570", { selector: ".dns-summary-metric strong" })).toHaveLength(2);
  expect(screen.getByText("No DNS checks have been executed for this scan.")).toBeInTheDocument();
  await waitFor(() => expect(getDnsSecurityHosts).toHaveBeenCalledWith({ scan_id: 17, page: 1, limit: 25 }));
  expect(getDnsSecuritySummary).toHaveBeenCalledTimes(1);
  expect(getDnsSecurityHosts).toHaveBeenCalledTimes(1);
});

test("groups checks by host and paginates distinct hosts", async () => {
  getDnsSecuritySummary.mockResolvedValue(loadedSummary);
  getDnsSecurityHosts.mockImplementation(({ page, limit, outcome, asset_class }) => Promise.resolve({
    ...emptyHosts,
    page,
    limit,
    total: outcome || asset_class ? 1 : limit === 50 ? 101 : 51,
    hosts: outcome || asset_class
      ? [{ ...host, outcome_distribution: { WARNING: 1, INCONCLUSIVE: 1 }, check_count: 2 }]
      : page === 2
        ? [{ ...host, domain_id: 43, domain: "dns.example.com", check_count: 1, checks: [] }]
        : [host],
  }));

  render(<App />);

  expect(await screen.findByText("Partial assessment coverage")).toBeInTheDocument();
  expect(screen.getByText("2 of 4 eligible assets assessed.")).toBeInTheDocument();
  expect(screen.getByText("Page 1 of 3 · 51 matching hosts")).toBeInTheDocument();
  expect(screen.getByText("mail.example.com")).toBeInTheDocument();
  expect(screen.getAllByText("INCONCLUSIVE").length).toBeGreaterThan(1);
  expect(screen.getAllByText("CLEAR").length).toBeGreaterThan(1);

  fireEvent.change(screen.getByLabelText("Page size"), { target: { value: "50" } });
  await waitFor(() => expect(getDnsSecurityHosts).toHaveBeenLastCalledWith({ scan_id: 17, page: 1, limit: 50 }));

  fireEvent.click(screen.getByRole("button", { name: "Next" }));
  await waitFor(() => expect(getDnsSecurityHosts).toHaveBeenLastCalledWith({ scan_id: 17, page: 2, limit: 50 }));
  expect(await screen.findByText("dns.example.com")).toBeInTheDocument();

  fireEvent.change(screen.getByLabelText("Outcome"), { target: { value: "WARNING" } });
  fireEvent.click(screen.getByRole("button", { name: "Apply" }));
  await waitFor(() => expect(getDnsSecurityHosts).toHaveBeenLastCalledWith({ scan_id: 17, page: 1, limit: 50, outcome: "WARNING" }));
  expect(window.location.hash).toContain("outcome=WARNING");
});

test("expands one host to show every recorded check and nested evidence", async () => {
  getDnsSecuritySummary.mockResolvedValue({ ...summary, eligible_assets: 1, checked_assets: 1, unchecked_assets: 0 });
  getDnsSecurityHosts.mockResolvedValue({ ...emptyHosts, total: 1, hosts: [host] });

  render(<App />);

  const expandButton = await screen.findByRole("button", { name: "Expand DNS checks for mail.example.com" });
  expect(getDnsSecurityHosts).toHaveBeenCalledTimes(1);
  expect(expandButton).toHaveAttribute("aria-expanded", "false");

  fireEvent.click(expandButton);
  expect(expandButton).toHaveAttribute("aria-expanded", "true");
  expect(screen.getAllByText("spf configuration").length).toBeGreaterThan(0);
  expect(screen.getAllByText("dmarc configuration").length).toBeGreaterThan(0);
  expect(screen.getByText("resolver outcome")).toBeInTheDocument();
  expect(screen.getByText("NXDOMAIN")).toBeInTheDocument();
  expect(screen.getByText("No authoritative answer")).toBeInTheDocument();
  expect(screen.getByText("Unavailable")).toBeInTheDocument();
  expect(document.body.textContent).not.toContain("[object Object]");

  fireEvent.click(screen.getByRole("button", { name: "Collapse DNS checks for mail.example.com" }));
  expect(screen.queryByText("No authoritative answer")).not.toBeInTheDocument();
});

test("outcome filtering preserves all checks for matching hosts", async () => {
  getDnsSecuritySummary.mockResolvedValue({ ...summary, eligible_assets: 2, checked_assets: 2, unchecked_assets: 0 });
  getDnsSecurityHosts.mockResolvedValue({ ...emptyHosts, total: 2, hosts: [
    { ...host, outcome_distribution: { WARNING: 1, INCONCLUSIVE: 1 } },
    { ...host, domain_id: 43, domain: "other.example.com", outcome_distribution: { WARNING: 1, CLEAR: 2 }, check_count: 3 },
  ] });
  window.location.hash = "#/risk/dns-security?outcome=WARNING";
  render(<App />);

  expect(await screen.findByText("other.example.com")).toBeInTheDocument();
  expect(getDnsSecurityHosts).toHaveBeenCalledWith({ scan_id: 17, page: 1, limit: 25, outcome: "WARNING" });
});

test("distinguishes filtered empty hosts", async () => {
  getDnsSecuritySummary.mockResolvedValue(summary);
  getDnsSecurityHosts.mockResolvedValue(emptyHosts);
  window.location.hash = "#/risk/dns-security?outcome=WARNING";
  render(<App />);

  expect(await screen.findByText("No matching hosts")).toBeInTheDocument();
  expect(getDnsSecurityHosts).toHaveBeenCalledWith({ scan_id: 17, page: 1, limit: 25, outcome: "WARNING" });
});

test("hostname search is trimmed, server-side, filter-composable, and paginated", async () => {
  getDnsSecuritySummary.mockResolvedValue(loadedSummary);
  getDnsSecurityHosts.mockImplementation((params) => Promise.resolve({
    ...emptyHosts, ...params, total: params.search ? 1 : 51,
    hosts: params.search ? [{ ...host, domain: "email.abc.com" }] : [host],
  }));
  window.location.hash = "#/risk/dns-security";
  render(<App />);

  expect(await screen.findByText("mail.example.com")).toBeInTheDocument();
  fireEvent.change(screen.getByRole("searchbox", { name: "Hostname" }), { target: { value: "  EMAIL.ABC.COM  " } });
  fireEvent.change(screen.getByLabelText("Outcome"), { target: { value: "CONFIRMED_ISSUE" } });
  fireEvent.change(screen.getByLabelText("Asset class"), { target: { value: "KNOWN" } });
  fireEvent.click(screen.getByRole("button", { name: "Apply" }));
  await waitFor(() => expect(getDnsSecurityHosts).toHaveBeenLastCalledWith({
    scan_id: 17, page: 1, limit: 25, outcome: "CONFIRMED_ISSUE", asset_class: "KNOWN",
    search: "EMAIL.ABC.COM", search_mode: "fragment",
  }));
  expect(await screen.findByText("email.abc.com")).toBeInTheDocument();
  expect(window.location.hash).toContain("search=EMAIL.ABC.COM");
  expect(screen.getByText("Page 1 of 1 · 1 matching hosts")).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "Clear" }));
  await waitFor(() => expect(getDnsSecurityHosts).toHaveBeenLastCalledWith({ scan_id: 17, page: 1, limit: 25 }));
  expect(screen.getByRole("searchbox", { name: "Hostname" })).toHaveValue("");
});

test("hostname search returns an explicit no-match state and rejects too-short fragments", async () => {
  getDnsSecuritySummary.mockResolvedValue(loadedSummary);
  getDnsSecurityHosts.mockResolvedValue(emptyHosts);
  window.location.hash = "#/risk/dns-security?search=none.example";
  render(<App />);

  expect(await screen.findByText("No matching hosts")).toBeInTheDocument();
  expect(getDnsSecurityHosts).toHaveBeenCalledWith({ scan_id: 17, page: 1, limit: 25, search: "none.example", search_mode: "fragment" });
  fireEvent.change(screen.getByRole("searchbox", { name: "Hostname" }), { target: { value: "x" } });
  fireEvent.click(screen.getByRole("button", { name: "Apply" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Enter at least 2 characters");
  expect(getDnsSecurityHosts).toHaveBeenCalledTimes(1);
});

test("shows a retryable state for summary request failures", async () => {
  getDnsSecuritySummary.mockRejectedValueOnce(new Error("request failed")).mockResolvedValueOnce(summary);
  getDnsSecurityHosts.mockResolvedValue(emptyHosts);
  render(<App />);

  expect(await screen.findByRole("heading", { name: "DNS Security unavailable" })).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Retry request" }));
  expect(await screen.findByText("No DNS checks have been executed for this scan.")).toBeInTheDocument();
});
