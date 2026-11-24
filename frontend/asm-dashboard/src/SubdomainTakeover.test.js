import React from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import SubdomainTakeoverPage from "./pages/SubdomainTakeoverPage";
import {
  exportSubdomainTakeoverCsv,
  getSubdomainTakeoverEvidence,
  getSubdomainTakeoverHostnames,
} from "./services/api";

jest.mock("./services/api", () => ({
  exportSubdomainTakeoverCsv: jest.fn(),
  getSubdomainTakeoverEvidence: jest.fn(),
  getSubdomainTakeoverHostnames: jest.fn(),
}));

const host = (hostname, id = 12) => ({
  domain_id: id, hostname, cname_destination: "bucket.example.net",
  provider: "Example Cloud", finding_category: "DNS_NEGATIVE_SIGNAL",
  confidence: "LOW", verification_status: "UNVERIFIED_LEGACY_EVIDENCE",
  observations: [{ source: "dns_security_checks", evidence_category: "DNS_NEGATIVE_SIGNAL",
    verification_status: "UNVERIFIED_LEGACY_EVIDENCE", rationale: "DNS evidence only.",
    evidence: { chain: [{ state: "potential_exposure" }] } }],
});

function mockPage(hosts = [host("edge.example.com")], total = hosts.length) {
  getSubdomainTakeoverEvidence.mockResolvedValue({
    scan_id: 36,
    summary: { dns_negative_hosts: total, unverified_provider_hosts: 2, provider_candidate_hosts: 0 },
    total,
    hosts,
  });
}

beforeEach(() => {
  jest.clearAllMocks();
  Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: jest.fn().mockResolvedValue(undefined) },
  });
});

test("single-host copy preserves hostname expansion and evidence details", async () => {
  mockPage();
  render(<SubdomainTakeoverPage query="tab=subdomain-takeover" />);
  const hostname = await screen.findByRole("button", { name: "edge.example.com" });
  fireEvent.click(hostname);
  expect(await screen.findByText("DNS evidence only.")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Copy edge.example.com" }));
  await waitFor(() => expect(navigator.clipboard.writeText).toHaveBeenCalledWith("edge.example.com"));
  await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Hostname copied."));
});

test("copy all requests every filtered hostname, independent of visible page", async () => {
  mockPage([host("zeta.example.com", 30)], 30);
  const all = Array.from({ length: 30 }, (_, index) => `host-${String(index + 1).padStart(2, "0")}.example.com`);
  getSubdomainTakeoverHostnames.mockResolvedValue(`${all.join("\n")}\n${all[0]}\n`);
  render(<SubdomainTakeoverPage query="scan_id=36&search=host&provider=AWS&category=UNKNOWN&verification_status=UNVERIFIED&page=2" />);
  await screen.findByText("zeta.example.com");
  fireEvent.click(screen.getByRole("button", { name: "Copy all hostnames" }));
  await waitFor(() => expect(getSubdomainTakeoverHostnames).toHaveBeenCalledWith({
    scan_id: "36", search: "host", provider: "AWS", category: "UNKNOWN",
    verification_status: "UNVERIFIED",
  }));
  await waitFor(() => expect(navigator.clipboard.writeText).toHaveBeenCalledWith(all.join("\n")));
  expect(screen.getByRole("status")).toHaveTextContent("Copied 30 hostnames.");
});

test("filter changes reload evidence and CSV export uses current filters, not page", async () => {
  mockPage();
  exportSubdomainTakeoverCsv.mockResolvedValue({ data: new Blob(["scan_id,hostname\n36,edge.example.com\n"]) });
  const previousCreate = URL.createObjectURL;
  const previousRevoke = URL.revokeObjectURL;
  const createObjectURL = jest.fn(() => "blob:takeover");
  const revokeObjectURL = jest.fn();
  Object.defineProperty(URL, "createObjectURL", { configurable: true, value: createObjectURL });
  Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: revokeObjectURL });
  const click = jest.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  render(<SubdomainTakeoverPage query="scan_id=36&page=2" />);
  await screen.findByText("edge.example.com");
  fireEvent.change(screen.getByLabelText("Provider"), { target: { value: "Example Cloud" } });
  await waitFor(() => expect(getSubdomainTakeoverEvidence).toHaveBeenLastCalledWith(
    expect.objectContaining({ provider: "Example Cloud", page: 1 }),
  ));
  await waitFor(() => expect(screen.getByRole("button", { name: "Export CSV" })).toBeEnabled());
  fireEvent.click(screen.getByRole("button", { name: "Export CSV" }));
  await waitFor(() => expect(exportSubdomainTakeoverCsv).toHaveBeenCalledWith({
    scan_id: "36", provider: "Example Cloud",
  }));
  expect(createObjectURL).toHaveBeenCalled();
  expect(revokeObjectURL).toHaveBeenCalledWith("blob:takeover");
  await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("CSV exported."));
  click.mockRestore();
  if (previousCreate) Object.defineProperty(URL, "createObjectURL", { configurable: true, value: previousCreate });
  else delete URL.createObjectURL;
  if (previousRevoke) Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: previousRevoke });
  else delete URL.revokeObjectURL;
});

test("empty result disables bulk actions and reports clipboard errors", async () => {
  mockPage([], 0);
  const emptyPage = render(<SubdomainTakeoverPage query="" />);
  expect(await screen.findByText("No matching takeover evidence.")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Copy all hostnames" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Export CSV" })).toBeDisabled();
  emptyPage.unmount();

  mockPage([host("edge.example.com")]);
  navigator.clipboard.writeText.mockRejectedValueOnce(new Error("denied"));
  const { unmount } = render(<SubdomainTakeoverPage query="" />);
  await screen.findByText("edge.example.com");
  fireEvent.click(screen.getByRole("button", { name: "Copy edge.example.com" }));
  await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Copy failed. Clipboard access is unavailable."));
  unmount();
});
