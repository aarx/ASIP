import React from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import SubdomainTakeoverPage from "./pages/SubdomainTakeoverPage";
import { getSubdomainTakeoverEvidence } from "./services/api";

jest.mock("./services/api", () => ({ getSubdomainTakeoverEvidence: jest.fn() }));

test("shows deduplicated host evidence, filters, and expandable details", async () => {
  getSubdomainTakeoverEvidence.mockResolvedValue({
    scan_id: 36,
    summary: { dns_negative_hosts: 1, unverified_provider_hosts: 1, provider_candidate_hosts: 0 },
    total: 1,
    hosts: [{
      domain_id: 12, hostname: "edge.example.com", cname_destination: "bucket.amazonaws.com",
      provider: "AWS", finding_category: "DNS_NEGATIVE_SIGNAL", confidence: "LOW",
      verification_status: "UNVERIFIED_LEGACY_EVIDENCE",
      observations: [{ source: "dns_security_checks", evidence_category: "DNS_NEGATIVE_SIGNAL",
        verification_status: "UNVERIFIED_LEGACY_EVIDENCE", rationale: "Raw DNS codes unavailable.",
        evidence: { chain: [{ state: "potential_exposure" }] } }],
    }],
  });
  render(<SubdomainTakeoverPage query="tab=subdomain-takeover" />);
  expect(await screen.findByText("edge.example.com")).toBeInTheDocument();
  expect(screen.getByText("DNS-negative signals").parentElement).toHaveTextContent("1");
  fireEvent.click(screen.getByRole("button", { name: "edge.example.com" }));
  expect(screen.getByText("Raw DNS codes unavailable.")).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("Provider"), { target: { value: "AWS" } });
  await waitFor(() => expect(getSubdomainTakeoverEvidence).toHaveBeenLastCalledWith(
    expect.objectContaining({ provider: "AWS" }),
  ));
});
