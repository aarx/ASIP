import React from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import CapdPage from "./pages/CapdPage";
import { getCapdChecks, getCapdRun, getCapdRunResults, getCapdRuns } from "./services/api";

jest.mock("./services/api", () => ({
  getCapdChecks: jest.fn(), getCapdRuns: jest.fn(), getCapdRun: jest.fn(), getCapdRunResults: jest.fn(),
}));

const checks = [
  { check_id: "CVE-X", check_revision: "1.2.0", cve_id: "CVE-X", vendor: "Example", product: "Widget", platform: "PHP runtime", category: "remote-code-execution", affected_ranges: [{ branch: "8.2", fixed: "8.2.35" }], version_scheme: "semver", required_evidence: { technology_labels: ["widget"], evidence_types: ["server_header"], minimum_detection_confidence: "medium" }, verification_method: "PASSIVE_VERSION_RANGE_MATCH", advisory_reference: "https://example.invalid/advisory", last_reviewed_at: "2026-10-28", enabled: true, coverage: "partial", limitations: ["Reported version needs independent validation."] },
];
const run = { run_id: "run-001", check_id: "CVE-X", check_revision: "1.2.0", cve_id: "CVE-X", source_scan_id: 19, execution_mode: "passive", status: "SUCCEEDED", started_at: "2026-11-10T10:00:00Z", completed_at: "2026-11-10T10:01:00Z", eligible_target_count: 1, selected_target_count: 1, skipped_target_count: 0, counts: { POTENTIAL_MATCH: 1, INSUFFICIENT_EVIDENCE: 1 } };
const results = [
  { result_id: 1, run_id: run.run_id, domain_id: 12, domain: "potential.example", asset_class: "KNOWN", result_status: "POTENTIAL_MATCH", candidate_classification: "VERSION_MATCHED", product: "Widget", version: "8.2.1", detection_confidence: "high", match_confidence: "medium", evidence: [{ source: "domain_technology_observations", version: "8.2.1", title: "<img src=x onerror=alert(1)>" }], explanation: "Reported version overlaps an affected range.", limitations: ["Installed patch level is unverified."] },
  { result_id: 2, run_id: run.run_id, domain_id: 13, domain: "unknown.example", asset_class: "SHADOW", result_status: "INSUFFICIENT_EVIDENCE", candidate_classification: "PRODUCT_MATCHED_VERSION_UNKNOWN", product: "Widget", version: null, detection_confidence: "medium", match_confidence: null, evidence: [], explanation: "Product observed; version unavailable.", limitations: [] },
];

beforeEach(() => {
  jest.clearAllMocks();
  getCapdChecks.mockResolvedValue({ checks });
  getCapdRuns.mockResolvedValue({ page: 1, limit: 20, total: 0, runs: [] });
  getCapdRun.mockResolvedValue(run);
  getCapdRunResults.mockResolvedValue({ run: { run_id: run.run_id }, page: 1, limit: 20, total: 0, results: [] });
});

test("renders catalog definitions and navigates to selected check metadata", async () => {
  const { rerender } = render(<CapdPage query="" />);
  expect(await screen.findByText("CVE-X")).toBeInTheDocument();
  expect(screen.getByText("1 catalog check available.")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: /CVE-X/ })).toHaveAttribute("href", "#/capd?check_id=CVE-X");
  rerender(<CapdPage query="check_id=CVE-X" />);
  expect(await screen.findByText("Affected version ranges")).toBeInTheDocument();
  expect(screen.getByText("1.2.0")).toBeInTheDocument();
  expect(screen.getByText(/signature match is an indicator/i)).toBeInTheDocument();
  expect(await screen.findByText("No CAPD assessments yet.")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /run/i })).not.toBeInTheDocument();
});

test("shows actual paginated runs and selected run result categories", async () => {
  getCapdRuns.mockResolvedValue({ page: 1, limit: 20, total: 1, runs: [run] });
  const { rerender } = render(<CapdPage query="check_id=CVE-X" />);
  expect(await screen.findByText("Scan #19")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: /run-001/i })).toHaveAttribute("href", "#/capd?check_id=CVE-X&run_id=run-001");
  getCapdRunResults.mockResolvedValue({ run: { run_id: run.run_id, cve_id: run.cve_id, check_revision: run.check_revision, source_scan_id: run.source_scan_id }, page: 1, limit: 20, total: 2, results });
  rerender(<CapdPage query="check_id=CVE-X&run_id=run-001" />);
  expect(await screen.findByText("potential.example")).toBeInTheDocument();
  expect(screen.getByText("Version unknown")).toBeInTheDocument();
  expect(screen.getAllByText(/CVE-X · revision 1.2.0 · Scan #19/).length).toBe(2);
  expect(screen.getAllByText("Potential Match").length).toBeGreaterThan(0);
  expect(screen.getAllByText("Insufficient Evidence").length).toBeGreaterThan(0);
  expect(screen.getByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
  expect(document.querySelector("img[src='x']")).not.toBeInTheDocument();
  const assetLink = screen.getByRole("link", { name: "potential.example" });
  expect(assetLink).toHaveAttribute("href", "#/assets/potential.example?return=capd&return_query=check_id%3DCVE-X%26run_id%3Drun-001");
});

test("uses server-side result status filter and pagination parameters", async () => {
  getCapdRunResults.mockResolvedValue({ run: { run_id: run.run_id }, page: 1, limit: 20, total: 0, results: [] });
  render(<CapdPage query="check_id=CVE-X&run_id=run-001" />);
  await screen.findByText("Assessment results");
  expect(getCapdRunResults).toHaveBeenCalledWith("run-001", { page: 1, limit: 20 });
  fireEvent.change(screen.getByLabelText("Assessment result filter"), { target: { value: "POTENTIAL_MATCH" } });
  await waitFor(() => expect(window.location.hash).toContain("result_status=POTENTIAL_MATCH"));
});

test("exposes backend errors and retry action", async () => {
  getCapdChecks.mockRejectedValueOnce(new Error("CAPD API unavailable"));
  render(<CapdPage query="" />);
  expect(await screen.findByRole("alert")).toHaveTextContent("CAPD API unavailable");
  fireEvent.click(screen.getByRole("button", { name: "Retry" }));
  await waitFor(() => expect(getCapdChecks).toHaveBeenCalledTimes(2));
});
