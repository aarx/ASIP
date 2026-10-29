import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import App from "./App";
import { getPhpRceCheck, getV2Scans } from "./services/api";

jest.mock("./services/api", () => ({
  getV2Overview: jest.fn(),
  getV2Assets: jest.fn(),
  exportV2AssetsCsv: jest.fn(),
  getV2AssetDetail: jest.fn(),
  updateV2AssetOwnership: jest.fn(),
  getV2Scans: jest.fn(),
  getPhpRceCheck: jest.fn(),
  getV2BrandAssets: jest.fn(),
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

const scanHistory = {
  current_authoritative_scan_id: 16,
  previous_authoritative_scan_id: 15,
  scans: [
    { scan_id: 16, status: "SUCCEEDED", completed_at: "2026-10-04T12:00:00", asset_count: 318 },
    { scan_id: 15, status: "SUCCEEDED", completed_at: "2026-09-28T12:00:00", asset_count: 320 },
    { scan_id: 14, status: "FAILED", completed_at: "2026-09-21T12:00:00", asset_count: 0 },
  ],
};

const emptyReview = {
  check: { id: "php-rce", assessment_date: "2026-10-28", dataset_revision: "2026-10-28", coverage: "partial" },
  scan: { scan_id: 16, status: "SUCCEEDED", completed_at: "2026-10-04T12:00:00", authoritative: true },
  scope: { scan_members: 318, authorized_assets: 0, http_eligible_assets: 0, evaluated_assets: 0, not_evaluated_assets: 0 },
  legacy_leads: [],
  count: 0,
  page: 1,
  limit: 25,
  results: [],
};

const structuredObservation = {
  technology: "PHP",
  version: "8.2.34",
  confidence: "high",
  evidence_type: "x-powered-by_header",
  sanitized_evidence: "PHP/8.2.34",
  observed_url: "https://app.example.com",
  detector_version: "sr-tech-02",
  persisted_at: "2026-10-04T12:01:00",
  lifecycle: {
    status: "security_support",
    matched_release_branch: "8.2",
    active_support_until: "2024-12-31",
    security_support_until: "2026-12-31",
    end_of_life: "2026-12-31",
    source_url: "https://www.php.net/supported-versions.php",
    assessment_date: "2026-10-28",
  },
  cve_intelligence: {
    assessment_date: "2026-10-28",
    dataset_revision: "2026-10-28",
    coverage: "partial",
    candidates: [{
      cve_id: "CVE-2026-109618",
      applicability_status: "potentially_affected",
      affected_version_range: "< 8.2.35 (PHP 8.2 branch)",
      fixed_version: "8.2.35",
      source_url: "https://example.test/CVE-2026-109618",
      evidence_confidence: "high_version_range_match",
      patch_status: "unknown",
      explanation_code: "php_version_within_verified_affected_range",
    }],
  },
};

const populatedReview = {
  ...emptyReview,
  scope: { scan_members: 318, authorized_assets: 3, http_eligible_assets: 2, evaluated_assets: 1, not_evaluated_assets: 2 },
  count: 3,
  results: [
    {
      domain: "app.example.com",
      scan_id: 16,
      evaluation_status: "Evaluated",
      classification: "Potential CVE",
      reason_code: "potential_cve_candidate",
      observations: [structuredObservation],
      legacy_php_label: false,
      legacy_php_lead: false,
      coverage: "partial",
    },
    {
      domain: "unknown.example.com",
      scan_id: 16,
      evaluation_status: "Not evaluated",
      classification: "No PHP observation",
      reason_code: "no_php_observation",
      observations: [],
      legacy_php_label: false,
      legacy_php_lead: false,
      coverage: "partial",
    },
    {
      domain: "legacy.example.com",
      scan_id: 16,
      evaluation_status: "Not evaluated",
      classification: "No PHP observation",
      reason_code: "legacy_php_label_without_structured_observation",
      observations: [],
      legacy_php_label: true,
      legacy_php_lead: true,
      coverage: "partial",
    },
  ],
  legacy_leads: [{
    domain: "legacy.example.com",
    scan_id: 16,
    technology: "php",
    reason_code: "legacy_php_label_without_structured_observation",
    structured_observation_present: false,
  }],
};

const historicalReview = {
  ...populatedReview,
  scan: { scan_id: 15, status: "SUCCEEDED", completed_at: "2026-09-28T12:00:00", authoritative: false },
  results: [{ ...populatedReview.results[0], domain: "historical.example.com", scan_id: 15 }],
  legacy_leads: [],
  count: 1,
};

beforeEach(() => {
  window.location.hash = "#/adhoc/php-rce";
  getV2Scans.mockReset();
  getPhpRceCheck.mockReset();
  getV2Scans.mockResolvedValue(scanHistory);
  getPhpRceCheck.mockResolvedValue(emptyReview);
});

test("adds Adhoc Checks navigation and loads the PHP RCE review route", async () => {
  render(<App />);

  expect(screen.getByRole("link", { name: "Adhoc Checks" })).toHaveAttribute("href", "#/adhoc/php-rce");
  expect(await screen.findByText("PHP Remote Code Execution")).toBeInTheDocument();
  await waitFor(() => expect(getPhpRceCheck).toHaveBeenCalledWith({ scan_id: 16, page: 1, limit: 25 }));
  expect(screen.getByText("Targeted vulnerability review")).toBeInTheDocument();
});

test("communicates an empty authorized scope without implying safety", async () => {
  render(<App />);

  expect(await screen.findByText("No authorized assets in selected scan")).toBeInTheDocument();
  expect(screen.getByText("318 scan members · 0 authorized assets")).toBeInTheDocument();
  expect(screen.queryByText(/Zero authorized assets is not evidence of safety/i)).not.toBeInTheDocument();
  expect(screen.queryByText("Assets needing attention")).not.toBeInTheDocument();
  expect(screen.queryByText("No matching filtered results")).not.toBeInTheDocument();
});

test("renders candidates, legacy leads, and expandable technical evidence", async () => {
  getPhpRceCheck.mockResolvedValue(populatedReview);
  render(<App />);

  expect(await screen.findByText("app.example.com")).toBeInTheDocument();
  expect(screen.getAllByText("Potential CVE").length).toBeGreaterThan(0);
  const legacyRow = screen.getByText("legacy.example.com").closest("tr");
  expect(within(legacyRow).getByText("Legacy evidence")).toBeInTheDocument();
  expect(within(legacyRow).getByText("Version unavailable")).toBeInTheDocument();
  expect(within(legacyRow).getByText("Not assessed")).toBeInTheDocument();
  expect(within(legacyRow).getByText("No PHP observation")).toBeInTheDocument();
  expect(screen.queryByText("Legacy PHP leads")).not.toBeInTheDocument();
  expect(screen.getAllByText("legacy.example.com")).toHaveLength(1);
  expect(screen.getByText("3 MATCHING RESULTS")).toBeInTheDocument();
  expect(within(screen.getByRole("table")).getAllByRole("row")).toHaveLength(4);

  const details = screen.getByText("Technical evidence").closest("details");
  expect(details).not.toHaveAttribute("open");
  fireEvent.click(screen.getByText("Technical evidence"));
  expect(details).toHaveAttribute("open");
  expect(within(details).getByText("PHP/8.2.34")).toBeInTheDocument();
  expect(within(details).getByText("CVE-2026-109618")).toBeInTheDocument();
  expect(within(details).getByText("Unknown")).toBeInTheDocument();
  expect(within(details).getByRole("link", { name: "https://example.test/CVE-2026-109618" })).toHaveAttribute(
    "href", "https://example.test/CVE-2026-109618"
  );
});

test("uses backend filters and pagination and resets page when a filter changes", async () => {
  getPhpRceCheck.mockResolvedValue({ ...populatedReview, count: 51 });
  render(<App />);
  await screen.findByText("app.example.com");

  fireEvent.click(screen.getByRole("button", { name: "Next" }));
  await waitFor(() => expect(getPhpRceCheck).toHaveBeenLastCalledWith({ scan_id: 16, page: 2, limit: 25 }));

  fireEvent.change(screen.getByLabelText("Classification"), { target: { value: "Potential CVE" } });
  await waitFor(() => expect(getPhpRceCheck).toHaveBeenLastCalledWith({
    scan_id: 16, page: 1, limit: 25, classification: "Potential CVE",
  }));
  expect(screen.getByText("Page 1 of 3 · 51 results")).toBeInTheDocument();
  expect(screen.queryByText(/Server-side filters/i)).not.toBeInTheDocument();
});

test("switches scan context and does not link historical results to current Asset Detail", async () => {
  getPhpRceCheck.mockImplementation((params) => Promise.resolve(params.scan_id === 15 ? historicalReview : populatedReview));
  render(<App />);
  await screen.findByText("app.example.com");

  fireEvent.change(screen.getByLabelText("Successful scan"), { target: { value: "15" } });
  expect(await screen.findByText("historical.example.com")).toBeInTheDocument();
  await waitFor(() => expect(getPhpRceCheck).toHaveBeenLastCalledWith({ scan_id: 15, page: 1, limit: 25 }));
  expect(screen.getByText("Historical successful")).toBeInTheDocument();
  expect(screen.queryByRole("link", { name: "historical.example.com" })).not.toBeInTheDocument();
});

test("reports loading and API failure states without inferred results", async () => {
  let resolveScans;
  getV2Scans.mockReturnValue(new Promise((resolve) => { resolveScans = resolve; }));
  const { unmount } = render(<App />);
  expect(screen.getByText("Loading Adhoc Checks")).toBeInTheDocument();
  resolveScans(scanHistory);
  unmount();

  getV2Scans.mockResolvedValue(scanHistory);
  getPhpRceCheck.mockRejectedValue(new Error("offline"));
  render(<App />);
  expect(await screen.findByText("PHP RCE review unavailable")).toBeInTheDocument();
  expect(screen.getByText(/No values have been inferred/i)).toBeInTheDocument();
});
