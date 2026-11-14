import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import App from "./App";
import {
  exportV2AssetsCsv,
  getV2AssetDetail,
  getV2Assets,
  getV2AssetsSummary,
  updateV2AssetOwnership,
} from "./services/api";

jest.mock("./services/api", () => ({
  getV2Overview: jest.fn(),
  getV2Assets: jest.fn(),
  getV2AssetsSummary: jest.fn(),
  exportV2AssetsCsv: jest.fn(),
  getV2AssetDetail: jest.fn(),
  updateV2AssetOwnership: jest.fn(),
  getV2Scans: jest.fn(),
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

const currentAsset = {
  domain: "app.example.com",
  ownership_status: "CONFIRMED",
  is_known: false,
  asset_class: "SHADOW",
  first_seen_scan: 40,
  last_seen_scan: 42,
  ip: "192.0.2.20",
  has_ip: true,
  http_live: true,
  http_observation_status: "RESPONDED",
  http_status: 302,
  title: "Application",
  final_url: null,
  final_status: null,
  redirect_evidence: {
    requested_url: "https://app.example.com/",
    http_status: 302,
    first_hop_location: "https://login.example.com",
    first_hop_destination: "https://login.example.com",
    observed_hops: [{ source_url: "https://app.example.com/", http_status: 302, location: "https://login.example.com", destination_url: "https://login.example.com", followed: false }],
    verified_terminal_url: null,
    completion_status: "UNRESOLVED",
    stop_reason: "redirect_traversal_disabled",
  },
  provider: "Example Cloud",
  asn: "AS64500",
  risk: { score: 8, priority: "High", reasons: ["shadow_asset", "finding"] },
};

const assetPage = {
  scan_id: 42,
  page: 1,
  limit: 25,
  count: 26,
  assets: [currentAsset],
};

const candidateDetail = {
  scan_id: 42,
  domain: "candidate.example",
  ownership_status: "CANDIDATE",
  is_known: false,
  asset_class: "CANDIDATE",
  first_seen_scan: 42,
  last_seen_scan: 42,
  first_seen_at: "2026-09-25T10:00:00",
  last_seen_at: "2026-09-25T10:00:00",
  seed: "example.com",
  risk: null,
  dns: { ip: "192.0.2.44", has_ip: true, reverse_dns: "edge.vendor.example" },
  http: {
    observation_status: "RESPONDED",
    live: true,
    status: 302,
    reason: "redirect",
    final_url: null,
    final_status: null,
    redirect_evidence: {
      requested_url: "https://candidate.example/",
      http_status: 302,
      first_hop_location: "https://vendor.example/login",
      first_hop_destination: "https://vendor.example/login",
      observed_hops: [{ source_url: "https://candidate.example/", http_status: 302, location: "https://vendor.example/login", destination_url: "https://vendor.example/login", followed: false }],
      verified_terminal_url: null,
      completion_status: "UNRESOLVED",
      stop_reason: "redirect_traversal_disabled",
    },
    title: "Vendor login",
  },
  ports: [{ port: 443, service: "https" }],
  asn: { asn: "AS64501", organization: "Vendor Networks", ip: "192.0.2.44" },
  provider: "Vendor Cloud",
  technologies: ["nginx"],
  certificate: { expiry_date: "2027-01-01", days_to_expiry: 98, status: "valid" },
  discovery: { sources: [{ source: "brand_tld", seed: "example.com" }] },
  findings: [{ finding: "redirect_review", severity: "MEDIUM", evidence: "external target" }],
};

const technologyDetail = {
  ...candidateDetail,
  domain: "technology.example",
  ownership_status: "CONFIRMED",
  asset_class: "KNOWN",
  is_known: true,
  technologies: ["nginx", "php"],
  technology_observations: [
    {
      technology: "php",
      version: "8.2.34",
      confidence: "high",
      evidence_type: "x-powered-by_header",
      sanitized_evidence: "PHP/8.2.34",
      observed_url: "https://technology.example",
      detector_version: "sr-tech-02",
      lifecycle: {
        status: "security_support",
        matched_release_branch: "8.2",
        active_support_until: "2024-12-31",
        security_support_until: "2026-12-31",
        end_of_life: "2026-12-31",
        source_url: "https://www.php.net/supported-versions.php",
        dataset_revision: "2026-10-28",
        assessment_date: "2026-10-28",
      },
      cve_intelligence: {
        assessment_date: "2026-10-28",
        dataset_revision: "2026-10-28",
        coverage: "partial",
        candidates: [
          {
            cve_id: "CVE-2026-109618",
            applicability_status: "potentially_affected",
            reported_version: "8.2.34",
            affected_version_range: "< 8.2.35 (PHP 8.2 branch)",
            fixed_version: "8.2.35",
            source_url: "https://example.test/cve-2026-109618",
            evidence_confidence: "high_version_range_match",
            patch_status: "unknown",
            explanation_code: "php_version_within_verified_affected_range",
          },
        ],
      },
    },
    {
      technology: "php",
      version: "8.1.0",
      confidence: "medium",
      evidence_type: "server_header",
      sanitized_evidence: "PHP/8.1.0",
      observed_url: "https://technology.example",
      detector_version: "sr-tech-02",
      lifecycle: { status: "unknown" },
      cve_intelligence: { coverage: "partial", candidates: [] },
    },
    {
      technology: "nginx",
      version: null,
      confidence: "low",
      evidence_type: "server_header",
      sanitized_evidence: "nginx",
      observed_url: "https://technology.example",
      detector_version: "sr-tech-02",
    },
  ],
};

beforeEach(() => {
  getV2Assets.mockReset();
  getV2AssetsSummary.mockReset();
  exportV2AssetsCsv.mockReset();
  getV2AssetDetail.mockReset();
  updateV2AssetOwnership.mockReset();
  getV2AssetsSummary.mockResolvedValue({
    scope: "current", scan_id: 42, count: 2133,
    classification_counts: { KNOWN: 60, SHADOW: 769, CANDIDATE: 1304 },
  });
});

test("explorer loads current assets, applies server filters, and clears them", async () => {
  window.location.hash = "#/assets";
  getV2Assets.mockResolvedValue(assetPage);
  render(<App />);

  expect(await screen.findByText("app.example.com")).toBeInTheDocument();
  expect(getV2Assets).toHaveBeenCalledWith({ scope: "current", page: 1, limit: 25, sort_by: "domain", sort_dir: "asc" });
  expect(getV2AssetsSummary).toHaveBeenCalledWith({ scope: "current" });
  expect(screen.getByRole("button", { name: "Current scan" })).toHaveAttribute("aria-pressed", "true");
  expect(screen.getByText("2,133 current scan assets")).toBeInTheDocument();
  expect(screen.getByText("Needs Verification 1,304")).toBeInTheDocument();
  expect(screen.getByText("26")).toBeInTheDocument();
  expect(screen.getByText("SHADOW")).toBeInTheDocument();
  expect(screen.getByText("Example Cloud")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Sort by Priority" })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Sort by Risk Score" })).toBeInTheDocument();
  expect(screen.getByText("8")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Sort by Asset, currently ascending" }).closest("th")).toHaveAttribute("aria-sort", "ascending");

  fireEvent.change(screen.getByLabelText("Search domain"), {
    target: { name: "search", value: "login" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));

  await waitFor(() => expect(getV2Assets).toHaveBeenLastCalledWith({
    scope: "current", page: 1, limit: 25, search: "login", sort_by: "domain", sort_dir: "asc",
  }));
  expect(await screen.findByText("search: login")).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "Clear" }));
  await waitFor(() => expect(window.location.hash).toBe("#/assets?limit=25"));
  expect(getV2AssetsSummary).toHaveBeenCalledTimes(1);
});

test("Asset Explorer distinguishes UNKNOWN and NO_RESPONSE HTTP status wording", async () => {
  window.location.hash = "#/assets";
  getV2Assets.mockResolvedValue({
    ...assetPage,
    count: 2,
    assets: [
      { ...currentAsset, domain: "unknown.example.com", http_live: null, http_observation_status: "UNKNOWN", http_status: 0 },
      { ...currentAsset, domain: "no-response.example.com", http_live: false, http_observation_status: "NO_RESPONSE", http_status: 0 },
    ],
  });
  render(<App />);

  const unknownRow = within(await screen.findByText("unknown.example.com").then((node) => node.closest("tr")));
  const noResponseRow = within(screen.getByText("no-response.example.com").closest("tr"));
  expect(unknownRow.getByText("UNKNOWN")).toBeInTheDocument();
  expect(unknownRow.getByText("No HTTP status recorded")).toBeInTheDocument();
  expect(noResponseRow.getByText("NO_RESPONSE")).toBeInTheDocument();
  expect(noResponseRow.getByText("No HTTP response")).toBeInTheDocument();
});

test("explorer pagination is server-backed and preserves deterministic ordering", async () => {
  window.location.hash = "#/assets?ownership=CONFIRMED&limit=25";
  getV2Assets.mockResolvedValue(assetPage);
  render(<App />);

  expect(await screen.findByText("app.example.com")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Next" }));

  await waitFor(() => expect(getV2Assets).toHaveBeenLastCalledWith({
    scope: "current", page: 2, limit: 25, ownership: "CONFIRMED", sort_by: "domain", sort_dir: "asc",
  }));
  expect(screen.getByText("ownership: CONFIRMED")).toBeInTheDocument();
  expect(screen.getByText("Ordered by domain")).toBeInTheDocument();
});

test("overview drill-down filters are consumed by the asset explorer", async () => {
  window.location.hash = "#/assets?asset_class=KNOWN&priority=High&limit=25";
  getV2Assets.mockResolvedValue(assetPage);
  render(<App />);

  await screen.findByText("app.example.com");
  expect(getV2Assets).toHaveBeenCalledWith({
    scope: "current", page: 1, limit: 25, asset_class: "KNOWN", priority: "High",
    sort_by: "domain", sort_dir: "asc",
  });
  expect(screen.getByText("asset class: KNOWN")).toBeInTheDocument();
  expect(screen.getByText("priority: High")).toBeInTheDocument();
});

test("asset explorer preserves exact brand-source drilldown filters and terminology", async () => {
  window.location.hash = "#/assets?discovery_source=brand_union&asset_class=CANDIDATE&limit=25";
  getV2Assets.mockResolvedValue(assetPage);
  render(<App />);

  await screen.findByText("app.example.com");
  expect(getV2Assets).toHaveBeenCalledWith({
    scope: "current", page: 1,
    limit: 25,
    asset_class: "CANDIDATE",
    discovery_source: "brand_union",
    sort_by: "domain",
    sort_dir: "asc",
  });
  expect(screen.getByText("asset class: Needs Verification")).toBeInTheDocument();
  expect(screen.getByText("discovery source: brand_union")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Open app.example.com" })).toHaveAttribute(
    "href", "#/assets/app.example.com?discovery_source=brand_union&asset_class=CANDIDATE&limit=25"
  );
});

test("Asset Explorer preserves its explicit HTTP observation filter", async () => {
  window.location.hash = "#/assets?ownership=CONFIRMED&http_observation_status=NO_RESPONSE&limit=25";
  getV2Assets.mockResolvedValue(assetPage);
  render(<App />);

  await screen.findByText("app.example.com");
  expect(getV2Assets).toHaveBeenCalledWith({
    scope: "current", page: 1,
    limit: 25,
    ownership: "CONFIRMED",
    http_observation_status: "NO_RESPONSE",
    sort_by: "domain",
    sort_dir: "asc",
  });
  expect(screen.getByText("ownership: CONFIRMED")).toBeInTheDocument();
  expect(screen.getByText("http observation status: NO_RESPONSE")).toBeInTheDocument();
});

test("Asset Explorer preserves naming exposure drill-down filters and pagination", async () => {
  window.location.hash = "#/assets?exposure_keyword=DEV&limit=25&page=2";
  getV2Assets.mockResolvedValue({ ...assetPage, page: 2, count: 32 });
  render(<App />);

  await screen.findByText("app.example.com");
  expect(getV2Assets).toHaveBeenCalledWith({
    scope: "current", page: 2,
    limit: 25,
    exposure_keyword: "DEV",
    sort_by: "domain",
    sort_dir: "asc",
  });
  expect(screen.getByText("exposure keyword: DEV")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Open app.example.com" })).toHaveAttribute(
    "href", "#/assets/app.example.com?exposure_keyword=DEV&limit=25&page=2"
  );
});

test("Asset Explorer forwards metric drill-down filters and preserves their active state", async () => {
  window.location.hash = "#/assets?risk_positive=true&has_ip=true&http_live=true&http_status_group=3xx&http_status=302&limit=25";
  getV2Assets.mockResolvedValue(assetPage);
  render(<App />);

  await screen.findByText("app.example.com");
  expect(getV2Assets).toHaveBeenCalledWith({
    scope: "current", page: 1,
    limit: 25,
    risk_positive: "true",
    has_ip: "true",
    http_live: "true",
    http_status: "302",
    http_status_group: "3xx",
    sort_by: "domain",
    sort_dir: "asc",
  });
  expect(screen.getByText("risk positive: true")).toBeInTheDocument();
  expect(screen.getByText("has ip: true")).toBeInTheDocument();
  expect(screen.getByText("http live: true")).toBeInTheDocument();
  expect(screen.getByText("http status: 302")).toBeInTheDocument();
  expect(screen.getByText("http status group: 3xx")).toBeInTheDocument();
});

test("HTTP group drilldown keeps its filter through pagination and Asset Detail, then clears it", async () => {
  window.location.hash = "#/assets?http_status_group=3xx";
  getV2Assets.mockResolvedValue(assetPage);
  render(<App />);

  await screen.findByText("app.example.com");
  expect(getV2Assets).toHaveBeenLastCalledWith({
    scope: "current", page: 1, limit: 25, http_status_group: "3xx", sort_by: "domain", sort_dir: "asc",
  });
  expect(screen.getByText("http status group: 3xx")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Open app.example.com" })).toHaveAttribute(
    "href", "#/assets/app.example.com?http_status_group=3xx"
  );

  fireEvent.click(screen.getByRole("button", { name: "Next" }));
  await waitFor(() => expect(getV2Assets).toHaveBeenLastCalledWith({
    scope: "current", page: 2, limit: 25, http_status_group: "3xx", sort_by: "domain", sort_dir: "asc",
  }));
  expect(screen.getByText("http status group: 3xx")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Open app.example.com" })).toHaveAttribute(
    "href", "#/assets/app.example.com?http_status_group=3xx&page=2&limit=25"
  );

  fireEvent.click(screen.getByRole("button", { name: "Clear" }));
  await waitFor(() => expect(getV2Assets).toHaveBeenLastCalledWith({
    scope: "current", page: 1, limit: 25, sort_by: "domain", sort_dir: "asc",
  }));
  expect(screen.queryByText("http status group: 3xx")).not.toBeInTheDocument();
});

test("asset drill-down routes respond to hash navigation in both directions", async () => {
  const noResponseHash = "#/assets?ownership=CONFIRMED&http_observation_status=NO_RESPONSE&limit=25";
  const respondedHash = "#/assets?ownership=CONFIRMED&http_observation_status=RESPONDED&limit=25";
  window.location.hash = noResponseHash;
  getV2Assets.mockResolvedValue(assetPage);
  render(<App />);

  await screen.findByText("app.example.com");
  window.history.pushState({}, "", respondedHash);
  fireEvent(window, new Event("hashchange"));
  await waitFor(() => expect(getV2Assets).toHaveBeenLastCalledWith({
    scope: "current", page: 1,
    limit: 25,
    ownership: "CONFIRMED",
    http_observation_status: "RESPONDED",
    sort_by: "domain",
    sort_dir: "asc",
  }));

  window.history.pushState({}, "", noResponseHash);
  fireEvent(window, new Event("hashchange"));
  await waitFor(() => expect(getV2Assets).toHaveBeenLastCalledWith({
    scope: "current", page: 1,
    limit: 25,
    ownership: "CONFIRMED",
    http_observation_status: "NO_RESPONSE",
    sort_by: "domain",
    sort_dir: "asc",
  }));
});

test("asset explorer exports the complete filtered authoritative dataset", async () => {
  window.location.hash = "#/assets?asset_class=SHADOW&provider=Example%20Cloud&limit=25";
  getV2Assets.mockResolvedValue(assetPage);
  exportV2AssetsCsv.mockResolvedValue({ data: new Blob(["Domain\r\napp.example.com\r\n"]) });
  const createObjectURL = jest.fn(() => "blob:assets");
  const revokeObjectURL = jest.fn();
  const anchorClick = jest.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  Object.defineProperty(window.URL, "createObjectURL", { configurable: true, value: createObjectURL });
  Object.defineProperty(window.URL, "revokeObjectURL", { configurable: true, value: revokeObjectURL });
  render(<App />);

  await screen.findByText("app.example.com");
  fireEvent.click(screen.getByRole("button", { name: "Export CSV" }));

  await waitFor(() => expect(exportV2AssetsCsv).toHaveBeenCalledWith({
    scope: "current",
    asset_class: "SHADOW", provider: "Example Cloud",
    sort_by: "domain", sort_dir: "asc",
  }));
  expect(createObjectURL).toHaveBeenCalled();
  await waitFor(() => expect(screen.getByRole("button", { name: "Export CSV" })).toBeEnabled());
  anchorClick.mockRestore();
});

test("All scans uses retained identity totals, preserves compatible filters, and marks unavailable evidence", async () => {
  window.location.hash = "#/assets?search=app&page=3&limit=25";
  const retainedAsset = {
    ...currentAsset,
    domain: "historical-only.example.com",
    asset_class: "CANDIDATE",
    current_scan_member: false,
    latest_evidence_scan_id: 18,
    latest_evidence_scan_status: "SUCCEEDED",
    http_observation_status: "UNKNOWN",
    http_live: null,
    http_status: null,
    field_availability: { dns: false, http: false, provider: false, asn: false, risk: false },
    risk_available: false,
    risk: null,
  };
  getV2Assets
    .mockResolvedValueOnce(assetPage)
    .mockResolvedValueOnce({
      scope: "retained_history", current_scan_id: 42, page: 1, limit: 25,
      count: 26, assets: [retainedAsset],
    })
    .mockResolvedValueOnce({
      scope: "retained_history", current_scan_id: 42, page: 2, limit: 25,
      count: 26, assets: [retainedAsset],
    })
    .mockResolvedValue(assetPage);
  getV2AssetsSummary
    .mockResolvedValueOnce({ scope: "current", count: 2133, classification_counts: { KNOWN: 60, SHADOW: 769, CANDIDATE: 1304 } })
    .mockResolvedValueOnce({
      scope: "retained_history", count: 2620,
      classification_counts: { KNOWN: 60, SHADOW: 857, CANDIDATE: 1703, EXTERNAL: 0 },
      retention: { scan_count_with_membership: 16, is_exhaustive_lifetime_history: false },
    })
    .mockResolvedValue({ scope: "current", count: 2133, classification_counts: { KNOWN: 60, SHADOW: 769, CANDIDATE: 1304 } });
  render(<App />);

  await screen.findByText("app.example.com");
  fireEvent.click(screen.getByRole("button", { name: "All scans" }));
  expect(await screen.findByText("historical-only.example.com")).toBeInTheDocument();
  expect(screen.getByText("Distinct retained identities")).toHaveAttribute("title", expect.stringContaining("Risk and HTTP fields reflect the API-selected observation"));
  expect(screen.getByRole("group", { name: "Inventory scope" })).toContainElement(screen.getByRole("button", { name: "All scans" }));
  expect(screen.getByRole("button", { name: "All scans" })).toHaveAttribute("aria-pressed", "true");
  expect(window.location.hash).toBe("#/assets?search=app&scope=retained_history&limit=25");
  expect(getV2Assets).toHaveBeenLastCalledWith({
    scope: "retained_history", page: 1, limit: 25, sort_by: "domain", sort_dir: "asc", search: "app",
  });
  expect(getV2AssetsSummary).toHaveBeenLastCalledWith({ scope: "retained_history" });
  expect(screen.getByRole("button", { name: "All scans" })).toHaveAttribute("aria-pressed", "true");
  expect(screen.getByText("2,620 retained identities")).toBeInTheDocument();
  expect(screen.getByText("Needs Verification 1,703")).toBeInTheDocument();
  const row = within(screen.getByText("historical-only.example.com").closest("tr"));
  expect(row.getByText("Historical-only identity")).toBeInTheDocument();
  expect(row.getByText("Evidence · scan #18 · SUCCEEDED")).toBeInTheDocument();
  expect(row.getAllByText("Evidence unavailable")).toHaveLength(2);
  expect(row.getAllByText("Unavailable")).toHaveLength(2);
  expect(row.getByRole("link", { name: "Open historical-only.example.com" })).toHaveAttribute(
    "href", "#/assets/historical-only.example.com?search=app&scope=retained_history&limit=25"
  );
  fireEvent.click(screen.getByRole("button", { name: "Next" }));
  await waitFor(() => expect(getV2Assets).toHaveBeenLastCalledWith({
    scope: "retained_history", page: 2, limit: 25, search: "app", sort_by: "domain", sort_dir: "asc",
  }));
  fireEvent.click(screen.getByRole("button", { name: "Current scan" }));
  await waitFor(() => expect(getV2Assets).toHaveBeenLastCalledWith({
    scope: "current", page: 1, limit: 25, search: "app", sort_by: "domain", sort_dir: "asc",
  }));
  expect(window.location.hash).toBe("#/assets?search=app&limit=25");
});

test("retained-history export sends scope and compatible filters for the full population", async () => {
  window.location.hash = "#/assets?has_ip=true&page=2&limit=25&sort_by=priority&sort_dir=desc";
  getV2Assets.mockResolvedValue({ ...assetPage, scope: "retained_history", current_scan_id: 42 });
  getV2AssetsSummary.mockResolvedValue({
    scope: "retained_history", count: 2620,
    classification_counts: { KNOWN: 60, SHADOW: 857, CANDIDATE: 1703, EXTERNAL: 0 },
  });
  exportV2AssetsCsv.mockResolvedValue({
    data: new Blob(["Identity Key,Domain\r\n"]),
    headers: { "content-disposition": "attachment; filename=shadowrecon-assets-retained-history.csv" },
  });
  let downloadedFilename;
  const anchorClick = jest.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function click() {
    downloadedFilename = this.download;
  });
  Object.defineProperty(window.URL, "createObjectURL", { configurable: true, value: jest.fn(() => "blob:history") });
  Object.defineProperty(window.URL, "revokeObjectURL", { configurable: true, value: jest.fn() });
  render(<App />);

  await screen.findByText("app.example.com");
  fireEvent.click(screen.getByRole("button", { name: "All scans" }));
  await screen.findByText("2,620 retained identities");
  fireEvent.click(screen.getByRole("button", { name: "Export CSV" }));

  await waitFor(() => expect(exportV2AssetsCsv).toHaveBeenCalledWith({
    scope: "retained_history", has_ip: "true", sort_by: "priority", sort_dir: "desc",
  }));
  expect(anchorClick).toHaveBeenCalled();
  expect(downloadedFilename).toBe("shadowrecon-assets-retained-history.csv");
  anchorClick.mockRestore();
});

test("missing retained classification totals are shown as unavailable instead of zero", async () => {
  window.location.hash = "#/assets?scope=retained_history";
  getV2Assets.mockResolvedValue({ scope: "retained_history", count: 0, assets: [] });
  getV2AssetsSummary.mockResolvedValue({
    scope: "retained_history", count: 2620,
    classification_counts: { KNOWN: null, SHADOW: 0, CANDIDATE: null, EXTERNAL: 0 },
  });
  render(<App />);

  expect(await screen.findByText("2,620 retained identities")).toBeInTheDocument();
  expect(screen.getByText("Some class totals unavailable")).toBeInTheDocument();
  expect(screen.getByText("Shadow 0")).toBeInTheDocument();
  expect(screen.getByText("External 0")).toBeInTheDocument();
  expect(screen.queryByText("Known 0")).not.toBeInTheDocument();
  expect(screen.queryByText("Needs Verification 0")).not.toBeInTheDocument();
});

test("retained Asset Detail requests historical scope and returns to the same inventory query", async () => {
  window.location.hash = "#/assets/historical-only.example.com?scope=retained_history&search=legacy&page=2&limit=25&sort_by=risk_score&sort_dir=desc";
  getV2AssetDetail.mockResolvedValue({
    ...candidateDetail,
    domain: "historical-only.example.com",
    scan_id: 12,
    scan_time: "2026-09-23T05:52:23",
    scope: "retained_history",
    current_scan_member: false,
    evidence_scan_status: "SUCCEEDED",
    evidence_scan_time: "2026-09-23T05:52:23",
    risk: null,
    dns: { ip: null, has_ip: null, reverse_dns: null, observation_available: false },
    http: {
      observation_status: "UNKNOWN", observation_available: false, live: null,
      status: null, reason: null, final_url: null, final_status: null, title: null,
      redirect_evidence: { completion_status: "UNKNOWN" },
    },
    ports: [],
    asn: null,
    provider: null,
    technologies: [],
    technology_observations: [],
    certificate: null,
    discovery: { sources: [{ source: "subfinder", seed: "example.com" }] },
    findings: [{ finding: "retained_indicator", severity: "LOW", evidence: "scan 12 observation" }],
  });
  render(<App />);

  expect(await screen.findByRole("heading", { name: "historical-only.example.com" })).toBeInTheDocument();
  expect(getV2AssetDetail).toHaveBeenCalledWith("historical-only.example.com", { scope: "retained_history" });
  expect(screen.getByText("Retained identity")).toBeInTheDocument();
  expect(screen.getByText("Not present in current scan")).toBeInTheDocument();
  expect(screen.getByText("Evidence scan status").parentElement).toHaveTextContent("SUCCEEDED");
  expect(screen.getByText("Last retained observation · scan #12 · 2026-09-23T05:52:23")).toBeInTheDocument();
  expect(screen.getAllByText(/Historical evidence from scan #12/).length).toBeGreaterThanOrEqual(1);
  expect(screen.getByText("Historical findings from scan #12; not current findings")).toBeInTheDocument();
  expect(screen.getByText("Provenance recorded in scan #12")).toBeInTheDocument();
  expect(screen.queryByText("Current evidence")).not.toBeInTheDocument();
  expect(screen.queryByText("How this asset entered the current scan")).not.toBeInTheDocument();
  expect(screen.queryByText(/recorded for this asset in the current scan/i)).not.toBeInTheDocument();
  expect(screen.getByText("Risk score unavailable for this retained evidence scan.")).toBeInTheDocument();
  expect(screen.getAllByText("Evidence unavailable").length).toBeGreaterThanOrEqual(2);
  expect(screen.queryByText("Ownership Review")).not.toBeInTheDocument();
  expect(screen.getByRole("link", { name: "← Back to Assets" })).toHaveAttribute(
    "href", "#/assets?scope=retained_history&search=legacy&page=2&limit=25&sort_by=risk_score&sort_dir=desc"
  );
});

test("retained identity evidence from the current authoritative scan is labeled current", async () => {
  window.location.hash = "#/assets/current-member.example?scope=retained_history";
  getV2AssetDetail.mockResolvedValue({
    ...candidateDetail,
    domain: "current-member.example",
    scan_id: 19,
    scan_time: "2026-11-11T05:56:53",
    scope: "retained_history",
    current_scan_member: true,
    evidence_scan_status: "SUCCEEDED",
    evidence_scan_time: "2026-11-11T05:56:53",
  });
  getV2AssetsSummary.mockResolvedValue({ scope: "current", scan_id: 19, count: 2133 });
  render(<App />);

  expect(await screen.findByRole("heading", { name: "current-member.example" })).toBeInTheDocument();
  expect(getV2AssetsSummary).toHaveBeenCalledWith({ scope: "current" });
  expect(screen.getByText("Current scan evidence · scan #19 · 2026-11-11T05:56:53")).toBeInTheDocument();
  expect(screen.getByText("Current scan membership").parentElement).toHaveTextContent("Present");
  expect(screen.getByText("How this asset entered the current scan")).toBeInTheDocument();
  expect(screen.queryByText("Historical evidence from scan #19")).not.toBeInTheDocument();
});

test("historical observations on a currently present identity remain tied to their evidence scan", async () => {
  window.location.hash = "#/assets/known-current.example?scope=retained_history";
  getV2AssetDetail.mockResolvedValue({
    ...candidateDetail,
    domain: "known-current.example",
    asset_class: "KNOWN",
    ownership_status: "CONFIRMED",
    scan_id: 12,
    scan_time: "2026-09-23T05:52:23",
    scope: "retained_history",
    current_scan_member: true,
    evidence_scan_status: "SUCCEEDED",
    evidence_scan_time: "2026-09-23T05:52:23",
  });
  getV2AssetsSummary.mockResolvedValue({ scope: "current", scan_id: 19, count: 2133 });
  render(<App />);

  expect(await screen.findByRole("heading", { name: "known-current.example" })).toBeInTheDocument();
  expect(screen.getByText("Current scan membership").parentElement).toHaveTextContent("Present");
  expect(screen.getByText("Last retained observation · scan #12 · 2026-09-23T05:52:23")).toBeInTheDocument();
  expect(screen.getAllByText(/Historical evidence from scan #12/).length).toBeGreaterThanOrEqual(1);
  expect(screen.getByText("Historical findings from scan #12; not current findings")).toBeInTheDocument();
  expect(screen.queryByText("Current-scan deterministic observations requiring investigation")).not.toBeInTheDocument();
});

test("missing historical membership and scan metadata stay unavailable without implying current evidence", async () => {
  window.location.hash = "#/assets/partial-history.example?scope=retained_history";
  getV2AssetDetail.mockResolvedValue({
    ...candidateDetail,
    domain: "partial-history.example",
    scan_id: 12,
    scan_time: null,
    scope: "retained_history",
    current_scan_member: null,
    evidence_scan_status: null,
    evidence_scan_time: null,
    dns: { observation_available: false },
    http: { observation_available: false, observation_status: "UNKNOWN" },
    discovery: { sources: [] },
    findings: [],
  });
  getV2AssetsSummary.mockRejectedValue(new Error("summary unavailable"));
  render(<App />);

  expect(await screen.findByRole("heading", { name: "partial-history.example" })).toBeInTheDocument();
  expect(screen.getByText("Retained evidence · scan #12 · —")).toBeInTheDocument();
  expect(screen.getByText("Current scan membership").parentElement).toHaveTextContent("Unavailable");
  expect(screen.getByText("Evidence scan status").parentElement).toHaveTextContent("—");
  expect(screen.getByText("No provenance rows are available for this evidence scan.")).toBeInTheDocument();
  expect(screen.getByText("No findings were recorded in retained evidence from scan #12.")).toBeInTheDocument();
  expect(screen.getAllByText("Evidence unavailable").length).toBeGreaterThanOrEqual(2);
  expect(screen.queryByText("Current evidence")).not.toBeInTheDocument();
  expect(screen.queryByText(/not present in current scan/i)).not.toBeInTheDocument();
});

test("asset explorer sorts by risk score server-side, resets pagination, and preserves filters", async () => {
  window.location.hash = "#/assets?search=app&ownership=CONFIRMED&page=3&limit=25";
  getV2Assets.mockResolvedValue(assetPage);
  render(<App />);

  await screen.findByText("app.example.com");
  fireEvent.click(screen.getByRole("button", { name: "Sort by Risk Score" }));

  await waitFor(() => expect(getV2Assets).toHaveBeenLastCalledWith({
    scope: "current", page: 1, limit: 25, search: "app", ownership: "CONFIRMED",
    sort_by: "risk_score", sort_dir: "desc",
  }));
  expect(window.location.hash).toBe(
    "#/assets?search=app&ownership=CONFIRMED&limit=25&sort_by=risk_score&sort_dir=desc"
  );
  expect(screen.getByRole("button", { name: "Sort by Risk Score, currently descending" }).closest("th")).toHaveAttribute("aria-sort", "descending");

  fireEvent.click(screen.getByRole("button", { name: "Sort by Risk Score, currently descending" }));
  await waitFor(() => expect(getV2Assets).toHaveBeenLastCalledWith({
    scope: "current", page: 1, limit: 25, search: "app", ownership: "CONFIRMED",
    sort_by: "risk_score", sort_dir: "asc",
  }));
  expect(screen.getByRole("button", { name: "Sort by Risk Score, currently ascending" }).closest("th")).toHaveAttribute("aria-sort", "ascending");
});

test("asset explorer uses canonical priority sorting defaults and keeps selected export ordering", async () => {
  window.location.hash = "#/assets?provider=Example%20Cloud&limit=25";
  getV2Assets.mockResolvedValue(assetPage);
  exportV2AssetsCsv.mockResolvedValue({ data: new Blob(["Domain\r\napp.example.com\r\n"]) });
  const anchorClick = jest.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  Object.defineProperty(window.URL, "createObjectURL", { configurable: true, value: jest.fn(() => "blob:assets") });
  Object.defineProperty(window.URL, "revokeObjectURL", { configurable: true, value: jest.fn() });
  render(<App />);

  await screen.findByText("app.example.com");
  fireEvent.click(screen.getByRole("button", { name: "Sort by Priority" }));
  await waitFor(() => expect(getV2Assets).toHaveBeenLastCalledWith({
    scope: "current", page: 1, limit: 25, provider: "Example Cloud", sort_by: "priority", sort_dir: "desc",
  }));
  fireEvent.click(screen.getByRole("button", { name: "Export CSV" }));
  await waitFor(() => expect(exportV2AssetsCsv).toHaveBeenCalledWith({
    scope: "current", provider: "Example Cloud", sort_by: "priority", sort_dir: "desc",
  }));
  anchorClick.mockRestore();
});

test("asset detail renders exact evidence and no risk for a Candidate", async () => {
  window.location.hash = "#/assets/candidate.example?ownership=CANDIDATE&limit=25";
  getV2AssetDetail.mockResolvedValue(candidateDetail);
  render(<App />);

  expect(await screen.findByRole("heading", { name: "candidate.example" })).toBeInTheDocument();
  expect(screen.getByText(/Current scan evidence · scan #42/)).toBeInTheDocument();
  expect(screen.getByText("How this asset entered the current scan")).toBeInTheDocument();
  expect(screen.getByText("Current-scan deterministic observations requiring investigation")).toBeInTheDocument();
  expect(screen.getByText("No organizational canonical risk applies to Needs Verification assets.")).toBeInTheDocument();
  expect(screen.getByText("edge.vendor.example")).toBeInTheDocument();
  expect(screen.getAllByText("https://vendor.example/login")).toHaveLength(2);
  expect(screen.getByText("nginx")).toBeInTheDocument();
  expect(screen.getByText("brand_tld")).toBeInTheDocument();
  expect(screen.getByText("external target")).toBeInTheDocument();
  expect(screen.getByText("Observed redirect destination is outside the reviewed hostname.")).toBeInTheDocument();
  expect(screen.getByText(/observational evidence only and is not authorized for active testing by association/i)).toBeInTheDocument();
  expect(screen.getByText(/does not establish external ownership, malicious activity, or a vulnerability/i)).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Open Brand Exposure" })).toHaveAttribute(
    "href", "#/brand?ownership=CANDIDATE"
  );
  expect(screen.getByRole("link", { name: "← Back to Assets" })).toHaveAttribute(
    "href", "#/assets?ownership=CANDIDATE&limit=25"
  );
});

test("asset detail separates effective class from stored ownership and groups provenance", async () => {
  window.location.hash = "#/assets/legacy.example?return=brand&search=legacy&ownership=CANDIDATE&page=2";
  getV2AssetDetail.mockResolvedValue({
    ...candidateDetail,
    domain: "legacy.example",
    ownership_status: "CONFIRMED",
    asset_class: "CANDIDATE",
    http: {
      ...candidateDetail.http,
      status: 0,
      final_status: 0,
      final_url: "https://historical.example/landing",
      redirect_evidence: {
        ...candidateDetail.http.redirect_evidence,
        completion_status: "LEGACY_UNKNOWN",
      },
    },
    discovery: {
      sources: [
        { source: "brand_tld", seed: "acme.com" },
        { source: "crt.sh", seed: "acme.com" },
        { source: "san", seed: "acme.com" },
        { source: "subfinder", seed: "acme.com" },
        { source: "internal-source-7", seed: "other.example" },
      ],
    },
  });

  render(<App />);

  expect(await screen.findByRole("heading", { name: "legacy.example" })).toBeInTheDocument();
  expect(screen.getAllByText("Current class").length).toBeGreaterThan(0);
  expect(screen.getByText("Stored ownership")).toBeInTheDocument();
  expect(screen.getByText("Historical URL (unverified)")).toBeInTheDocument();
  expect(screen.queryByText("Historical status (unverified)")).not.toBeInTheDocument();
  const httpPanel = screen.getByText("HTTP").closest("section");
  expect(within(httpPanel).getByText("No HTTP status recorded")).toBeInTheDocument();
  const provenancePanel = screen.getByText("Discovery & provenance").closest("section");
  expect(within(provenancePanel).getByText("Brand exposure")).toBeInTheDocument();
  expect(within(provenancePanel).getByText("Certificate exposure")).toBeInTheDocument();
  expect(within(provenancePanel).getByText("Certificate exposure · SAN expansion")).toBeInTheDocument();
  expect(within(provenancePanel).getByText("Pentest tools")).toBeInTheDocument();
  expect(within(provenancePanel).getByText("internal-source-7")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "← Back to Brand Exposure" })).toHaveAttribute(
    "href", "#/brand?search=legacy&ownership=CANDIDATE&page=2"
  );
});

test("asset detail renders technology intelligence and expands structured evidence", async () => {
  window.location.hash = "#/assets/technology.example";
  getV2AssetDetail.mockResolvedValue(technologyDetail);
  render(<App />);

  expect(await screen.findByText("Technology Intelligence")).toBeInTheDocument();
  expect(screen.getByText("Technology")).toBeInTheDocument();
  expect(screen.getAllByText("8.2.34")).toHaveLength(2);
  expect(screen.getAllByText("Security support")).toHaveLength(2);
  expect(screen.getByText("1 Potential CVE")).toBeInTheDocument();
  expect(screen.getByText("No local candidates")).toBeInTheDocument();
  expect(screen.getByText("Version unavailable")).toBeInTheDocument();
  expect(screen.getByText(/Local CVE advisory coverage is partial/)).toBeInTheDocument();
  expect(screen.getAllByText("php")).toHaveLength(2);

  const nginxRow = screen.getAllByText("nginx")[0].closest("tr");
  expect(within(nginxRow).getAllByText("Not assessed")).toHaveLength(2);

  const phpRow = screen.getAllByText("8.2.34")[0].closest("tr");
  const details = within(phpRow).getByText("Technical details").closest("details");
  expect(details).not.toHaveAttribute("open");
  fireEvent.click(within(phpRow).getByText("Technical details"));
  expect(details).toHaveAttribute("open");
  expect(within(details).getByText("PHP/8.2.34")).toBeInTheDocument();
  expect(within(details).getByText("CVE-2026-109618")).toBeInTheDocument();
  expect(within(details).getByText("Unknown")).toBeInTheDocument();
  expect(within(details).getByRole("link", { name: "https://example.test/cve-2026-109618" })).toHaveAttribute(
    "href", "https://example.test/cve-2026-109618"
  );
});

test("asset detail preserves legacy-only technology labels and empty states", async () => {
  window.location.hash = "#/assets/legacy.example";
  getV2AssetDetail.mockResolvedValue({
    ...candidateDetail,
    domain: "legacy.example",
    technologies: ["Apache HTTP Server", "Apache HTTP Server"],
    technology_observations: [],
  });
  render(<App />);

  expect(await screen.findByText("Apache HTTP Server")).toBeInTheDocument();
  expect(screen.getAllByText("Not assessed")).toHaveLength(2);
  expect(screen.getByText("No structured observation")).toBeInTheDocument();

  getV2AssetDetail.mockResolvedValueOnce({
    ...candidateDetail,
    domain: "empty.example",
    technologies: [],
    technology_observations: [],
  });
  window.location.hash = "#/assets/empty.example";
  fireEvent(window, new HashChangeEvent("hashchange"));
  expect(await screen.findByText("No technology evidence available.")).toBeInTheDocument();
});

test("asset detail uses effective outside-scope class over historical confirmation", async () => {
  window.location.hash = "#/assets/legacy-outside.example";
  getV2AssetDetail.mockResolvedValue({
    ...candidateDetail,
    domain: "legacy-outside.example",
    ownership_status: "CONFIRMED",
    asset_class: "CANDIDATE",
    risk: null,
  });

  render(<App />);

  expect((await screen.findAllByText("Needs Verification")).length).toBeGreaterThan(0);
  expect(screen.getByText("Stored ownership status").parentElement).toHaveTextContent("CONFIRMED");
  expect(screen.getByText("No organizational canonical risk applies to Needs Verification assets.")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Open Brand Exposure" })).toHaveAttribute(
    "href", "#/brand?ownership=CANDIDATE"
  );
});

test("ownership review confirms only after confirmation and refreshes classification", async () => {
  window.location.hash = "#/assets/candidate.example?return=brand";
  getV2AssetDetail
    .mockResolvedValueOnce(candidateDetail)
    .mockResolvedValueOnce({
      ...candidateDetail,
      ownership_status: "CONFIRMED",
      asset_class: "SHADOW",
      risk: { score: 3, priority: "Low", reasons: ["new_asset"] },
    });
  updateV2AssetOwnership.mockResolvedValue({
    domain: "candidate.example",
    ownership_status: "CONFIRMED",
    asset_class: "SHADOW",
  });
  render(<App />);

  expect(await screen.findByText("Ownership Review")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Confirm Organizational Asset" }));
  expect(updateV2AssetOwnership).not.toHaveBeenCalled();
  expect(screen.getByRole("alertdialog", { name: "Confirm ownership decision" })).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Confirm decision" }));

  await waitFor(() => expect(updateV2AssetOwnership).toHaveBeenCalledWith("candidate.example", "CONFIRMED"));
  expect(await screen.findByText("Ownership updated to CONFIRMED.")).toBeInTheDocument();
  await waitFor(() => expect(screen.getAllByText("SHADOW").length).toBeGreaterThan(0));
  expect(screen.getByText("3")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Open Shadow workflow" })).toHaveAttribute("href", "#/shadow");
  expect(screen.getByText(/does not grant active-scanning authorization/i)).toBeInTheDocument();
});

test("ownership review can retain Candidate or mark only the reviewed asset External", async () => {
  window.location.hash = "#/assets/candidate.example";
  getV2AssetDetail
    .mockResolvedValueOnce(candidateDetail)
    .mockResolvedValueOnce({ ...candidateDetail, ownership_status: "EXTERNAL", asset_class: "EXTERNAL" });
  updateV2AssetOwnership.mockResolvedValue({
    domain: "candidate.example",
    ownership_status: "EXTERNAL",
    asset_class: "EXTERNAL",
  });
  render(<App />);

  await screen.findByText("Ownership Review");
  fireEvent.click(screen.getByRole("button", { name: "Leave Candidate" }));
  expect(screen.getByText("Candidate retained. No ownership decision was persisted.")).toBeInTheDocument();
  expect(updateV2AssetOwnership).not.toHaveBeenCalled();

  fireEvent.click(screen.getByRole("button", { name: "Mark External / Not Ours" }));
  expect(screen.getByText(/applies only to/i)).toHaveTextContent("candidate.example");
  fireEvent.click(screen.getByRole("button", { name: "Confirm decision" }));
  await waitFor(() => expect(updateV2AssetOwnership).toHaveBeenCalledWith("candidate.example", "EXTERNAL"));
  expect(await screen.findByText("Ownership updated to EXTERNAL.")).toBeInTheDocument();
});

test("ownership review reports mutation failures without changing displayed evidence", async () => {
  window.location.hash = "#/assets/candidate.example";
  getV2AssetDetail.mockResolvedValue(candidateDetail);
  updateV2AssetOwnership.mockRejectedValue({ response: { data: { detail: "decision rejected" } } });
  render(<App />);

  await screen.findByText("Ownership Review");
  fireEvent.click(screen.getByRole("button", { name: "Confirm Organizational Asset" }));
  fireEvent.click(screen.getByRole("button", { name: "Confirm decision" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("decision rejected");
  expect(screen.getAllByText("CANDIDATE").length).toBeGreaterThan(0);
  expect(screen.getByText("No organizational canonical risk applies to Needs Verification assets.")).toBeInTheDocument();
});

test("asset detail presents API membership errors without inventing evidence", async () => {
  window.location.hash = "#/assets/historical.example";
  getV2AssetDetail.mockResolvedValue({
    error: "domain not found in current authoritative scan",
  });
  render(<App />);

  expect(await screen.findByText("Asset is not in the current surface")).toBeInTheDocument();
  expect(screen.getByText("domain not found in current authoritative scan")).toBeInTheDocument();
  expect(screen.queryByText("Canonical risk")).not.toBeInTheDocument();
});

test("asset explorer and detail expose explicit request failure states", async () => {
  window.location.hash = "#/assets";
  getV2Assets.mockRejectedValue(new Error("offline"));
  const { unmount } = render(<App />);
  expect(await screen.findByText("Asset inventory unavailable")).toBeInTheDocument();
  unmount();

  window.location.hash = "#/assets/app.example.com";
  getV2AssetDetail.mockRejectedValue(new Error("offline"));
  render(<App />);
  expect(await screen.findByText("Asset detail unavailable")).toBeInTheDocument();
});
