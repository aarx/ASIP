import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import App from "./App";
import { getV2AssetDetail, getV2BrandAssets, updateV2AssetOwnership } from "./services/api";

jest.mock("./services/api", () => ({
  getV2Overview: jest.fn(),
  getV2Assets: jest.fn(),
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

const candidate = {
  domain: "acme-example.net",
  ownership_status: "CANDIDATE",
  asset_class: "CANDIDATE",
  ip: "192.0.2.81",
  has_ip: true,
  http_observation_status: "RESPONDED",
  http_status: 302,
  final_url: null,
  final_status: null,
  final_url_verification: "UNRESOLVED",
  redirect_evidence: {
    requested_url: "https://acme-example.net/",
    http_status: 302,
    first_hop_location: "https://vendor.example/acme",
    first_hop_destination: "https://vendor.example/acme",
    observed_hops: [],
    verified_terminal_url: null,
    completion_status: "UNRESOLVED",
    stop_reason: "redirect_traversal_disabled",
  },
  title: "Vendor landing page",
  discovery_sources: ["brand_tld", "crtsh"],
  seeds: ["acme.com"],
  risk: null,
};

const external = {
  domain: "acme-reference.org",
  ownership_status: "EXTERNAL",
  asset_class: "EXTERNAL",
  ip: null,
  has_ip: false,
  http_observation_status: "UNKNOWN",
  http_status: null,
  final_url: null,
  final_status: null,
  title: null,
  discovery_sources: ["brand_pattern"],
  seeds: ["acme.com"],
  risk: null,
};

function brandResponse({ count = 2, assets = [candidate, external], page = 1, limit = 25 } = {}) {
  return { scan_id: 42, page, limit, count, assets };
}

function mockBrandCounts(inventory = brandResponse()) {
  getV2BrandAssets.mockImplementation((params) => {
    if (params.limit === 25) return Promise.resolve(inventory);
    if (params.asset_class === "CANDIDATE") return Promise.resolve(brandResponse({ count: 1, assets: [], limit: 1 }));
    if (params.asset_class === "EXTERNAL") return Promise.resolve(brandResponse({ count: 1, assets: [], limit: 1 }));
    return Promise.resolve(brandResponse({ count: 2, assets: [], limit: 1 }));
  });
}

beforeEach(() => {
  getV2BrandAssets.mockReset();
  getV2AssetDetail.mockReset();
  updateV2AssetOwnership.mockReset();
});

test("Brand Perimeter separates Candidate and External evidence from organizational risk", async () => {
  window.location.hash = "#/brand";
  mockBrandCounts();

  render(<App />);

  expect(await screen.findByText("acme-example.net")).toBeInTheDocument();
  expect(screen.getByText("acme-reference.org")).toBeInTheDocument();
  expect(screen.getByText("CANDIDATE")).toBeInTheDocument();
  expect(screen.getByText("EXTERNAL")).toBeInTheDocument();
  expect(screen.getByText("https://vendor.example/acme")).toBeInTheDocument();
  expect(screen.getByText("Outside confirmed surface")).toBeInTheDocument();
  expect(screen.getByText("Potential brand misuse or lookalike domains")).toBeInTheDocument();
  expect(screen.queryByText("Candidate and External assets are shown for review and do not receive organizational risk.")).not.toBeInTheDocument();
  expect(screen.queryByText("Why discovered")).not.toBeInTheDocument();
  expect(screen.queryByText("No org. risk")).not.toBeInTheDocument();
  expect(document.querySelector(".status-shadow")).not.toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Open acme-example.net" })).toHaveAttribute(
    "href", "#/assets/acme-example.net?return=brand"
  );
});

test("Brand Perimeter sends supported search, ownership, and page filters", async () => {
  window.location.hash = "#/brand?search=reference&ownership=EXTERNAL&page=2";
  mockBrandCounts(brandResponse({ count: 26, assets: [external], page: 2 }));

  render(<App />);

  expect(await screen.findByText("acme-reference.org")).toBeInTheDocument();
  expect(getV2BrandAssets).toHaveBeenCalledWith({
    page: 2, limit: 25, search: "reference", asset_class: "EXTERNAL",
  });
  expect(screen.getByText("Page 2 of 2 · 26 matching")).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "Previous" }));
  await waitFor(() => expect(window.location.hash).toBe("#/brand?search=reference&ownership=EXTERNAL"));
});

test("Brand Perimeter uses effective class for counts and badges when stored ownership differs", async () => {
  window.location.hash = "#/brand?ownership=CANDIDATE";
  const effectiveCandidate = {
    ...candidate,
    ownership_status: "CONFIRMED",
    asset_class: "CANDIDATE",
  };
  mockBrandCounts(brandResponse({ count: 1, assets: [effectiveCandidate] }));

  render(<App />);

  expect(await screen.findByText("acme-example.net")).toBeInTheDocument();
  expect(screen.getByText("CANDIDATE")).toBeInTheDocument();
  expect(getV2BrandAssets).toHaveBeenCalledWith({ page: 1, limit: 25, asset_class: "CANDIDATE" });
  expect(getV2BrandAssets).toHaveBeenCalledWith({ page: 1, limit: 1, asset_class: "CANDIDATE" });
});

test("Brand Perimeter has a truthful empty state", async () => {
  window.location.hash = "#/brand";
  mockBrandCounts(brandResponse({ count: 0, assets: [] }));

  render(<App />);

  expect(await screen.findByText("No Brand Perimeter assets match")).toBeInTheDocument();
  expect(screen.queryByText("No org. risk")).not.toBeInTheDocument();
});

test("Candidate detail keeps the Brand Perimeter return context and no canonical risk", async () => {
  window.location.hash = "#/assets/acme-example.net?return=brand";
  getV2AssetDetail.mockResolvedValue({
    scan_id: 42,
    domain: candidate.domain,
    ownership_status: "CANDIDATE",
    asset_class: "CANDIDATE",
    first_seen_scan: 42,
    last_seen_scan: 42,
    first_seen_at: "2026-09-25T10:00:00Z",
    last_seen_at: "2026-09-25T10:00:00Z",
    seed: "acme.com",
    risk: null,
    dns: { ip: candidate.ip, has_ip: true, reverse_dns: null },
    http: { observation_status: "RESPONDED", status: 302, final_url: null, final_status: null, redirect_evidence: candidate.redirect_evidence, title: candidate.title },
    ports: [],
    asn: null,
    provider: null,
    technologies: [],
    certificate: null,
    discovery: { sources: [{ source: "brand_tld", seed: "acme.com" }] },
    findings: [],
  });

  render(<App />);

  expect(await screen.findByRole("heading", { name: candidate.domain })).toBeInTheDocument();
  expect(screen.getByText("No organizational canonical risk applies to CANDIDATE assets.")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "← Back to Brand Perimeter" })).toHaveAttribute("href", "#/brand");
});

test("development acceptance fixture exercises Brand review without backend data or persistence", async () => {
  window.location.hash = "#/brand?fixture=ownership-review";
  const inventory = render(<App />);

  expect(await screen.findByText("Development acceptance fixture")).toBeInTheDocument();
  expect(screen.getByText("abc-login-test.invalid")).toBeInTheDocument();
  expect(screen.getByText("outside-reference.invalid")).toBeInTheDocument();
  expect(getV2BrandAssets).not.toHaveBeenCalled();
  inventory.unmount();

  window.location.hash = "#/assets/abc-login-test.invalid?return=brand&return_query=fixture%3Downership-review";
  render(<App />);
  expect(await screen.findByText("DEVELOPMENT FIXTURE · NO PERSISTENCE")).toBeInTheDocument();
  expect(getV2AssetDetail).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Confirm Organizational Asset" }));
  fireEvent.click(screen.getByRole("button", { name: "Confirm decision" }));
  expect(await screen.findByText("Fixture preview only: CONFIRMED was not persisted.")).toBeInTheDocument();
  expect(updateV2AssetOwnership).not.toHaveBeenCalled();
  expect(screen.getByText("No organizational canonical risk applies to CANDIDATE assets.")).toBeInTheDocument();
});
