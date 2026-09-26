import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import App from "./App";
import { getV2AssetDetail, getV2Assets } from "./services/api";

jest.mock("./services/api", () => ({
  getV2Overview: jest.fn(),
  getV2Assets: jest.fn(),
  getV2AssetDetail: jest.fn(),
  getV2Scans: jest.fn(),
  getV2BrandAssets: jest.fn(),
  getV2AssetAssistant: jest.fn(),
  getInvestigationAssets: jest.fn(),
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
  http_observation_status: "RESPONDED",
  http_status: 302,
  title: "Application",
  final_url: "https://login.example.com",
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

beforeEach(() => {
  getV2Assets.mockReset();
  getV2AssetDetail.mockReset();
});

test("explorer loads current assets, applies server filters, and clears them", async () => {
  window.location.hash = "#/assets";
  getV2Assets.mockResolvedValue(assetPage);
  render(<App />);

  expect(await screen.findByText("app.example.com")).toBeInTheDocument();
  expect(getV2Assets).toHaveBeenCalledWith({ page: 1, limit: 25 });
  expect(screen.getByText("26")).toBeInTheDocument();
  expect(screen.getByText("SHADOW")).toBeInTheDocument();
  expect(screen.getByText("Example Cloud")).toBeInTheDocument();

  fireEvent.change(screen.getByLabelText("Search domain"), {
    target: { name: "search", value: "login" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Apply filters" }));

  await waitFor(() => expect(getV2Assets).toHaveBeenLastCalledWith({
    page: 1, limit: 25, search: "login",
  }));
  expect(await screen.findByText("search: login")).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "Clear" }));
  await waitFor(() => expect(window.location.hash).toBe("#/assets?limit=25"));
});

test("explorer pagination is server-backed and preserves deterministic ordering", async () => {
  window.location.hash = "#/assets?ownership=CONFIRMED&limit=25";
  getV2Assets.mockResolvedValue(assetPage);
  render(<App />);

  expect(await screen.findByText("app.example.com")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Next" }));

  await waitFor(() => expect(getV2Assets).toHaveBeenLastCalledWith({
    page: 2, limit: 25, ownership: "CONFIRMED",
  }));
  expect(screen.getByText("ownership: CONFIRMED")).toBeInTheDocument();
  expect(screen.getByText("Ordered by domain")).toBeInTheDocument();
});

test("asset detail renders exact evidence and no risk for a Candidate", async () => {
  window.location.hash = "#/assets/candidate.example?ownership=CANDIDATE&limit=25";
  getV2AssetDetail.mockResolvedValue({
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
      final_url: "https://vendor.example/login",
      final_status: 200,
      title: "Vendor login",
    },
    ports: [{ port: 443, service: "https" }],
    asn: { asn: "AS64501", organization: "Vendor Networks", ip: "192.0.2.44" },
    provider: "Vendor Cloud",
    technologies: ["nginx"],
    certificate: { expiry_date: "2027-01-01", days_to_expiry: 98, status: "valid" },
    discovery: { sources: [{ source: "brand_tld", seed: "example.com" }] },
    findings: [{ finding: "redirect_review", severity: "MEDIUM", evidence: "external target" }],
  });
  render(<App />);

  expect(await screen.findByRole("heading", { name: "candidate.example" })).toBeInTheDocument();
  expect(screen.getByText("No organizational canonical risk applies to CANDIDATE assets.")).toBeInTheDocument();
  expect(screen.getByText("edge.vendor.example")).toBeInTheDocument();
  expect(screen.getByText("https://vendor.example/login")).toBeInTheDocument();
  expect(screen.getByText("nginx")).toBeInTheDocument();
  expect(screen.getByText("brand_tld")).toBeInTheDocument();
  expect(screen.getByText("external target")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "← Back to Assets" })).toHaveAttribute(
    "href", "#/assets?ownership=CANDIDATE&limit=25"
  );
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
