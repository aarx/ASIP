import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import App from "./App";
import { getV2AssetDetail, getV2Assets, updateV2AssetOwnership } from "./services/api";

jest.mock("./services/api", () => ({
  getV2Overview: jest.fn(),
  getV2Assets: jest.fn(),
  getV2AssetDetail: jest.fn(),
  updateV2AssetOwnership: jest.fn(),
  getV2Scans: jest.fn(),
  getV2BrandAssets: jest.fn(),
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
};

beforeEach(() => {
  getV2Assets.mockReset();
  getV2AssetDetail.mockReset();
  updateV2AssetOwnership.mockReset();
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
  getV2AssetDetail.mockResolvedValue(candidateDetail);
  render(<App />);

  expect(await screen.findByRole("heading", { name: "candidate.example" })).toBeInTheDocument();
  expect(screen.getByText("No organizational canonical risk applies to CANDIDATE assets.")).toBeInTheDocument();
  expect(screen.getByText("edge.vendor.example")).toBeInTheDocument();
  expect(screen.getAllByText("https://vendor.example/login")).toHaveLength(2);
  expect(screen.getByText("nginx")).toBeInTheDocument();
  expect(screen.getByText("brand_tld")).toBeInTheDocument();
  expect(screen.getByText("external target")).toBeInTheDocument();
  expect(screen.getByText("Final destination is outside the reviewed hostname.")).toBeInTheDocument();
  expect(screen.getByText(/observational evidence only and is not authorized for active testing by association/i)).toBeInTheDocument();
  expect(screen.getByText(/does not establish external ownership, malicious activity, or a vulnerability/i)).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "← Back to Assets" })).toHaveAttribute(
    "href", "#/assets?ownership=CANDIDATE&limit=25"
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
  await waitFor(() => expect(screen.getByText("SHADOW")).toBeInTheDocument());
  expect(screen.getByText("3")).toBeInTheDocument();
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
  expect(screen.getByText("No organizational canonical risk applies to CANDIDATE assets.")).toBeInTheDocument();
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
