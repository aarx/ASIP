import { render, screen } from "@testing-library/react";
import App from "./App";
import {
  getDisappearedDomains,
  getNewDomainsDelta,
  getV2AssetDetail,
  getV2Overview,
} from "./services/api";

jest.mock("./services/api", () => ({
  getV2Overview: jest.fn(),
  getV2Assets: jest.fn(),
  getV2AssetDetail: jest.fn(),
  updateV2AssetOwnership: jest.fn(),
  getV2AssetAssistant: jest.fn(),
  getV2Scans: jest.fn(),
  getV2BrandAssets: jest.fn(),
  getV2ReviewIndicators: jest.fn(),
  getRiskyDomains: jest.fn(),
  getFindings: jest.fn(),
  getSensitiveExposure: jest.fn(),
  getExposureSummary: jest.fn(),
  getInvestigationAssets: jest.fn(),
  getNewDomainsDelta: jest.fn(),
  getDisappearedDomains: jest.fn(),
}));
jest.mock("recharts", () => {
  const actual = jest.requireActual("recharts");
  return { ...actual, ResponsiveContainer: ({ children }) => <div>{children}</div> };
});

const overview = {
  current_scan_id: 42,
  previous_scan_id: 41,
  counts: { organizational: 12, known: 8, shadow: 4, candidate: 2, external: 1 },
  risk_distribution: { High: 1, Elevated: 2, Review: 3, Low: 6 },
  changes: { new_assets: 2, disappeared_assets: 1 },
  needs_attention: [{ domain: "attention.example", score: 9, priority: "High", reasons: ["finding"] }],
};

const detail = {
  scan_id: 42,
  domain: "new.example",
  ownership_status: "CONFIRMED",
  is_known: true,
  asset_class: "KNOWN",
  first_seen_scan: 42,
  last_seen_scan: 42,
  first_seen_at: "2026-09-26T10:00:00Z",
  last_seen_at: "2026-09-26T10:00:00Z",
  seed: "example.com",
  risk: { score: 1, priority: "Low", reasons: ["http_exposed"] },
  dns: { ip: "192.0.2.20", has_ip: true, reverse_dns: null },
  http: { observation_status: "RESPONDED", status: 200 },
  ports: [],
  asn: null,
  provider: null,
  technologies: [],
  certificate: null,
  discovery: { sources: [] },
  findings: [],
};

beforeEach(() => {
  getV2Overview.mockReset();
  getNewDomainsDelta.mockReset();
  getDisappearedDomains.mockReset();
  getV2AssetDetail.mockReset();
});

test("Overview metrics and attention assets lead into analyst workflows", async () => {
  window.location.hash = "#/risk/needs-attention";
  getV2Overview.mockResolvedValue(overview);
  render(<App />);

  expect(await screen.findByText("attention.example")).toBeInTheDocument();
  expect(screen.getByText("attention.example").closest("a")).toHaveAttribute("href", "#/assets/attention.example?return=risk%2Fneeds-attention");
  expect(screen.getByRole("link", { name: "Overview" })).toHaveAttribute("href", "#/overview");
  expect(screen.getByRole("link", { name: "Risk Overview" })).toHaveAttribute("href", "#/risk");
});

test("change intelligence shows exact successful-scan membership deltas", async () => {
  window.location.hash = "#/changes?view=new";
  getNewDomainsDelta.mockResolvedValue({ from_scan: 41, to_scan: 42, new_domains: ["new.example"] });
  getDisappearedDomains.mockResolvedValue({ from_scan: 41, to_scan: 42, disappeared_domains: ["gone.example"] });
  const view = render(<App />);

  expect(await screen.findByText("new.example")).toBeInTheDocument();
  expect(screen.getByText("Previous authoritative")).toBeInTheDocument();
  expect(screen.getByText("Current authoritative")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "new.example" })).toHaveAttribute(
    "href", "#/assets/new.example?return=changes&return_query=view%3Dnew"
  );
  expect(screen.getByText(/does not infer why an asset appeared or disappeared/i)).toBeInTheDocument();
  view.unmount();

  window.location.hash = "#/changes?view=disappeared";
  render(<App />);
  expect(await screen.findByText("gone.example")).toBeInTheDocument();
  expect(screen.getByText("Last compared in scan #41 · not current")).toBeInTheDocument();
  expect(screen.queryByRole("link", { name: "gone.example" })).not.toBeInTheDocument();
  expect(screen.getByText("No current detail")).toBeInTheDocument();
});

test("Asset Detail preserves change context and links to Investigation", async () => {
  window.location.hash = "#/assets/new.example?return=changes&return_query=view%3Dnew";
  getV2AssetDetail.mockResolvedValue(detail);
  render(<App />);

  expect(await screen.findByRole("heading", { name: "new.example" })).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "← Back to Change Intelligence" })).toHaveAttribute("href", "#/changes?view=new");
  expect(screen.getByRole("link", { name: "Investigate asset" })).toHaveAttribute(
    "href", "#/investigate?domain=new.example&detail_return=return%3Dchanges%26return_query%3Dview%253Dnew"
  );
});

test("change intelligence handles a missing previous successful baseline", async () => {
  window.location.hash = "#/changes?view=new";
  getNewDomainsDelta.mockResolvedValue({ from_scan: null, to_scan: 42, new_domains: [] });
  getDisappearedDomains.mockResolvedValue({ from_scan: null, to_scan: 42, disappeared_domains: [] });
  render(<App />);

  expect(await screen.findByText("No previous authoritative baseline")).toBeInTheDocument();
  expect(screen.getByText(/after at least two successful scans/i)).toBeInTheDocument();
});
