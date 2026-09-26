import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import App from "./App";
import { getV2Overview, getV2Scans } from "./services/api";

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
jest.mock("recharts", () => {
  const actual = jest.requireActual("recharts");
  return {
    ...actual,
    ResponsiveContainer: ({ children }) => <div>{children}</div>,
  };
});

const overview = {
  current_scan_id: 42,
  previous_scan_id: 41,
  counts: { organizational: 18, known: 11, shadow: 7, candidate: 3, external: 2 },
  risk_distribution: { High: 1, Elevated: 2, Review: 4, Low: 11 },
  changes: { new_assets: 3, disappeared_assets: 1 },
  needs_attention: [{
    domain: "alpha.example",
    score: 9,
    priority: "High",
    reasons: ["finding", "shadow_asset"],
  }],
};

beforeEach(() => {
  window.location.hash = "#/overview";
  getV2Overview.mockReset();
  getV2Scans.mockReset();
});

test("renders the permanent shell and authoritative overview", async () => {
  getV2Overview.mockResolvedValue(overview);
  jest.spyOn(Date, "now").mockReturnValue(new Date("2026-09-26T12:00:00Z").getTime());
  getV2Scans.mockResolvedValue({
    current_authoritative_scan_id: 42,
    scans: [
      { scan_id: 43, status: "RUNNING", completed_at: null, is_current_authoritative: false },
      { scan_id: 42, status: "SUCCEEDED", completed_at: "2026-09-26T10:00:00Z", is_current_authoritative: true },
    ],
  });
  render(<App />);

  expect(screen.getByText("Loading authoritative state")).toBeInTheDocument();
  expect(await screen.findByText("alpha.example")).toBeInTheDocument();
  expect(screen.getByText("Organizational assets")).toBeInTheDocument();
  expect(screen.getByText("Brand perimeter")).toBeInTheDocument();
  expect(screen.getByText("scan 41 → 42")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Overview" })).toHaveAttribute("aria-current", "page");
  expect(screen.getByRole("link", { name: "Assets" })).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Settings" })).toBeInTheDocument();
  expect(screen.getByRole("link", { name: /Authoritative scan #42 completed 2h ago/i })).toHaveAttribute("href", "#/scans");
  expect(screen.queryByText(/Authoritative scan #43/)).not.toBeInTheDocument();
  expect(screen.getByRole("link", { name: /Authoritative scan #42/i })).toHaveAttribute("title", expect.stringContaining("2026"));
  expect(screen.getByRole("link", { name: "High 1" })).toHaveAttribute("href", "#/assets?priority=High&limit=25");
  expect(screen.getByRole("link", { name: "Elevated 2" })).toHaveAttribute("href", "#/assets?priority=Elevated&limit=25");
  expect(screen.getByRole("link", { name: "Review 4" })).toHaveAttribute("href", "#/assets?priority=Review&limit=25");
  expect(screen.getByRole("link", { name: "Low 11" })).toHaveAttribute("href", "#/assets?priority=Low&limit=25");
  expect(screen.getByRole("link", { name: "Open Known assets" })).toHaveAttribute("href", "#/assets?asset_class=KNOWN&limit=25");
  expect(screen.getByRole("link", { name: "Open Shadow assets" })).toHaveAttribute("href", "#/shadow");
  expect(screen.getByRole("link", { name: "Open Candidate assets" })).toHaveAttribute("href", "#/brand?ownership=CANDIDATE");
  expect(screen.getByRole("link", { name: "Open External assets" })).toHaveAttribute("href", "#/brand?ownership=EXTERNAL");
  Date.now.mockRestore();
});

test("shows no-authoritative-scan state without fabricating values", async () => {
  getV2Overview.mockResolvedValue({
    ...overview,
    current_scan_id: null,
    previous_scan_id: null,
    counts: { organizational: 0, known: 0, shadow: 0, candidate: 0, external: 0 },
    risk_distribution: { High: 0, Elevated: 0, Review: 0, Low: 0 },
    changes: { new_assets: 0, disappeared_assets: 0 },
    needs_attention: [],
  });
  render(<App />);

  expect(await screen.findByText("No authoritative scan yet")).toBeInTheDocument();
  expect(screen.queryByText("alpha.example")).not.toBeInTheDocument();
});

test("shows an API error and retries the overview request", async () => {
  getV2Overview.mockRejectedValueOnce(new Error("offline")).mockResolvedValueOnce(overview);
  render(<App />);

  expect(await screen.findByText("Overview unavailable")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Retry request" }));

  expect(await screen.findByText("alpha.example")).toBeInTheDocument();
  await waitFor(() => expect(getV2Overview).toHaveBeenCalledTimes(2));
});
