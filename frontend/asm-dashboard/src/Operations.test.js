import { render, screen, within } from "@testing-library/react";
import App from "./App";
import {
  getExposureSummary,
  getFindings,
  getRiskyDomains,
  getSensitiveExposure,
  getV2Assets,
  getV2Overview,
  getV2ReviewIndicators,
  getV2Scans,
} from "./services/api";

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
  counts: { organizational: 10, known: 6, shadow: 4, candidate: 2, external: 1 },
  risk_distribution: { High: 1, Elevated: 2, Review: 3, Low: 4 },
  changes: { new_assets: 2, disappeared_assets: 1 },
  needs_attention: [],
};

beforeEach(() => {
  [
    getExposureSummary,
    getFindings,
    getRiskyDomains,
    getSensitiveExposure,
    getV2Assets,
    getV2Overview,
    getV2ReviewIndicators,
    getV2Scans,
  ].forEach((mockFunction) => mockFunction.mockReset());
});

test("risk workspace presents canonical risk and positive exposure evidence", async () => {
  window.location.hash = "#/risk?section=review-indicators";
  const scrollIntoView = jest.fn();
  Element.prototype.scrollIntoView = scrollIntoView;
  getV2Overview.mockResolvedValue(overview);
  getRiskyDomains.mockResolvedValue([{
    domain: "critical.example.com",
    risk_score: 9,
    priority: "High",
    reasons: ["finding", "sensitive_ports"],
  }]);
  getFindings.mockResolvedValue([{
    domain: "critical.example.com",
    finding: "takeover_indicator",
    severity: "HIGH",
    evidence: "deterministic fingerprint match",
  }]);
  getSensitiveExposure.mockResolvedValue([{
    domain: "critical.example.com", port: 22, risk: 4, service: "SSH administration",
  }]);
  getExposureSummary.mockResolvedValue({
    scan_id: 42, total_domains: 10, resolving_domains: 8, http_responding_domains: 6,
  });
  getV2ReviewIndicators.mockResolvedValue({
    scan_id: 42,
    count: 2,
    indicators: [
      {
        type: "CROSS_HOST_HTTP_REDIRECT",
        domain: "critical.example.com",
        ownership_status: "CONFIRMED",
        asset_class: "SHADOW",
        http_observation_status: "RESPONDED",
        http_status: 302,
        final_url: "https://external.example/login",
        final_status: 200,
        final_hostname: "external.example",
        destination_confirmed: false,
        destination_asset_class: null,
      },
      {
        type: "CROSS_HOST_HTTP_REDIRECT",
        domain: "known.example.com",
        ownership_status: "CONFIRMED",
        asset_class: "KNOWN",
        http_observation_status: "RESPONDED",
        http_status: 301,
        final_url: "https://portal.example.com/home",
        final_status: 200,
        final_hostname: "portal.example.com",
        destination_confirmed: true,
        destination_asset_class: "KNOWN",
      },
    ],
  });

  render(<App />);

  expect((await screen.findAllByText("critical.example.com"))[0]).toBeInTheDocument();
  expect(screen.getByText("Canonical risk posture")).toBeInTheDocument();
  expect(screen.getByText("deterministic fingerprint match")).toBeInTheDocument();
  expect(screen.getByText("SSH administration")).toBeInTheDocument();
  expect(screen.getByText("Sensitivity 4")).toBeInTheDocument();
  expect(screen.getAllByText("Review Indicators")).toHaveLength(2);
  expect(screen.getByText("https://external.example/login")).toBeInTheDocument();
  expect(screen.getByText("Not currently confirmed")).toBeInTheDocument();
  expect(screen.getByText("Independently confirmed current asset")).toBeInTheDocument();
  expect(screen.getAllByText("Review only · not a vulnerability conclusion")).toHaveLength(2);
  expect(screen.getByText("No ownership or testing authorization by redirect")).toBeInTheDocument();
  const actionable = screen.getByRole("region", { name: "Actionable evidence" });
  expect(actionable.querySelector('a[href="#/risk?section=findings"]')).toBeInTheDocument();
  expect(actionable.querySelector('a[href="#/risk?section=sensitive-ports"]')).toBeInTheDocument();
  expect(actionable.querySelector('a[href="#/risk?section=review-indicators"]')).toBeInTheDocument();
  expect(document.getElementById("findings")).toBeInTheDocument();
  expect(document.getElementById("sensitive-ports")).toBeInTheDocument();
  expect(document.getElementById("review-indicators")).toBeInTheDocument();
  expect(scrollIntoView).toHaveBeenCalled();
  screen.getAllByRole("link", { name: "Open critical.example.com" }).forEach((link) => {
    expect(link).toHaveAttribute("href", "#/assets/critical.example.com?return=risk");
  });
});

test("review indicators have truthful empty and isolated failure states", async () => {
  const baseContracts = () => {
    getV2Overview.mockResolvedValue(overview);
    getRiskyDomains.mockResolvedValue([]);
    getFindings.mockResolvedValue([]);
    getSensitiveExposure.mockResolvedValue([]);
    getExposureSummary.mockResolvedValue({
      scan_id: 42, total_domains: 10, resolving_domains: 8, http_responding_domains: 6,
    });
  };

  window.location.hash = "#/risk";
  baseContracts();
  getV2ReviewIndicators.mockResolvedValue({ scan_id: 42, count: 0, indicators: [] });
  const empty = render(<App />);
  expect(await screen.findByText("No cross-host HTTP redirects were observed in the current authoritative scan.")).toBeInTheDocument();
  empty.unmount();

  baseContracts();
  getV2ReviewIndicators.mockRejectedValue(new Error("offline"));
  render(<App />);
  expect(await screen.findByRole("alert")).toHaveTextContent("Redirect review evidence could not be loaded");
  expect(screen.getByText("Canonical risk posture")).toBeInTheDocument();
});

test("Shadow Centre uses effective asset class rather than stored ownership status", async () => {
  window.location.hash = "#/shadow";
  getV2Assets.mockResolvedValue({
    scan_id: 42,
    page: 1,
    limit: 25,
    count: 1,
    assets: [
      {
        domain: "shadow.example.com",
        ownership_status: "CONFIRMED",
        asset_class: "SHADOW",
        first_seen_scan: 42,
        ip: "192.0.2.10",
        http_observation_status: "UNKNOWN",
        http_status: 0,
        provider: null,
        risk: { score: 8, priority: "High", reasons: ["shadow_asset"] },
      },
      {
        domain: "candidate.example.net",
        ownership_status: "CANDIDATE",
        asset_class: "CANDIDATE",
        first_seen_scan: 42,
        risk: null,
      },
      {
        domain: "legacy-outside.example.net",
        ownership_status: "CONFIRMED",
        asset_class: "CANDIDATE",
        first_seen_scan: 5,
        risk: null,
      },
    ],
  });

  render(<App />);

  expect(await screen.findByText("shadow.example.com")).toBeInTheDocument();
  expect(getV2Assets).toHaveBeenCalledWith({ page: 1, limit: 25, asset_class: "SHADOW" });
  expect(screen.getByText("New in scan #42")).toBeInTheDocument();
  expect(screen.getByText("UNKNOWN")).toBeInTheDocument();
  expect(screen.queryByText("candidate.example.net")).not.toBeInTheDocument();
  expect(screen.queryByText("legacy-outside.example.net")).not.toBeInTheDocument();
  expect(screen.queryByText("Mark as Known")).not.toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Open shadow.example.com" })).toHaveAttribute(
    "href", "#/assets/shadow.example.com?return=shadow"
  );
});

test("Scan Centre marks only successful authoritative scans as authoritative", async () => {
  window.location.hash = "#/scans";
  getV2Overview.mockResolvedValue(overview);
  getV2Scans.mockResolvedValue({
    current_authoritative_scan_id: 42,
    previous_authoritative_scan_id: 41,
    scans: [
      { scan_id: 43, status: "RUNNING", started_at: "2026-09-25T13:00:00Z", completed_at: null, duration_seconds: null, asset_count: 2, seed: "example.com", is_current_authoritative: false, is_previous_authoritative: false },
      { scan_id: 42, status: "SUCCEEDED", started_at: "2026-09-25T12:00:00Z", completed_at: "2026-09-25T12:01:00Z", duration_seconds: 60, asset_count: 10, seed: "example.com", is_current_authoritative: true, is_previous_authoritative: false },
      { scan_id: 41, status: "SUCCEEDED", started_at: "2026-09-24T12:00:00Z", completed_at: "2026-09-24T12:00:30Z", duration_seconds: 30, asset_count: 9, seed: "example.com", is_current_authoritative: false, is_previous_authoritative: true },
      { scan_id: 40, status: "FAILED", started_at: "2026-09-23T12:00:00Z", completed_at: "2026-09-23T12:00:10Z", duration_seconds: 10, asset_count: 1, seed: "example.com", is_current_authoritative: false, is_previous_authoritative: false },
      { scan_id: 39, status: "UNKNOWN", started_at: null, completed_at: null, duration_seconds: null, asset_count: 0, seed: "example.com", is_current_authoritative: false, is_previous_authoritative: false },
    ],
  });

  render(<App />);

  expect(await screen.findByText("Scan history")).toBeInTheDocument();
  expect(getV2Scans).toHaveBeenCalledWith(100);
  const historyTable = screen.getByRole("table");
  expect(within(within(historyTable).getByText("#42").closest("tr")).getByText("Current authoritative")).toBeInTheDocument();
  expect(within(within(historyTable).getByText("#41").closest("tr")).getByText("Previous baseline")).toBeInTheDocument();
  ["#43", "#40", "#39"].forEach((scanId) => {
    expect(within(within(historyTable).getByText(scanId).closest("tr")).getByText("Not authoritative")).toBeInTheDocument();
  });
});

test("new workflows expose honest error and empty states", async () => {
  window.location.hash = "#/risk";
  getV2Overview.mockRejectedValue(new Error("offline"));
  getRiskyDomains.mockResolvedValue([]);
  getFindings.mockResolvedValue([]);
  getSensitiveExposure.mockResolvedValue([]);
  getExposureSummary.mockResolvedValue({});
  getV2ReviewIndicators.mockResolvedValue({ scan_id: 42, count: 0, indicators: [] });
  const risk = render(<App />);
  expect(await screen.findByText("Risk workspace unavailable")).toBeInTheDocument();
  risk.unmount();

  window.location.hash = "#/shadow";
  getV2Assets.mockResolvedValue({ scan_id: 42, page: 1, limit: 25, count: 0, assets: [] });
  const shadow = render(<App />);
  expect(await screen.findByText("No Shadow assets match")).toBeInTheDocument();
  shadow.unmount();

  window.location.hash = "#/scans";
  getV2Scans.mockResolvedValue({ current_authoritative_scan_id: null, previous_authoritative_scan_id: null, scans: [] });
  getV2Overview.mockResolvedValue({ ...overview, current_scan_id: null });
  render(<App />);
  expect(await screen.findByText("No scan history")).toBeInTheDocument();
});
