import React from "react";
import { render, screen, within } from "@testing-library/react";
import OverviewIntelligence, {
  classifyCertificateExpiry,
  normalizeNamingExposure,
  normalizeCertificateRecords,
  parseCertificateExpiry,
} from "./OverviewIntelligence";

jest.mock("recharts", () => {
  const actual = jest.requireActual("recharts");
  return {
    ...actual,
    ResponsiveContainer: ({ children }) => <div>{children}</div>,
  };
});

const growth = [
  { scan_id: 41, total: 10, live: 8, shadow: 3 },
  { scan_id: 42, total: 12, live: 9, shadow: 4 },
];

test("renders supported aggregate charts with their scope", () => {
  render(
    <OverviewIntelligence
      assetGrowth={growth}
      httpStatus={{ "2xx": 4, "3xx": 2, "4xx": 1, "5xx": 0, no_response: 3 }}
      discoverySummary={{ scan_id: 42, candidate: 3, external: 2 }}
    />
  );

  expect(screen.getByText("Confirmed organizational assets across successful scans")).toBeInTheDocument();
  expect(screen.getByTestId("overview-asset-growth-chart")).toHaveClass("overview-chart-canvas");
  expect(screen.getByText("Current authoritative confirmed-organizational scan")).toBeInTheDocument();
  expect(screen.getByTestId("overview-http-status-chart")).toHaveClass("overview-chart-canvas");
  expect(screen.getByTestId("overview-http-status-chart").parentElement).toHaveClass("overview-http-status-chart");
  expect(screen.getByText(/not the explicit NO_RESPONSE observation enum/i)).toBeInTheDocument();
  expect(screen.getByTestId("overview-http-status-chart")).toHaveAttribute(
    "aria-label",
    expect.stringContaining("No recorded HTTP status")
  );
  expect(screen.queryByRole("link", { name: /Open confirmed assets with no response/i })).not.toBeInTheDocument();
  expect(screen.queryByText("NO_RESPONSE")).not.toBeInTheDocument();
  expect(screen.queryByText("UNKNOWN")).not.toBeInTheDocument();
  expect(screen.queryByRole("link", { name: /2xx|3xx|4xx|5xx/i })).not.toBeInTheDocument();
});

test("renders current unique-domain discovery totals with exact Brand Perimeter links", () => {
  render(<OverviewIntelligence discoverySummary={{ scan_id: 42, candidate: 3, external: 2 }} />);

  const panel = document.getElementById("overview-discovery-validation");
  expect(within(panel).getByText("SCAN #42")).toBeInTheDocument();
  expect(within(panel).getByRole("link", { name: "Open Brand Perimeter Candidate assets (3)" })).toHaveAttribute(
    "href",
    "#/brand?ownership=CANDIDATE"
  );
  expect(within(panel).getByRole("link", { name: "Open Brand Perimeter External assets (2)" })).toHaveAttribute(
    "href",
    "#/brand?ownership=EXTERNAL"
  );
  expect(within(panel).getByText(/count unique domains/i)).toBeInTheDocument();
  expect(within(panel).getByText(/Historical discovery-only records are excluded/i)).toBeInTheDocument();
});

test("normalizes overlapping naming categories without treating them as additive", () => {
  expect(normalizeNamingExposure([
    { keyword: "DEV", count: 2 },
    { keyword: "ADMIN", count: 1 },
    { keyword: "STAGE", count: 3 },
    { keyword: "STAGING", count: 4 },
    { keyword: "DEV", count: 2 },
    { keyword: "UNSUPPORTED", count: 99 },
  ])).toEqual([
    { keyword: "ADMIN", count: 1 },
    { keyword: "DEV", count: 2 },
    { keyword: "STAGE", count: 3 },
    { keyword: "STAGING", count: 4 },
  ]);
});

test("renders naming exposure as non-clickable current-scan signals", () => {
  render(<OverviewIntelligence namingExposure={[
    { keyword: "DEV", count: 20 },
    { keyword: "STAGE", count: 2 },
    { keyword: "STAGING", count: 4 },
  ]} certificateScanId={16} />);

  const panel = document.getElementById("overview-naming-exposure");
  expect(within(panel).getByText("SCAN #16")).toBeInTheDocument();
  expect(within(panel).getByLabelText("DEV: 20 matching confirmed assets")).toBeInTheDocument();
  expect(within(panel).getByLabelText("STAGE: 2 matching confirmed assets")).toBeInTheDocument();
  expect(within(panel).getByLabelText("STAGING: 4 matching confirmed assets")).toBeInTheDocument();
  expect(within(panel).getByText(/Categories may overlap/i)).toBeInTheDocument();
  expect(panel.querySelectorAll("a")).toHaveLength(0);
});

test("renders naming exposure loading, failure, and empty states", () => {
  const { rerender } = render(<OverviewIntelligence namingExposureStatus="loading" />);
  expect(screen.getByText("Loading naming exposure")).toBeInTheDocument();

  rerender(<OverviewIntelligence namingExposureStatus="error" />);
  expect(screen.getByText("Naming exposure unavailable")).toBeInTheDocument();

  rerender(<OverviewIntelligence namingExposure={[]} />);
  expect(screen.getByText("No naming matches")).toBeInTheDocument();
});

test("preserves zero discovery totals and handles loading or failed discovery requests", () => {
  const { rerender } = render(<OverviewIntelligence discoverySummary={{ scan_id: 42, candidate: 0, external: 0 }} />);
  const panel = document.getElementById("overview-discovery-validation");
  expect(within(panel).getAllByText("0")).toHaveLength(2);

  rerender(<OverviewIntelligence discoverySummaryStatus="loading" />);
  expect(screen.getByText("Loading discovery validation")).toBeInTheDocument();

  rerender(<OverviewIntelligence discoverySummaryStatus="error" />);
  expect(screen.getByText("Discovery validation unavailable")).toBeInTheDocument();
});

test("renders loading, API failure, and insufficient-history states", () => {
  render(
    <OverviewIntelligence
      assetGrowthStatus="loading"
      httpStatusStatus="error"
    />
  );
  expect(screen.getByText("Loading history")).toBeInTheDocument();
  expect(screen.getByText("HTTP status unavailable")).toBeInTheDocument();

  const { rerender } = render(<OverviewIntelligence assetGrowth={[]} httpStatus={{}} />);
  expect(screen.getByText("Insufficient scan history")).toBeInTheDocument();
  expect(screen.getByText("No HTTP observations")).toBeInTheDocument();
  rerender(<OverviewIntelligence assetGrowth={growth.slice(0, 1)} httpStatus={{ no_response: 2 }} />);
  expect(screen.getByText("A trend appears after two successful scans.")).toBeInTheDocument();
  expect(screen.getByTestId("overview-http-status-chart")).toBeInTheDocument();
});

test("classifies certificate expiry at explicit date boundaries", () => {
  const now = new Date("2026-11-02T12:00:00Z");

  expect(parseCertificateExpiry("2026-11-02")).toBeInstanceOf(Date);
  expect(parseCertificateExpiry("2026-02-30")).toBeNull();
  expect(classifyCertificateExpiry("2026-11-01", now).bucket).toBe("expired");
  expect(classifyCertificateExpiry("2026-11-09", now).bucket).toBe("within7");
  expect(classifyCertificateExpiry("2026-11-10", now).bucket).toBe("within30");
  expect(classifyCertificateExpiry("2026-12-02", now).bucket).toBe("within30");
  expect(classifyCertificateExpiry("2026-12-03", now).bucket).toBe("healthy");
  expect(classifyCertificateExpiry(null, now).bucket).toBe("unknown");
});

test("renders bounded certificate health observations with verified asset links", () => {
  const now = new Date("2026-11-02T12:00:00Z");
  const records = [
    { domain: "expired.example", expiry: "2026-11-01", days: 900, status: "healthy" },
    { domain: "seven.example", expiry: "2026-11-09", days: 900, status: "healthy" },
    { domain: "eight.example", expiry: "2026-11-10", days: 900, status: "healthy" },
    { domain: "later.example", expiry: "2026-12-03", days: 900, status: "healthy" },
    { domain: "unknown.example", expiry: "not-a-date", days: null, status: "unknown" },
    { domain: "expired.example", expiry: "2026-12-31", days: 900, status: "healthy" },
  ];

  const normalized = normalizeCertificateRecords(records, now);
  expect(normalized.map((record) => record.domain)).toEqual([
    "expired.example",
    "seven.example",
    "eight.example",
    "unknown.example",
    "later.example",
  ]);

  render(
    <OverviewIntelligence
      assetGrowth={growth}
      httpStatus={{ "2xx": 1 }}
      certificateExpiry={records}
      certificateScanId={16}
      certificateNow={now}
    />
  );

  expect(screen.getByText("Certificate health")).toBeInTheDocument();
  const certificatePanel = screen.getByText("Certificate health").closest("section");
  expect(within(certificatePanel).getByText("SCAN #16")).toBeInTheDocument();
  const summary = screen.getByLabelText("Certificate health summary");
  expect(within(summary).getByText("Expired")).toBeInTheDocument();
  expect(within(summary).getByText("Within 7 days")).toBeInTheDocument();
  expect(within(summary).getByText("Within 8–30 days")).toBeInTheDocument();
  expect(within(summary).getByText("Unknown expiry")).toBeInTheDocument();
  expect(screen.getAllByRole("link", { name: /\.example$/i }).map((link) => link.textContent)).toEqual([
    "expired.example",
    "seven.example",
    "eight.example",
  ]);
  expect(screen.getByRole("link", { name: "expired.example" })).toHaveAttribute(
    "href",
    "#/assets/expired.example?return=overview"
  );
  expect(screen.queryByRole("link", { name: "unknown.example" })).not.toBeInTheDocument();
});

test("renders certificate loading, failure, and empty states", () => {
  const { rerender } = render(<OverviewIntelligence certificateExpiryStatus="loading" />);
  expect(screen.getByText("Loading certificate observations")).toBeInTheDocument();

  rerender(<OverviewIntelligence certificateExpiryStatus="error" />);
  expect(screen.getByText("Certificate health unavailable")).toBeInTheDocument();

  rerender(<OverviewIntelligence certificateExpiry={[]} />);
  expect(screen.getByText("No certificate observations")).toBeInTheDocument();
});
