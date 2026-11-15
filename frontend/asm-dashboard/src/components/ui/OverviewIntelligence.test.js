import React from "react";
jest.mock("../../services/api", () => ({ getBrandHistorySummary: jest.fn() }));
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { Bar, BarChart, Cell, XAxis } from "recharts";
import OverviewIntelligence, {
  BrandDiscoveryPanel,
  AssetGrowthPanel,
  GrowthLegend,
  GrowthTooltip,
  HttpStatusBar,
  HttpStatusTick,
  classifyCertificateExpiry,
  normalizeBrandDiscovery,
  normalizeNamingExposure,
  normalizeCertificateRecords,
  normalizeGrowth,
  normalizeSeedDistribution,
  parseCertificateExpiry,
  SeedDistributionPanel,
} from "./OverviewIntelligence";

jest.mock("recharts", () => {
  const actual = jest.requireActual("recharts");
  return {
    ...actual,
    ResponsiveContainer: ({ children }) => <div>{children}</div>,
  };
});

const growth = [
  { scan_id: 41, total_scan_assets: 21, organizational_assets: 10, known_assets: 7, shadow_assets: 3, ip_present_assets: 8, http_responding_assets: 6 },
  { scan_id: 42, total_scan_assets: 23, organizational_assets: 12, known_assets: 8, shadow_assets: 4, ip_present_assets: 9, http_responding_assets: 7 },
];

test("renders supported aggregate charts with their scope", () => {
  render(
    <OverviewIntelligence
      assetGrowth={growth}
      httpStatus={{ "2xx": 4, "3xx": 2, "4xx": 1, "5xx": 0, no_response: 3 }}
    />
  );

  expect(screen.getByText("Total scan membership across successful scans · classes use current effective rules")).toBeInTheDocument();
  expect(screen.getByTestId("overview-asset-growth-chart")).toHaveClass("overview-chart-canvas");
  expect(screen.getByTestId("overview-asset-growth-chart")).toHaveAttribute(
    "aria-label", expect.stringContaining("Total Scan Assets, Known Assets, Shadow Assets, Organizational Assets, IP-Present Assets, HTTP-Responding Assets")
  );
  expect(screen.getByRole("button", { name: "Total Scan Assets" })).toHaveAttribute("aria-pressed", "true");
  expect(screen.getByRole("button", { name: "Known Assets" })).toHaveAttribute("aria-pressed", "false");
  expect(screen.getByText("Current authoritative confirmed-organizational scan")).toBeInTheDocument();
  expect(screen.getByTestId("overview-http-status-chart")).toHaveClass("overview-chart-canvas");
  expect(screen.getByTestId("overview-http-status-chart").parentElement).toHaveClass("overview-http-status-chart");
  expect(screen.getByText(/NO_RESPONSE is shown separately/i)).toBeInTheDocument();
  expect(screen.getByTestId("overview-http-status-chart")).toHaveAttribute(
    "aria-label",
    expect.stringContaining("No HTTP status recorded")
  );
  expect(screen.queryByRole("link", { name: /Open confirmed assets with no response/i })).not.toBeInTheDocument();
  expect(screen.queryByText("NO_RESPONSE")).not.toBeInTheDocument();
  expect(screen.queryByText("UNKNOWN")).not.toBeInTheDocument();
});

test("asset growth keeps missing totals unavailable and retains API ordering", () => {
  expect(normalizeGrowth([
    { scan_id: 18, total_scan_assets: 921 },
    { scan_id: 19, total_scan_assets: null },
  ])).toEqual([
    { scan: 18, totalScanAssets: 921, organizational: null, known: null, shadow: null, ipPresent: null, httpResponding: null },
    { scan: 19, totalScanAssets: null, organizational: null, known: null, shadow: null, ipPresent: null, httpResponding: null },
  ]);
});

test("asset growth tooltip reports scan and exact metric values", () => {
  render(<GrowthTooltip active label={19} payload={[
    { dataKey: "totalScanAssets", name: "Total Scan Assets", value: 2133, color: "#4655a6" },
    { dataKey: "known", name: "Known Assets", value: 60, color: "#5c6bc0" },
  ]} />);

  expect(screen.getByText("Scan #19")).toBeInTheDocument();
  expect(screen.getByText("Total Scan Assets").nextSibling).toHaveTextContent("2,133");
  expect(screen.getByText("Known Assets").nextSibling).toHaveTextContent("60");
});

test("growth legend controls series visibility accessibly", () => {
  function Harness() {
    const [visibleKeys, setVisibleKeys] = React.useState(new Set(["totalScanAssets"]));
    return <GrowthLegend
      series={[["totalScanAssets", "Total Scan Assets", "#4655a6"], ["known", "Known Assets", "#5c6bc0"]]}
      visibleKeys={visibleKeys}
      onToggle={(key) => setVisibleKeys((current) => {
        const next = new Set(current);
        if (next.has(key)) next.delete(key); else next.add(key);
        return next;
      })}
    />;
  }
  render(<Harness />);
  const total = screen.getByRole("button", { name: "Total Scan Assets" });
  const known = screen.getByRole("button", { name: "Known Assets" });
  expect(total).toHaveAttribute("aria-pressed", "true");
  fireEvent.click(known);
  expect(known).toHaveAttribute("aria-pressed", "true");
  fireEvent.click(total);
  expect(total).toHaveAttribute("aria-pressed", "false");
});

test("HTTP chart bars and labels link only exact server-filtered groups", () => {
  const groups = ["2xx", "3xx", "4xx", "5xx", "no_response", "unknown"];
  const labels = ["2xx", "3xx", "4xx", "5xx", "No HTTP response", "No HTTP status recorded"];
  const { container } = render(<svg>
    {groups.map((key, index) => <g key={key}>
      <HttpStatusBar payload={{ key, label: labels[index] }} x={index * 30} y={10} width={20} height={index === 3 ? 0 : 20} fill="#398261" />
      <HttpStatusTick x={index * 30} y={40} payload={{ value: labels[index] }} />
    </g>)}
  </svg>);

  for (const group of groups.slice(0, 4)) {
    const links = [...container.querySelectorAll(`a[href="#/assets?http_status_group=${group}"]`)];
    expect(links).toHaveLength(2);
    links.forEach((link) => {
      expect(link).toHaveAttribute("aria-label", `Show ${group} assets`);
      expect(link).toHaveAttribute("tabindex", "0");
    });
  }
  expect(container.querySelectorAll('a[href*="no_response"], a[href*="unknown"]')).toHaveLength(0);
});

test("Recharts renders a keyboard reachable HTTP bar and category label", async () => {
  window.location.hash = "#/overview";
  const { container } = render(<BarChart width={480} height={220} data={[{ key: "2xx", label: "2xx", count: 4, color: "#398261" }]}>
    <XAxis dataKey="label" tick={<HttpStatusTick />} />
    <Bar dataKey="count" shape={<HttpStatusBar />} isAnimationActive={false}><Cell fill="#398261" /></Bar>
  </BarChart>);

  const links = [...container.querySelectorAll('a[href="#/assets?http_status_group=2xx"]')];
  expect(links).toHaveLength(2);
  links.forEach((link) => expect(link).toHaveAttribute("tabindex", "0"));
  expect(links[0].querySelector(".recharts-rectangle")).toHaveAttribute("fill", "#398261");
  act(() => links[1].focus());
  expect(links[1]).toHaveFocus();
  fireEvent.keyDown(links[1], { key: "Enter" });
  expect(window.location.hash).toBe("#/assets?http_status_group=2xx");
  window.location.hash = "#/overview";
  fireEvent.click(links[0]);
  expect(window.location.hash).toBe("#/assets?http_status_group=2xx");
  window.history.back();
  await waitFor(() => expect(window.location.hash).toBe("#/overview"));
});

test("normalizes and renders verified current-scan seed groups", async () => {
  expect(normalizeSeedDistribution([
    { seed: "beta.example", domains_discovered: 4 },
    { seed: "alpha.example", domains_discovered: 8 },
    { seed: "beta.example", domains_discovered: 2 },
    { seed: "invalid", domains_discovered: -1 },
  ])).toEqual([
    { seed: "beta.example", count: 6 },
    { seed: "alpha.example", count: 8 },
  ].sort((left, right) => right.count - left.count || left.seed.localeCompare(right.seed)));

  render(<SeedDistributionPanel
    value={[
      { seed: "alpha.example", domains_discovered: 8 },
      { seed: "beta.example", domains_discovered: 6 },
    ]}
    scanId={42}
  />);

  expect(screen.getByText("Seeds distribution")).toBeInTheDocument();
  expect(screen.getByTestId("overview-seed-distribution-chart")).toHaveAttribute(
    "aria-label", "Current authoritative scan 42 seed distribution"
  );
  expect(screen.getByRole("listitem", { name: "alpha.example: 8 discovered domains" })).toBeInTheDocument();
  expect(screen.getByRole("listitem", { name: "beta.example: 6 discovered domains" })).toBeInTheDocument();
  await waitFor(() => expect(document.querySelectorAll(".seed-distribution-bar-rise")).toHaveLength(2));
  expect(screen.getAllByText("8")).toHaveLength(1);
  expect(screen.getAllByText("6")).toHaveLength(1);
});

test("keeps seed distribution unavailable without verified data", () => {
  const { rerender } = render(<SeedDistributionPanel status="error" />);
  expect(screen.getByText("Seed distribution unavailable")).toBeInTheDocument();
  rerender(<SeedDistributionPanel value={[]} />);
  expect(screen.getByText("No verified current-scan seed attribution is available.")).toBeInTheDocument();
  expect(screen.queryByTestId("overview-seed-distribution-chart")).not.toBeInTheDocument();
});

test("renders seed bars at final heights when reduced motion is requested", async () => {
  const originalMatchMedia = window.matchMedia;
  window.matchMedia = jest.fn().mockReturnValue({ matches: true });
  try {
    render(<SeedDistributionPanel value={[{ seed: "alpha.example", domains_discovered: 8 }]} scanId={42} />);
    await waitFor(() => expect(document.querySelector(".seed-distribution-bar-reduced-motion")).toBeInTheDocument());
    const bar = document.querySelector(".seed-distribution-bar-reduced-motion");
    expect(bar).toHaveStyle({ height: "100%" });
  } finally {
    window.matchMedia = originalMatchMedia;
  }
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

test("renders naming exposure as clickable inferred hostname signals", () => {
  render(<OverviewIntelligence namingExposure={[
    { keyword: "DEV", count: 20 },
    { keyword: "STAGE", count: 2 },
    { keyword: "STAGING", count: 4 },
  ]} certificateScanId={16} />);

  const panel = document.getElementById("overview-naming-exposure");
  expect(within(panel).getByText("SCAN #16")).toBeInTheDocument();
  expect(within(panel).getByRole("link", { name: "Open DEV matching assets (20)" })).toHaveAttribute("href", "#/assets?exposure_keyword=DEV&limit=25");
  expect(within(panel).getByRole("link", { name: "Open STAGE matching assets (2)" })).toHaveAttribute("href", "#/assets?exposure_keyword=STAGE&limit=25");
  expect(within(panel).getByRole("link", { name: "Open STAGING matching assets (4)" })).toHaveAttribute("href", "#/assets?exposure_keyword=STAGING&limit=25");
  expect(within(panel).getByText(/not a verified environment/i)).toBeInTheDocument();
});

test("renders naming exposure loading, failure, and empty states", () => {
  const { rerender } = render(<OverviewIntelligence namingExposureStatus="loading" />);
  expect(screen.getByText("Loading naming exposure")).toBeInTheDocument();

  rerender(<OverviewIntelligence namingExposureStatus="error" />);
  expect(screen.getByText("Naming exposure unavailable")).toBeInTheDocument();

  rerender(<OverviewIntelligence namingExposure={[]} />);
  expect(screen.getByText("No naming matches")).toBeInTheDocument();
});

test("renders authoritative brand discovery totals with exact full and review drilldowns", () => {
  const value = {
    scan_id: 42,
    source_counts: {
      brand_tld: { domains: 20, by_asset_class: { candidate: 7, external: 2, known: 6, shadow: 5 } },
      brand_pattern: { domains: 15, by_asset_class: { candidate: 6, external: 1, known: 5, shadow: 3 } },
      brand_union: { domains: 32, by_asset_class: { candidate: 10, external: 2, known: 12, shadow: 8 } },
    },
  };

  expect(normalizeBrandDiscovery(value, 42)).toEqual(value);
  expect(normalizeBrandDiscovery(value, 41)).toBeNull();

  const { rerender } = render(<BrandDiscoveryPanel value={value} scanId={42} query="brand_scope=current" />);
  expect(screen.getByRole("link", { name: "Open Brand-related domains (32)" })).toHaveAttribute(
    "href", "#/assets?discovery_source=brand_union&limit=25"
  );
  expect(screen.getByRole("link", { name: "Open Needs Verification (10)" })).toHaveAttribute(
    "href", "#/assets?discovery_source=brand_union&asset_class=CANDIDATE&limit=25"
  );
  rerender(<BrandDiscoveryPanel value={value} scanId={42} mode="brand" query="brand_scope=current" />);
  expect(screen.getByRole("link", { name: "Open Brand-related domains (32)" })).toHaveAttribute(
    "href", "#/assets?discovery_source=brand_union&limit=25"
  );
  expect(screen.getByRole("link", { name: "Open Known (12)" })).toHaveAttribute(
    "href", "#/assets?discovery_source=brand_union&asset_class=KNOWN&limit=25"
  );
  expect(screen.getByRole("link", { name: "Open Needs Verification (10)" })).toHaveAttribute(
    "href", "#/brand?discovery_source=brand_union&asset_class=CANDIDATE&brand_scope=current"
  );
});

test("does not fabricate brand discovery totals when the response is absent or incomplete", () => {
  render(<BrandDiscoveryPanel value={{ scan_id: 42, source_counts: {} }} scanId={42} query="brand_scope=current" />);
  expect(screen.getByText("Brand discovery unavailable")).toBeInTheDocument();
  expect(screen.queryByText("0")).not.toBeInTheDocument();
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
