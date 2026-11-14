import React from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import App from "./App";
import { BrandDiscoveryPanel } from "./components/ui/OverviewIntelligence";
import BrandHistoryPage from "./pages/BrandHistoryPage";
import { getBrandHistoryAssets, getBrandHistoryDetail, getBrandHistorySummary } from "./services/api";

jest.mock("./services/api", () => ({
  getBrandHistorySummary: jest.fn(), getBrandHistoryAssets: jest.fn(), getBrandHistoryDetail: jest.fn(),
  getV2Overview: jest.fn(), getV2BrandAssets: jest.fn(),
}));

const summary = {
  scope: "retained_brand_source_history", total: 32,
  counts: { needs_verification: 29, known: 2, shadow: 1, unknown: 0 },
};
const current = {
  scan_id: 19,
  source_counts: {
    brand_tld: { domains: 10, by_asset_class: { candidate: 9, external: 0, known: 0, shadow: 1 } },
    brand_pattern: { domains: 22, by_asset_class: { candidate: 20, external: 0, known: 2, shadow: 0 } },
    brand_union: { domains: 32, by_asset_class: { candidate: 29, external: 0, known: 2, shadow: 1 } },
  },
};
const row = {
  identity: "old.example", domain: "old.example", review_class: "NEEDS_VERIFICATION",
  first_evidence_scan_id: 1, last_evidence_scan_id: 16,
};
const page = (overrides = {}) => ({
  scope: "retained_brand_source_history", page: 1, limit: 25, count: 26,
  classification: null, search: null, sort_by: "domain", sort_dir: "asc", assets: [row], ...overrides,
});

beforeEach(() => {
  window.location.hash = "#/brand/history?from=overview";
  getBrandHistorySummary.mockReset();
  getBrandHistoryAssets.mockReset();
  getBrandHistoryDetail.mockReset();
  getBrandHistorySummary.mockResolvedValue(summary);
  getBrandHistoryAssets.mockResolvedValue(page());
});

test("defaults to retained history, uses four exact class drilldowns, and switches to current scan", async () => {
  const { rerender } = render(<BrandDiscoveryPanel value={current} scanId={19} />);
  expect(await screen.findByRole("link", { name: "Open Brand-related domains (32)" })).toHaveAttribute("href", "#/brand/history?from=overview");
  expect(screen.getByRole("link", { name: "Open Needs Verification (29)" })).toHaveAttribute("href", "#/brand/history?from=overview&classification=NEEDS_VERIFICATION");
  expect(screen.getByRole("link", { name: "Open Known (2)" })).toHaveAttribute("href", "#/brand/history?from=overview&classification=KNOWN");
  expect(screen.getByRole("link", { name: "Open Shadow (1)" })).toHaveAttribute("href", "#/brand/history?from=overview&classification=SHADOW");
  expect(screen.getByRole("link", { name: "All-time" })).toHaveAttribute("aria-current", "page");
  expect(screen.getByTitle(/Only retained brand-source history/)).toHaveTextContent("Retained history");
  rerender(<BrandDiscoveryPanel value={current} scanId={19} query="brand_scope=current" />);
  expect(screen.getByRole("link", { name: "Current scan" })).toHaveAttribute("aria-current", "page");
  expect(screen.getByRole("link", { name: "Open Known (2)" })).toHaveAttribute("href", "#/assets?discovery_source=brand_union&asset_class=KNOWN&limit=25");
  expect(getBrandHistorySummary).toHaveBeenCalledTimes(1);
});

test("history errors do not silently show current-scan counts", async () => {
  getBrandHistorySummary.mockRejectedValue(new Error("unavailable"));
  render(<BrandDiscoveryPanel value={current} scanId={19} />);
  expect(await screen.findByText("Brand discovery unavailable")).toBeInTheDocument();
  expect(screen.queryByRole("link", { name: "Open Known (2)" })).not.toBeInTheDocument();
});

test("incomplete historical counts are unavailable rather than zero", async () => {
  getBrandHistorySummary.mockResolvedValue({ scope: "retained_brand_source_history", total: 0, counts: { known: 0, shadow: 0 } });
  render(<BrandDiscoveryPanel value={current} scanId={19} />);
  expect(await screen.findByText("Brand discovery unavailable")).toBeInTheDocument();
  expect(screen.queryByRole("link", { name: "Open Needs Verification (0)" })).not.toBeInTheDocument();
});

test("historical listing uses server filters, pagination, sorting, and exact detail return", async () => {
  window.location.hash = "#/brand/history?from=overview&classification=NEEDS_VERIFICATION&page=2&sort_by=last_seen&sort_dir=desc";
  render(<App />);
  expect(await screen.findByText("old.example")).toBeInTheDocument();
  expect(getBrandHistoryAssets).toHaveBeenCalledWith({ page: 2, limit: 25, classification: "NEEDS_VERIFICATION", search: undefined, sort_by: "last_seen", sort_dir: "desc" });
  expect(screen.getByText("Page 2 of 2 · 26 matching")).toBeInTheDocument();
  const detail = screen.getByRole("link", { name: "Open historical old.example" });
  expect(detail.getAttribute("href")).toContain("return_query=");
  fireEvent.click(screen.getByRole("button", { name: "Previous" }));
  await waitFor(() => expect(window.location.hash).not.toContain("page=2"));
});

test("historical search and clear filter preserve listing scope", async () => {
  const { rerender } = render(<BrandHistoryPage query="from=brand&classification=KNOWN" />);
  await screen.findByText("old.example");
  fireEvent.change(screen.getByRole("textbox", { name: "Search domain" }), { target: { value: "old" } });
  fireEvent.click(screen.getByRole("button", { name: "Search" }));
  expect(window.location.hash).toContain("search=old");
  rerender(<BrandHistoryPage query="from=brand&classification=KNOWN&search=old" />);
  await waitFor(() => expect(getBrandHistoryAssets).toHaveBeenCalledWith(expect.objectContaining({ classification: "KNOWN", search: "old" })));
  fireEvent.click(screen.getByRole("button", { name: "Clear filter" }));
  expect(window.location.hash).toBe("#/brand/history?from=brand");
});

test("historical-only identity uses historical detail and reports unavailable evidence", async () => {
  getBrandHistoryDetail.mockResolvedValue({
    scope: "retained_brand_source_history", domain: "old.example", review_class: "NEEDS_VERIFICATION",
    first_evidence_scan_id: 1, last_evidence_scan_id: 16, retained_scan_count: 3,
    discovery_sources: ["brand_tld"], current_scan_member: false,
    detail_availability: "UNAVAILABLE", detail: null,
    limitation: "Missing rows are unavailable evidence, not negative findings.",
  });
  render(<BrandHistoryPage domain="old.example" query="return_query=from%3Doverview%26classification%3DNEEDS_VERIFICATION%26page%3D2" />);
  expect(await screen.findByText("old.example")).toBeInTheDocument();
  expect(getBrandHistoryDetail).toHaveBeenCalledWith("old.example");
  expect(screen.getByText("Unavailable")).toBeInTheDocument();
  expect(screen.queryByRole("link", { name: "Open current asset detail" })).not.toBeInTheDocument();
  expect(screen.getByRole("link", { name: /Back to Brand discovery/ })).toHaveAttribute("href", "#/brand/history?from=overview&classification=NEEDS_VERIFICATION&page=2");
});

test("available historical evidence identifies its scan and preserves return context", async () => {
  getBrandHistoryDetail.mockResolvedValue({
    domain: "old.example", review_class: "KNOWN", first_evidence_scan_id: 1,
    last_evidence_scan_id: 19, retained_scan_count: 16, discovery_sources: ["brand_pattern"],
    current_scan_member: true, detail_evidence_scan_id: 19, detail_evidence_scan_status: "SUCCEEDED",
    detail_availability: "AVAILABLE", detail: { dns: { ip: "192.0.2.1" }, http: { observation_status: "RESPONDED", status: 200 } },
  });
  render(<BrandHistoryPage domain="old.example" query="return_query=from%3Dbrand" />);
  expect(await screen.findByText("Scan #19 · SUCCEEDED")).toBeInTheDocument();
  expect(screen.getByText("192.0.2.1")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Open current asset detail" }).getAttribute("href")).toContain("return=brand%2Fhistory");
});

test("historical listing shows loading, error, and empty states", async () => {
  getBrandHistoryAssets.mockImplementation(() => new Promise(() => {}));
  const view = render(<BrandHistoryPage query="from=overview" />);
  expect(screen.getByText("Loading historical brand assets")).toBeInTheDocument();
  view.unmount();
  getBrandHistoryAssets.mockRejectedValueOnce(new Error("network"));
  const failed = render(<BrandHistoryPage query="from=overview" />);
  expect(await screen.findByText("Historical brand assets unavailable")).toBeInTheDocument();
  failed.unmount();
  getBrandHistoryAssets.mockResolvedValue(page({ count: 0, assets: [] }));
  render(<BrandHistoryPage query="from=overview" />);
  expect(await screen.findByText("No historical brand assets match")).toBeInTheDocument();
});
