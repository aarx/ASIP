import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import App from "./App";
import { getInvestigationAssets, getV2AssetAssistant, getV2AssetDetail } from "./services/api";

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

const selectedAsset = {
  scan_id: 42,
  domain: "investigate.example.com",
  ownership_status: "CONFIRMED",
  is_known: false,
  asset_class: "SHADOW",
  first_seen_scan: 40,
  last_seen_scan: 42,
  first_seen_at: "2026-09-20T10:00:00Z",
  last_seen_at: "2026-09-25T10:00:00Z",
  seed: "example.com",
  risk: { score: 8, priority: "High", reasons: ["shadow_asset", "finding"] },
  dns: { ip: "192.0.2.10", has_ip: true, reverse_dns: "edge.example.net" },
  http: { observation_status: "RESPONDED", status: 302, final_url: null, final_status: null, redirect_evidence: {
    requested_url: "https://investigate.example.com/", http_status: 302,
    first_hop_location: "https://login.example.com", first_hop_destination: "https://login.example.com",
    observed_hops: [], verified_terminal_url: null, completion_status: "UNRESOLVED",
    stop_reason: "redirect_traversal_disabled",
  }, title: "Login" },
  ports: [{ port: 443, service: "https" }],
  asn: { asn: "AS64500", organization: "Example Networks" },
  provider: "Example Cloud",
  technologies: ["nginx"],
  certificate: { status: "valid", expiry_date: "2027-01-01", days_to_expiry: 97 },
  discovery: { sources: [{ source: "subfinder", seed: "example.com" }] },
  findings: [{ finding: "review_indicator", severity: "MEDIUM", evidence: "stored evidence" }],
};

const investigationList = {
  page: 1,
  limit: 20,
  count: 1,
  assets: [{
    domain: selectedAsset.domain,
    ownership_status: "CONFIRMED",
    risk: 8,
    priority: "High",
    reasons: ["shadow_asset", "finding"],
  }],
};

beforeEach(() => {
  window.location.hash = "#/investigate";
  getInvestigationAssets.mockReset();
  getV2AssetDetail.mockReset();
  getV2AssetAssistant.mockReset();
});

test("selects the first queue asset by default and runs grounded actions without auto-running AI", async () => {
  getInvestigationAssets.mockResolvedValue(investigationList);
  getV2AssetDetail.mockResolvedValue(selectedAsset);
  getV2AssetAssistant.mockImplementation((domain, action) => Promise.resolve({
    domain,
    action,
    response: `**${action}** grounded response`,
    source: "ShadowRecon deterministic evidence + Gemma",
    model: "gemma3:4b",
  }));

  render(<App />);

  expect(await screen.findByText("Authoritative ShadowRecon evidence")).toBeInTheDocument();
  expect(window.location.hash).toBe("#/investigate?domain=investigate.example.com");
  expect(screen.getByLabelText("Search assets")).toBeInTheDocument();
  expect(getV2AssetAssistant).not.toHaveBeenCalled();
  expect(screen.getByText("192.0.2.10")).toBeInTheDocument();
  expect(screen.getByText("RESPONDED")).toBeInTheDocument();
  expect(screen.getByText("443")).toBeInTheDocument();
  expect(screen.getByText("nginx")).toBeInTheDocument();
  expect(screen.getByText("stored evidence")).toBeInTheDocument();
  expect(screen.getByText("subfinder")).toBeInTheDocument();
  expect(screen.getByText("Grounded AI Assistance")).toBeInTheDocument();
  expect(screen.getByText("AI · NOT EVIDENCE")).toBeInTheDocument();
  expect(screen.queryByText("Current stored observations")).not.toBeInTheDocument();
  expect(screen.queryByText("Positive evidence only")).not.toBeInTheDocument();
  expect(screen.queryByText("Recorded deterministic observations")).not.toBeInTheDocument();
  expect(screen.queryByText("Why this asset entered the current scan")).not.toBeInTheDocument();
  expect(screen.queryByText(/AI may explain, summarize/)).not.toBeInTheDocument();
  expect(screen.queryByText("Choose an action to request a grounded response.")).not.toBeInTheDocument();

  for (const [label, action] of [
    ["Explain Risk", "explain_risk"],
    ["Investigation Plan", "investigation_plan"],
    ["Summarize Asset", "summarize_asset"],
  ]) {
    fireEvent.click(screen.getByRole("button", { name: label }));
    expect(await screen.findByText(`${action} grounded response`)).toBeInTheDocument();
    expect(getV2AssetAssistant).toHaveBeenLastCalledWith(selectedAsset.domain, action);
  }
  expect(screen.queryByText(/Its prose is not an ASM observation/)).not.toBeInTheDocument();
  expect(screen.queryByText(/\*\*/)).not.toBeInTheDocument();
  expect(screen.queryByText(/Gemma|Ollama|Qwen|gemma3:4b/i)).not.toBeInTheDocument();
});

test("preserves an explicitly requested domain over the default queue selection", async () => {
  window.location.hash = "#/investigate?domain=explicit.example.com";
  getInvestigationAssets.mockResolvedValue(investigationList);
  getV2AssetDetail.mockResolvedValue({ ...selectedAsset, domain: "explicit.example.com" });

  render(<App />);

  expect(await screen.findByText("Authoritative ShadowRecon evidence")).toBeInTheDocument();
  expect(window.location.hash).toBe("#/investigate?domain=explicit.example.com");
  expect(getV2AssetDetail).toHaveBeenCalledWith("explicit.example.com");
  expect(getV2AssetAssistant).not.toHaveBeenCalled();
});

test("does not replace a user selection while the investigation queue is loading", async () => {
  let resolveList;
  getInvestigationAssets.mockReturnValue(new Promise((resolve) => { resolveList = resolve; }));
  getV2AssetDetail.mockResolvedValue({ ...selectedAsset, domain: "user-selected.example.com" });

  render(<App />);
  window.location.hash = "#/investigate?domain=user-selected.example.com";
  fireEvent(window, new HashChangeEvent("hashchange"));
  resolveList({ ...investigationList, assets: [{ ...investigationList.assets[0], domain: "first.example.com" }] });

  expect(await screen.findByText("Authoritative ShadowRecon evidence")).toBeInTheDocument();
  expect(window.location.hash).toBe("#/investigate?domain=user-selected.example.com");
  expect(getV2AssetDetail).toHaveBeenCalledWith("user-selected.example.com");
});

test("Candidate assets retain the no-organizational-risk boundary", async () => {
  window.location.hash = "#/investigate?domain=candidate.example.net";
  getInvestigationAssets.mockResolvedValue({ ...investigationList, count: 0, assets: [] });
  getV2AssetDetail.mockResolvedValue({
    ...selectedAsset,
    domain: "candidate.example.net",
    ownership_status: "CANDIDATE",
    asset_class: "CANDIDATE",
    risk: null,
  });
  getV2AssetAssistant.mockResolvedValue({
    domain: "candidate.example.net",
    action: "explain_risk",
    response: "No organizational canonical risk applies.",
    source: "ShadowRecon deterministic evidence + Gemma",
    model: "gemma3:4b",
  });

  render(<App />);

  expect(await screen.findByText("No organizational canonical risk applies to CANDIDATE assets.")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Explain Risk" }));
  expect(await screen.findByText("No organizational canonical risk applies.")).toBeInTheDocument();
  expect(screen.queryByText("score 8")).not.toBeInTheDocument();
});

test("Investigation workspace exposes loading, empty, and request-error states", async () => {
  getInvestigationAssets.mockReturnValueOnce(new Promise(() => {}));
  const loading = render(<App />);
  expect(screen.getByText("Loading investigation assets")).toBeInTheDocument();
  loading.unmount();

  getInvestigationAssets.mockResolvedValueOnce({ page: 1, limit: 20, count: 0, assets: [] });
  const empty = render(<App />);
  expect(await screen.findByText("No investigation assets")).toBeInTheDocument();
  expect(window.location.hash).toBe("#/investigate");
  empty.unmount();

  getInvestigationAssets.mockRejectedValueOnce(new Error("offline"));
  render(<App />);
  expect(await screen.findByText("Investigation queue unavailable")).toBeInTheDocument();
});

test("assistant errors do not alter or hide authoritative evidence", async () => {
  window.location.hash = `#/investigate?domain=${selectedAsset.domain}`;
  getInvestigationAssets.mockResolvedValue(investigationList);
  getV2AssetDetail.mockResolvedValue(selectedAsset);
  getV2AssetAssistant.mockRejectedValue(new Error("offline"));

  render(<App />);

  expect(await screen.findByText("Authoritative ShadowRecon evidence")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Summarize Asset" }));
  expect(await screen.findByText("Grounded assistance is unavailable. Authoritative ShadowRecon evidence remains unchanged.")).toBeInTheDocument();
  expect(screen.getByText("192.0.2.10")).toBeInTheDocument();
});

test("presentation treats null and NaN-like strings as missing without hiding semantic states", async () => {
  window.location.hash = `#/investigate?domain=${selectedAsset.domain}`;
  getInvestigationAssets.mockResolvedValue(investigationList);
  getV2AssetDetail.mockResolvedValue({
    ...selectedAsset,
    http: { observation_status: "UNKNOWN", status: 0, final_url: "nan", title: "NaN" },
  });
  render(<App />);

  expect(await screen.findByText("Authoritative ShadowRecon evidence")).toBeInTheDocument();
  expect(screen.getByText("UNKNOWN")).toBeInTheDocument();
  expect(screen.getByText("Unknown")).toBeInTheDocument();
  expect(screen.getAllByText("Not observed")).toHaveLength(2);
  expect(screen.getByText("Unresolved or unavailable")).toBeInTheDocument();
  expect(screen.queryByText(/^nan$/i)).not.toBeInTheDocument();
});
