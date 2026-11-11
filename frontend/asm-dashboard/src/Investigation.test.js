import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import App from "./App";
import { askShadowRecon, getInvestigationAssets, getV2AssetAssistant, getV2AssetDetail } from "./services/api";

jest.mock("./services/api", () => ({
  getV2Overview: jest.fn(),
  getV2Assets: jest.fn(),
  getV2AssetDetail: jest.fn(),
  updateV2AssetOwnership: jest.fn(),
  getV2AssetAssistant: jest.fn(),
  askShadowRecon: jest.fn(),
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
  askShadowRecon.mockReset();
});

test("selects the first queue asset by default and runs grounded actions without auto-running AI", async () => {
  getInvestigationAssets.mockResolvedValue(investigationList);
  getV2AssetDetail.mockResolvedValue(selectedAsset);
  getV2AssetAssistant.mockImplementation((domain, action) => Promise.resolve({
    domain,
    action,
    response: `**${action}** grounded response`,
    source: "ShadowRecon deterministic evidence",
    mode: "model_free",
    model: null,
    context: { scan_scope: "CURRENT_AUTHORITATIVE_SCAN" },
    coverage: { dns: "OBSERVED" },
    limitations: ["Missing observations remain unknown."],
    next_actions: ["Review the asset evidence."],
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
  expect(screen.getByText("Investigation Assistant")).toBeInTheDocument();
  expect(screen.getByText("EVIDENCE-BASED")).toBeInTheDocument();
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
  const actionDetails = screen.getByText("Evidence details").closest("details");
  expect(actionDetails.open).toBe(false);
  fireEvent.click(screen.getByText("Evidence details"));
  expect(screen.getByText("model_free")).toBeInTheDocument();
  expect(screen.getByText("ShadowRecon deterministic evidence")).toBeInTheDocument();
  expect(screen.getByText(/scan scope: CURRENT_AUTHORITATIVE_SCAN/)).toBeInTheDocument();
  expect(screen.getByText(/dns: OBSERVED/)).toBeInTheDocument();
  expect(screen.getByText("Missing observations remain unknown.")).toBeInTheDocument();
  expect(screen.getByText("Review the asset evidence.")).toBeInTheDocument();
  expect(screen.queryByText(/Its prose is not an ASM observation/)).not.toBeInTheDocument();
  expect(screen.queryByText(/\*\*/)).not.toBeInTheDocument();
  expect(screen.queryByText(/Gemma|Ollama|Qwen|gemma3:4b/i)).not.toBeInTheDocument();
});

test("asks global and selected-asset questions through the model-free endpoint", async () => {
  window.location.hash = `#/investigate?domain=${selectedAsset.domain}`;
  getInvestigationAssets.mockResolvedValue(investigationList);
  getV2AssetDetail.mockResolvedValue(selectedAsset);
  askShadowRecon.mockImplementation((question, domain) => Promise.resolve({
    question,
    answer: `${question} answer`,
    data: { risk_distribution: { High: 2, Review: 4 }, next_tier_assets: [{ domain: "priority.example.com", priority: "Review", score: 4 }] },
    context: { scan_id: 42 },
    coverage: { asset_classification: "CURRENT_AUTHORITATIVE_SCAN" },
    limitations: ["Returned evidence is bounded."],
    next_actions: ["Review the returned assets."],
    suggested_questions: [],
    source: "ShadowRecon deterministic evidence",
    mode: "model_free",
    model: null,
  }));

  render(<App />);

  const input = await screen.findByLabelText("Ask ShadowRecon a security question");
  fireEvent.change(input, { target: { value: "What is our current attack surface?" } });
  expect(input).toHaveValue("What is our current attack surface?");
  fireEvent.submit(input.closest("form"));
  expect(await screen.findByText("What is our current attack surface? answer")).toBeInTheDocument();
  expect(askShadowRecon).toHaveBeenLastCalledWith("What is our current attack surface?", null);
  expect(screen.getAllByText("High").length).toBeGreaterThan(0);
  expect(screen.getByText("priority.example.com")).toBeInTheDocument();
  fireEvent.click(screen.getByText("Evidence details"));
  expect(screen.getByText("ShadowRecon deterministic evidence")).toBeInTheDocument();
  expect(screen.getByText(/scan id: 42/)).toBeInTheDocument();

  fireEvent.change(input, { target: { value: "Why is this domain risky?" } });
  fireEvent.submit(input.closest("form"));
  expect(await screen.findByText("Why is this domain risky? answer")).toBeInTheDocument();
  expect(askShadowRecon).toHaveBeenLastCalledWith("Why is this domain risky?", selectedAsset.domain);
});

test("renders nested comparison state without object stringification", async () => {
  getInvestigationAssets.mockResolvedValue(investigationList);
  getV2AssetDetail.mockResolvedValue(selectedAsset);
  askShadowRecon.mockResolvedValue({
    question: "Compare the last two successful scans",
    answer: "The scan comparison is available.",
    data: {
      http_dns_state_changes: [{
        domain: "changed.example.com",
        before: { http_status: 200, dns_state: "RESOLVING" },
        after: { http_status: 404, dns_state: "UNRESOLVED" },
      }],
    },
    coverage: { state_changes_total: 1 },
    context: { scan_ids: [41, 42] },
    limitations: [],
    next_actions: [],
    suggested_questions: [],
    mode: "model_free",
    source: "ShadowRecon deterministic evidence",
    model: null,
  });

  render(<App />);

  const input = await screen.findByLabelText("Ask ShadowRecon a security question");
  fireEvent.change(input, { target: { value: "Compare the last two successful scans" } });
  fireEvent.submit(input.closest("form"));

  expect(await screen.findByText("changed.example.com")).toBeInTheDocument();
  expect(screen.getByText(/before: http status: 200 · dns state: RESOLVING/)).toBeInTheDocument();
  expect(screen.getByText(/after: http status: 404 · dns state: UNRESOLVED/)).toBeInTheDocument();
  expect(screen.queryByText(/\[object Object\]/)).not.toBeInTheDocument();
});

test("suggested questions populate the input without submitting", async () => {
  getInvestigationAssets.mockResolvedValue(investigationList);
  getV2AssetDetail.mockResolvedValue(selectedAsset);

  render(<App />);

  const input = await screen.findByLabelText("Ask ShadowRecon a security question");
  fireEvent.click(screen.getByRole("button", { name: "Are there DNS Security concerns?" }));
  expect(input).toHaveValue("Are there DNS Security concerns?");
  expect(askShadowRecon).not.toHaveBeenCalled();
});

test("renders unsupported, ambiguous, and selection-required responses with supported suggestions", async () => {
  getInvestigationAssets.mockResolvedValue(investigationList);
  getV2AssetDetail.mockResolvedValue(selectedAsset);
  askShadowRecon
    .mockResolvedValueOnce({ question: "What is the weather?", answer: "I cannot answer that question.", data: {}, context: {}, coverage: { routing: "UNSUPPORTED" }, limitations: [], next_actions: [], suggested_questions: ["What is our current attack surface?"], mode: "model_free", source: "ShadowRecon deterministic evidence", model: null })
    .mockResolvedValueOnce({ question: "Why is this asset risky and which assets need attention?", answer: "Please ask about one topic at a time.", data: {}, context: {}, coverage: { routing: "AMBIGUOUS" }, limitations: [], next_actions: [], suggested_questions: ["Which assets need attention?"], mode: "model_free", source: "ShadowRecon deterministic evidence", model: null })
    .mockResolvedValueOnce({ question: "Why is this domain risky?", answer: "Select an asset from the current authoritative scan.", data: {}, context: {}, coverage: { asset: "SELECTION_REQUIRED" }, limitations: [], next_actions: ["Select a current asset."], suggested_questions: [], mode: "model_free", source: "ShadowRecon deterministic evidence", model: null });

  render(<App />);

  const input = await screen.findByLabelText("Ask ShadowRecon a security question");
  for (const question of ["What is the weather?", "Why is this asset risky and which assets need attention?", "Why is this domain risky?"]) {
    fireEvent.change(input, { target: { value: question } });
    fireEvent.submit(input.closest("form"));
    await screen.findByText(/cannot answer|one topic at a time|Select an asset/);
  }
  expect(askShadowRecon).toHaveBeenCalledTimes(3);
});

test("question loading and request errors are retryable without hiding asset evidence", async () => {
  getInvestigationAssets.mockResolvedValue(investigationList);
  getV2AssetDetail.mockResolvedValue(selectedAsset);
  let rejectQuestion;
  askShadowRecon.mockReturnValue(new Promise((resolve, reject) => { rejectQuestion = reject; }));

  render(<App />);

  const input = await screen.findByLabelText("Ask ShadowRecon a security question");
  fireEvent.change(input, { target: { value: "Which assets need attention?" } });
  fireEvent.submit(input.closest("form"));
  fireEvent.submit(input.closest("form"));
  expect(screen.getByText("Reading current ShadowRecon evidence…")).toBeInTheDocument();
  expect(askShadowRecon).toHaveBeenCalledTimes(1);
  expect(screen.getByRole("button", { name: "Asking…" })).toBeDisabled();
  rejectQuestion(new Error("offline"));
  expect(await screen.findByText("ShadowRecon questions are unavailable. Try again.")).toBeInTheDocument();
  expect(screen.getByText("192.0.2.10")).toBeInTheDocument();
});

test("ignores a question response after the selected asset changes", async () => {
  window.location.hash = `#/investigate?domain=${selectedAsset.domain}`;
  getInvestigationAssets.mockResolvedValue(investigationList);
  getV2AssetDetail.mockImplementation((domain) => Promise.resolve({ ...selectedAsset, domain }));
  let resolveQuestion;
  askShadowRecon.mockReturnValue(new Promise((resolve) => { resolveQuestion = resolve; }));

  render(<App />);

  const input = await screen.findByLabelText("Ask ShadowRecon a security question");
  fireEvent.change(input, { target: { value: "Why is this domain risky?" } });
  fireEvent.submit(input.closest("form"));
  window.location.hash = "#/investigate?domain=other.example.com";
  fireEvent(window, new HashChangeEvent("hashchange"));
  resolveQuestion({ question: "Why is this domain risky?", answer: "stale response", data: {}, context: {}, coverage: {}, limitations: [], next_actions: [], suggested_questions: [], mode: "model_free", source: "ShadowRecon deterministic evidence", model: null });

  expect(await screen.findByText("other.example.com")).toBeInTheDocument();
  expect(screen.queryByText("stale response")).not.toBeInTheDocument();
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
    source: "ShadowRecon deterministic evidence",
    mode: "model_free",
    model: null,
  });

  render(<App />);

  expect(await screen.findByText("No organizational canonical risk applies to Needs Verification assets.")).toBeInTheDocument();
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

test("shows an invalid selected domain without requesting assistant output", async () => {
  window.location.hash = "#/investigate?domain=missing.example.com";
  getInvestigationAssets.mockResolvedValue(investigationList);
  getV2AssetDetail.mockResolvedValue({ error: "Asset not found in the current authoritative scan." });

  render(<App />);

  expect(await screen.findByText("Asset is not current")).toBeInTheDocument();
  expect(screen.queryByText("Investigation Assistant")).not.toBeInTheDocument();
  expect(getV2AssetAssistant).not.toHaveBeenCalled();
});

test("assistant errors do not alter or hide authoritative evidence", async () => {
  window.location.hash = `#/investigate?domain=${selectedAsset.domain}`;
  getInvestigationAssets.mockResolvedValue(investigationList);
  getV2AssetDetail.mockResolvedValue(selectedAsset);
  getV2AssetAssistant.mockRejectedValue(new Error("offline"));

  render(<App />);

  expect(await screen.findByText("Authoritative ShadowRecon evidence")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Summarize Asset" }));
  expect(await screen.findByText("Investigation Assistant is unavailable. Authoritative ShadowRecon evidence remains unchanged.")).toBeInTheDocument();
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
  expect(screen.getByText("No HTTP status recorded")).toBeInTheDocument();
  expect(screen.getAllByText("Not observed")).toHaveLength(2);
  expect(screen.getByText("Unresolved or unavailable")).toBeInTheDocument();
  expect(screen.queryByText(/^nan$/i)).not.toBeInTheDocument();
});
