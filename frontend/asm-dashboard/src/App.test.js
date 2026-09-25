import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import App from "./App";
import { getV2Overview } from "./services/api";

jest.mock("./services/api", () => ({ getV2Overview: jest.fn() }));
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
});

test("renders the permanent shell and authoritative overview", async () => {
  getV2Overview.mockResolvedValue(overview);
  render(<App />);

  expect(screen.getByText("Loading authoritative state")).toBeInTheDocument();
  expect(await screen.findByText("alpha.example")).toBeInTheDocument();
  expect(screen.getByText("Organizational assets")).toBeInTheDocument();
  expect(screen.getByText("Brand perimeter")).toBeInTheDocument();
  expect(screen.getByText("scan 41 → 42")).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Overview" })).toHaveAttribute("aria-current", "page");
  expect(screen.getByRole("link", { name: "Assets" })).toBeInTheDocument();
  expect(screen.getByRole("link", { name: "Settings" })).toBeInTheDocument();
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
