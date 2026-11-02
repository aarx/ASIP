import React from "react";
import { render, screen } from "@testing-library/react";
import OverviewIntelligence from "./OverviewIntelligence";

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
    />
  );

  expect(screen.getByText("Confirmed organizational assets across successful scans")).toBeInTheDocument();
  expect(screen.getByTestId("overview-asset-growth-chart")).toHaveClass("overview-chart-canvas");
  expect(screen.getByText("Current authoritative confirmed-organizational scan")).toBeInTheDocument();
  expect(screen.getByTestId("overview-http-status-chart")).toHaveClass("overview-chart-canvas");
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
