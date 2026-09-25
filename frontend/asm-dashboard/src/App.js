import React, { useEffect, useState } from "react";
import AppShell from "./components/AppShell";
import OverviewPage from "./pages/OverviewPage";
import AssetExplorerPage from "./pages/AssetExplorerPage";
import AssetDetailPage from "./pages/AssetDetailPage";
import RiskExposurePage from "./pages/RiskExposurePage";
import ShadowCentrePage from "./pages/ShadowCentrePage";
import ScanCentrePage from "./pages/ScanCentrePage";
import BrandPerimeterPage from "./pages/BrandPerimeterPage";
import PlaceholderPage from "./pages/PlaceholderPage";
import "./App.css";

const ROUTES = {
  overview: ["Overview", "Attack surface operations", "Authoritative exposure, change, and priority signals."],
  assets: ["Assets", "Inventory", "Explore current organizational and perimeter assets."],
  risk: ["Risk & Exposure", "Prioritization", "Review deterministic risk and exposure evidence."],
  shadow: ["Shadow", "Unmanaged inventory", "Investigate confirmed organizational assets outside documented inventory."],
  brand: ["Brand Perimeter", "Ownership intelligence", "Review Candidate and External assets without assuming ownership."],
  scans: ["Scans", "Operations", "Monitor scan lifecycle and authoritative history."],
  investigate: ["Investigate", "Analyst workspace", "Move from deterministic evidence to focused investigation."],
  settings: ["Settings", "Administration", "Application and operational configuration."],
};

function locationFromHash() {
  const raw = window.location.hash.replace(/^#\/?/, "");
  const [path, query = ""] = raw.split("?");
  const segments = path.split("/").filter(Boolean);
  const route = ROUTES[segments[0]] ? segments[0] : "overview";
  const domain = route === "assets" && segments.length > 1
    ? decodeURIComponent(segments.slice(1).join("/"))
    : null;
  return { route, domain, query };
}

function App() {
  const [location, setLocation] = useState(locationFromHash);

  useEffect(() => {
    const onHashChange = () => setLocation(locationFromHash());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  const { route, domain, query } = location;
  const [title, eyebrow, description] = ROUTES[route];
  const routeMeta = domain
    ? { title: "Asset detail", eyebrow: "Current evidence", description: domain }
    : { title, eyebrow, description };

  let page = <PlaceholderPage title={title} />;
  if (route === "overview") page = <OverviewPage />;
  if (route === "assets") {
    page = domain
      ? <AssetDetailPage domain={domain} returnQuery={query} />
      : <AssetExplorerPage query={query} />;
  }
  if (route === "risk") page = <RiskExposurePage />;
  if (route === "shadow") page = <ShadowCentrePage query={query} />;
  if (route === "scans") page = <ScanCentrePage />;
  if (route === "brand") page = <BrandPerimeterPage query={query} />;

  return (
    <AppShell activeRoute={route} routeMeta={routeMeta}>
      {page}
    </AppShell>
  );
}

export default App;
