import React, { useEffect, useState } from "react";
import AppShell from "./components/AppShell";
import OverviewPage from "./pages/OverviewPage";
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

function routeFromHash() {
  const value = window.location.hash.replace(/^#\/?/, "");
  return ROUTES[value] ? value : "overview";
}

function App() {
  const [route, setRoute] = useState(routeFromHash);

  useEffect(() => {
    const onHashChange = () => setRoute(routeFromHash());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  const [title, eyebrow, description] = ROUTES[route];
  return (
    <AppShell
      activeRoute={route}
      routeMeta={{ title, eyebrow, description }}
    >
      {route === "overview" ? <OverviewPage /> : <PlaceholderPage title={title} />}
    </AppShell>
  );
}

export default App;
