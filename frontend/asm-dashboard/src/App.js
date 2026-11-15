import React, { useEffect, useState } from "react";
import AppShell from "./components/AppShell";
import OverviewPage from "./pages/OverviewPage";
import AssetExplorerPage from "./pages/AssetExplorerPage";
import AssetDetailPage from "./pages/AssetDetailPage";
import RiskExposurePage from "./pages/RiskExposurePage";
import RiskNeedsAttentionPage from "./pages/RiskNeedsAttentionPage";
import ShadowCentrePage from "./pages/ShadowCentrePage";
import ScanCentrePage from "./pages/ScanCentrePage";
import BrandPerimeterPage from "./pages/BrandPerimeterPage";
import InvestigationPage from "./pages/InvestigationPage";
import ChangeIntelligencePage from "./pages/ChangeIntelligencePage";
import AdhocChecksPage from "./pages/AdhocChecksPage";
import DnsSecurityPage from "./pages/DnsSecurityPage";
import SecurityFindingsPage from "./pages/SecurityFindingsPage";
import CapdPage from "./pages/CapdPage";
import SecurityReviewPage from "./pages/SecurityReviewPage";
import BrandHistoryPage from "./pages/BrandHistoryPage";
import "./App.css";

const ROUTES = {
  overview: ["Overview", "Attack surface operations", "Authoritative exposure, change, and priority signals."],
  assets: ["Assets", "Inventory", "Explore current organizational and perimeter assets."],
  risk: ["Risk Overview", "Prioritization", "Review deterministic risk and exposure evidence."],
  "risk-security-review": ["Security Review", "Risk & Exposure", "Review prioritized assets and evidence signals."],
  "risk-findings": ["Security Findings", "Risk & Exposure", "Review source-recorded observations and exposure signals."],
  "risk-needs-attention": ["Needs Attention", "Risk & Exposure", "Top deterministic risk scores followed by canonical risk distribution."],
  "risk-dns-security": ["DNS Security", "Risk & Exposure", "Read-only DNS assessment evidence from the current authoritative scan."],
  shadow: ["Shadow", "Unmanaged inventory", "Investigate confirmed organizational assets outside documented inventory."],
  brand: ["Brand Exposure", "Ownership intelligence", "Review Needs Verification and External assets without assuming ownership."],
  "brand-history": ["Brand discovery history", "Analytics", "Retained brand-source observations."],
  scans: ["Scans", "Operations", "Monitor scan lifecycle and authoritative history."],
  investigate: ["Investigate", "Analyst workspace", "Move from deterministic evidence to focused investigation."],
  changes: ["Change Intelligence", "Successful-scan comparison", "Inspect exact membership changes between authoritative scans."],
  adhoc: ["Adhoc Checks", "Targeted review", "Review vulnerability-specific intelligence without active scanning."],
  capd: ["CAPD · CVE Checks", "On-demand assessment history", "Browse passive, inventory-based CVE assessments. Checks are run by an operator from the CLI."],
};

function locationFromHash() {
  const raw = window.location.hash.replace(/^#\/?/, "");
  const [path, query = ""] = raw.split("?");
  const segments = path.split("/").filter(Boolean);
  if (segments[0] === "settings") {
    window.history.replaceState(null, "", "#/overview");
    return { route: "overview", domain: null, query: "" };
  }
  if (segments[0] === "overview" && segments[1] === "risk-distribution") {
    const params = new URLSearchParams(query);
    params.set("section", "risk-distribution");
    const nextQuery = params.toString();
    window.history.replaceState(null, "", `#/risk?${nextQuery}`);
    return { route: "risk", domain: null, query: nextQuery };
  }
  if (segments[0] === "overview" && segments[1] === "needs-attention") {
    const params = new URLSearchParams(query);
    normalizePrioritizedQuery(params);
    const nextQuery = params.toString();
    window.history.replaceState(null, "", `#/risk/security-review${nextQuery ? `?${nextQuery}` : ""}`);
    return { route: "risk-security-review", domain: null, query: nextQuery };
  }
  if (segments[0] === "risk" && !segments[1] && new URLSearchParams(query).get("section") === "priority-assets") {
    const params = new URLSearchParams(query);
    params.delete("section");
    params.set("tab", "prioritized-assets");
    const nextQuery = params.toString();
    window.history.replaceState(null, "", `#/risk/security-review${nextQuery ? `?${nextQuery}` : ""}`);
    return { route: "risk-security-review", domain: null, query: nextQuery };
  }
  if (segments[0] === "risk" && !segments[1]) {
    const params = new URLSearchParams(query);
    const legacySection = params.get("section") || params.get("view");
    const targetTab = legacySection === "sensitive-ports" ? "sensitive-ports"
      : legacySection === "review-indicators" ? "evidence-signals" : null;
    if (targetTab) {
      params.delete("section");
      params.delete("view");
      params.set("tab", targetTab);
      if (legacySection === "review-indicators") {
        params.set("signals", "review-indicators");
      }
      const nextQuery = params.toString();
      window.history.replaceState(null, "", `#/risk/security-review${nextQuery ? `?${nextQuery}` : ""}`);
      return { route: "risk-security-review", domain: null, query: nextQuery };
    }
    if (legacySection === "dns-security") {
      params.delete("section");
      params.delete("view");
      const nextQuery = params.toString();
      window.history.replaceState(null, "", `#/risk/dns-security${nextQuery ? `?${nextQuery}` : ""}`);
      return { route: "risk-dns-security", domain: null, query: nextQuery };
    }
  }
  if (segments[0] === "risk" && segments[1] === "findings") {
    const params = new URLSearchParams(query);
    params.set("tab", "evidence-signals");
    const nextQuery = params.toString();
    window.history.replaceState(null, "", `#/risk/security-review?${nextQuery}`);
    return { route: "risk-security-review", domain: null, query: nextQuery };
  }
  if (segments[0] === "risk" && segments[1] === "needs-attention") {
    const params = new URLSearchParams(query);
    normalizePrioritizedQuery(params);
    const nextQuery = params.toString();
    window.history.replaceState(null, "", `#/risk/security-review?${nextQuery}`);
    return { route: "risk-security-review", domain: null, query: nextQuery };
  }
  if (segments[0] === "risk" && segments[1] === "security-review" && new URLSearchParams(query).get("tab") === "review-queue") {
    const params = new URLSearchParams(query);
    normalizePrioritizedQuery(params);
    const nextQuery = params.toString();
    window.history.replaceState(null, "", `#/risk/security-review?${nextQuery}`);
    return { route: "risk-security-review", domain: null, query: nextQuery };
  }
  const riskSubroute = segments[0] === "risk" && segments[1] === "needs-attention"
    ? "risk-needs-attention"
    : segments[0] === "risk" && segments[1] === "findings"
      ? "risk-findings"
    : segments[0] === "risk" && segments[1] === "security-review"
      ? "risk-security-review"
    : segments[0] === "risk" && segments[1] === "dns-security"
      ? "risk-dns-security"
      : null;
  const brandHistoryRoute = segments[0] === "brand" && segments[1] === "history";
  const route = brandHistoryRoute ? "brand-history" : ROUTES[riskSubroute] ? riskSubroute : (ROUTES[segments[0]] ? segments[0] : "overview");
  const domain = route === "assets" && segments.length > 1
    ? decodeURIComponent(segments.slice(1).join("/"))
    : route === "brand-history" && segments.length > 2
      ? decodeURIComponent(segments.slice(2).join("/"))
    : null;
  return { route, domain, query };
}

function normalizePrioritizedQuery(params) {
  const page = Number(params.get("page"));
  const limit = Number(params.get("limit"));
  params.delete("page");
  params.delete("limit");
  if (limit === 25 && Number.isInteger(page) && page > 0) params.set("priority_page", String(page));
  params.set("tab", "prioritized-assets");
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
    ? { title: route === "brand-history" ? "Historical brand asset" : "Asset detail", eyebrow: route === "brand-history" ? "Retained evidence" : "Asset detail", description: domain }
    : { title, eyebrow, description };

  let page = null;
  if (route === "overview") page = <OverviewPage query={query} />;
  if (route === "assets") {
    page = domain
      ? <AssetDetailPage domain={domain} returnQuery={query} />
      : <AssetExplorerPage query={query} />;
  }
  if (route === "risk") page = <RiskExposurePage query={query} />;
  if (route === "risk-security-review") page = <SecurityReviewPage query={query} />;
  if (route === "risk-findings") page = <SecurityFindingsPage query={query} />;
  if (route === "risk-needs-attention") page = <RiskNeedsAttentionPage query={query} />;
  if (route === "risk-dns-security") page = <DnsSecurityPage query={query} />;
  if (route === "shadow") page = <ShadowCentrePage query={query} />;
  if (route === "scans") page = <ScanCentrePage query={query} />;
  if (route === "brand") page = <BrandPerimeterPage query={query} />;
  if (route === "brand-history") page = <BrandHistoryPage query={query} domain={domain} />;
  if (route === "investigate") page = <InvestigationPage query={query} />;
  if (route === "changes") page = <ChangeIntelligencePage query={query} />;
  if (route === "adhoc") page = <AdhocChecksPage query={query} />;
  if (route === "capd") page = <CapdPage query={query} />;

  return (
    <AppShell activeRoute={route === "brand-history" ? "brand" : route} routeMeta={routeMeta}>
      {page}
    </AppShell>
  );
}

export default App;
