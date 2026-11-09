import React, { useEffect, useState } from "react";

const NAV_ITEMS = [
  ["assets", "AS", "Assets"],
  ["risk", "RX", "Risk & Exposure"],
  ["scans", "SC", "Scans"],
  ["investigate", "IN", "Investigate"],
  ["adhoc", "AC", "Adhoc Checks", "/php-rce"],
];

const OVERVIEW_NAV_ITEMS = [
  ["overview", "OV", "Dashboard", "overview"],
  ["overview-needs-attention", "NA", "Needs Attention", "overview/needs-attention"],
  ["overview-risk-distribution", "RD", "Risk Distribution", "overview/risk-distribution"],
];

const DISCOVERY_NAV_ITEMS = [
  ["shadow", "SH", "Shadow assets"],
  ["brand", "BP", "Brand exposure"],
];

function NavLink({ route, symbol, label, activeRoute, suffix = "", hrefRoute = route }) {
  const active = route === activeRoute;
  return (
    <a
      className={`nav-link${active ? " active" : ""}`}
      href={`#/${hrefRoute}${suffix}`}
      aria-current={active ? "page" : undefined}
      title={label}
    >
      <span className="nav-symbol" aria-hidden="true">{symbol}</span>
      <span className="nav-label">{label}</span>
    </a>
  );
}

export default function AppShell({ activeRoute, routeMeta, children }) {
  const [overviewOpen, setOverviewOpen] = useState(activeRoute.startsWith("overview"));

  useEffect(() => {
    if (activeRoute.startsWith("overview")) setOverviewOpen(true);
  }, [activeRoute]);

  return (
    <div className="app-shell">
      <aside className="app-sidebar" aria-label="Primary navigation">
        <div className="brand-lockup">
          <div className="brand-mark" aria-hidden="true">S//</div>
          <div className="brand-copy">
            <div className="brand-name">ShadowRecon</div>
            <div className="brand-subtitle">Attack Surface Management</div>
          </div>
        </div>

        <nav className="sidebar-nav">
          <div className="nav-section-label">Workspace</div>
          <details className="nav-overview-group" open={overviewOpen} onToggle={(event) => setOverviewOpen(event.currentTarget.open)}>
            <summary className="nav-overview-summary" aria-label="Overview navigation">
              <span className="nav-symbol" aria-hidden="true">OV</span>
              <span className="nav-label">Overview</span>
            </summary>
            <div className="nav-overview-links">
              {OVERVIEW_NAV_ITEMS.map(([route, symbol, label, hrefRoute]) => (
                <NavLink
                  key={route}
                  route={route}
                  symbol={symbol}
                  label={label}
                  activeRoute={activeRoute}
                  hrefRoute={hrefRoute}
                />
              ))}
            </div>
          </details>
          {NAV_ITEMS.map(([route, symbol, label, suffix]) => (
            <NavLink
              key={route}
              route={route}
              symbol={symbol}
              label={label}
              activeRoute={activeRoute}
              suffix={suffix}
            />
          ))}
          <div className="nav-section-label nav-section-label-discovery">Asset Discovery</div>
          {DISCOVERY_NAV_ITEMS.map(([route, symbol, label, suffix]) => (
            <NavLink
              key={route}
              route={route}
              symbol={symbol}
              label={label}
              activeRoute={activeRoute}
              suffix={suffix}
            />
          ))}
        </nav>

        <div className="sidebar-admin">
          <div className="sidebar-status">
            <i className="status-dot" aria-hidden="true" />
            <span>Deterministic engine</span>
          </div>
        </div>
      </aside>

      <main className="app-main">
        <header className={`page-context page-context-${activeRoute}`}>
          <div>
            <div className="page-eyebrow">{routeMeta.eyebrow}</div>
            <h1 className="page-title">{routeMeta.title}</h1>
            <p className="page-description">{routeMeta.description}</p>
          </div>
        </header>
        <div className={`page-content page-content-${activeRoute}`}>{children}</div>
      </main>
    </div>
  );
}
