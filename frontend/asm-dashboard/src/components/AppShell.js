import React from "react";

const NAV_ITEMS = [
  ["overview", "OV", "Overview"],
  ["assets", "AS", "Assets"],
  ["risk", "RX", "Risk & Exposure"],
  ["shadow", "SH", "Shadow"],
  ["brand", "BP", "Brand Perimeter"],
  ["scans", "SC", "Scans"],
  ["investigate", "IN", "Investigate"],
  ["adhoc", "AC", "Adhoc Checks", "/php-rce"],
];

function NavLink({ route, symbol, label, activeRoute, suffix = "" }) {
  const active = route === activeRoute;
  return (
    <a
      className={`nav-link${active ? " active" : ""}`}
      href={`#/${route}${suffix}`}
      aria-current={active ? "page" : undefined}
      title={label}
    >
      <span className="nav-symbol" aria-hidden="true">{symbol}</span>
      <span className="nav-label">{label}</span>
    </a>
  );
}

export default function AppShell({ activeRoute, routeMeta, children }) {
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
        </nav>

        <div className="sidebar-admin">
          <div className="sidebar-status">
            <i className="status-dot" aria-hidden="true" />
            <span>Deterministic engine</span>
          </div>
          <NavLink
            route="settings"
            symbol="ST"
            label="Settings"
            activeRoute={activeRoute}
          />
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
