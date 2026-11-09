import React, { useEffect, useState } from "react";

const DIRECT_NAV_ITEMS = [
  ["overview", "OV", "Overview"],
  ["investigate", "IN", "Investigate"],
];

const NAV_GROUPS = [
  {
    key: "assets",
    symbol: "AS",
    label: "Assets",
    items: [["assets", "AI", "Asset Inventory"], ["shadow", "SH", "Shadow Assets"]],
  },
  {
    key: "risk",
    symbol: "RX",
    label: "Risk & Exposure",
    items: [
      ["risk", "RX", "Risk & Exposure"],
      ["risk-needs-attention", "NA", "Needs Attention", "risk/needs-attention"],
      ["brand", "BP", "Brand Exposure"],
    ],
  },
  {
    key: "scans",
    symbol: "SC",
    label: "Scans",
    items: [["scans", "SC", "Scan Centre"], ["adhoc", "AC", "Adhoc Checks", "adhoc/php-rce"]],
  },
];

function NavLink({ route, symbol, label, activeRoute, hrefRoute = route }) {
  const active = route === activeRoute;
  return (
    <a
      className={`nav-link${active ? " active" : ""}`}
      href={`#/${hrefRoute}`}
      aria-current={active ? "page" : undefined}
      title={label}
    >
      <span className="nav-symbol" aria-hidden="true">{symbol}</span>
      <span className="nav-label">{label}</span>
    </a>
  );
}

function NavGroup({ group, activeRoute, open, onToggle }) {
  const active = group.items.some(([route]) => route === activeRoute);
  return (
    <details className="nav-group" open={open} onToggle={onToggle}>
      <summary className={`nav-group-summary${active ? " active" : ""}`} aria-label={`${group.label} navigation`} aria-expanded={open}>
        <span className="nav-symbol" aria-hidden="true">{group.symbol}</span>
        <span className="nav-label">{group.label}</span>
      </summary>
      <div className="nav-group-links">
        {group.items.map(([route, symbol, label, hrefRoute]) => (
          <NavLink key={route} route={route} symbol={symbol} label={label} activeRoute={activeRoute} hrefRoute={hrefRoute || route} />
        ))}
      </div>
    </details>
  );
}

export default function AppShell({ activeRoute, routeMeta, children }) {
  const [openGroups, setOpenGroups] = useState(() => Object.fromEntries(
    NAV_GROUPS.map((group) => [group.key, true])
  ));

  useEffect(() => {
    setOpenGroups((current) => Object.fromEntries(
      NAV_GROUPS.map((group) => [
        group.key,
        current[group.key] || group.items.some(([route]) => route === activeRoute),
      ])
    ));
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
          {DIRECT_NAV_ITEMS.map(([route, symbol, label]) => (
            <NavLink key={route} route={route} symbol={symbol} label={label} activeRoute={activeRoute} />
          ))}
          {NAV_GROUPS.map((group) => (
            <NavGroup
              key={group.key}
              group={group}
              activeRoute={activeRoute}
              open={openGroups[group.key]}
              onToggle={(event) => {
                const nextOpen = event.currentTarget.open;
                setOpenGroups((current) => ({ ...current, [group.key]: nextOpen }));
              }}
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
