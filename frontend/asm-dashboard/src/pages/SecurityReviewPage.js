import React, { useEffect, useRef, useState } from "react";
import PriorityAssetsPanel from "../components/ui/PriorityAssetsPanel";
import ReviewIndicatorsPanel from "../components/ui/ReviewIndicatorsPanel";
import SensitivePortsPanel from "../components/ui/SensitivePortsPanel";
import SecurityFindingsPage from "./SecurityFindingsPage";
import SubdomainTakeoverPage from "./SubdomainTakeoverPage";

const TABS = [
  ["prioritized-assets", "Prioritized Assets"],
  ["evidence-signals", "Evidence & Signals"],
  ["sensitive-ports", "Sensitive Ports"],
  ["subdomain-takeover", "Subdomain Takeover"],
];

function readTab(query) {
  const requested = new URLSearchParams(query).get("tab");
  return TABS.some(([tab]) => tab === requested) ? requested : "prioritized-assets";
}

export default function SecurityReviewPage({ query = "" }) {
  const [tab, setTab] = useState(() => readTab(query));
  const tabRefs = useRef({});

  useEffect(() => setTab(readTab(query)), [query]);

  const selectTab = (nextTab) => {
    const params = new URLSearchParams(query);
    params.delete("section");
    params.delete("signals");
    params.set("tab", nextTab);
    setTab(nextTab);
    window.location.hash = `#/risk/security-review?${params}`;
  };

  const moveTab = (currentTab, direction) => {
    const currentIndex = TABS.findIndex(([value]) => value === currentTab);
    const nextTab = TABS[(currentIndex + direction + TABS.length) % TABS.length][0];
    selectTab(nextTab);
    tabRefs.current[nextTab]?.focus();
  };

  const handleKeyDown = (event, currentTab) => {
    if (event.key === "ArrowRight" || event.key === "ArrowDown") {
      event.preventDefault();
      moveTab(currentTab, 1);
    } else if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
      event.preventDefault();
      moveTab(currentTab, -1);
    } else if (event.key === "Home" || event.key === "End") {
      event.preventDefault();
      const nextTab = event.key === "Home" ? TABS[0][0] : TABS[TABS.length - 1][0];
      selectTab(nextTab);
      tabRefs.current[nextTab]?.focus();
    }
  };

  return (
    <div className="security-review-workspace operations-grid">
      <section className="security-review-tabs-panel operation-panel-full" aria-label="Security Review sections">
        <div className="security-review-tabs" role="tablist" aria-label="Security Review tabs">
          {TABS.map(([value, label]) => (
            <button
              type="button"
              role="tab"
              id={`${value}-tab`}
              aria-selected={tab === value}
              aria-controls={value}
              tabIndex={tab === value ? 0 : -1}
              className={tab === value ? "active" : ""}
              onClick={() => selectTab(value)}
              onKeyDown={(event) => handleKeyDown(event, value)}
              ref={(element) => { tabRefs.current[value] = element; }}
              key={value}
            >
              {label}
            </button>
          ))}
        </div>
      </section>

      <div id="prioritized-assets" role="tabpanel" aria-labelledby="prioritized-assets-tab" hidden={tab !== "prioritized-assets"}>
        {tab === "prioritized-assets" && <PriorityAssetsPanel query={query} />}
      </div>
      <div id="evidence-signals" role="tabpanel" aria-labelledby="evidence-signals-tab" hidden={tab !== "evidence-signals"}>
        {tab === "evidence-signals" && (new URLSearchParams(query).get("signals") === "review-indicators"
          ? <ReviewIndicatorsPanel />
          : <SecurityFindingsPage query={query} routePrefix="risk/security-review" />)}
      </div>
      <div id="sensitive-ports" role="tabpanel" aria-labelledby="sensitive-ports-tab" hidden={tab !== "sensitive-ports"}>
        {tab === "sensitive-ports" && <SensitivePortsPanel />}
      </div>
      <div id="subdomain-takeover" role="tabpanel" aria-labelledby="subdomain-takeover-tab" hidden={tab !== "subdomain-takeover"}>
        {tab === "subdomain-takeover" && <SubdomainTakeoverPage query={query} />}
      </div>
    </div>
  );
}
