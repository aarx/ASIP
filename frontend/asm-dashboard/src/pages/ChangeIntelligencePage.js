import React, { useEffect, useMemo, useState } from "react";
import { getDisappearedDomains, getNewDomainsDelta } from "../services/api";
import AssetLink from "../components/ui/AssetLink";
import Panel from "../components/ui/Panel";
import { EmptyState, ErrorState, LoadingState } from "../components/ui/AsyncState";

function viewFromQuery(query) {
  return new URLSearchParams(query).get("view") === "disappeared" ? "disappeared" : "new";
}

export default function ChangeIntelligencePage({ query }) {
  const view = useMemo(() => viewFromQuery(query), [query]);
  const [data, setData] = useState(null);
  const [status, setStatus] = useState("loading");
  const [requestVersion, setRequestVersion] = useState(0);

  useEffect(() => {
    let active = true;
    setStatus("loading");
    Promise.all([getNewDomainsDelta(), getDisappearedDomains()])
      .then(([newAssets, disappeared]) => { if (active) { setData({ newAssets, disappeared }); setStatus("ready"); } })
      .catch(() => { if (active) setStatus("error"); });
    return () => { active = false; };
  }, [requestVersion]);

  if (status === "loading") return <LoadingState title="Loading change intelligence" copy="Comparing exact membership across successful authoritative scans." />;
  if (status === "error") return <ErrorState title="Change intelligence unavailable" copy="The successful-scan membership comparison could not be loaded." onRetry={() => setRequestVersion((value) => value + 1)} />;

  const selected = view === "new" ? data.newAssets : data.disappeared;
  const domains = view === "new" ? selected.new_domains : selected.disappeared_domains;
  const noBaseline = selected.from_scan == null;

  return (
    <div className="change-workspace">
      <section className="change-context-bar">
        <div><span>Previous authoritative</span><strong>{selected.from_scan == null ? "—" : `#${selected.from_scan}`}</strong></div>
        <div><span>Current authoritative</span><strong>{selected.to_scan == null ? "—" : `#${selected.to_scan}`}</strong></div>
        <p>Membership comparison uses successful scans only. It does not infer why an asset appeared or disappeared.</p>
      </section>

      <nav className="change-tabs" aria-label="Change intelligence views">
        <a className={view === "new" ? "active" : ""} href="#/changes?view=new">New assets <span>{data.newAssets.new_domains.length}</span></a>
        <a className={view === "disappeared" ? "active" : ""} href="#/changes?view=disappeared">Disappeared <span>{data.disappeared.disappeared_domains.length}</span></a>
      </nav>

      <Panel
        title={view === "new" ? "New organizational assets" : "Disappeared organizational assets"}
        subtitle={view === "new" ? "Present now and absent from the previous successful scan" : "Present previously and absent from the current successful scan"}
        meta="UP TO 100"
      >
        {noBaseline ? <EmptyState title="No previous authoritative baseline" copy="A membership delta is available after at least two successful scans." /> : domains.length ? (
          <div className="change-domain-list">
            {domains.map((domain) => (
              <div className="change-domain-row" key={domain}>
                <div>
                  {view === "new" ? <AssetLink domain={domain} returnTo="changes" returnQuery="view=new" /> : <span className="technical-value">{domain}</span>}
                  <span className="asset-secondary">{view === "new" ? `Current member · scan #${selected.to_scan}` : `Last compared in scan #${selected.from_scan} · not current`}</span>
                </div>
                {view === "new" ? <AssetLink domain={domain} returnTo="changes" returnQuery="view=new" className="row-action">→</AssetLink> : <span className="not-applicable">No current detail</span>}
              </div>
            ))}
          </div>
        ) : <EmptyState title={view === "new" ? "No new assets" : "No disappeared assets"} copy="No confirmed organizational membership changes were recorded for this successful-scan comparison." />}
      </Panel>
    </div>
  );
}
