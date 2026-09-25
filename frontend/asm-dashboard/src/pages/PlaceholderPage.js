import React from "react";
import Panel from "../components/ui/Panel";

export default function PlaceholderPage({ title }) {
  return (
    <div className="placeholder-grid">
      <Panel title={`${title} workspace`} subtitle="Scheduled for a later Frontend V2 phase">
        <div className="placeholder-detail">
          <span className="placeholder-index">FUTURE</span>
          <span>This navigation destination is reserved. No synthetic data or unfinished controls are shown.</span>
        </div>
      </Panel>
    </div>
  );
}
