import React from "react";

export default function Panel({ title, subtitle, meta, className = "", children }) {
  return (
    <section className={`panel ${className}`}>
      <header className="panel-header">
        <div>
          <h2 className="panel-title">{title}</h2>
          {subtitle && <p className="panel-subtitle">{subtitle}</p>}
        </div>
        {meta && <div className="scan-context">{meta}</div>}
      </header>
      <div className="panel-body">{children}</div>
    </section>
  );
}
