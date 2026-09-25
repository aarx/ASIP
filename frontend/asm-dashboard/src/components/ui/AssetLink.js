import React from "react";

export default function AssetLink({ domain, returnTo, className = "asset-domain-link", children }) {
  const query = returnTo ? `?return=${encodeURIComponent(returnTo)}` : "";
  const label = className.includes("row-action") ? `Open ${domain}` : undefined;
  return (
    <a aria-label={label} className={className} href={`#/assets/${encodeURIComponent(domain)}${query}`}>
      {children || domain}
    </a>
  );
}
