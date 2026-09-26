import React from "react";

export default function AssetLink({ domain, returnTo, returnQuery, className = "asset-domain-link", children }) {
  const params = new URLSearchParams();
  if (returnTo) params.set("return", returnTo);
  if (returnQuery) params.set("return_query", returnQuery);
  const query = params.toString() ? `?${params}` : "";
  const label = className.includes("row-action") ? `Open ${domain}` : undefined;
  return (
    <a aria-label={label} className={className} href={`#/assets/${encodeURIComponent(domain)}${query}`}>
      {children || domain}
    </a>
  );
}
