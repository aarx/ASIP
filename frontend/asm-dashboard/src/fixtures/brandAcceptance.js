const FIXTURE_KEY = "ownership-review";

const assets = [
  {
    domain: "abc-login-test.invalid",
    ownership_status: "CANDIDATE",
    ip: "192.0.2.41",
    has_ip: true,
    http_observation_status: "RESPONDED",
    http_status: 302,
    final_url: "https://vendor-reference.invalid/landing",
    final_status: null,
    final_url_verification: "LEGACY_UNKNOWN",
    redirect_evidence: {
      requested_url: null,
      http_status: null,
      first_hop_location: null,
      first_hop_destination: null,
      observed_hops: [],
      verified_terminal_url: null,
      completion_status: "LEGACY_UNKNOWN",
      stop_reason: "historical_record_predates_redirect_evidence",
      legacy_url: "https://vendor-reference.invalid/landing",
    },
    title: "Synthetic ownership review fixture",
    discovery_sources: ["brand_pattern"],
    seeds: ["abc.com"],
    risk: null,
  },
  {
    domain: "outside-reference.invalid",
    ownership_status: "EXTERNAL",
    ip: null,
    has_ip: false,
    http_observation_status: "UNKNOWN",
    http_status: null,
    final_url: null,
    final_status: null,
    title: null,
    discovery_sources: ["brand_tld"],
    seeds: ["abc.com"],
    risk: null,
  },
];

export function isBrandAcceptanceFixture(query = "") {
  const params = new URLSearchParams(query);
  const returnParams = new URLSearchParams(params.get("return_query") || "");
  return process.env.NODE_ENV !== "production"
    && (params.get("fixture") === FIXTURE_KEY || returnParams.get("fixture") === FIXTURE_KEY);
}

export function brandAcceptanceInventory({ page = 1, limit = 25, search = "", ownership = "" } = {}) {
  const filtered = assets.filter((asset) => (
    (!search || asset.domain.includes(search.toLowerCase()))
    && (!ownership || asset.ownership_status === ownership)
  ));
  const start = (page - 1) * limit;
  return { scan_id: 9000, page, limit, count: filtered.length, assets: filtered.slice(start, start + limit) };
}

export function brandAcceptanceDetail(domain) {
  const asset = assets.find((item) => item.domain === domain);
  if (!asset) return { error: "Synthetic fixture asset not found" };
  return {
    scan_id: 9000,
    domain: asset.domain,
    ownership_status: asset.ownership_status,
    is_known: false,
    asset_class: asset.ownership_status,
    first_seen_scan: 9000,
    last_seen_scan: 9000,
    first_seen_at: "2026-01-01T00:00:00Z",
    last_seen_at: "2026-01-01T00:00:00Z",
    seed: asset.seeds[0],
    risk: null,
    dns: { ip: asset.ip, has_ip: asset.has_ip, reverse_dns: null },
    http: {
      observation_status: asset.http_observation_status,
      status: asset.http_status,
      final_url: asset.final_url,
      final_status: asset.final_status,
      redirect_evidence: asset.redirect_evidence,
      title: asset.title,
    },
    ports: [],
    asn: null,
    provider: null,
    technologies: [],
    certificate: null,
    discovery: { sources: asset.discovery_sources.map((source) => ({ source, seed: asset.seeds[0] })) },
    findings: [],
  };
}
