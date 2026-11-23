import axios from "axios";

const API_URL = "http://localhost:8555";

export const getV2Overview = async () => {
  const res = await axios.get(`${API_URL}/v2/overview`);
  return res.data;
};

export const getNewDomainsDelta = async () => {
  const res = await axios.get(`${API_URL}/new-domains-delta`);
  return res.data;
};

export const getDisappearedDomains = async () => {
  const res = await axios.get(`${API_URL}/disappeared-domains`);
  return res.data;
};

export const getV2Assets = async (params) => {
  const res = await axios.get(`${API_URL}/v2/assets`, { params });
  return res.data;
};

export const getV2AssetsSummary = async (params) => {
  const res = await axios.get(`${API_URL}/v2/assets/summary`, { params });
  return res.data;
};

export const exportV2AssetsCsv = async (params) => {
  return axios.get(`${API_URL}/v2/assets/export`, {
    params,
    responseType: "blob",
  });
};

export const getV2AssetDetail = async (domain, params) => {
  const res = await axios.get(`${API_URL}/v2/assets/${encodeURIComponent(domain)}`, { params });
  return res.data;
};

export const updateV2AssetOwnership = async (domain, ownershipStatus) => {
  const res = await axios.post(
    `${API_URL}/v2/assets/${encodeURIComponent(domain)}/ownership`,
    { ownership_status: ownershipStatus }
  );
  return res.data;
};

export const getV2AssetAssistant = async (domain, action) => {
  const res = await axios.get(
    `${API_URL}/v2/assets/${encodeURIComponent(domain)}/assistant`,
    { params: { action } }
  );
  return res.data;
};

export const askShadowRecon = async (question, domain = null) => {
  const res = await axios.post(`${API_URL}/v2/assistant/ask`, { question, domain });
  return res.data;
};

export const getSecurityFindings = async (params) => {
  const res = await axios.get(`${API_URL}/v2/security-findings`, { params });
  return res.data;
};

export const getSecurityFindingsSummary = async () => {
  const res = await axios.get(`${API_URL}/v2/security-findings/summary`);
  return res.data;
};

export const getV2Scans = async (limit = 100, sort = {}) => {
  const res = await axios.get(`${API_URL}/v2/scans`, { params: { limit, ...sort } });
  return res.data;
};

export const getV2ScanDetail = async (scanId) => {
  const res = await axios.get(`${API_URL}/v2/scans/${encodeURIComponent(scanId)}`);
  return res.data;
};

export const exportV2ScanReport = async (scanId) => axios.get(
  `${API_URL}/v2/scans/${encodeURIComponent(scanId)}/export`,
  { responseType: "blob" },
);

export const getPhpRceCheck = async (params) => {
  const res = await axios.get(`${API_URL}/v2/adhoc/checks/php-rce`, { params });
  return res.data;
};

export const getV2AdhocCampaigns = async (params) => {
  const res = await axios.get(`${API_URL}/v2/adhoc/campaigns`, { params });
  return res.data;
};

export const getCapdChecks = async () => {
  const res = await axios.get(`${API_URL}/v2/capd/checks`);
  return res.data;
};

export const getCapdRuns = async (params) => {
  const res = await axios.get(`${API_URL}/v2/capd/runs`, { params });
  return res.data;
};

export const getCapdRun = async (runId) => {
  const res = await axios.get(`${API_URL}/v2/capd/runs/${encodeURIComponent(runId)}`);
  return res.data;
};

export const getCapdRunResults = async (runId, params) => {
  const res = await axios.get(`${API_URL}/v2/capd/runs/${encodeURIComponent(runId)}/results`, { params });
  return res.data;
};

export const exportV2AdhocCampaign = async (campaignId) => axios.get(
  `${API_URL}/v2/adhoc/campaigns/${encodeURIComponent(campaignId)}/export`,
  { responseType: "blob" },
);

export const getV2BrandAssets = async (params) => {
  const res = await axios.get(`${API_URL}/v2/brand-assets`, { params });
  return res.data;
};

export const getBrandHistorySummary = async () => {
  const res = await axios.get(`${API_URL}/v2/brand-discovery/history/summary`);
  return res.data;
};

export const getBrandHistoryAssets = async (params) => {
  const res = await axios.get(`${API_URL}/v2/brand-discovery/history/assets`, { params });
  return res.data;
};

export const getBrandHistoryDetail = async (domain) => {
  const res = await axios.get(`${API_URL}/v2/brand-discovery/history/assets/${encodeURIComponent(domain)}`);
  return res.data;
};

export const getDnsSecuritySummary = async () => {
  const res = await axios.get(`${API_URL}/v2/dns-security/summary`);
  return res.data;
};

export const getDnsSecurityFindings = async (params) => {
  const res = await axios.get(`${API_URL}/v2/dns-security/findings`, { params });
  return res.data;
};

export const getSubdomainTakeoverEvidence = async (params) => {
  const res = await axios.get(`${API_URL}/v2/subdomain-takeover`, { params });
  return res.data;
};

export const getDnsSecurityHosts = async (params) => {
  const res = await axios.get(`${API_URL}/v2/dns-security/hosts`, { params });
  return res.data;
};

export const getCertificateHosts = async (params) => {
  const res = await axios.get(`${API_URL}/v2/certificates/hosts`, { params });
  return res.data;
};

export const getSensitivePortHosts = async (params) => {
  const res = await axios.get(`${API_URL}/v2/sensitive-ports/hosts`, { params });
  return res.data;
};

export const getDnsSecurityDomainEvidence = async (domainId, scanId) => {
  const res = await axios.get(`${API_URL}/v2/dns-security/domains/${encodeURIComponent(domainId)}`, { params: { scan_id: scanId } });
  return res.data;
};

export const getNamingAssetExposure = async () => {
  const res = await axios.get(`${API_URL}/naming-asset-exposure`);
  return res.data;
};

export const getV2ReviewIndicators = async () => {
  const res = await axios.get(`${API_URL}/v2/review-indicators`);
  return res.data;
};

export const getRiskHistorySummary = async () => {
  const res = await axios.get(`${API_URL}/v2/risk-history/summary`);
  return res.data;
};

export const getRiskHistoryAssets = async (params) => {
  const res = await axios.get(`${API_URL}/v2/risk-history/assets`, { params });
  return res.data;
};

export const getRiskyDomains = async () => {
  const res = await axios.get(`${API_URL}/risky-domains`);
  return res.data;
};

export const getFindings = async () => {
  const res = await axios.get(`${API_URL}/findings`);
  return res.data;
};

export const getSensitiveExposure = async () => {
  const res = await axios.get(`${API_URL}/sensitive-exposure`);
  return res.data;
};

export const getExposureSummary = async () => {
  const res = await axios.get(`${API_URL}/exposure-summary`);
  return res.data;
};

export const getDiscoverySources = async () => {
  const res = await axios.get(`${API_URL}/metrics/discovery-sources`);
  return res.data;
};

export const getSummary = async () => {
  const res = await axios.get(`${API_URL}/summary`);
  return res.data;
};

export const getSources = async () => {
  const res = await axios.get(`${API_URL}/sources`);
  return res.data;
};

export const getHttpStatus = async () => {
  const res = await axios.get(`${API_URL}/http-status`);
  return res.data;
};

export const getAssetGrowth = async () => {
  const res = await axios.get(`${API_URL}/asset-growth`);
  return res.data;
};

export const getSeeds = async () => {
  const res = await axios.get(`${API_URL}/seeds`);
  return res.data;
};

export const getCertExpiry = async (params) => {
  const res = await axios.get(`${API_URL}/cert-expiry`, { params });
  return res.data;
};

export async function getRiskLeaderboard() {
  const res = await fetch("http://127.0.0.1:8555/risk-leaderboard");
  return res.json();
}
export async function getProviders() {
  const res = await fetch("http://localhost:8555/providers");
  return res.json();
}

export async function getTech() {
  const res = await fetch("http://localhost:8555/tech");
  return res.json();
}

export async function getExposureDrift() {
  const res = await fetch("http://localhost:8555/exposure-drift");
  return res.json();
}

export const getInvestigationAssets = async (page, limit, provider, extra = {}) => {
  const res = await axios.get(
    "http://localhost:8555/investigation-assets",
    { params: { page, limit, provider: provider || "", ...extra } },
  );
  return res.data;
};
