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

export const exportV2AssetsCsv = async (params) => {
  return axios.get(`${API_URL}/v2/assets/export`, {
    params,
    responseType: "blob",
  });
};

export const getV2AssetDetail = async (domain) => {
  const res = await axios.get(`${API_URL}/v2/assets/${encodeURIComponent(domain)}`);
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

export const getV2Scans = async (limit = 100) => {
  const res = await axios.get(`${API_URL}/v2/scans`, { params: { limit } });
  return res.data;
};

export const getPhpRceCheck = async (params) => {
  const res = await axios.get(`${API_URL}/v2/adhoc/checks/php-rce`, { params });
  return res.data;
};

export const getV2BrandAssets = async (params) => {
  const res = await axios.get(`${API_URL}/v2/brand-assets`, { params });
  return res.data;
};

export const getV2ReviewIndicators = async () => {
  const res = await axios.get(`${API_URL}/v2/review-indicators`);
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

export const getInvestigationAssets = async (page, limit, provider) => {
  const res = await axios.get(
    `http://localhost:8555/investigation-assets?page=${page}&limit=${limit}&provider=${provider || ""}`
  );
  return res.data;
};
