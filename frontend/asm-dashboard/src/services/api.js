import axios from "axios";

const API_URL = "http://localhost:8555";

export const getV2Overview = async () => {
  const res = await axios.get(`${API_URL}/v2/overview`);
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
