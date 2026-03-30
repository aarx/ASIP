import axios from "axios";

const API_URL = "http://localhost:8000";

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
  const res = await fetch("http://127.0.0.1:8000/risk-leaderboard");
  return res.json();
}
export async function getProviders() {
  const res = await fetch("http://localhost:8000/providers");
  return res.json();
}

export async function getTech() {
  const res = await fetch("http://localhost:8000/tech");
  return res.json();
}

export async function getExposureDrift() {
  const res = await fetch("http://localhost:8000/exposure-drift");
  return res.json();
}

export async function getInvestigationAssets(page = 1, limit = 20) {
  const res = await fetch(
    `http://localhost:8000/investigation-assets?page=${page}&limit=${limit}`
  );

  return res.json();
}
