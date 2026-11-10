export function isMissingEvidence(value) {
  if (value === null || value === undefined) return true;
  if (typeof value === "number") return Number.isNaN(value);
  if (typeof value !== "string") return false;
  const normalized = value.trim().toLowerCase();
  return normalized === "" || normalized === "nan" || normalized === "null" || normalized === "undefined";
}

export function displayEvidence(value, fallback = "—") {
  return isMissingEvidence(value) ? fallback : String(value);
}

export function displayAssetClass(value) {
  return value === "CANDIDATE" ? "Needs Verification" : value;
}

export function isUsableHttpStatus(value) {
  if (value === null || value === undefined || value === "") return false;
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric > 0;
}

export function displayHttpStatus(observationStatus, value) {
  if (isUsableHttpStatus(value)) return value;
  switch (String(observationStatus || "UNKNOWN").toUpperCase()) {
    case "NO_RESPONSE":
      return "No HTTP response";
    case "FAILED":
      return "HTTP status unavailable";
    default:
      return "No HTTP status recorded";
  }
}
