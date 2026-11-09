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
