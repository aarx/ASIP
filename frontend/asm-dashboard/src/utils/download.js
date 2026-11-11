function safeFilename(value, fallback) {
  const cleaned = String(value || "")
    .replace(/[\\/:*?"<>|\r\n]/g, "_")
    .trim();
  return cleaned || fallback;
}

function responseFilename(response, fallback) {
  const header = response?.headers?.["content-disposition"]
    || response?.headers?.["Content-Disposition"]
    || "";
  const match = header.match(/filename\*=UTF-8''([^;]+)|filename="?([^";]+)"?/i);
  let filename = match?.[1] || match?.[2] || "";
  if (match?.[1]) {
    try { filename = decodeURIComponent(filename); } catch { /* use the encoded value safely */ }
  }
  return safeFilename(filename, fallback);
}

export function downloadBlobResponse(response, fallbackFilename) {
  const url = window.URL.createObjectURL(response.data);
  const link = document.createElement("a");
  link.href = url;
  link.download = responseFilename(response, fallbackFilename);
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
}

export function downloadErrorKind(error) {
  const status = error?.response?.status;
  if (status === 404) return "not-found";
  if (status === 409) return "unavailable";
  return "error";
}
