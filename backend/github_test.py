import requests
import os

TOKEN = os.getenv("GITHUB_TOKEN")
if not TOKEN:
    raise SystemExit("GITHUB_TOKEN is required")

headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json"
}

url = "https://api.github.com/search/code"

params = {
    "q": "\".metlife.com\""
}

r = requests.get(
    url,
    headers=headers,
    params=params
)

print("Status:", r.status_code)

data = r.json()

print("Total Results:", data.get("total_count"))

for item in data.get("items", [])[:20]:

    print(item["repository"]["full_name"])
    print(item["html_url"])
    print("-" * 50)
