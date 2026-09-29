import requests
import os

TOKEN = os.getenv("GITHUB_TOKEN")
if not TOKEN:
    raise SystemExit("GITHUB_TOKEN is required")

headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json"
}

r = requests.get(
    "https://api.github.com/rate_limit",
    headers=headers
)

print(r.status_code)
print(r.json())
