import requests

TOKEN = "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"

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
