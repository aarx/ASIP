# grep_test.py

import requests

query = "abc.com"

url = f"https://grep.app/api/search?q={query}"

r = requests.get(
    url,
    timeout=20,
    headers={
        "User-Agent": "Mozilla/5.0"
    }
)

print("Status:", r.status_code)
print(r.text[:1000])
