import requests
import sys
import re
import json

BASE_URL = "http://asm_mcp:8000/tools"


def route_query(query: str):
    q = query.lower()
    print("DEBUG:", q)

    # 🔥 INVESTIGATION FIRST (highest priority)
    if "investigate" in q or "how" in q:
        print("HIT INVESTIGATION BLOCK")

        match = re.search(
            r"(dangling_dns|suspicious_dns|open_port|sensitive_port|http_exposed|ssl|takeover)",
            q
        )

        if match:
            finding = match.group(0)

            if finding == "takeover":
                finding = "dangling_dns"

            return f"{BASE_URL}/investigation-guide?finding={finding}"

        return {
            "error": "Please specify a finding (dangling_dns, open_port, ssl_issue)"
        }

    # -------------------------
    # OTHER ROUTES
    # -------------------------

    elif "summary" in q:
        return f"{BASE_URL}/summary"

    elif "shadow" in q:
        return f"{BASE_URL}/shadow-assets"

    elif "finding" in q:
        return f"{BASE_URL}/findings"

    elif "domain" in q:
        match = re.search(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", query)
        if match:
            return f"{BASE_URL}/domain?domain={match.group(0).lower()}"

    elif "risk" in q:
        return f"{BASE_URL}/high-risk"

    elif "priority" in q or "unknown domains" in q:
        return f"{BASE_URL}/priority-targets"

    return None
        

def pretty_print(data):
    if isinstance(data, list):
        for i, item in enumerate(data[:10], 1):
            if isinstance(item, dict):
                print(f"{i}. " + " | ".join(f"{k}={v}" for k, v in item.items()))
            else:
                print(f"{i}. {item}")

    elif isinstance(data, dict):
        for k, v in data.items():
            print(f"{k}: {v}")

    else:
        print(data)


def main():
    print("\n🧠 ASM MCP Assistant (type 'exit' to quit)\n")

    while True:
        query = input(">> ")

        if query.lower() in ["exit", "quit"]:
            print("👋 Exiting...")
            break

        url = route_query(query)

        if not url:
            print("❌ Didn't understand that\n")
            continue

        print(f"➡️ {url}")

        try:
            if isinstance(url, dict):
                print(url)
                continue
            
            res = requests.get(url)
            data = res.json()

            
            pretty_print(data)
            print()

        except Exception as e:
            print("❌ Error:", e)


if __name__ == "__main__":
    main()
