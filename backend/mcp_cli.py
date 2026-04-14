import requests
import sys

BASE_URL = "http://localhost:8666/tools"


def route_query(query: str):
    q = query.lower()

    # -------------------------
    # SIMPLE ROUTER
    # -------------------------

    if "summary" in q:
        return f"{BASE_URL}/summary"

    elif "shadow" in q:
        return f"{BASE_URL}/shadow-assets"

    elif "finding" in q or "takeover" in q:
        return f"{BASE_URL}/findings"

    elif "domain" in q:
        parts = q.split()
        for p in parts:
            if "." in p:
                return f"{BASE_URL}/domain?domain={p}"
                
    elif "risk" in q:
        return f"{BASE_URL}/shadow-assets"
    
    elif "top" in q:
        return f"{BASE_URL}/findings"
        
    elif "high risk" in q:
        return f"{BASE_URL}/high-risk"

    return None

def pretty_print(data):
    if isinstance(data, list):
        for i, item in enumerate(data[:10], 1):
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
            res = requests.get(url)
            data = res.json()

            import json
            pretty_print(data)
            print()

        except Exception as e:
            print("❌ Error:", e)


if __name__ == "__main__":
    main()
