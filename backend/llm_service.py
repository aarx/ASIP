import requests
from config import LLM_MODEL, LLM_URL

MODEL = LLM_MODEL

print("=" * 60)
print(f"[LLM] Using model: {MODEL}")
print(f"[LLM] Endpoint: {LLM_URL}")
print("=" * 60)

def ask_llm(prompt):

    try:
        response = requests.post(
            LLM_URL,
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False
            },
            timeout=120
        )

        response.raise_for_status()

        return response.json()["response"]

    except Exception as e:
        print(f"[LLM ERROR] {e}")
        return f"LLM request failed: {e}"
