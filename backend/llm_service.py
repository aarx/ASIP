import os
import requests

# ==========================================
# LLM CONFIGURATION
#
# Current:
# Windows Host running Ollama
#
# Future:
# localhost
# docker service
# remote Ollama
# vLLM
#
# CHANGE ONLY THESE VARIABLES
# ==========================================

LLM_URL = os.getenv(
    "LLM_URL",
    "http://192.168.29.222:11434/api/generate"
)

MODEL = os.getenv(
    "LLM_MODEL",
    "gemma3:4b"
)

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
