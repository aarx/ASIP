import os

# ==========================
# Database
# ==========================

DB_HOST = os.getenv("DB_HOST", "db")
DB_NAME = os.getenv("DB_NAME", "asm_db")
DB_USER = os.getenv("DB_USER", "asm")
DB_PASSWORD = os.getenv("DB_PASSWORD")

# ==========================
# LLM
# ==========================

LLM_URL = os.getenv(
    "LLM_URL",
    "http://localhost:11434/api/generate"
)

LLM_MODEL = os.getenv(
    "LLM_MODEL",
    "gemma3:4b"
)

# ==========================
# API Keys
# ==========================

CERTSPOTTER_API_KEY = os.getenv(
    "CERTSPOTTER_API_KEY",
    ""
)

GITHUB_TOKEN = os.getenv(
    "GITHUB_TOKEN",
    ""
)

CENSYS_API_ID = os.getenv(
    "CENSYS_API_ID",
    ""
)

CENSYS_API_SECRET = os.getenv(
    "CENSYS_API_SECRET",
    ""
)
