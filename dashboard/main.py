from fastapi import FastAPI
from loader import get_dataframe
from stats import summary_stats, http_status_stats, source_stats, domains_per_seed
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="ShadowRecon Attack Surface Management API")

@app.get("/")
def home():
    return {"message": "ShadowRecon Attack Surface Management API running"}

@app.get("/summary")
def summary():
    return summary_stats()

@app.get("/http-status")
def http_status():
    df = get_dataframe()
    return http_status_stats()

@app.get("/sources")
def sources():
    return source_stats()

@app.get("/seeds")
def seeds():
    return domains_per_seed()

@app.get("/assets")
def assets():

    df = get_dataframe()

    return df.to_dict(orient="records")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
