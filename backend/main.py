from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging
import os
from fastapi import APIRouter
from fastapi.responses import StreamingResponse
import csv
import io
import requests
import re
from datetime import datetime
from llm_service import ask_llm
from urllib.parse import urlparse
from db import get_conn

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/app.log"),
        logging.StreamHandler()
    ]
)

app = FastAPI(title="External Attack Surface API")

@app.get("/")
def home():
    return {"message": "ASM Dashboard API running"}

@app.get("/summary")
def summary():

    conn = get_conn()
    cur = conn.cursor()

    # total unique domains ever discovered
    cur.execute("SELECT COUNT(*) FROM domains")
    total_domains = cur.fetchone()[0]

    # latest scan
    cur.execute("SELECT MAX(scan_id) FROM domain_states")
    latest_scan = cur.fetchone()[0]

    # domains resolving in latest scan
    cur.execute("""
        SELECT COUNT(*)
        FROM domain_states
        WHERE scan_id=%s
        AND has_ip = TRUE
    """, (latest_scan,))
    live_domains = cur.fetchone()[0]

    # http live
    cur.execute("""
        SELECT COUNT(*)
        FROM domain_states
        WHERE scan_id=%s
        AND http_live = TRUE
    """, (latest_scan,))
    http_live = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*) 
        FROM domain_findings 
        WHERE scan_id = %s
    """, (latest_scan,))
    
    findings_count = cur.fetchone()[0]

    
    # Potential Shadow Assets
    cur.execute("""
        SELECT COUNT(*)
        FROM domain_states ds
        JOIN domains d ON d.id = ds.domain_id
        WHERE ds.scan_id = %s
        AND ds.has_ip = TRUE
        AND d.is_known = FALSE
    """, (latest_scan,))
    shadow_assets = cur.fetchone()[0]
    
    # Non-Web Assets
    cur.execute("""
        SELECT COUNT(*)
        FROM domain_states
        WHERE scan_id = %s
        AND has_ip = TRUE
        AND http_live = FALSE
    """, (latest_scan,))
    non_web_assets = cur.fetchone()[0]
    
    # KNOWN DOMAINS COUNT (LATEST SCAN)
    cur.execute("""
        SELECT COUNT(DISTINCT d.id)
        FROM domain_states ds
        JOIN domains d ON d.id = ds.domain_id
        WHERE ds.scan_id = %s
        AND ds.has_ip = TRUE
        AND d.is_known = TRUE
    """, (latest_scan,))
    
    known_domains = cur.fetchone()[0]
    
    # Needs Validation Domains
    cur.execute("""
        SELECT COUNT(*)
        FROM domains
        WHERE scannable = False
    """)
    needs_validation = cur.fetchone()[0]
    
 
    conn.close()
    
    return {
        "total_domains": total_domains,
        "live_domains": live_domains,
        "known_domains": known_domains,
        "new_domains": http_live,
        "findings": findings_count,
        "shadow_assets": shadow_assets,
        "non_web_assets": non_web_assets,
        "unverified_domains": needs_validation
    }
    

@app.get("/http-status")
def http_status():

    conn = get_conn()
    cur = conn.cursor()

    # get latest scan
    cur.execute("SELECT MAX(id) FROM scans")
    latest = cur.fetchone()[0]

    cur.execute("""
    SELECT
        CASE
            WHEN ds.http_status BETWEEN 200 AND 299 THEN '2xx'
            WHEN ds.http_status BETWEEN 300 AND 399 THEN '3xx'
            WHEN ds.http_status BETWEEN 400 AND 499 THEN '4xx'
            WHEN ds.http_status BETWEEN 500 AND 599 THEN '5xx'
            ELSE 'no_response'
        END AS status_group,
        COUNT(DISTINCT ds.domain_id)
    FROM domain_states ds
    WHERE ds.scan_id = %s
    GROUP BY status_group
    """, (latest,))   # ✅ FIXED

    rows = cur.fetchall()   # ✅ FIXED

    result = {
        "2xx": 0,
        "3xx": 0,
        "4xx": 0,
        "5xx": 0,
        "no_response": 0
    }

    for status, count in rows:
        result[status] = count

    conn.close()

    return result

@app.get("/sources")
def sources():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT MAX(id) FROM scans")
    latest = cur.fetchone()[0]

    cur.execute("""
        SELECT seed, COUNT(*)
        FROM scan_results
        WHERE scan_id = %s
        GROUP BY seed
        ORDER BY COUNT(*) DESC
    """, (latest,))

    rows = cur.fetchall()

    conn.close()

    return [
        {"source": r[0], "count": r[1]}
        for r in rows
    ]

@app.get("/seeds")
def seeds():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT MAX(id) FROM scans")
    latest = cur.fetchone()[0]

    cur.execute("""
        SELECT seed, COUNT(domain_id)
        FROM scan_results
        WHERE scan_id = %s
        GROUP BY seed
        ORDER BY COUNT(domain_id) DESC
    """, (latest,))

    rows = cur.fetchall()

    conn.close()

    return [
        {"seed": r[0], "domains_discovered": r[1]}
        for r in rows
    ]

@app.get("/assets")
def assets():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT MAX(id) FROM scans")
    latest = cur.fetchone()[0]

    cur.execute("""
        SELECT 
            d.domain,
            sr.seed,
            ds.has_ip,
            ds.http_live
        FROM domains d
        JOIN scan_results sr
        ON d.id = sr.domain_id
        JOIN domain_states ds
        ON ds.domain_id = d.id
        AND ds.scan_id = sr.scan_id
        WHERE sr.scan_id = %s
        LIMIT 5000
    """, (latest,))

    rows = cur.fetchall()

    conn.close()

    return [
        {
            "domain": r[0],
            "seed": r[1],
            "has_ip": r[2],
            "http_live": r[3]
        }
        for r in rows
    ]
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/new-domains")
def new_domains():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT MAX(id) FROM scans")
    row = cur.fetchone()

    if not row or row[0] is None:
        conn.close()
        return {"latest_scan": None, "new_domains": []}

    latest_scan = row[0]

    cur.execute("""
        SELECT d.domain
        FROM domains d
        JOIN scan_domains sd
        ON d.id = sd.domain_id
        WHERE sd.scan_id = %s
        ORDER BY d.first_seen DESC
        LIMIT 100
    """, (latest_scan,))

    rows = cur.fetchall()

    conn.close()

    return {
        "latest_scan": latest_scan,
        "new_domains": [r[0] for r in rows]
    }

@app.get("/disappeared-domains")
def disappeared():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT MAX(id) FROM scans")
    latest = cur.fetchone()[0]

    previous = latest - 1

    cur.execute("""
        SELECT d.domain
        FROM domains d
        JOIN scan_results sr
        ON d.id = sr.domain_id
        WHERE sr.scan_id = %s
        AND d.id NOT IN (
            SELECT domain_id
            FROM scan_results
            WHERE scan_id = %s
        )
        LIMIT 100
    """, (previous, latest))

    rows = cur.fetchall()

    conn.close()

    return {
        "from_scan": previous,
        "to_scan": latest,
        "disappeared_domains": [r[0] for r in rows]
    }

@app.get("/new-domains-delta")
def new_domains_delta():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT MAX(id) FROM scans")
    latest = cur.fetchone()[0]

    previous = latest - 1

    cur.execute("""
        SELECT d.domain
        FROM domains d
        JOIN scan_results sr
        ON d.id = sr.domain_id
        WHERE sr.scan_id = %s
        AND d.id NOT IN (
            SELECT domain_id
            FROM scan_results
            WHERE scan_id = %s
        )
        LIMIT 100
    """, (latest, previous))

    rows = cur.fetchall()

    conn.close()

    return {
        "from_scan": previous,
        "to_scan": latest,
        "new_domains": [r[0] for r in rows]
    }
@app.get("/exposure-summary")
def exposure_summary():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT MAX(id) FROM scans")
    latest = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*)
        FROM domain_states
        WHERE scan_id = %s
    """, (latest,))
    total = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*)
        FROM domain_states
        WHERE scan_id = %s
        AND has_ip = TRUE
    """, (latest,))
    resolving = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*)
        FROM domain_states
        WHERE scan_id = %s
        AND http_live = TRUE
    """, (latest,))
    http_live = cur.fetchone()[0]

    conn.close()

    return {
        "scan_id": latest,
        "total_domains": total,
        "resolving_domains": resolving,
        "http_responding_domains": http_live
    }
    
@app.get("/newly-live")
def newly_live():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT MAX(id) FROM scans")
    latest = cur.fetchone()[0]
    previous = latest - 1

    cur.execute("""
        SELECT d.domain
        FROM domain_states s1
        JOIN domain_states s2
        ON s1.domain_id = s2.domain_id
        JOIN domains d
        ON d.id = s1.domain_id
        WHERE s1.scan_id = %s
        AND s2.scan_id = %s
        AND s1.has_ip = FALSE
        AND s2.has_ip = TRUE
        LIMIT 100
    """, (previous, latest))

    rows = cur.fetchall()

    conn.close()

    return {
        "from_scan": previous,
        "to_scan": latest,
        "newly_live_domains": [r[0] for r in rows]
    }

@app.get("/newly-dead")
def newly_dead():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT MAX(id) FROM scans")
    latest = cur.fetchone()[0]
    previous = latest - 1

    cur.execute("""
        SELECT d.domain
        FROM domain_states s1
        JOIN domain_states s2
        ON s1.domain_id = s2.domain_id
        JOIN domains d
        ON d.id = s1.domain_id
        WHERE s1.scan_id = %s
        AND s2.scan_id = %s
        AND s1.has_ip = TRUE
        AND s2.has_ip = FALSE
        LIMIT 100
    """, (previous, latest))

    rows = cur.fetchall()

    conn.close()

    return {
        "from_scan": previous,
        "to_scan": latest,
        "newly_dead_domains": [r[0] for r in rows]
    }

@app.get("/exposure-trend")
def exposure_trend():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            scan_id,
            COUNT(*) AS total,
            SUM(CASE WHEN has_ip THEN 1 ELSE 0 END) AS resolving,
            SUM(CASE WHEN http_live THEN 1 ELSE 0 END) AS http_live
        FROM domain_states
        GROUP BY scan_id
        ORDER BY scan_id
    """)

    rows = cur.fetchall()

    conn.close()

    return [
        {
            "scan_id": r[0],
            "total": r[1],
            "resolving": r[2],
            "http_live": r[3]
        }
        for r in rows
    ]

@app.get("/volatile-domains")
def volatile_domains():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        WITH ordered AS (
            SELECT
                domain_id,
                scan_id,
                has_ip,
                LAG(has_ip) OVER (
                    PARTITION BY domain_id
                    ORDER BY scan_id
                ) AS prev_state
            FROM domain_states
        )
        SELECT
            d.domain,
            COUNT(*) AS volatility_score
        FROM ordered o
        JOIN domains d
        ON d.id = o.domain_id
        WHERE prev_state IS NOT NULL
        AND prev_state != has_ip
        GROUP BY d.domain
        HAVING COUNT(*) > 0
        ORDER BY volatility_score DESC
        LIMIT 100
    """)

    rows = cur.fetchall()

    conn.close()

    return [
        {
            "domain": r[0],
            "volatility_score": r[1]
        }
        for r in rows
    ]

@app.get("/risky-domains")
def risky_domains():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT MAX(id) FROM scans")
    latest_scan = cur.fetchone()[0]

    cur.execute("""
        WITH volatility AS (
            SELECT
                domain_id,
                COUNT(*) AS flips
            FROM (
                SELECT
                    domain_id,
                    has_ip,
                    LAG(has_ip) OVER (
                        PARTITION BY domain_id
                        ORDER BY scan_id
                    ) AS prev_state
                FROM domain_states
            ) t
            WHERE prev_state IS NOT NULL
            AND prev_state != has_ip
            GROUP BY domain_id
        ),
        latest_state AS (
            SELECT *
            FROM domain_states
            WHERE scan_id = %s
        )
        SELECT
            d.domain,
            (
                CASE
                    WHEN d.first_seen_scan = %s THEN 3
                    ELSE 0
                END
                +
                CASE
                    WHEN ls.http_live = TRUE THEN 2
                    WHEN ls.has_ip = TRUE THEN 1
                    ELSE 0
                END
                +
                CASE
                    WHEN v.flips >= 2 THEN 4
                    ELSE 0
                END
            ) AS risk_score
        FROM domains d
        JOIN latest_state ls
        ON d.id = ls.domain_id
        LEFT JOIN volatility v
        ON d.id = v.domain_id
        ORDER BY risk_score DESC
        LIMIT 100
    """, (latest_scan, latest_scan))

    rows = cur.fetchall()

    conn.close()

    return [
        {
            "domain": r[0],
            "risk_score": r[1]
        }
        for r in rows
    ]
@app.get("/sensitive-exposure")
def sensitive_exposure():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT MAX(scan_id) FROM domain_ports")
    scan_id = cur.fetchone()[0]

    cur.execute("""
        SELECT 
            d.domain,
            dp.port,
            sp.risk,
            COALESCE(sp.description, 'unknown') as description
        FROM domain_ports dp
        JOIN sensitive_ports sp
            ON dp.port = sp.port
        JOIN domains d
            ON dp.domain_id = d.id
        WHERE dp.scan_id = %s
        ORDER BY sp.risk DESC
        LIMIT 20
    """, (scan_id,))

    rows = cur.fetchall()

    conn.close()

    return [
        {
            "domain": r[0],
            "port": r[1],
            "risk": r[2],
            "service": r[3]
        }
        for r in rows
    ]

@app.get("/hygiene-score")
def hygiene_score():

    conn = get_conn()
    cur = conn.cursor()

    # latest scan with domain_states
    cur.execute("SELECT MAX(scan_id) FROM domain_states")
    scan_id = cur.fetchone()[0]

    cur.execute("""

        SELECT
            d.id,
            d.domain,
            ds.has_ip,
            ds.http_live,
            COUNT(dp.port) AS port_count,
            COUNT(sp.port) AS sensitive_ports

        FROM domains d

        JOIN domain_states ds
            ON d.id = ds.domain_id

        LEFT JOIN domain_ports dp
            ON d.id = dp.domain_id
            AND dp.scan_id = ds.scan_id

        LEFT JOIN sensitive_ports sp
            ON dp.port = sp.port

        WHERE ds.scan_id = %s

        GROUP BY d.id, d.domain, ds.has_ip, ds.http_live

    """, (scan_id,))

    rows = cur.fetchall()

    conn.close()

    results = []

    for r in rows:

        domain = r[1]
        has_ip = r[2]
        http_live = r[3]
        port_count = r[4]
        sensitive_ports = r[5]

        score = 5

        if has_ip:
            score += 2

        if http_live:
            score += 2

        if sensitive_ports > 0:
            score -= 3

        if port_count > 3:
            score -= 1

        if score >= 7:
            status = "Healthy"
        elif score >= 4:
            status = "Medium"
        else:
            status = "Poor"

        results.append({
            "domain": domain,
            "score": score,
            "status": status,
            "ports": port_count,
            "sensitive_ports": sensitive_ports
        })

    return results
@app.get("/provider-clusters")
def provider_clusters():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT MAX(scan_id) FROM domain_provider")
    scan_id = cur.fetchone()[0]

    cur.execute("""
        SELECT 
            CASE 
                WHEN provider IS NULL OR provider = '' 
                THEN 'Unknown'
                ELSE provider
            END AS provider,
            COUNT(*)
        FROM domain_provider
        WHERE scan_id = %s
        GROUP BY provider
        ORDER BY COUNT(*) DESC
    """, (scan_id,))

    rows = cur.fetchall()

    conn.close()

    return [
        {
            "provider": r[0],
            "count": r[1]
        }
        for r in rows
    ]
@app.get("/shadow-assets")
def shadow_assets():

    conn = get_conn()
    cur = conn.cursor()

    # latest scan ids
    cur.execute("SELECT MAX(scan_id) FROM domain_states")
    state_scan = cur.fetchone()[0]

    cur.execute("""
        SELECT
            d.domain,
            ds.has_ip,
            ds.http_live,
            COUNT(dp2.port) as ports,
            COUNT(sp.port) as sensitive,
            dp.provider
        FROM domains d
    
        JOIN domain_states ds
            ON d.id = ds.domain_id
    
        LEFT JOIN domain_ports dp2
            ON d.id = dp2.domain_id
            AND dp2.scan_id = ds.scan_id
    
        LEFT JOIN sensitive_ports sp
            ON dp2.port = sp.port
    
        LEFT JOIN domain_provider dp
            ON d.id = dp.domain_id
            AND dp.scan_id = ds.scan_id
    
        WHERE ds.scan_id = %s
    
        GROUP BY d.domain, ds.has_ip, ds.http_live, dp.provider
    """, (state_scan,))

    rows = cur.fetchall()

    conn.close()

    results = []
    
    for r in rows:
    
        domain, has_ip, http_live, ports, sensitive, provider = r
    
        score = 0
        reasons = []
    
        if has_ip and not http_live:
            score += 2
            reasons.append("resolves_no_http")
    
        if sensitive > 0:
            score += 3
            reasons.append("sensitive_ports")
    
        if ports > 3:
            score += 1
            reasons.append("many_ports")
    
        if provider and any(x in provider.lower() for x in ["amazon", "aws", "azure", "gcp"]):
            score += 1
            reasons.append("cloud")
    
        # 🎯 Only keep meaningful ones
        if score >= 3:
            results.append({
                "domain": domain,
                "score": score,
                "reasons": reasons
            })
    
    # sort + limit
    return sorted(results, key=lambda x: x["score"], reverse=True)[:50]

    return sorted(results, key=lambda x: x["score"], reverse=True)

@app.get("/risk-leaderboard")
def risk_leaderboard():

    conn = get_conn()
    cur = conn.cursor()

    # latest scan
    cur.execute("SELECT MAX(id) FROM scans")
    scan_id = cur.fetchone()[0]

    query = """
    SELECT d.domain, dr.risk_score, dr.reasons
    FROM domain_risk dr
    JOIN domains d ON dr.domain_id = d.id
    JOIN domain_states ds ON d.id = ds.domain_id
    WHERE ds.has_ip = TRUE
    ORDER BY dr.risk_score DESC
    LIMIT 50;
    """

    cur.execute(query, (scan_id,))
    rows = cur.fetchall()

    conn.close()

    result = []

    for domain, score, reasons in rows:

        if isinstance(reasons, str):
            reasons = reasons.split(",")

        result.append({
            "domain": domain,
            "risk": score,
            "reasons": reasons
        })

    return result    


@app.get("/domain/{domain_name}")
def domain_detail(domain_name: str):

    conn = get_conn()
    cur = conn.cursor()

    # latest scan id
    cur.execute("SELECT MAX(id) FROM scans")
    scan_id = cur.fetchone()[0]

    if not scan_id:
        conn.close()
        return {"error": "no scans yet"}

    # domain basic
    cur.execute("""
        SELECT id, first_seen_scan, last_seen_scan, is_known
        FROM domains
        WHERE domain=%s
    """, (domain_name,))
    
    row = cur.fetchone()

    if not row:
        conn.close()
        return {"error": "domain not found"}

    domain_id, first_seen, last_seen, is_known = row

    # state
    cur.execute("""
        SELECT ip, has_ip, http_live, http_status
        FROM domain_states
        WHERE domain_id=%s
        AND scan_id=%s
    """, (domain_id, scan_id))

    state = cur.fetchone()

    # ports
    cur.execute("""
        SELECT port
        FROM domain_ports
        WHERE domain_id=%s
        AND scan_id=%s
    """, (domain_id, scan_id))

    ports = [r[0] for r in cur.fetchall()]

    # provider
    cur.execute("""
        SELECT provider
        FROM domain_provider
        WHERE domain_id=%s
        AND scan_id=%s
    """, (domain_id, scan_id))

    prov = cur.fetchone()

    # ASN
    cur.execute("""
        SELECT asn, org
        FROM domain_asn
        WHERE domain_id=%s
        AND scan_id=%s
    """, (domain_id, scan_id))

    asn = cur.fetchone()

    # tech
    cur.execute("""
        SELECT tech
        FROM domain_tech
        WHERE domain_id=%s
        AND scan_id=%s
    """, (domain_id, scan_id))

    tech = cur.fetchone()

    conn.close()

    return {
        "domain": domain_name,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "is_known": is_known,

        "ip": state[0] if state else None,
        "has_ip": state[1] if state else False,
        "http_live": state[2] if state else False,
        "http_status": state[3] if state else 0,

        "ports": ports,
        "provider": prov[0] if prov else "Unknown",
        "asn": asn[0] if asn else "Unknown",
        "org": asn[1] if asn else "Unknown",
        "tech": tech[0] if tech else "Unknown"
    }
    
    
@app.get("/domain/{domain_name}/analysis")
def domain_analysis(domain_name: str):

    domain_data = domain_detail(domain_name)

    if "error" in domain_data:
        return domain_data

    prompt = f"""
You are an Attack Surface Management analyst.

Analyze the following asset.

Domain: {domain_data.get("domain")}
IP: {domain_data.get("ip")}
Provider: {domain_data.get("provider")}
ASN: {domain_data.get("asn")}
Organization: {domain_data.get("org")}
Ports: {domain_data.get("ports")}
Technology: {domain_data.get("tech")}

Provide:

1. Executive Summary

2. Key Risks

3. Recommended Actions

Keep the response concise and practical.
"""

    analysis = ask_llm(prompt)

    return {
        "domain": domain_name,
        "analysis": analysis
    }

@app.get("/providers")
def providers():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT dp.provider, COUNT(*)
        FROM domain_provider dp
        JOIN domain_states ds 
          ON dp.domain_id = ds.domain_id
        WHERE ds.has_ip = TRUE
        GROUP BY dp.provider
        ORDER BY COUNT(*) DESC
    """)

    rows = cur.fetchall()

    conn.close()

    return [
        {"provider": r[0], "count": r[1]}
        for r in rows
    ]



@app.get("/tech")
def tech():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT dt.tech, COUNT(*)
        FROM domain_tech dt
        JOIN domain_states ds 
          ON dt.domain_id = ds.domain_id
        WHERE ds.has_ip = TRUE
        GROUP BY dt.tech
        ORDER BY COUNT(*) DESC;
    """)

    rows = cur.fetchall()

    conn.close()

    return [
        {"tech": r[0], "count": r[1]}
        for r in rows
    ]

@app.get("/exposure-drift")
def exposure_drift():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT MAX(id) FROM scans")
    latest = cur.fetchone()[0]

    cur.execute("SELECT MAX(id) FROM scans WHERE id < %s", (latest,))
    prev = cur.fetchone()[0]

    if not prev:
        return {"new":0,"disappeared":0}

    # new domains
    cur.execute("""
        SELECT COUNT(*)
        FROM domain_states ds
        WHERE ds.scan_id = %s
        AND ds.domain_id NOT IN (
            SELECT domain_id
            FROM domain_states
            WHERE scan_id = %s
        )
    """,(latest, prev))

    new_domains = cur.fetchone()[0]

    # disappeared domains
    cur.execute("""
        SELECT COUNT(*)
        FROM domain_states ds
        WHERE ds.scan_id = %s
        AND ds.domain_id NOT IN (
            SELECT domain_id
            FROM domain_states
            WHERE scan_id = %s
        )
    """,(prev, latest))

    disappeared = cur.fetchone()[0]

    conn.close()

    return {
        "new": new_domains,
        "disappeared": disappeared,
        "latest_scan": latest,
        "previous_scan": prev
    }

@app.get("/targets")
def export_targets():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT 
            d.domain,
            ds.ip,
            ds.http_live,
            COUNT(dp.port) as open_ports,
            COALESCE(da.asn, 'unknown'),
            COALESCE(pr.provider, 'unknown')
        FROM domains d
        JOIN domain_states ds 
            ON d.id = ds.domain_id
        LEFT JOIN domain_ports dp 
            ON d.id = dp.domain_id
        LEFT JOIN domain_asn da 
            ON d.id = da.domain_id
        LEFT JOIN domain_provider pr 
            ON d.id = pr.domain_id
        WHERE ds.scan_id = (SELECT MAX(id) FROM scans)
        GROUP BY d.domain, ds.ip, ds.http_live, da.asn, pr.provider
        ORDER BY open_ports DESC
        LIMIT 500
    """)

    rows = cur.fetchall()

    conn.close()

    return [
        {
            "domain": r[0],
            "ip": r[1],
            "http_live": r[2],
            "open_ports": r[3],
            "asn": r[4],
            "provider": r[5]
        }
        for r in rows
    ]

from fastapi.responses import StreamingResponse
import io
import pandas as pd


@app.get("/export")
def export_enriched_csv():

    import pandas as pd
    import io
    from datetime import datetime
    from fastapi.responses import StreamingResponse

    conn = get_conn()
    cur = conn.cursor()

    # latest scan
    cur.execute("SELECT MAX(id) FROM scans")
    scan_id = cur.fetchone()[0]

    query = """
    SELECT 
        d.domain,
        d.is_known,
        d.first_seen_scan,
        d.last_seen_scan,
        d.first_seen_at,
        d.last_seen_at,
        ds.ip,
        ds.http_status,
        ds.reverse_dns,
        ds.final_url,
        ds.title,
    
        COALESCE(dp.provider, 'Unknown') as provider,
        COALESCE(da.asn, 'Unknown') as asn,
    
        COALESCE(dr.risk_score, 0) as risk_score,
        COALESCE(dr.reasons, '') as reasons,
    
        COALESCE(dc.cert_status, 'unknown') as cert_status,
        COALESCE(dc.days_to_expiry, -1) as days_to_expiry,
    
        ds.has_ip,
        ds.http_live,
    
        d.scannable,
        d.confidence_score,
        d.confidence_label,
        d.confidence_reasons
    
    FROM domains d
    
    LEFT JOIN domain_states ds
        ON d.id = ds.domain_id AND ds.scan_id = %s
    
    LEFT JOIN domain_provider dp
        ON d.id = dp.domain_id AND dp.scan_id = %s
    
    LEFT JOIN domain_asn da
        ON d.id = da.domain_id AND da.scan_id = %s
    
    LEFT JOIN domain_risk dr
        ON d.id = dr.domain_id AND dr.scan_id = %s
    
    LEFT JOIN domain_cert dc
        ON d.id = dc.domain_id AND dc.scan_id = %s
    """

    cur.execute(query, (scan_id, scan_id, scan_id, scan_id, scan_id))
    rows = cur.fetchall()

    columns = [
        "domain",
        "is_known",
        "first_seen_scan",
        "last_seen_scan",
        "first_seen_at",
        "last_seen_at",
        "ip",
        "http_status",
        "reverse_dns",
        "final_url",
        "title",
        "provider",
        "asn",
        "risk_score",
        "reasons",
        "cert_status",
        "days_to_expiry",
        "has_ip",
        "http_live",
        "scannable",
        "confidence_score",
        "confidence_label",
        "confidence_reasons",
    ]

    df = pd.DataFrame(rows, columns=columns)
    
    cur.execute("""
    SELECT LOWER(domain)
    FROM seed_domains
    """)
    
    trusted_roots = [r[0] for r in cur.fetchall()]
    
    # fix reasons
    df["confidence_reasons"] = df["confidence_reasons"].apply(
        lambda x: ", ".join(x) if isinstance(x, list) else (x or "")
    )
    
    print("COLUMNS:", df.columns.tolist())
    print("SAMPLE:\n", df.head(2))
    
    
    # safer boolean conversion
    df["scannable"] = df["scannable"].apply(lambda x: "yes" if x else "no")


    # ⭐ PORT aggregation
    cur.execute("""
        SELECT d.domain, dp.port
        FROM domain_ports dp
        JOIN domains d ON dp.domain_id = d.id
        WHERE dp.scan_id = %s
    """, (scan_id,))

    port_rows = cur.fetchall()

    port_map = {}
    for domain, port in port_rows:
        port_map.setdefault(domain, []).append(str(port))

    df["ports"] = df["domain"].map(
        lambda d: ",".join(port_map.get(d, [])) or "none"
    )

    # TECH aggregation
    cur.execute("""
        SELECT d.domain, dt.tech
        FROM domain_tech dt
        JOIN domains d ON dt.domain_id = d.id
        WHERE dt.scan_id = %s
    """, (scan_id,))
    
    tech_rows = cur.fetchall()
    
    tech_map = {}
    for domain, tech in tech_rows:
        tech_map.setdefault(domain, []).append(tech)
    
    df["tech"] = df["domain"].map(
        lambda d: ",".join(sorted(set(tech_map.get(d, [])))) or "unknown"
    )
    print(df.columns.tolist())
    df["Redirect Category"] = df.apply(
        lambda row: classify_redirect(
            row["domain"],
            row["http_status"],
            row["final_url"],
            trusted_roots
        ),
        axis=1
    )

    # remove duplicate domains 
    df = df.drop_duplicates(subset=["domain"])
    
    # sort by risk 
    df = df.sort_values(by="risk_score", ascending=False)

    # ⭐ SENSITIVE PORTS
    cur.execute("""
        SELECT d.domain, COUNT(*) 
        FROM domain_ports dp
        JOIN sensitive_ports sp ON dp.port = sp.port
        JOIN domains d ON dp.domain_id = d.id
        WHERE dp.scan_id = %s
        GROUP BY d.domain
    """, (scan_id,))

    sens_rows = cur.fetchall()
    sens_map = {d: c for d, c in sens_rows}

    df["sensitive_ports"] = df["domain"].map(
        lambda d: sens_map.get(d, 0)
    )

    conn.close()

    # ⭐ SHADOW TYPE
    def get_shadow(row):
        if not row["is_known"] and row["has_ip"]:
            return "unknown"
        elif row["has_ip"] and not row["http_live"]:
            return "non_web"
        elif not row["is_known"] and not row["http_live"]:
            return "both"
        return "none"

    df["shadow_type"] = df.apply(get_shadow, axis=1)

    # ⭐ EXPOSURE
    def get_exposure(row):
        ports = row.get("ports", "")
        if row["http_live"] and ports:
            return "mixed"
        elif row["http_live"]:
            return "web"
        return "non-web"

    df["exposure"] = df.apply(get_exposure, axis=1)

    # ❌ REMOVE NOISE
    df.drop(columns=["has_ip", "http_live"], inplace=True)

    # ⭐ RENAME COLUMNS
    df.rename(columns={
        "domain": "Domain",
        "is_known": "Is Known",
        "first_seen_scan": "First Seen",
        "last_seen_scan": "Last Seen",
        "ip": "IP",
        "http_status": "HTTP Status",
        "reverse_dns": "Reverse DNS",
        "final_url": "Final URL",
        "title": "Title",
        "provider": "Provider",
        "asn": "ASN",
        "tech": "Tech",
        "risk_score": "Risk Score",
        "reasons": "Reasons",
        "ports": "Open Ports",
        "sensitive_ports": "Sensitive Ports",
        "shadow_type": "Shadow Type",
        "exposure": "Exposure",
        "cert_status": "Cert Status",
        "days_to_expiry": "Days to Expiry"
    }, inplace=True)

    # ⭐ CSV STREAM
    stream = io.StringIO()
    df.to_csv(stream, index=False)

    response = StreamingResponse(
        iter([stream.getvalue()]),
        media_type="text/csv"
    )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    response.headers["Content-Disposition"] = \
        f"attachment; filename=asm_scan_{scan_id}_{timestamp}.csv"

    return response

@app.get("/investigation-assets")
def investigation_assets(page: int = 1, limit: int = 20, provider: str = None):

    offset = (page - 1) * limit

    conn = get_conn()
    cur = conn.cursor()

    # latest scan id
    cur.execute("SELECT MAX(id) FROM scans")
    scan_id = cur.fetchone()[0]

    query = """
    SELECT 
        d.domain,
        d.is_known,
        ds.ip,
        ds.has_ip,
        ds.http_status,
        COALESCE(dp.provider,'Unknown') as provider,
        COALESCE(da.asn,'Unknown') as asn,
        COALESCE(dt.tech,'Unknown') as tech,
    
        COALESCE(STRING_AGG(DISTINCT p.port::text, ','), '') as ports,
        COALESCE(dr.risk_score, 0) as risk
    
    FROM domains d
    
    LEFT JOIN domain_states ds
        ON d.id = ds.domain_id
        AND ds.scan_id = %s
    
    LEFT JOIN domain_provider dp
        ON d.id = dp.domain_id
        AND dp.scan_id = %s
    
    LEFT JOIN domain_asn da
        ON d.id = da.domain_id
        AND da.scan_id = %s
    
    LEFT JOIN domain_tech dt
        ON d.id = dt.domain_id
        AND dt.scan_id = %s
    
    LEFT JOIN domain_ports p
        ON d.id = p.domain_id
        AND p.scan_id = %s
    
    LEFT JOIN domain_risk dr
        ON d.id = dr.domain_id
        AND dr.scan_id = %s
    
    WHERE ds.has_ip = TRUE
    AND dp.provider IS NOT NULL
    AND dp.provider != 'Unknown'
    AND (%s IS NULL OR %s = '' OR LOWER(dp.provider) = LOWER(%s))
    
    GROUP BY 
        d.domain, d.is_known,
        ds.ip, ds.has_ip, ds.http_status,
        dp.provider, da.asn, dt.tech,
        dr.risk_score
    """

    cur.execute(
        query + " LIMIT %s OFFSET %s",
        (
            scan_id, scan_id, scan_id, scan_id, scan_id, scan_id,
            provider, provider, provider,
            limit, offset
        )
    )

    rows = cur.fetchall()

    assets = []

    for r in rows:
        assets.append({
            "domain": r[0],
            "is_known": r[1],
            "ip": r[2],
            "has_ip": r[3],
            "http_status": r[4],
            "provider": r[5],
            "asn": r[6],
            "tech": r[7],
            "ports": r[8],
            "risk": r[9]
        })

    conn.close()

    return {
        "page": page,
        "limit": limit,
        "count": len(assets),
        "assets": assets
    }

@app.get("/findings")
def findings():

    conn = get_conn()
    cur = conn.cursor()

    # latest scan
    cur.execute("SELECT MAX(id) FROM scans")
    scan_id = cur.fetchone()[0]

    cur.execute("""
        SELECT 
            d.domain,
            df.finding,
            df.severity,
            df.evidence
        FROM domain_findings df
        JOIN domains d 
            ON d.id = df.domain_id
        WHERE df.scan_id = %s
        ORDER BY 
            CASE 
                WHEN df.severity = 'HIGH' THEN 1
                WHEN df.severity = 'MEDIUM' THEN 2
                ELSE 3
            END
    """, (scan_id,))

    rows = cur.fetchall()
    conn.close()

    return [
        {
            "domain": r[0],
            "finding": r[1],
            "severity": r[2],
            "evidence": r[3]
        }
        for r in rows
    ]
    
@app.get("/cert-expiry")
def cert_expiry():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT 
            d.domain,
            dc.expiry_date,
            dc.days_to_expiry,
            dc.cert_status
        FROM domain_cert dc
        JOIN domains d ON d.id = dc.domain_id
        WHERE dc.scan_id = (SELECT MAX(id) FROM scans)
        ORDER BY dc.days_to_expiry ASC NULLS LAST
        LIMIT 50
    """)

    rows = cur.fetchall()
    conn.close()

    return [
        {
            "domain": r[0],
            "expiry": str(r[1]) if r[1] else None,
            "days": r[2],
            "status": r[3]
        }
        for r in rows
    ]
    
@app.get("/shadow-summary")
def shadow_summary():

    conn = get_conn()
    cur = conn.cursor()

    # latest scan
    cur.execute("SELECT MAX(scan_id) FROM domain_states")
    scan_id = cur.fetchone()[0]

    cur.execute("""
        SELECT 
            CASE
                WHEN COUNT(sp.port) >= 3 THEN 'High'
                WHEN COUNT(sp.port) >= 1 THEN 'Medium'
                ELSE 'Low'
            END as risk,
            COUNT(*) as count
        FROM domains d
        JOIN domain_states ds ON d.id = ds.domain_id
        LEFT JOIN domain_ports dp 
            ON d.id = dp.domain_id AND dp.scan_id = ds.scan_id
        LEFT JOIN sensitive_ports sp 
            ON dp.port = sp.port
        WHERE ds.scan_id = %s
        AND ds.has_ip = TRUE
        AND ds.http_live = FALSE
        GROUP BY risk
    """, (scan_id,))

    rows = cur.fetchall()
    conn.close()

    return [{"risk": r[0], "count": r[1]} for r in rows]
    
@app.get("/shadow-by-provider")
def shadow_by_provider():

    conn = get_conn()
    cur = conn.cursor()

    # latest scan
    cur.execute("SELECT MAX(scan_id) FROM domain_states")
    scan_id = cur.fetchone()[0]

    cur.execute("""
        SELECT 
            COALESCE(dp.provider, 'Unknown') as provider,
            COUNT(*)
        FROM domain_provider dp
        JOIN domains d ON d.id = dp.domain_id
        WHERE dp.scan_id = %s
        AND d.is_known = FALSE
        GROUP BY provider
        ORDER BY COUNT(*) DESC
    """, (scan_id,))

    rows = cur.fetchall()
    conn.close()

    return [{"provider": r[0], "count": r[1]} for r in rows]
    
@app.get("/non-web-summary")
def non_web_summary():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT MAX(scan_id) FROM domain_states")
    scan_id = cur.fetchone()[0]

    cur.execute("""
        SELECT 
            CASE
                WHEN COUNT(sp.port) >= 3 THEN 'High'
                WHEN COUNT(sp.port) >= 1 THEN 'Medium'
                ELSE 'Low'
            END as risk,
            COUNT(*) as count
        FROM domain_states ds

        LEFT JOIN domain_ports dp
            ON ds.domain_id = dp.domain_id
            AND ds.scan_id = dp.scan_id

        LEFT JOIN sensitive_ports sp
            ON dp.port = sp.port

        WHERE ds.scan_id = %s
        AND ds.has_ip = TRUE
        AND ds.http_live = FALSE

        GROUP BY risk
    """, (scan_id,))

    rows = cur.fetchall()
    conn.close()

    return [{"risk": r[0], "count": r[1]} for r in rows]    
    
@app.get("/unknown-high-risk")
def unknown_high_risk():

    conn = get_conn()
    cur = conn.cursor()

    # latest scan
    cur.execute("SELECT MAX(scan_id) FROM domain_states")
    scan_id = cur.fetchone()[0]

    cur.execute("""
        SELECT d.domain, dr.risk_score
        FROM domain_risk dr
        JOIN domains d ON d.id = dr.domain_id
        JOIN domain_states ds ON ds.domain_id = d.id

        WHERE dr.scan_id = %s
        AND ds.scan_id = %s
        AND d.is_known = FALSE
        AND dr.risk_score >= 3

        ORDER BY dr.risk_score DESC
        LIMIT 20
    """, (scan_id, scan_id))

    rows = cur.fetchall()
    conn.close()

    return [
        {"domain": r[0], "risk": r[1]}
        for r in rows
    ]

@app.get("/metrics/unvalidated-brand-footprint")
def unvalidated_brand_footprint():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    SELECT 
        COUNT(*) FILTER (
            WHERE d.scannable = FALSE
            AND EXISTS (
                SELECT 1 FROM seed_domains s
                WHERE d.domain = s.domain
                   OR d.domain LIKE '%.' || s.domain
                   OR d.domain LIKE '%' || split_part(s.domain, '.', 1) || '%'
            )
        ) AS count,
        COUNT(*) AS total
    FROM domains d
    """)

    count, total = cur.fetchone()

    percentage = (count / total * 100) if total else 0

    conn.close()

    return {
        "count": count,
        "total": total,
        "percentage": round(percentage, 2)
    }
    
@app.get("/metrics/unvalidated-breakdown")
def unvalidated_breakdown():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    SELECT 
        confidence_label,
        COUNT(*)
    FROM domains
    WHERE scannable = FALSE
    GROUP BY confidence_label
    """)

    rows = cur.fetchall()
    conn.close()

    result = {"high": 0, "medium": 0, "low": 0}

    for label, count in rows:
        result[label] = count

    return result

@app.get("/metrics/discovery-sources")
def discovery_sources():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    SELECT 
        CASE
            WHEN source = 'san' THEN 'SAN Expansion'
            WHEN source LIKE '%brand%' THEN 'Brand Expansion'
            ELSE 'Pentest Tool'
        END as src,
        COUNT(*)
    FROM domains
    GROUP BY src
    """)

    rows = cur.fetchall()
    conn.close()

    result = {}

    for src, count in rows:
        result[src] = count

    return result


@app.get("/chat")
def chat(q: str):

    q_lower = q.lower()

    # -------------------------
    # 🧠 INVESTIGATION (NEW)
    # -------------------------
    if "investigate" in q_lower or "how" in q_lower:

        match = re.search(
            r"(dangling_dns|suspicious_dns|open_port|sensitive_port|http_exposed|ssl|takeover)",
            q_lower
        )

        if match:
            finding = match.group(0)

            if finding == "takeover":
                finding = "dangling_dns"

            try:
                res = requests.get(
                    "http://asm_mcp:8000/tools/investigation-guide",
                    params={"finding": finding},
                    timeout=5
                )
                return res.json()
            except Exception as e:
                return {"error": f"MCP request failed: {str(e)}"}

        return {"message": "Please specify a finding (e.g., dangling_dns)"}

    # -------------------------
    # EXISTING LOGIC (UNCHANGED)
    # -------------------------
    if "unknown" in q_lower and "risk" in q_lower:
        return unknown_high_risk()

    elif "risk" in q_lower:
        return risky_domains()  

    elif "shadow" in q_lower:
        return shadow_assets()

    elif "finding" in q_lower:
        return findings()

    elif "summary" in q_lower:
        return summary()

    return {"message": "Didn't understand"}


@app.get("/llm-test")
def llm_test():

    answer = ask_llm(
        "What is an attack surface? Answer in one sentence."
    )

    return {
        "response": answer
    }


@app.get("/asset-growth")
def asset_growth():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            ds.scan_id,

            COUNT(*) AS total_assets,

            SUM(
                CASE
                    WHEN ds.has_ip = TRUE THEN 1
                    ELSE 0
                END
            ) AS live_assets,

            SUM(
                CASE
                    WHEN ds.has_ip = TRUE
                    AND d.is_known = FALSE
                    THEN 1
                    ELSE 0
                END
            ) AS shadow_assets

        FROM domain_states ds

        JOIN domains d
            ON ds.domain_id = d.id

        GROUP BY ds.scan_id
        ORDER BY ds.scan_id
    """)

    rows = cur.fetchall()

    conn.close()

    return [
        {
            "scan_id": r[0],
            "total": r[1],
            "live": r[2],
            "shadow": r[3]
        }
        for r in rows
    ]


def classify_redirect(source_domain, http_status, final_url, trusted_roots):

    # Only HTTP redirects should be classified
    try:
        http_status = int(http_status)
    except:
        return "None"

    if http_status < 300 or http_status >= 400:
        return "None"

    if final_url is None:
        return "None"

    final_url = str(final_url).strip().lower()

    if final_url in ("", "nan", "none", "null"):
        return "None"

    try:

        parsed = urlparse(final_url)

        destination = parsed.netloc.lower().split(":")[0]

        if not destination:
            return "None"

        if destination.startswith("www."):
            destination = destination[4:]

        source_domain = source_domain.lower()

        # Internal
        if (
            destination == source_domain
            or destination.endswith("." + source_domain)
            or source_domain.endswith("." + destination)
        ):
            return "Internal"

        # Trusted External
        for root in trusted_roots:
            root = root.lower()

            if destination == root or destination.endswith("." + root):
                return "Trusted External"

        return "Untrusted External"

    except Exception:
        return "None"


@app.get("/redirect-summary")
        
def redirect_summary():

    conn = get_conn()
    cur = conn.cursor()

    # trusted roots
    cur.execute("""
        SELECT LOWER(domain)
        FROM seed_domains
    """)

    trusted_roots = [r[0] for r in cur.fetchall()]

    # redirects
    cur.execute("""
    SELECT
        d.domain,
        ds.http_status,
        ds.final_url
    FROM domain_states ds
    JOIN domains d
        ON d.id = ds.domain_id
    WHERE ds.http_status BETWEEN 300 AND 399
      AND ds.final_url <> ''
      AND ds.final_url <> 'nan'
    """)

    rows = cur.fetchall()

    internal = 0
    trusted_external = 0
    untrusted_external = 0
    
    for source_domain, http_status, final_url in rows:
    
        classification = classify_redirect(
            source_domain,
            http_status,
            final_url,
            trusted_roots
        )
    
        if classification == "Internal":
            internal += 1
    
        elif classification == "Trusted External":
            trusted_external += 1
    
        elif classification == "Untrusted External":
            untrusted_external += 1
    
    conn.close()
    
    return {
        "total": internal + trusted_external + untrusted_external,
        "internal": internal,
        "trusted_external": trusted_external,
        "untrusted_external": untrusted_external
    }
    
@app.get("/naming-asset-exposure")
def naming_asset_exposure():

    conn = get_conn()
    cur = conn.cursor()

    keywords = [
        "dev",
        "test",
        "uat",
        "qa",
        "admin",
        "mail",
        "temp",
        "stage",
        "staging",
        "sandbox",
        "preprod",
        "pre-prod",
        "nonprod",
        "non-prod",
        "lab",
        "demo"
    ]

    results = []

    for keyword in keywords:

        # Keep STAGE and STAGING as separate categories
        if keyword == "stage":
            condition = """
                d.domain ILIKE %s
                AND d.domain NOT ILIKE %s
            """
            params = ("%stage%", "%staging%")

        else:
            condition = """
                d.domain ILIKE %s
            """
            params = (f"%{keyword}%",)

        query = f"""
            SELECT COUNT(DISTINCT d.domain)
            FROM domains d
            WHERE {condition}
        """

        cur.execute(query, params)

        count = cur.fetchone()[0]

        if count > 0:
            results.append({
                "keyword": keyword.upper(),
                "count": count
            })

    conn.close()

    return results
