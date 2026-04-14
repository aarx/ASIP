from fastapi import FastAPI
import psycopg2
import os

app = FastAPI(title="ASM MCP Server")

def get_conn():
    return psycopg2.connect(
        host="db",
        dbname="asm_db",
        user="asm",
        password="asm123"
    )

# -------------------------
# TOOL 1: SUMMARY
# -------------------------
@app.get("/tools/summary")
def get_summary():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT MAX(scan_id) FROM domain_states")
    scan_id = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*)
        FROM domain_states
        WHERE scan_id = %s AND has_ip = TRUE
    """, (scan_id,))
    live = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*)
        FROM domain_states ds
        JOIN domains d ON d.id = ds.domain_id
        WHERE ds.scan_id = %s AND d.is_known = FALSE AND ds.has_ip = TRUE
    """, (scan_id,))
    shadow = cur.fetchone()[0]

    conn.close()

    return {
        "scan_id": scan_id,
        "live_domains": live,
        "shadow_assets": shadow
    }


# -------------------------
# TOOL 2: SHADOW ASSETS
# -------------------------
@app.get("/tools/shadow-assets")
def get_shadow_assets():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT MAX(scan_id) FROM domain_states")
    scan_id = cur.fetchone()[0]

    cur.execute("""
        SELECT d.domain, ds.ip
        FROM domain_states ds
        JOIN domains d ON d.id = ds.domain_id
        WHERE ds.scan_id = %s
        AND ds.has_ip = TRUE
        AND d.is_known = FALSE
        LIMIT 50
    """, (scan_id,))

    rows = cur.fetchall()
    conn.close()

    return [
        {"domain": r[0], "ip": r[1]}
        for r in rows
    ]


# -------------------------
# TOOL 3: DOMAIN DETAILS
# -------------------------
@app.get("/tools/domain")
def get_domain(domain: str):

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT 
            d.domain,
            d.is_known,
            ds.ip,
            ds.http_status,
            dr.risk_score,
            dr.reasons
        FROM domains d
        LEFT JOIN domain_states ds ON d.id = ds.domain_id
        LEFT JOIN domain_risk dr ON d.id = dr.domain_id
        WHERE d.domain = %s
        ORDER BY ds.scan_id DESC
        LIMIT 1
    """, (domain,))

    row = cur.fetchone()
    conn.close()

    if not row:
        return {"error": "domain not found"}

    return {
        "domain": row[0],
        "is_known": row[1],
        "ip": row[2],
        "http_status": row[3],
        "risk_score": row[4],
        "reasons": row[5]
    }


# -------------------------
# TOOL 4: FINDINGS
# -------------------------
@app.get("/tools/findings")
def get_findings():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT d.domain, f.issue
        FROM domain_findings f
        JOIN domains d ON d.id = f.domain_id
        ORDER BY f.scan_id DESC
        LIMIT 50
    """)

    rows = cur.fetchall()
    conn.close()

    return [
        {"domain": r[0], "issue": r[1]}
        for r in rows
    ]

@app.get("/tools/high-risk")
def high_risk():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT d.domain, dr.risk_score
        FROM domain_risk dr
        JOIN domains d ON d.id = dr.domain_id
        WHERE dr.risk_score >= 3
        ORDER BY dr.risk_score DESC
        LIMIT 20
    """)

    rows = cur.fetchall()
    conn.close()

    return [
        {"domain": r[0], "risk": r[1]}
        for r in rows
    ]
