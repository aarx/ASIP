from fastapi import FastAPI
import os
from db import get_conn

app = FastAPI(title="ASM MCP Server")

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
        WHERE f.scan_id = (
            SELECT MAX(scan_id) FROM domain_findings
        )
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
   
   
# -------------------------
# TOOL 5: Priority Targets
# -------------------------    

@app.get("/tools/priority-targets")
def priority_targets():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
        SELECT 
            d.domain,
            d.scannable,
            d.confidence_score,
            d.confidence_label,
            COALESCE(dr.risk_score, 0) as risk_score
        FROM domains d

        LEFT JOIN domain_risk dr
            ON d.id = dr.domain_id

        WHERE d.scannable = FALSE
        AND d.confidence_label IN ('medium', 'high')
        
        AND EXISTS (
            SELECT 1 
            FROM domain_states ds
            WHERE ds.domain_id = d.id
            AND ds.has_ip = TRUE
        )

        ORDER BY 
            COALESCE(dr.risk_score, 0) DESC,
            d.confidence_score DESC

        LIMIT 20
    """)

    rows = cur.fetchall()
    conn.close()

    return [
        {
            "domain": r[0],
            "scannable": r[1],
            "confidence_score": r[2],
            "confidence_label": r[3],
            "risk_score": r[4]
        }
        for r in rows
    ]
    
# -------------------------
# TOOL 6: INVESTIGATION GUIDE
# -------------------------
@app.get("/tools/investigation-guide")
def investigation_guide(finding: str):

    finding = finding.lower().strip()

    guides = {

        # -------------------------
        # TAKEOVER / DNS
        # -------------------------
        "dangling_dns": [
            "Check CNAME record using: dig <domain> CNAME",
            "Verify if target service exists (S3, GitHub, etc.)",
            "Open domain in browser and inspect response",
            "Look for provider-specific error messages",
            "Attempt to claim the resource if unclaimed"
        ],

        "suspicious_dns": [
            "Check DNS records (A, CNAME, TXT)",
            "Verify if domain resolves consistently",
            "Check if service behind domain exists",
            "Inspect HTTP response manually"
        ],

        # -------------------------
        # PORT / EXPOSURE
        # -------------------------
        "open_port": [
            "Run: nmap -p <port> <domain>",
            "Identify service running on port",
            "Check for default credentials",
            "Test for known vulnerabilities (search CVEs)"
        ],

        "sensitive_port": [
            "Confirm service using nmap/service detection",
            "Try accessing service via browser or client",
            "Check authentication requirements",
            "Look for exposed admin panels"
        ],

        # -------------------------
        # HTTP / WEB
        # -------------------------
        "http_exposed": [
            "Open domain in browser",
            "Check headers (curl -I)",
            "Inspect technologies used",
            "Run directory brute force (ffuf/dirsearch)"
        ],

        "tech_detected": [
            "Identify framework/version",
            "Search for known vulnerabilities",
            "Check outdated components"
        ],

        # -------------------------
        # CERT / SSL
        # -------------------------
        "ssl_issue": [
            "Check certificate via browser or openssl",
            "Verify expiry date",
            "Check issuer and trust chain",
            "Look for weak configurations"
        ],

        # -------------------------
        # FALLBACK
        # -------------------------
        "default": [
            "Manually inspect the domain",
            "Check DNS and HTTP response",
            "Look for unusual behavior",
            "Correlate with other assets"
        ]
    }

    # match logic
    for key in guides:
        if key in finding:
            return {
                "finding": finding,
                "steps": guides[key]
            }

    return {
        "finding": finding,
        "steps": guides["default"]
    }
    
    
