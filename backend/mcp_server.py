from fastapi import FastAPI
import os
from db import get_conn, get_latest_authoritative_scan_id
from risk_engine import calculate_scan_risks

app = FastAPI(title="ASM MCP Server")

# -------------------------
# TOOL 1: SUMMARY
# -------------------------
@app.get("/tools/summary")
def get_summary():

    conn = get_conn()
    cur = conn.cursor()

    scan_id = get_latest_authoritative_scan_id(cur)

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

    scan_id = get_latest_authoritative_scan_id(cur)

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

    scan_id = get_latest_authoritative_scan_id(cur)

    if scan_id is None:
        conn.close()
        return {"error": "domain not found"}

    cur.execute("""
        SELECT 
            d.id,
            d.domain,
            d.is_known,
            ds.ip,
            ds.http_status
        FROM domains d
        LEFT JOIN domain_states ds
          ON d.id = ds.domain_id
         AND ds.scan_id = %s
        WHERE d.domain = %s
        LIMIT 1
    """, (scan_id, domain))

    row = cur.fetchone()

    if not row:
        conn.close()
        return {"error": "domain not found"}

    canonical_risk = next(
        (
            risk for risk in calculate_scan_risks(cur, scan_id)
            if risk.domain_id == row[0]
        ),
        None,
    )
    conn.close()

    return {
        "domain": row[1],
        "is_known": row[2],
        "ip": row[3],
        "http_status": row[4],
        "risk_score": canonical_risk.result.score if canonical_risk else 0,
        "priority": canonical_risk.result.priority if canonical_risk else "Low",
        "reasons": list(canonical_risk.result.reasons) if canonical_risk else [],
    }


# -------------------------
# TOOL 4: FINDINGS
# -------------------------
@app.get("/tools/findings")
def get_findings():

    conn = get_conn()
    cur = conn.cursor()

    scan_id = get_latest_authoritative_scan_id(cur)

    cur.execute("""
        SELECT d.domain, f.finding
        FROM domain_findings f
        JOIN domains d ON d.id = f.domain_id
        WHERE f.scan_id = %s
        LIMIT 50
    """, (scan_id,))

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

    scan_id = get_latest_authoritative_scan_id(cur)

    if scan_id is None:
        conn.close()
        return []

    canonical_risks = calculate_scan_risks(cur, scan_id)
    conn.close()

    ranked = sorted(
        (risk for risk in canonical_risks if risk.result.priority == "High"),
        key=lambda risk: (risk.result.score, risk.domain),
        reverse=True,
    )[:20]
    return [
        {
            "domain": risk.domain,
            "risk": risk.result.score,
            "priority": risk.result.priority,
            "reasons": list(risk.result.reasons),
        }
        for risk in ranked
    ]
   
   
# -------------------------
# TOOL 5: Priority Targets
# -------------------------    

@app.get("/tools/priority-targets")
def priority_targets():

    conn = get_conn()
    cur = conn.cursor()

    scan_id = get_latest_authoritative_scan_id(cur)

    if scan_id is None:
        conn.close()
        return []

    cur.execute("""
        SELECT 
            d.domain,
            d.scannable,
            d.confidence_score,
            d.confidence_label,
            d.id
        FROM domains d

        WHERE d.scannable = FALSE
        AND d.confidence_label IN ('medium', 'high')
        
        AND EXISTS (
            SELECT 1 
            FROM domain_states ds
            WHERE ds.domain_id = d.id
            AND ds.scan_id = %s
            AND ds.has_ip = TRUE
        )

    """, (scan_id,))

    rows = cur.fetchall()
    canonical_by_id = {
        risk.domain_id: risk
        for risk in calculate_scan_risks(cur, scan_id)
    }
    conn.close()

    results = [
        {
            "domain": r[0],
            "scannable": r[1],
            "confidence_score": r[2],
            "confidence_label": r[3],
            "risk_score": canonical_by_id[r[4]].result.score
            if r[4] in canonical_by_id else 0,
            "priority": canonical_by_id[r[4]].result.priority
            if r[4] in canonical_by_id else "Low",
        }
        for r in rows
    ]
    results.sort(
        key=lambda item: (item["risk_score"], item["confidence_score"]),
        reverse=True,
    )
    return results[:20]
    
# -------------------------
# TOOL 6: INVESTIGATION GUIDE
# -------------------------
@app.get("/tools/investigation-guide")
def investigation_guide(finding: str):

    finding = finding.lower().strip()
    if finding == "ssl":
        finding = "ssl_issue"

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
    
    
