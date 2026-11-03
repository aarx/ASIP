from fastapi import FastAPI
import os
from db import get_conn, get_latest_authoritative_scan_id
from asset_reporting import current_scan_asset_classes, current_scan_risks

app = FastAPI(title="ShadowRecon MCP Server")

# -------------------------
# TOOL 1: SUMMARY
# -------------------------
@app.get("/tools/summary")
def get_summary():

    conn = get_conn()
    cur = conn.cursor()

    scan_id = get_latest_authoritative_scan_id(cur)

    if scan_id is None:
        conn.close()
        return {
            "scan_id": None,
            "live_domains": 0,
            "shadow_assets": 0,
        }

    asset_classes = current_scan_asset_classes(cur, scan_id)

    cur.execute("""
        SELECT sr.domain_id, COALESCE(ds.has_ip, FALSE)
        FROM scan_results sr
        LEFT JOIN domain_states ds
          ON ds.domain_id = sr.domain_id AND ds.scan_id = sr.scan_id
        WHERE sr.scan_id = %s
    """, (scan_id,))
    state_rows = cur.fetchall()
    ip_by_id = {domain_id: bool(has_ip) for domain_id, has_ip in state_rows}
    live = sum(
        has_ip and asset_classes.get(domain_id) in ("KNOWN", "SHADOW")
        for domain_id, has_ip in ip_by_id.items()
    )
    live_shadow = sum(
        has_ip and asset_classes.get(domain_id) == "SHADOW"
        for domain_id, has_ip in ip_by_id.items()
    )
    totals = {
        asset_class: sum(value == asset_class for value in asset_classes.values())
        for asset_class in ("KNOWN", "SHADOW", "CANDIDATE", "EXTERNAL")
    }

    conn.close()

    return {
        "scan_id": scan_id,
        "live_domains": live,
        "shadow_assets": live_shadow,
        "total_domains": len(asset_classes),
        "organizational_assets": totals["KNOWN"] + totals["SHADOW"],
        "known_assets": totals["KNOWN"],
        "total_shadow_assets": totals["SHADOW"],
        "candidate_assets": totals["CANDIDATE"],
        "external_assets": totals["EXTERNAL"],
    }


# -------------------------
# TOOL 2: SHADOW ASSETS
# -------------------------
@app.get("/tools/shadow-assets")
def get_shadow_assets():

    conn = get_conn()
    cur = conn.cursor()

    scan_id = get_latest_authoritative_scan_id(cur)

    if scan_id is None:
        conn.close()
        return []

    asset_classes = current_scan_asset_classes(cur, scan_id)

    cur.execute("""
        SELECT d.id, d.domain, ds.ip
        FROM scan_results sr
        JOIN domains d ON d.id = sr.domain_id
        JOIN domain_states ds
          ON ds.domain_id = sr.domain_id AND ds.scan_id = sr.scan_id
        WHERE sr.scan_id = %s AND ds.has_ip = TRUE
        ORDER BY d.domain
    """, (scan_id,))
    rows = [
        row for row in cur.fetchall()
        if asset_classes.get(row[0]) == "SHADOW"
    ][:50]
    conn.close()

    return [
        {"domain": r[1], "ip": r[2]}
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
            d.ownership_status,
            ds.ip,
            ds.http_status
        FROM scan_results sr
        JOIN domains d
          ON d.id = sr.domain_id
        LEFT JOIN domain_states ds
          ON d.id = ds.domain_id
         AND ds.scan_id = sr.scan_id
        WHERE sr.scan_id = %s
        AND d.domain = %s
        LIMIT 1
    """, (scan_id, domain))

    row = cur.fetchone()

    if not row:
        conn.close()
        return {"error": "domain not found"}

    asset_classes = current_scan_asset_classes(cur, scan_id)
    asset_class = asset_classes.get(row[0], "CANDIDATE")
    canonical_risk = next(
        (
            risk for risk in current_scan_risks(cur, scan_id, asset_classes)
            if risk.domain_id == row[0]
        ),
        None,
    )
    conn.close()

    return {
        "domain": row[1],
        "is_known": row[2],
        "ownership_status": row[3],
        "asset_class": asset_class,
        "ip": row[4],
        "http_status": row[5],
        "risk_score": canonical_risk.result.score if canonical_risk else None,
        "priority": canonical_risk.result.priority if canonical_risk else None,
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

    canonical_risks = current_scan_risks(cur, scan_id)
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
        FROM scan_results sr
        JOIN domains d ON d.id = sr.domain_id
        JOIN domain_states ds
          ON ds.domain_id = sr.domain_id AND ds.scan_id = sr.scan_id
        WHERE sr.scan_id = %s
          AND ds.has_ip = TRUE
          AND d.confidence_label IN ('medium', 'high')
        ORDER BY d.domain
    """, (scan_id,))
    asset_classes = current_scan_asset_classes(cur, scan_id)
    rows = [row for row in cur.fetchall()
            if asset_classes.get(row[4]) == "CANDIDATE"]

    conn.close()

    results = [
        {
            "domain": r[0],
            "scannable": r[1],
            "confidence_score": r[2],
            "confidence_label": r[3],
            "asset_class": asset_classes.get(r[4], "CANDIDATE"),
            "risk_score": None,
            "priority": None,
        }
        for r in rows
    ]
    results.sort(
        key=lambda item: (
            item["risk_score"] if item["risk_score"] is not None else -1,
            item["confidence_score"],
        ),
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
    
    
