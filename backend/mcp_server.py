from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
import os
from db import get_conn, get_latest_authoritative_scan_id
from asset_reporting import current_scan_asset_classes, current_scan_risks
from ownership import reporting_asset_class_sql
from scan_diagnostics import api_diagnostics

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
            "answer": "No successful authoritative scan is available.",
            "context": {"scan_id": None, "scan_time": None},
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
    cur.execute("SELECT scan_time, status FROM scans WHERE id = %s", (scan_id,))
    scan_meta = cur.fetchone()

    conn.close()

    return {
        "answer": (f"Authoritative scan #{scan_id} contains {len(asset_classes)} members: "
                   f"{totals['KNOWN']} Known, {totals['SHADOW']} Shadow, "
                   f"{totals['CANDIDATE']} Candidate, and {totals['EXTERNAL']} External."),
        "context": {"scan_id": scan_id, "scan_time": scan_meta[0] if scan_meta else None,
                    "status": scan_meta[1] if scan_meta else "UNKNOWN"},
        "scan_id": scan_id,
        "live_domains": live,
        "shadow_assets": live_shadow,
        "total_domains": len(asset_classes),
        "organizational_assets": totals["KNOWN"] + totals["SHADOW"],
        "known_assets": totals["KNOWN"],
        "total_shadow_assets": totals["SHADOW"],
        "candidate_assets": totals["CANDIDATE"],
        "external_assets": totals["EXTERNAL"],
        "coverage": {"asset_classification": "CURRENT_AUTHORITATIVE_SCAN",
                     "live_domains": "IP_PRESENT_KNOWN_OR_SHADOW_ONLY"},
        "limitations": ["Candidates are reported separately and are not included as confirmed organizational assets."],
        "next_actions": ["Use /tools/high-risk for canonical organizational risk priorities."],
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
        SELECT DISTINCT d.id, d.domain, ds.ip
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
            ds.http_status,
            ds.http_observation_status,
            ds.http_live
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
    cur.execute("SELECT scan_time, status FROM scans WHERE id = %s", (scan_id,))
    scan_meta = cur.fetchone()
    cur.execute("""
        SELECT dp.port, dp.service, sp.risk, sp.description
          FROM domain_ports dp JOIN sensitive_ports sp ON sp.port = dp.port
         WHERE dp.scan_id = %s AND dp.domain_id = %s ORDER BY dp.port LIMIT 20
    """, (scan_id, row[0]))
    ports = [{"port": item[0], "service": item[1], "risk": item[2],
              "description": item[3]} for item in cur.fetchall()]
    cur.execute("""
        SELECT expiry_date, days_to_expiry, cert_status FROM domain_cert
         WHERE scan_id = %s AND domain_id = %s LIMIT 1
    """, (scan_id, row[0]))
    certificate_row = cur.fetchone()
    certificate = ({"expiry_date": certificate_row[0],
                    "days_to_expiry_at_scan": certificate_row[1],
                    "status": certificate_row[2]} if certificate_row else None)
    cur.execute("""
        SELECT technology, version, confidence, evidence_type, sanitized_evidence
          FROM domain_technology_observations
         WHERE scan_id = %s AND domain_id = %s
         ORDER BY technology, version NULLS FIRST LIMIT 30
    """, (scan_id, row[0]))
    technologies = [{"technology": item[0], "version": item[1],
                     "confidence": item[2], "evidence_type": item[3],
                     "evidence": item[4]} for item in cur.fetchall()]
    cur.execute("""
        SELECT finding, severity, evidence FROM domain_findings
         WHERE scan_id = %s AND domain_id = %s
         ORDER BY severity, finding LIMIT 30
    """, (scan_id, row[0]))
    findings = [{"finding": item[0], "severity": item[1], "evidence": item[2]}
                for item in cur.fetchall()]
    cur.execute("""
        SELECT DISTINCT record_type FROM domain_dns
         WHERE scan_id = %s AND domain_id = %s ORDER BY record_type
    """, (scan_id, row[0]))
    dns_record_types = [item[0] for item in cur.fetchall()]
    dns_checks = None
    try:
        cur.execute("""
            SELECT check_key, target_identity, record_type, outcome, severity,
                   confidence, evidence, remediation, checked_at
              FROM dns_security_checks
             WHERE scan_id = %s AND domain_id = %s
             ORDER BY check_key, target_identity, record_type LIMIT 10
        """, (scan_id, row[0]))
        dns_checks = [{"check_key": item[0], "target": item[1], "record_type": item[2],
                       "outcome": item[3], "severity": item[4], "confidence": item[5],
                       "evidence": item[6], "remediation": item[7], "checked_at": item[8]}
                      for item in cur.fetchall()]
    except Exception as exc:
        if getattr(exc, "pgcode", None) not in ("42P01", "42703"):
            raise
    conn.close()

    return {
        "answer": (f"{row[1]} is {asset_class} in scan #{scan_id}; canonical risk is "
                   f"{canonical_risk.result.score} ({canonical_risk.result.priority})."
                   if canonical_risk else f"{row[1]} is {asset_class} in scan #{scan_id}; no organizational risk score applies."),
        "context": {"scan_id": scan_id, "scan_time": scan_meta[0] if scan_meta else None,
                    "domain_id": row[0], "asset_class": asset_class},
        "domain": row[1],
        "domain_id": row[0],
        "scan_id": scan_id,
        "scan_time": scan_meta[0] if scan_meta else None,
        "is_known": row[2],
        "ownership_status": row[3],
        "asset_class": asset_class,
        "ip": row[4],
        "http_status": row[5],
        "http_observation_status": row[6],
        "http_live": bool(row[7]) if row[7] is not None else None,
        "risk_score": canonical_risk.result.score if canonical_risk else None,
        "priority": canonical_risk.result.priority if canonical_risk else None,
        "reasons": list(canonical_risk.result.reasons) if canonical_risk else [],
        "certificate": certificate,
        "technologies": technologies,
        "sensitive_ports": ports,
        "findings": findings,
        "dns_record_types": dns_record_types,
        "dns_security_checks": dns_checks,
        "coverage": {
            "dns_records": "RECORD_TYPES_RECORDED" if dns_record_types else "NO_ROWS_COVERAGE_UNKNOWN",
            "http": row[6] or "UNKNOWN",
            "certificate": "OBSERVATION_RECORDED" if certificate else "NO_SCAN_ROW",
            "technologies": "OBSERVATIONS_RECORDED" if technologies else "NO_ROWS_COVERAGE_UNKNOWN",
            "sensitive_ports": "POSITIVE_ROWS_RECORDED" if ports else "NO_POSITIVE_ROWS_COVERAGE_UNKNOWN",
            "findings": "RECORDED" if findings else "NO_ROWS_COVERAGE_UNKNOWN",
            "dns_security": ("SCHEMA_UNAVAILABLE" if dns_checks is None else
                             "CHECK_RECORDS_RECORDED" if dns_checks else "NO_CHECK_ROWS_UNASSESSED_OR_NOT_RUN"),
        },
        "limitations": ["Only scan-specific stored observations are returned.",
                        "Absence of rows is not evidence that an assessment completed clear.",
                        "DNS record values are not returned; only stored record types are listed."],
        "next_actions": ["Review coverage gaps before drawing conclusions.",
                         "Use the scan-scoped stored evidence when coordinating with the asset owner."],
    }


# -------------------------
# TOOL 4: FINDINGS
# -------------------------
@app.get("/tools/findings")
def get_findings():

    conn = get_conn()
    cur = conn.cursor()

    scan_id = get_latest_authoritative_scan_id(cur)

    if scan_id is None:
        conn.close()
        return []
    asset_class_sql = reporting_asset_class_sql("d.domain", "d.ownership_status")
    cur.execute("""
        SELECT d.id, d.domain, f.finding, f.severity, f.evidence, CLASS_EXPR
          FROM domain_findings f
          JOIN domains d ON d.id = f.domain_id
         WHERE f.scan_id = %s AND CLASS_EXPR IN ('KNOWN', 'SHADOW')
         ORDER BY f.severity, d.domain, f.finding LIMIT 50
    """.replace("CLASS_EXPR", asset_class_sql), (scan_id,))

    rows = cur.fetchall()
    conn.close()

    return [
        {"domain": r[1], "issue": r[2], "severity": r[3], "evidence": r[4], "scan_id": scan_id,
         "asset_class": r[5]}
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
            "domain_id": risk.domain_id,
            "scan_id": scan_id,
            "risk": risk.result.score,
            "priority": risk.result.priority,
            "reasons": list(risk.result.reasons),
            "investigation_ref": f"/tools/domain?domain={risk.domain}",
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
        SELECT DISTINCT
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
    target_rows = cur.fetchall()
    asset_classes = current_scan_asset_classes(cur, scan_id)
    rows = [row for row in target_rows
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
        "dangling_dns": [
            "Review the scan-scoped DNS Security outcome and target evidence.",
            "Correlate the target with approved DNS and service inventory.",
            "Treat provider fingerprints and NXDOMAIN as indicators, not proof of takeover.",
        ],
        "suspicious_dns": [
            "Review the stored DNS record observations and their scan timestamp.",
            "Compare with the responsible team's approved DNS configuration.",
            "If a new query or active validation is needed, obtain the applicable authorization first.",
        ],
        "open_port": [
            "Confirm the recorded hostname, port, service, and source scan.",
            "Ask the asset owner whether the service is expected.",
            "Any further network validation requires separate authorization.",
        ],
        "sensitive_port": [
            "Review the recorded hostname, port, and service observation.",
            "Confirm expected exposure with the responsible asset owner.",
            "Check assessment coverage; no positive row does not establish a completed negative assessment.",
        ],
        "http_exposed": [
            "Review the stored HTTP status and redirect evidence for the scan.",
            "Correlate the endpoint with approved application inventory.",
        ],
        "tech_detected": [
            "Review the observed technology, version, confidence, and fingerprint evidence.",
            "Confirm the component and version with the application owner before assessing applicability.",
        ],
        "ssl_issue": [
            "Review the scan-recorded certificate status and days-to-expiry value.",
            "Verify expiry date against the timestamp of that scan; do not recalculate historical status using today's date.",
            "Confirm certificate ownership and renewal status with the responsible team.",
        ],
        "default": [
            "Review the scan-scoped evidence and its coverage state.",
            "Correlate the asset with internal ownership and service inventory.",
        ],
    }
    key = next((key for key in guides if key in finding), "default")
    return {
        "finding": finding,
        "steps": guides[key],
        "mode": "deterministic_advisory",
        "limitations": ["No scan, probe, or other action is launched by this guidance."],
    }


def _resolve_scan(cur, scan_id=None):
    if scan_id is not None and scan_id <= 0:
        raise HTTPException(status_code=400, detail="scan_id must be positive")
    scan_id = scan_id if scan_id is not None else get_latest_authoritative_scan_id(cur)
    if scan_id is None:
        raise HTTPException(status_code=404, detail="No successful scan is available")
    cur.execute(
        """SELECT s.status, s.scan_time, s.completed_at,
                  (SELECT COUNT(DISTINCT sr.domain_id)
                     FROM scan_results sr WHERE sr.scan_id = s.id) AS asset_count,
                  s.stage_diagnostics
             FROM scans s WHERE s.id = %s""",
        (scan_id,),
    )
    row = cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan_id, row


@app.get("/tools/scan-health")
def scan_health(scan_id: int = None):
    """Return persisted execution diagnostics; overall success is not full coverage."""
    conn = get_conn()
    try:
        cur = conn.cursor()
        selected_id, scan = _resolve_scan(cur, scan_id)
        diagnostics = api_diagnostics(scan[4], scan[0])
        attempts = diagnostics.get("attempts", []) if isinstance(diagnostics, dict) else []
        return {
            "answer": f"Scan #{selected_id} is {scan[0]}; stage coverage is shown from persisted diagnostics.",
            "context": {"scan_id": selected_id, "scan_time": scan[1], "completed_at": scan[2]},
            "data": {"status": scan[0], "asset_count": scan[3], "stage_diagnostics": diagnostics},
            "coverage": {
                "diagnostics_available": scan[4] is not None,
                "stage_attempts": len(attempts),
                "interpretation": "A successful scan does not mean every optional stage assessed every asset.",
            },
            "limitations": [] if scan[4] is not None else ["Persisted stage diagnostics are unavailable for this scan."],
            "next_actions": ["Review failed, skipped, timed-out, and optional stage attempts before interpreting coverage."],
        }
    finally:
        conn.close()


@app.get("/tools/scan-comparison")
def scan_comparison(before_scan_id: int = Query(gt=0), after_scan_id: int = Query(gt=0)):
    """Compare retained scan membership and state observations, without substituting current state."""
    conn = get_conn()
    try:
        cur = conn.cursor()
        before_id, before = _resolve_scan(cur, before_scan_id)
        after_id, after = _resolve_scan(cur, after_scan_id)
        if before[0] != "SUCCEEDED" or after[0] != "SUCCEEDED":
            raise HTTPException(status_code=409, detail="Comparison requires two successful scans")
        cur.execute("""
            WITH before_members AS (
            SELECT DISTINCT sr.domain_id, d.domain FROM scan_results sr
                JOIN domains d ON d.id = sr.domain_id WHERE sr.scan_id = %s
            ), after_members AS (
                SELECT DISTINCT sr.domain_id, d.domain FROM scan_results sr
                JOIN domains d ON d.id = sr.domain_id WHERE sr.scan_id = %s
            )
            SELECT 'ADDED', a.domain_id, a.domain FROM after_members a
             WHERE NOT EXISTS (SELECT 1 FROM before_members b WHERE b.domain_id = a.domain_id)
            UNION ALL
            SELECT 'REMOVED', b.domain_id, b.domain FROM before_members b
             WHERE NOT EXISTS (SELECT 1 FROM after_members a WHERE a.domain_id = b.domain_id)
            ORDER BY 1, 3
        """, (before_id, after_id))
        membership = cur.fetchall()
        added = [{"domain_id": r[1], "domain": r[2]} for r in membership if r[0] == "ADDED"]
        removed = [{"domain_id": r[1], "domain": r[2]} for r in membership if r[0] == "REMOVED"]
        cur.execute("""
            SELECT DISTINCT d.domain, old.http_observation_status, old.http_status, old.has_ip,
                   new.http_observation_status, new.http_status, new.has_ip
              FROM scan_results a
              JOIN scan_results b ON b.domain_id = a.domain_id
              JOIN domains d ON d.id = a.domain_id
              LEFT JOIN domain_states old ON old.scan_id = a.scan_id AND old.domain_id = a.domain_id
              LEFT JOIN domain_states new ON new.scan_id = b.scan_id AND new.domain_id = b.domain_id
             WHERE a.scan_id = %s AND b.scan_id = %s
             ORDER BY d.domain
        """, (before_id, after_id))
        state_changes = []
        for r in cur.fetchall():
            old = (r[1], r[2], r[3])
            new = (r[4], r[5], r[6])
            if old != new:
                state_changes.append({"domain": r[0], "before": {"http_status": r[2], "http_observation_status": r[1], "has_ip": r[3]},
                                      "after": {"http_status": r[5], "http_observation_status": r[4], "has_ip": r[6]}})
        state_changes = state_changes[:100]
        return {
            "answer": f"Compared scans #{before_id} and #{after_id}: {len(added)} members added and {len(removed)} removed.",
            "context": {"before": {"scan_id": before_id, "scan_time": before[1]}, "after": {"scan_id": after_id, "scan_time": after[1]}},
            "data": {"added": added[:100], "removed": removed[:100], "http_dns_state_changes": state_changes},
            "coverage": {"membership": "SCAN_SCOPED", "state_changes": "SCAN_SCOPED", "state_change_rows_returned": len(state_changes)},
            "limitations": ["Historical effective classifications and risk scores are not reconstructed from current ownership or current risk state.",
                            "State-change detail is limited to the first 100 changed shared members."],
            "next_actions": ["Investigate changed assets in their respective scan records."],
        }
    finally:
        conn.close()


@app.get("/tools/evidence")
def evidence(category: str, scan_id: int = None, page: int = Query(default=1, ge=1), limit: int = Query(default=25, ge=1, le=100)):
    """Bounded, scan-scoped evidence catalog with fixed categories and SQL."""
    category = category.strip().lower()
    queries = {
        "ports": ("""SELECT d.id,d.domain,cls,dp.port,dp.service,sp.risk,sp.description FROM domain_ports dp
                    JOIN domains d ON d.id=dp.domain_id JOIN sensitive_ports sp ON sp.port=dp.port
                    CROSS JOIN LATERAL (SELECT CLASS_EXPR AS cls) c WHERE dp.scan_id=%s AND CLASS_EXPR IN ('KNOWN','SHADOW')
                    AND EXISTS (SELECT 1 FROM scan_results sr WHERE sr.scan_id=dp.scan_id AND sr.domain_id=dp.domain_id)
                    ORDER BY d.domain,dp.port""", "Observed sensitive-port rows"),
        "certificates": ("""SELECT d.id,d.domain,cls,dc.cert_status,dc.expiry_date,dc.days_to_expiry FROM domain_cert dc
                    JOIN domains d ON d.id=dc.domain_id
                    CROSS JOIN LATERAL (SELECT CLASS_EXPR AS cls) c WHERE dc.scan_id=%s AND CLASS_EXPR IN ('KNOWN','SHADOW')
                    AND EXISTS (SELECT 1 FROM scan_results sr WHERE sr.scan_id=dc.scan_id AND sr.domain_id=dc.domain_id)
                    ORDER BY d.domain""", "Stored certificate observations"),
        "technologies": ("""SELECT d.id,d.domain,cls,dto.technology,dto.version,dto.confidence,dto.evidence_type,dto.sanitized_evidence FROM domain_technology_observations dto
                    JOIN domains d ON d.id=dto.domain_id
                    CROSS JOIN LATERAL (SELECT CLASS_EXPR AS cls) c WHERE dto.scan_id=%s AND CLASS_EXPR IN ('KNOWN','SHADOW')
                    AND EXISTS (SELECT 1 FROM scan_results sr WHERE sr.scan_id=dto.scan_id AND sr.domain_id=dto.domain_id)
                    ORDER BY d.domain,dto.technology,dto.version""", "Stored technology fingerprints"),
        "http": ("""SELECT d.id,d.domain,cls,ds.http_observation_status,ds.http_live,ds.http_status,ds.final_url,ds.final_status FROM domain_states ds
                    JOIN domains d ON d.id=ds.domain_id
                    CROSS JOIN LATERAL (SELECT CLASS_EXPR AS cls) c WHERE ds.scan_id=%s AND CLASS_EXPR IN ('KNOWN','SHADOW')
                    AND EXISTS (SELECT 1 FROM scan_results sr WHERE sr.scan_id=ds.scan_id AND sr.domain_id=ds.domain_id)
                    ORDER BY d.domain""", "Stored HTTP observations"),
    }
    if category not in queries:
        raise HTTPException(status_code=400, detail="category must be ports, certificates, technologies, or http")
    conn = get_conn()
    try:
        cur = conn.cursor()
        selected_id, scan = _resolve_scan(cur, scan_id)
        if scan[0] != "SUCCEEDED":
            raise HTTPException(status_code=409, detail="Evidence reporting requires a successful scan")
        sql, description = queries[category]
        class_sql = reporting_asset_class_sql("d.domain", "d.ownership_status")
        sql = sql.replace("CLASS_EXPR", class_sql)
        cur.execute(f"SELECT COUNT(*) FROM ({sql}) evidence_count", (selected_id,))
        total = int(cur.fetchone()[0])
        cur.execute(sql + " LIMIT %s OFFSET %s", (selected_id, limit, (page - 1) * limit))
        rows = cur.fetchall()
        field_names = {
            "ports": ("domain_id", "domain", "asset_class", "port", "service", "risk", "description"),
            "certificates": ("domain_id", "domain", "asset_class", "status", "expiry_date", "days_to_expiry_at_scan"),
            "technologies": ("domain_id", "domain", "asset_class", "technology", "version", "confidence", "evidence_type", "evidence"),
            "http": ("domain_id", "domain", "asset_class", "observation_status", "live", "status", "final_url", "final_status"),
        }[category]
        return {
            "answer": f"{total} {description.lower()} are stored for scan #{selected_id}.",
            "context": {"scan_id": selected_id, "scan_time": scan[1], "asset_class_scope": ["KNOWN", "SHADOW"]},
            "data": {"category": category,
                     "items": [dict(zip(field_names, row)) for row in rows],
                     "page": page, "limit": limit, "total": total},
            "coverage": {"meaning": "Positive persisted observations only; absence of rows does not prove assessment or clearance."},
            "limitations": ["Historical values are read only from the requested scan.", "Results are bounded and paginated."],
            "next_actions": ["Review asset-specific evidence and assessment coverage."],
        }
    finally:
        conn.close()


@app.get("/tools/dns-security")
def dns_security_intelligence(scan_id: int = None):
    """Separate checked assets, check records, outcomes, and unknown coverage."""
    conn = get_conn()
    try:
        cur = conn.cursor()
        selected_id, scan = _resolve_scan(cur, scan_id)
        if scan[0] != "SUCCEEDED":
            raise HTTPException(status_code=409, detail="DNS Security reporting requires a successful scan")
        classes = current_scan_asset_classes(cur, selected_id)
        cur.execute("""
            SELECT DISTINCT sr.domain_id FROM scan_results sr
            JOIN domains d ON d.id = sr.domain_id
            WHERE sr.scan_id = %s AND d.scannable IS TRUE
        """, (selected_id,))
        eligible_ids = {row[0] for row in cur.fetchall()}
        eligible = {domain_id for domain_id, asset_class in classes.items()
                    if domain_id in eligible_ids and asset_class in ("KNOWN", "SHADOW")}
        try:
            cur.execute("""
                SELECT domain_id, outcome, severity, check_key, target_identity,
                       record_type, confidence, evidence, remediation, checked_at
                  FROM dns_security_checks WHERE scan_id = %s
                 ORDER BY domain_id, check_key, target_identity, record_type
            """, (selected_id,))
            rows = [row for row in cur.fetchall() if row[0] in eligible]
        except Exception as exc:
            if getattr(exc, "pgcode", None) in ("42P01", "42703"):
                return JSONResponse(status_code=503, content={
                    "scan_id": selected_id,
                    "availability_state": "SCHEMA_UNAVAILABLE",
                    "detail": "DNS Security storage is not installed",
                })
            raise
        diagnostics = api_diagnostics(scan[4], scan[0])
        attempts = diagnostics.get("attempts", []) if isinstance(diagnostics, dict) else []
        dns_attempts = [item for item in attempts if item.get("stage") == "DNS Security"]
        execution_state = (
            dns_attempts[-1].get("status") if dns_attempts else
            "NOT_EXECUTED" if isinstance(diagnostics, dict) else "UNKNOWN"
        )
        checked_ids = {row[0] for row in rows if row[1] != "NOT_CHECKED"}
        outcome_counts = {}
        severity_counts = {}
        category_counts = {}
        for row in rows:
            outcome_counts[row[1]] = outcome_counts.get(row[1], 0) + 1
            severity_counts[row[2]] = severity_counts.get(row[2], 0) + 1
            category_counts[row[3]] = category_counts.get(row[3], 0) + 1
        affected_ids = {row[0] for row in rows if row[1] in (
            "CONFIRMED_ISSUE", "POTENTIAL_EXPOSURE", "WARNING"
        )}
        count = len(rows)
        return {
            "answer": (f"Scan #{selected_id} has {len(checked_ids)} assessed eligible assets and "
                       f"{len(eligible - checked_ids)} eligible assets without a completed check; "
                       f"{len(affected_ids)} distinct assets have an issue/exposure/warning outcome."),
            "context": {"scan_id": selected_id, "scan_time": scan[1]},
            "data": {
                "eligible_assets": len(eligible), "checked_assets": len(checked_ids),
                "unchecked_assets": len(eligible - checked_ids), "check_records": count,
                "distinct_affected_assets": len(affected_ids),
                "checks_executed": sum(row[1] != "NOT_CHECKED" for row in rows),
                "outcomes_by_check_record": outcome_counts,
                "severities_by_check_record": severity_counts,
                "categories_by_check_record": category_counts,
                "checks": [{"domain_id": row[0], "asset_class": classes.get(row[0]),
                            "outcome": row[1], "severity": row[2], "check_key": row[3],
                            "target": row[4], "record_type": row[5], "confidence": row[6],
                            "evidence": row[7], "remediation": row[8], "checked_at": row[9]}
                           for row in rows[:100]],
            },
            "coverage": {"execution_state": execution_state,
                         "data_state": "CHECK_RECORDS_PRESENT" if count else "NO_CHECK_RECORDS",
                         "checked_asset_semantics": "Assets with at least one non-NOT_CHECKED record."},
            "limitations": ["No check rows means unassessed, not clear.",
                            "Only the first 100 check records are returned; aggregate counts cover all matching records.",
                            "Historical effective class uses current ownership and trusted-inventory inputs; a historical ownership snapshot is not stored here."],
            "next_actions": ["Review WARNING, POTENTIAL_EXPOSURE, and INCONCLUSIVE records with their stored evidence."],
        }
    finally:
        conn.close()
    
    
