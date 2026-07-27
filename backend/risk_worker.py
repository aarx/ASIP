from datetime import datetime
import logging
import os
import sys
from db import get_conn

scan_id = int(sys.argv[1])

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/app.log"),
        logging.StreamHandler()
    ]
)


SENSITIVE_PORTS = {21,22,23,25,53,110,143,445,3389,3306,8080}


def compute_risk(row):
    risk = 0
    reasons = []

    # 🚫 Skip dead domains entirely
    if not row["has_ip"]:
        return None, None

    # 🌐 HTTP signal (minor)
    if row["http_status"] == 0:
        risk += 1
        reasons.append("no_http")

    # 🔥 Sensitive port = PRIMARY signal
    port_score = row.get("sensitive_port_score", 0)

    if port_score > 0:

        # base severity (independent of HTTP)
        base = min(port_score / 2, 4)   # normalize
        risk += base
        reasons.append("sensitive_port_exposed")

        # critical ports (DB, RDP, FTP etc.)
        if port_score >= 9:
            risk += 1.5
            reasons.append("critical_port_exposed")

        # small context boost (not dominant)
        if row["http_status"] > 0:
            risk += 0.5
            reasons.append("web_entrypoint_present")
        else:
            risk += 0.5
            reasons.append("infra_only_exposure")

    # Tech visibility (weak)
    if not row["techs"]:
        if risk == 0:
            risk += 1
            reasons.append("unknown_stack")

    # Provider visibility (very weak)
    if not row["providers"]:
        if risk == 0:
            risk += 0.5
            reasons.append("unknown_hosting")

    # SSL expiry
    if row["cert_days"] is not None and row["cert_days"] < 15:
        risk += 2
        reasons.append("cert_expiring")
    # Sensitive port exposed + Unknown tech    
    if port_score >= 9 and not row["techs"]:
        risk += 1
        reasons.append("high_risk_unknown_service")											   
												   
    return min(int(risk), 5), ",".join(reasons)

def main():

    conn = get_conn()
    cur = conn.cursor()

    print("Computing risk for scan:", scan_id)

    cur.execute("""
    SELECT 
        d.id,
        d.domain,
        ds.has_ip,
        ds.http_status,
        COALESCE(dp.provider,'Unknown'),
        COALESCE(dt.tech,'unknown'),
        ce.days_to_expiry,
    
        COALESCE((
            SELECT MAX(sp.risk)
            FROM domain_ports p
            JOIN sensitive_ports sp
              ON p.port = sp.port
            WHERE p.domain_id = d.id
            AND p.scan_id = %s
        ), 0) as sensitive_port_score
    
    FROM domains d
    
    LEFT JOIN domain_states ds
        ON d.id = ds.domain_id
        AND ds.scan_id = %s  
    
    LEFT JOIN domain_provider dp
        ON d.id = dp.domain_id
        AND dp.scan_id = %s  
    
    LEFT JOIN domain_tech dt
        ON d.id = dt.domain_id
        AND dt.scan_id = %s   
    
    LEFT JOIN cert_expiry ce
        ON d.id = ce.domain_id
        AND ce.scan_id = %s
        
    WHERE ds.has_ip = TRUE
    
    """, (scan_id, scan_id, scan_id, scan_id, scan_id))   
    
    rows = cur.fetchall()
    
    print("Rows fetched for risk:", len(rows))
    
    risk_inputs = {}
    
    for r in rows:
    
        domain_id = r[0]
    
        if domain_id not in risk_inputs:
            risk_inputs[domain_id] = {
                "has_ip": r[2],
                "http_status": r[3],
                "providers": set(),
                "techs": set(),
                "cert_days": r[6],
                "sensitive_port_score": 0
            }
    
        entry = risk_inputs[domain_id]
    
        # collect multiple values
        if r[4] and r[4] != "Unknown":
            entry["providers"].add(r[4])
    
        if r[5] and r[5] != "unknown":
            entry["techs"].add(r[5])
    
        if r[7]:
            entry["sensitive_port_score"] = max(entry["sensitive_port_score"], r[7])
    		
    count = 0
    
    for domain_id, data in risk_inputs.items():
    
        risk, reasons = compute_risk(data)
        
        if risk is None:
            continue
    
        cur.execute("""
        INSERT INTO domain_risk(domain_id, scan_id, risk_score, reasons)
        VALUES (%s,%s,%s,%s)
        ON CONFLICT(domain_id,scan_id)
        DO UPDATE SET
            risk_score = EXCLUDED.risk_score,
            reasons = EXCLUDED.reasons
        """, (domain_id, scan_id, risk, reasons))
    
        count += 1
    
        if count % 200 == 0:
            print("Processed:", count)
    
        
    conn.commit()
    conn.close()

    print("Risk computation complete:", count)


if __name__ == "__main__":
    main()
