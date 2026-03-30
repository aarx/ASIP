import psycopg2
from datetime import datetime

def get_conn():
    return psycopg2.connect(
        host="db",
        dbname="asm_db",
        user="asm",
        password="asm123"
    )


SENSITIVE_PORTS = {21,22,23,25,53,110,143,445,3389,3306,8080}


def compute_risk(row):
    risk = 0
    reasons = []

    # 🚫 Skip dead domains entirely
    if not row["has_ip"]:
        return None, None

    # 🌐 HTTP exposure check
    if row["http_status"] == 0:
        risk += 1
        reasons.append("no_http")

    # Sensitive port logic (context-aware)
    if row["sensitive_port"]:
        if row["http_status"] == 0:
            # Infra exposure (e.g., SSH, RDP)
            risk += 3
            reasons.append("infra_exposed_port")
        else:
            # Web + service exposed
            risk += 2
            reasons.append("web_with_sensitive_port")

    # Tech visibility (weak signal)
    if not row["techs"]:
        if risk == 0:
            risk += 1
            reasons.append("unknown_stack")

    # Provider visibility (very weak signal)
    if not row["providers"]:
        if risk == 0:
            risk += 0.5
            reasons.append("unknown_hosting")

    #  SSL expiry (strong signal)
    if row["cert_days"] is not None and row["cert_days"] < 15:
        risk += 2
        reasons.append("cert_expiring")

    # Final cap
    return min(int(risk), 5), ",".join(reasons)

def main():

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT MAX(id) FROM scans")
    scan_id = cur.fetchone()[0]

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

        EXISTS(
            SELECT 1 FROM domain_ports p
            JOIN sensitive_ports sp
            ON p.port = sp.port
            WHERE p.domain_id = d.id
        ) as sensitive_port

    FROM domains d

    LEFT JOIN domain_states ds
        ON d.id = ds.domain_id

    LEFT JOIN domain_provider dp
        ON d.id = dp.domain_id

    LEFT JOIN domain_tech dt
        ON d.id = dt.domain_id

    LEFT JOIN cert_expiry ce
        ON d.id = ce.domain_id
    """)
    
    rows = cur.fetchall()
    
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
                "sensitive_port": False
            }
    
        entry = risk_inputs[domain_id]
    
        # collect multiple values
        if r[4] and r[4] != "Unknown":
            entry["providers"].add(r[4])
    
        if r[5] and r[5] != "unknown":
            entry["techs"].add(r[5])
    
        if r[7]:
            entry["sensitive_port"] = True
    		
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
