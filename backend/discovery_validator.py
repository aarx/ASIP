import psycopg2
import logging
import os
import sys

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

def get_conn():
    return psycopg2.connect(
        host="db",
        dbname="asm_db",
        user="asm",
        password="asm123"
    )


def extract_keywords(seeds):
    keywords = set()
    for s in seeds:
        root = s.split(".")[0]
        keywords.add(root.lower())
    return list(keywords)


def compute_score(domain, data, keywords):
    score = 0
    reasons = []

    # 1. Name similarity
    for k in keywords:
        if k in domain:
            score += 3
            reasons.append(f"contains keyword '{k}'")
            break

    # 2. SAN relation
    if data["san_related"]:
        score += 4
        reasons.append("SAN match with known domain")

    # 3. IP match
    if data["same_ip"]:
        score += 3
        reasons.append("shares IP with known asset")

    # 4. ASN/provider match
    if data["same_provider"]:
        score += 2
        reasons.append("same ASN/provider")

    # 5. Tech similarity
    if data["same_tech"]:
        score += 1
        reasons.append("similar tech stack")

    # 6. Reverse DNS
    if data["rdns_match"]:
        score += 2
        reasons.append("reverse DNS indicates relation")

    # fallback
    if score == 0:
        reasons.append("no correlation signals")

    return score, reasons


def label(score):
    if score >= 7:
        return "high"
    elif score >= 4:
        return "medium"
    else:
        return "low"


def main():

    conn = get_conn()
    cur = conn.cursor()

    print("Running discovery validator for scan:", scan_id)

    # load seeds
    cur.execute("SELECT domain FROM seed_domains")
    seeds = [r[0].strip().lower() for r in cur.fetchall()]
    keywords = extract_keywords(seeds)

    print("Keywords:", keywords)

    # fetch candidates
    cur.execute("""
    SELECT 
        d.id,
        d.domain,

        EXISTS(
            SELECT 1 
            FROM domain_san ds
            JOIN domains d2 ON d2.id = ds.domain_id
            WHERE ds.domain_id = d.id
            AND d2.scannable = TRUE
        ) as san_related,

        EXISTS(
            SELECT 1 FROM domain_states s1
            JOIN domain_states s2
              ON s1.ip = s2.ip
            JOIN domains d2 ON d2.id = s2.domain_id
            WHERE s1.domain_id = d.id
            AND d2.scannable = TRUE
            AND s1.scan_id = %s
            AND s2.scan_id = %s
        ) as same_ip,

        EXISTS(
            SELECT 1 FROM domain_provider p1
            JOIN domain_provider p2
              ON p1.provider = p2.provider
            JOIN domains d2 ON d2.id = p2.domain_id
            WHERE p1.domain_id = d.id
            AND d2.scannable = TRUE
            AND p1.scan_id = %s
            AND p2.scan_id = %s
        ) as same_provider,

        EXISTS(
            SELECT 1 FROM domain_tech t1
            JOIN domain_tech t2
              ON t1.tech = t2.tech
            JOIN domains d2 ON d2.id = t2.domain_id
            WHERE t1.domain_id = d.id
            AND d2.scannable = TRUE
            AND t1.scan_id = %s
            AND t2.scan_id = %s
        ) as same_tech,

        EXISTS(
            SELECT 1 FROM domain_states s
            WHERE s.domain_id = d.id
            AND s.reverse_dns ILIKE ANY(%s)
            AND s.scan_id = %s
        ) as rdns_match

    FROM domains d
    WHERE d.scannable = FALSE
    """, (
        scan_id, scan_id,
        scan_id, scan_id,
        scan_id, scan_id,
        [f"%{k}%" for k in keywords], scan_id
    ))

    rows = cur.fetchall()

    print("Domains to score:", len(rows))

    count = 0

    for r in rows:
        domain_id = r[0]
        domain = r[1]

        data = {
            "san_related": r[2],
            "same_ip": r[3],
            "same_provider": r[4],
            "same_tech": r[5],
            "rdns_match": r[6],
        }
        
        cur.execute("SELECT validation_source FROM domains WHERE id = %s", (domain_id,))
        source = cur.fetchone()[0]
    
        if source == "manual":
            print(f"Skipping manual domain: {domain}")
            continue        

        score, reasons = compute_score(domain, data, keywords)
        lbl = label(score)

        cur.execute("""
        UPDATE domains
        SET confidence_score = %s,
            confidence_label = %s,
            confidence_reasons = %s
        WHERE id = %s
        """, (score, lbl, reasons, domain_id))

        count += 1

        if count % 100 == 0:
            print("Processed:", count)

    conn.commit()
    conn.close()

    print("Discovery validation complete:", count)


if __name__ == "__main__":
    main()
