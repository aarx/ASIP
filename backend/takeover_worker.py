import psycopg2
import requests
import sys
import dns.resolver

scan_id = int(sys.argv[1])


def get_conn():
    return psycopg2.connect(
        host="db",
        dbname="asm_db",
        user="asm",
        password="asm123"
    )


def get_live_cname(domain):
    try:
        answers = dns.resolver.resolve(domain, "CNAME")
        for r in answers:
            return r.to_text().rstrip(".")
    except:
        return None
    return None


# 🔥 fingerprints
FINGERPRINTS = {
    "aws": [
        "NoSuchBucket",
        "The specified bucket does not exist"
    ],
    "github": [
        "There isn't a GitHub Pages site here"
    ],
    "heroku": [
        "No such app"
    ],
    "shopify": [
        "Sorry, this shop is currently unavailable"
    ],
    "azure": [
        "404 Web Site not found"
    ],
    "gcp": [
        "Error 404 (Not Found)"
    ],
    "fastly": [
        "Fastly error: unknown domain"
    ],
    "netlify": [
        "Not Found - Request ID"
    ],
    "vercel": [
        "The deployment could not be found"
    ],
}


def identify_provider(cname):

    cname = cname.lower()

    if "amazonaws.com" in cname:
        return "aws"
    if "github.io" in cname:
        return "github"
    if "herokuapp.com" in cname:
        return "heroku"
    if "shopify.com" in cname:
        return "shopify"
    if "azurewebsites.net" in cname or "cloudapp.net" in cname:
        return "azure"
    if "googleusercontent.com" in cname or "appspot.com" in cname:
        return "gcp"
    if "fastly.net" in cname:
        return "fastly"
    if "cloudflare.net" in cname:
        return "cloudflare"
    if "netlify.app" in cname:
        return "netlify"
    if "vercel.app" in cname:
        return "vercel"
    if "lync.com" in cname or "microsoft.com" in cname:
        return "microsoft"

    return None


def check_takeover(target):

    for scheme in ["https", "http"]:
        try:
            r = requests.get(f"{scheme}://{target}", timeout=5)

            return {
                "body": r.text,
                "status": r.status_code,
                "length": len(r.text)
            }

        except:
            continue

    return {
        "body": "",
        "status": 0,
        "length": 0
    }


def main():

    conn = get_conn()
    cur = conn.cursor()

    print("Takeover scan for scan_id:", scan_id)

    cur.execute("""
    SELECT d.id, d.domain, dd.value
    FROM domain_dns dd
    JOIN domains d ON d.id = dd.domain_id
    WHERE dd.scan_id = %s
    AND dd.record_type = 'CNAME'
    AND d.scannable = TRUE   
    """, (scan_id,))

    rows = cur.fetchall()

    print("Domains to check:", len(rows))

    for domain_id, domain, cname in rows:

        live_cname = get_live_cname(domain)

        print(f"{domain} → DB: {cname} → LIVE: {live_cname}")

        if not live_cname or live_cname != cname:
            print(f"Skipping {domain} → DNS mismatch")
            continue

        provider = identify_provider(cname)

        print(f"{domain} → Provider: {provider}")

        if not provider:
            continue

        print(f"Checking {domain}")

        resp = check_takeover(domain)

        body = resp["body"]
        status = resp["status"]
        length = resp["length"]

        print(f"{domain} → status: {status}, length: {length}")

        # 🔥 HIGH confidence (fingerprints)
        fingerprints = FINGERPRINTS.get(provider, [])

        found = False

        for fp in fingerprints:
            if fp.lower() in body.lower():

                print(f"🚨 HIGH: TAKEOVER → {domain}")

                cur.execute("""
                INSERT INTO domain_findings(domain_id, scan_id, finding, severity, evidence)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (domain_id, scan_id, finding) DO NOTHING
                """, (
                    domain_id,
                    scan_id,
                    "dangling_dns",
                    "HIGH",
                    fp
                ))

                found = True
                break

        # 🔥 MEDIUM / LOW signals
        if not found:
        
            severity = None
        
            if status in [404, 410]:
                print(f"⚠️ MEDIUM: suspicious status → {domain}")
                severity = "MEDIUM"
        
            elif length < 50:
                print(f"⚠️ LOW: suspicious dns empty → {domain}")
                severity = "LOW"
        
            # only insert if we actually flagged something
            if severity:
                cur.execute("""
                INSERT INTO domain_findings(domain_id, scan_id, finding, severity, evidence)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (domain_id, scan_id, finding) DO NOTHING
                """, (
                    domain_id,
                    scan_id,
                    "suspicious_dns",
                    severity,
                    f"status={status}, length={length}"
                ))

    conn.commit()
    conn.close()

    print("Takeover detection complete")


if __name__ == "__main__":
    main()
