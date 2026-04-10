import psycopg2
import dns.resolver
import sys

scan_id = int(sys.argv[1])


def get_conn():
    return psycopg2.connect(
        host="db",
        dbname="asm_db",
        user="asm",
        password="asm123"
    )


def resolve_dns(domain):

    records = []

    # A record
    try:
        answers = dns.resolver.resolve(domain, "A")
        for r in answers:
            records.append(("A", r.to_text()))
    except:
        pass

    # CNAME
    try:
        answers = dns.resolver.resolve(domain, "CNAME")
        for r in answers:
            records.append(("CNAME", r.to_text().rstrip(".")))
    except:
        pass

    return records


def main():

    conn = get_conn()
    cur = conn.cursor()

    print("DNS worker running for scan:", scan_id)

    cur.execute("""
    SELECT d.id, d.domain
    FROM domains d

    JOIN domain_states ds
      ON d.id = ds.domain_id
      AND ds.scan_id = %s

    LEFT JOIN domain_dns dd
      ON d.id = dd.domain_id
      AND dd.scan_id = %s

    WHERE ds.has_ip = TRUE
    AND dd.domain_id IS NULL
    """, (scan_id, scan_id))

    rows = cur.fetchall()

    print("Domains to process:", len(rows))

    for domain_id, domain in rows:

        print("Resolving:", domain)

        records = resolve_dns(domain)

        for rtype, value in records:

            cur.execute("""
            INSERT INTO domain_dns(domain_id, scan_id, record_type, value)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT DO NOTHING
            """, (domain_id, scan_id, rtype, value))

    conn.commit()
    conn.close()

    print("DNS enrichment complete")


if __name__ == "__main__":
    main()
