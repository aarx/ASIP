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

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 3

        # A record
        try:
            answers = resolver.resolve(domain, "A")
            for r in answers:
                records.append(("A", r.to_text()))
        except Exception as e:
            print(f"[A FAIL] {domain} → {e}")

        # CNAME
        try:
            answers = resolver.resolve(domain, "CNAME")
            for r in answers:
                records.append(("CNAME", r.to_text().rstrip(".")))
        except Exception as e:
            print(f"[CNAME FAIL] {domain} → {e}")

    except Exception as e:
        print(f"[DNS ERROR] {domain} → {e}")

    return records


def main():

    conn = get_conn()
    cur = conn.cursor()

    print("\n🌐 DNS worker running for scan:", scan_id)

    # 🔥 safer query (do NOT skip everything)
    cur.execute("""
    SELECT d.id, d.domain
    FROM domains d

    JOIN domain_states ds
      ON d.id = ds.domain_id
      AND ds.scan_id = %s

    WHERE ds.has_ip = TRUE
    """, (scan_id,))

    rows = cur.fetchall()

    print("📊 Domains fetched:", len(rows))

    if not rows:
        print("⚠️ No domains found. Check domain_states for this scan_id.")
        return

    processed = 0
    inserted = 0

    for domain_id, domain in rows:

        print(f"\n🔍 Processing: {domain}")

        records = resolve_dns(domain)

        print(f"Resolved records: {records}")

        if not records:
            print(f"⛔ No DNS records for {domain}")
            continue

        for rtype, value in records:

            print(f"➡️ INSERT: {domain} | {rtype} | {value}")

            cur.execute("""
            INSERT INTO domain_dns(domain_id, scan_id, record_type, value)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT DO NOTHING
            """, (domain_id, scan_id, rtype, value))

            inserted += 1

        processed += 1

        # 🔥 periodic commit (safe)
        if processed % 50 == 0:
            conn.commit()
            print(f"💾 Checkpoint commit at {processed}")

    conn.commit()
    conn.close()

    print("\n✅ DNS enrichment complete")
    print(f"Processed domains: {processed}")
    print(f"Inserted records: {inserted}")


if __name__ == "__main__":
    main()
