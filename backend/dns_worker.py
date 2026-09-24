import dns.resolver
import socket
import sys
from db import get_conn, require_running_scan

scan_id = int(sys.argv[1])

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


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror as e:
        # h_errno 1 (HOST_NOT_FOUND) and 4 (NO_DATA) conclusively mean
        # that no PTR name exists. Other resolver failures are operational.
        if e.errno in (1, 4):
            return "N/A"
        print(f"[PTR FAIL] {ip} → {e}")
        return None
    except (socket.timeout, socket.gaierror, OSError) as e:
        print(f"[PTR FAIL] {ip} → {e}")
        return None


def main():

    conn = get_conn()
    cur = conn.cursor()
    require_running_scan(cur, scan_id)

    print("\n🌐 DNS worker running for scan:", scan_id)

    # 🔥 safer query (do NOT skip everything)
    cur.execute("""
    SELECT d.id, d.domain, ds.has_ip
    FROM domains d

    JOIN scan_results sr
      ON d.id = sr.domain_id
      AND sr.scan_id = %s

    JOIN domain_states ds
      ON d.id = ds.domain_id
      AND ds.scan_id = %s

    """, (scan_id, scan_id))

    rows = cur.fetchall()

    print("📊 Domains fetched:", len(rows))

    if not rows:
        print("⚠️ No domains found. Check domain_states for this scan_id.")
        return

    processed = 0
    inserted = 0
    membership_recheck_required = False

    for domain_id, domain, has_ip in rows:

        # The original candidate list survives checkpoint commits. Once that
        # happens, revalidate each remaining candidate before network work.
        if membership_recheck_required:
            cur.execute("""
            SELECT EXISTS (
                SELECT 1
                FROM scan_results sr
                WHERE sr.scan_id = %s
                AND sr.domain_id = %s
            )
            """, (scan_id, domain_id))
            if not cur.fetchone()[0]:
                print(f"Skipping non-member DNS candidate: {domain}")
                continue

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
            SELECT %s, %s, %s, %s
            WHERE EXISTS (
                SELECT 1
                FROM scan_results sr
                WHERE sr.scan_id = %s
                AND sr.domain_id = %s
            )
            ON CONFLICT DO NOTHING
            """, (
                domain_id, scan_id, rtype, value,
                scan_id, domain_id,
            ))

            inserted += 1

        if not has_ip:
            a_records = sorted({value for rtype, value in records if rtype == "A"})
            if a_records:
                ip = a_records[0]
                cur.execute("""
                UPDATE domain_states
                SET ip = %s,
                    has_ip = TRUE,
                    reverse_dns = COALESCE(%s, reverse_dns)
                WHERE domain_id = %s
                AND scan_id = %s
                AND has_ip IS NOT TRUE
                AND EXISTS (
                    SELECT 1
                    FROM scan_results sr
                    WHERE sr.scan_id = domain_states.scan_id
                    AND sr.domain_id = domain_states.domain_id
                )
                """, (
                    ip, reverse_dns(ip), domain_id, scan_id,
                ))

        processed += 1

        # 🔥 periodic commit (safe)
        if processed % 50 == 0:
            conn.commit()
            require_running_scan(cur, scan_id)
            membership_recheck_required = True
            print(f"💾 Checkpoint commit at {processed}")

    conn.commit()
    conn.close()

    print("\n✅ DNS enrichment complete")
    print(f"Processed domains: {processed}")
    print(f"Inserted records: {inserted}")


if __name__ == "__main__":
    main()
