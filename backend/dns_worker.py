import dns.resolver
import socket
import sys
from db import get_conn, require_running_scan
from authorization_policy import passive_dns_discovery_sql

scan_id = int(sys.argv[1])

class PassiveDnsAuthorizationDenied(RuntimeError):
    pass


class PassiveDnsPolicyError(RuntimeError):
    pass


def passive_dns_target_allowed(cur, target_scan_id, domain_id):
    try:
        cur.execute(f"""
        SELECT EXISTS (
            SELECT 1
            FROM domains d
            JOIN scan_results sr
              ON sr.domain_id = d.id
             AND sr.scan_id = %s
            WHERE d.id = %s
              AND {passive_dns_discovery_sql('d', 'sr')}
        )
        """, (target_scan_id, domain_id))
    except Exception as exc:
        # A policy/database failure is not a DNS lookup failure. Let it abort
        # the worker rather than being swallowed by the resolver's error path.
        raise PassiveDnsPolicyError("passive DNS authorization check failed") from exc
    row = cur.fetchone()
    return bool(row and row[0])


def resolve_dns(domain, before_query=None):
    records = []

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 3

        # A record
        try:
            if before_query is not None and not before_query():
                raise PassiveDnsAuthorizationDenied(domain)
            answers = resolver.resolve(domain, "A")
            for r in answers:
                records.append(("A", r.to_text()))
        except PassiveDnsAuthorizationDenied:
            raise
        except PassiveDnsPolicyError:
            raise
        except Exception as e:
            print(f"[A FAIL] {domain} → {e}")

        # CNAME
        try:
            if before_query is not None and not before_query():
                raise PassiveDnsAuthorizationDenied(domain)
            answers = resolver.resolve(domain, "CNAME")
            for r in answers:
                records.append(("CNAME", r.to_text().rstrip(".")))
        except PassiveDnsAuthorizationDenied:
            raise
        except PassiveDnsPolicyError:
            raise
        except Exception as e:
            print(f"[CNAME FAIL] {domain} → {e}")

    except PassiveDnsAuthorizationDenied:
        raise
    except PassiveDnsPolicyError:
        raise
    except Exception as e:
        print(f"[DNS ERROR] {domain} → {e}")

    return records


def reverse_dns(ip, before_query=None):
    if before_query is not None and not before_query():
        raise PassiveDnsAuthorizationDenied(ip)
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
    cur.execute(f"""
    SELECT d.id, d.domain, ds.has_ip
    FROM domains d

    JOIN scan_results sr
      ON d.id = sr.domain_id
      AND sr.scan_id = %s

    JOIN domain_states ds
      ON d.id = ds.domain_id
      AND ds.scan_id = %s

    WHERE {passive_dns_discovery_sql('d', 'sr')}

    """, (scan_id, scan_id))

    rows = cur.fetchall()

    print("📊 Domains fetched:", len(rows))

    if not rows:
        print("⚠️ No domains found. Check domain_states for this scan_id.")
        return

    processed = 0
    inserted = 0
    for domain_id, domain, has_ip in rows:

        if not passive_dns_target_allowed(cur, scan_id, domain_id):
            print(f"Skipping DNS target outside permitted discovery scope: {domain}")
            continue

        def recheck_discovery_scope():
            return passive_dns_target_allowed(cur, scan_id, domain_id)

        print(f"\n🔍 Processing: {domain}")

        try:
            records = resolve_dns(domain, before_query=recheck_discovery_scope)
        except PassiveDnsAuthorizationDenied:
            print(f"DNS discovery authorization changed during resolution: {domain}")
            continue

        print(f"Resolved records: {records}")

        if not records:
            print(f"⛔ No DNS records for {domain}")
            continue

        a_records = sorted({value for rtype, value in records if rtype == "A"})
        ptr_value = None
        if not has_ip and a_records:
            try:
                ptr_value = reverse_dns(
                    a_records[0], before_query=recheck_discovery_scope
                )
            except PassiveDnsAuthorizationDenied:
                print(f"DNS discovery authorization changed before PTR lookup: {domain}")
                continue

        for rtype, value in records:

            print(f"➡️ INSERT: {domain} | {rtype} | {value}")

            cur.execute(f"""
            INSERT INTO domain_dns(domain_id, scan_id, record_type, value)
            SELECT %s, %s, %s, %s
            WHERE EXISTS (
                SELECT 1
                FROM scan_results sr
                JOIN domains d ON d.id = sr.domain_id
                WHERE sr.scan_id = %s
                  AND sr.domain_id = %s
                  AND {passive_dns_discovery_sql('d', 'sr')}
            )
            ON CONFLICT DO NOTHING
            """, (
                domain_id, scan_id, rtype, value,
                scan_id, domain_id,
            ))

            inserted += 1

        if not has_ip and a_records:
            cur.execute(f"""
                UPDATE domain_states
                SET ip = %s,
                    has_ip = TRUE,
                    reverse_dns = COALESCE(%s, reverse_dns)
                WHERE domain_states.domain_id = %s
                AND domain_states.scan_id = %s
                AND domain_states.has_ip IS NOT TRUE
                AND EXISTS (
                    SELECT 1
                    FROM scan_results sr
                    JOIN domains d ON d.id = sr.domain_id
                    WHERE sr.scan_id = domain_states.scan_id
                    AND sr.domain_id = domain_states.domain_id
                    AND {passive_dns_discovery_sql('d', 'sr')}
                )
                """, (
                    a_records[0], ptr_value, domain_id, scan_id,
                ))

        processed += 1

        # 🔥 periodic commit (safe)
        if processed % 50 == 0:
            conn.commit()
            require_running_scan(cur, scan_id)
            print(f"💾 Checkpoint commit at {processed}")

    conn.commit()
    conn.close()

    print("\n✅ DNS enrichment complete")
    print(f"Processed domains: {processed}")
    print(f"Inserted records: {inserted}")


if __name__ == "__main__":
    main()
