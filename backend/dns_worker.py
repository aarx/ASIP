import dns.resolver
import dns.exception
import dns.reversename
import sys
import time
from db import get_conn, require_running_scan
from authorization_policy import passive_dns_discovery_sql
from ownership import normalize_hostname
from stage_progress import emit_stage_progress

scan_id = int(sys.argv[1])
DNS_PROGRESS_INTERVAL_SECONDS = 30


def format_dns_progress(visited, total, records_found, no_records,
                        authorization_skips, elapsed_seconds):
    return (
        f"DNS progress: visited {visited}/{total}; "
        f"records_found_domains={records_found}; no_record_domains={no_records}; "
        f"authorization_skips={authorization_skips}; "
        f"elapsed_seconds={elapsed_seconds:.1f}"
    )

class PassiveDnsAuthorizationDenied(RuntimeError):
    pass


class PassiveDnsPolicyError(RuntimeError):
    pass


def passive_dns_target_allowed(cur, target_scan_id, domain_id, conn):
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
        row = cur.fetchone()
        # psycopg2 starts a transaction for SELECT too. End this read-only
        # authorization transaction before the caller performs network I/O.
        conn.rollback()
    except Exception as exc:
        try:
            conn.rollback()
        except Exception:
            pass
        # A policy/database failure is not a DNS lookup failure. Let it abort
        # the worker rather than being swallowed by the resolver's error path.
        raise PassiveDnsPolicyError("passive DNS authorization check failed") from exc
    return bool(row and row[0])


def resolve_dns(domain, before_query=None):
    records = []
    normalized_domain = normalize_hostname(domain, require_fqdn=True)
    if normalized_domain is None:
        return records
    domain = normalized_domain

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
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 3
        reverse_name = dns.reversename.from_address(ip)
        answers = resolver.resolve(reverse_name, "PTR")
        if not answers:
            return "N/A"
        return answers[0].to_text().rstrip(".")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        # Match gethostbyaddr's previous "no PTR record" result.
        return "N/A"
    except (dns.exception.DNSException, OSError, ValueError) as e:
        print(f"[PTR FAIL] {ip} → {e}")
        return None


def main():
    conn = get_conn()
    try:
        _run_dns_worker(conn)
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        conn.close()


def _run_dns_worker(conn):
    cur = conn.cursor()
    require_running_scan(cur, scan_id)

    print("\n🌐 DNS worker running for scan:", scan_id)
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
    # Release the FOR UPDATE lock from require_running_scan and close the
    # target-selection read transaction before resolver calls begin.
    conn.commit()

    print("📊 Domains fetched:", len(rows))
    if not rows:
        print("⚠️ No domains found. Check domain_states for this scan_id.")
        return

    processed = 0
    inserted = 0
    invalid_hostname_skips = 0
    authorization_skips = 0
    no_record_domains = 0
    visited = 0
    progress_started = time.monotonic()
    last_progress = progress_started

    def report_progress(force=False):
        nonlocal last_progress
        now = time.monotonic()
        if force or now - last_progress >= DNS_PROGRESS_INTERVAL_SECONDS:
            print(format_dns_progress(
                visited, len(rows), processed, no_record_domains,
                authorization_skips, now - progress_started,
            ))
            emit_stage_progress(
                scan_id, "DNS Resolution", selected=len(rows), total=len(rows),
                processed=visited, completed=visited, succeeded=processed,
                failed=0, skipped=authorization_skips + invalid_hostname_skips,
                elapsed_seconds=now - progress_started,
            )
            last_progress = now

    report_progress(force=True)
    for domain_id, domain, has_ip in rows:
        visited += 1
        normalized_domain = normalize_hostname(domain, require_fqdn=True)
        if normalized_domain is None:
            invalid_hostname_skips += 1
            report_progress()
            continue
        domain = normalized_domain

        if not passive_dns_target_allowed(cur, scan_id, domain_id, conn):
            print(f"Skipping DNS target outside permitted discovery scope: {domain}")
            authorization_skips += 1
            report_progress()
            continue

        def recheck_discovery_scope():
            return passive_dns_target_allowed(cur, scan_id, domain_id, conn)

        print(f"\n🔍 Processing: {domain}")
        try:
            records = resolve_dns(domain, before_query=recheck_discovery_scope)
        except PassiveDnsAuthorizationDenied:
            print(f"DNS discovery authorization changed during resolution: {domain}")
            authorization_skips += 1
            report_progress()
            continue

        print(f"Resolved records: {records}")
        if not records:
            print(f"⛔ No DNS records for {domain}")
            no_record_domains += 1
            report_progress()
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
                authorization_skips += 1
                report_progress()
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
        # Keep all DNS rows and the corresponding state update for this
        # hostname atomic, and release FK/row locks before the next lookup.
        conn.commit()
        if processed % 50 == 0:
            require_running_scan(cur, scan_id)
            conn.commit()
            print(f"💾 Checkpoint commit at {processed}")
        report_progress()

    print("\n✅ DNS enrichment complete")
    print(f"Processed domains: {processed}")
    print(f"Inserted records: {inserted}")
    if invalid_hostname_skips:
        print(
            "Skipped invalid DNS hostnames before resolver calls: "
            f"{invalid_hostname_skips}"
        )
    report_progress(force=True)

if __name__ == "__main__":
    main()
