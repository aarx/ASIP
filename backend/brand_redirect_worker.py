"""Run bounded redirect observations for provenance-linked Candidates."""

import json
import logging
import sys
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

from psycopg2.extras import register_uuid

from authorization_policy import default_operation_enabled
from brand_redirect_intelligence import (
    BRAND_DISCOVERY_SOURCES,
    BRAND_REDIRECT_SCOPE,
    EVIDENCE_SOURCE,
    MAX_CONCURRENCY,
    MAX_REQUESTS_PER_SCAN,
    RequestBudgetExceeded,
    observe_redirect_chain,
)
from db import get_conn, require_running_scan
from ownership import normalize_hostname, reporting_asset_class_sql


logger = logging.getLogger("brand_redirect_intelligence")
logging.basicConfig(level=logging.INFO, format="%(message)s")
register_uuid()


def _exclusion_sql(domain_expression):
    """Keep legacy explicit campaign exclusions as deny-only rules."""
    canonical = f"LOWER(TRIM(TRAILING '.' FROM {domain_expression}))"
    return f"""
        EXISTS (
            SELECT 1
              FROM active_scan_scopes scope_block
              CROSS JOIN LATERAL unnest(scope_block.excluded_domains)
                    AS excluded(domain)
             WHERE scope_block.testing_level = '{BRAND_REDIRECT_SCOPE}'
               AND scope_block.status = 'ACTIVE'
               AND (scope_block.expires_at IS NULL
                    OR scope_block.expires_at > CURRENT_TIMESTAMP)
               AND (
                    {canonical} = LOWER(TRIM(TRAILING '.' FROM excluded.domain))
                    OR RIGHT(
                        {canonical},
                        LENGTH(LOWER(TRIM(TRAILING '.' FROM excluded.domain))) + 1
                    ) = '.' || LOWER(TRIM(TRAILING '.' FROM excluded.domain))
               )
        )
    """


def select_targets(scan_id):
    """Select only current-scan Candidates with brand discovery provenance.

    ``domain_sources.seed`` records which configured discovery input produced
    each result. Database trusted seeds are not joined and do not become
    discovery inputs. Brand TLD/pattern provenance also permits related
    lookalikes outside the seed's DNS suffix.
    """
    if not default_operation_enabled(BRAND_REDIRECT_SCOPE):
        return []

    conn = get_conn()
    try:
        cur = conn.cursor()
        require_running_scan(cur, scan_id)
        reporting_class = reporting_asset_class_sql("d.domain", "d.ownership_status")
        cur.execute(f"""
            SELECT d.id, d.domain,
                   array_agg(DISTINCT source.source ORDER BY source.source),
                   array_agg(DISTINCT BTRIM(source.seed) ORDER BY BTRIM(source.seed))
              FROM scan_results sr
              JOIN domains d ON d.id = sr.domain_id
              JOIN domain_sources source
                ON source.scan_id = sr.scan_id
               AND source.domain_id = sr.domain_id
             WHERE sr.scan_id = %s
               AND ({reporting_class}) = 'CANDIDATE'
               AND NOT COALESCE(
                   'manually rejected' = ANY(d.confidence_reasons), FALSE
               )
               AND source.source = ANY(%s)
               AND NULLIF(BTRIM(source.seed), '') IS NOT NULL
               AND NOT ({_exclusion_sql('d.domain')})
             GROUP BY d.id, d.domain
             ORDER BY d.id
             LIMIT %s
        """, (int(scan_id), list(BRAND_DISCOVERY_SOURCES), MAX_REQUESTS_PER_SCAN))
        selected = []
        for domain_id, domain, sources, seeds in cur.fetchall():
            hostname = normalize_hostname(domain, require_fqdn=True)
            if hostname:
                selected.append((
                    domain_id, domain, f"https://{hostname}/",
                    list(sources or ()), list(seeds or ()),
                ))
        conn.rollback()
        return selected
    finally:
        conn.close()


class _RequestBudget:
    """Thread-safe deployment-wide request counter for one scan stage."""

    def __init__(self, limit=MAX_REQUESTS_PER_SCAN):
        self.limit = min(MAX_REQUESTS_PER_SCAN, max(0, int(limit)))
        self.used = 0
        self.lock = threading.Lock()

    def reserve(self):
        with self.lock:
            if self.used >= self.limit:
                raise RequestBudgetExceeded("brand redirect request budget exhausted")
            self.used += 1


def _run_target(row, scan_id, operation_id, request_budget):
    domain_id, domain, initial_url, discovery_sources, discovery_seeds = row
    conn = get_conn()
    try:
        cur = conn.cursor()
        def authorize(origin):
            # Redirect destinations need no ownership or DNS-suffix grant.
            # Each request still rechecks the enabled operation, the current
            # Candidate's scan provenance, explicit exclusions, and manual
            # rejections. IP and URL safety are independently enforced by the
            # observer immediately before connecting.
            if not default_operation_enabled(BRAND_REDIRECT_SCOPE):
                return False
            try:
                parsed = urlsplit(origin)
                if parsed.scheme not in {"http", "https"} or parsed.port not in (
                    None, 80 if parsed.scheme == "http" else 443
                ):
                    return False
                target_host = normalize_hostname(parsed.hostname, require_fqdn=True)
            except (TypeError, ValueError):
                return False
            if target_host is None:
                return False

            reporting_class = reporting_asset_class_sql(
                "candidate.domain", "candidate.ownership_status"
            )
            cur.execute(f"""
                SELECT 1
                  FROM scans scan
                  JOIN scan_results sr
                    ON sr.scan_id = scan.id AND sr.domain_id = %s
                  JOIN domains candidate ON candidate.id = sr.domain_id
                 WHERE scan.id = %s AND scan.status = 'RUNNING'
                   AND ({reporting_class}) = 'CANDIDATE'
                   AND NOT COALESCE(
                       'manually rejected' = ANY(candidate.confidence_reasons), FALSE
                   )
                   AND EXISTS (
                        SELECT 1 FROM domain_sources source
                         WHERE source.scan_id = sr.scan_id
                           AND source.domain_id = sr.domain_id
                           AND source.source = ANY(%s)
                           AND NULLIF(BTRIM(source.seed), '') IS NOT NULL
                   )
                   AND NOT ({_exclusion_sql('%s')})
                   AND NOT EXISTS (
                       SELECT 1 FROM domains rejected_destination
                        WHERE LOWER(TRIM(TRAILING '.' FROM rejected_destination.domain)) = %s
                          AND COALESCE(
                              'manually rejected' = ANY(rejected_destination.confidence_reasons),
                              FALSE
                          )
                   )
                 LIMIT 1
            """, (
                domain_id, int(scan_id), list(BRAND_DISCOVERY_SOURCES),
                target_host, target_host, target_host,
            ))
            return cur.fetchone() is not None

        evidence = observe_redirect_chain(
            domain,
            initial_url,
            scan_id=scan_id,
            operation_id=operation_id,
            authorize=authorize,
            on_request=request_budget.reserve,
        )
        evidence.update({
            "monitoring_policy": "deployment_default_brand_provenance",
            "discovery_sources": discovery_sources,
            "discovery_seeds": discovery_seeds,
            "request_budget": MAX_REQUESTS_PER_SCAN,
        })
        require_running_scan(cur, scan_id)
        cur.execute("""
            INSERT INTO brand_redirect_observations (
                scan_id, domain_id, operation_id, evidence_source,
                completeness, evidence
            ) VALUES (%s, %s, %s, %s, %s, %s::jsonb)
        """, (
            scan_id, domain_id, operation_id, EVIDENCE_SOURCE,
            evidence["completeness"], json.dumps(evidence, separators=(",", ":")),
        ))
        conn.commit()
        return evidence["completeness"]
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def run(scan_id):
    operation_id = uuid.uuid4()
    if not default_operation_enabled(BRAND_REDIRECT_SCOPE):
        return {
            "scan_id": int(scan_id), "operation_id": str(operation_id),
            "selected": 0, "completed": 0,
            "disabled_reason": "deployment operation policy does not enable brand redirect observation",
        }

    rows = select_targets(scan_id)
    if not rows:
        return {
            "scan_id": int(scan_id), "operation_id": str(operation_id),
            "selected": 0, "completed": 0,
            "request_budget": MAX_REQUESTS_PER_SCAN,
            "disabled_reason": "no current Candidate members have brand_tld or brand_pattern provenance",
        }

    request_budget = _RequestBudget()
    with ThreadPoolExecutor(
        max_workers=MAX_CONCURRENCY,
        thread_name_prefix="brand-redirect",
    ) as executor:
        states = list(executor.map(
            lambda row: _run_target(row, scan_id, operation_id, request_budget),
            rows,
        ))
    counts = {state: states.count(state) for state in sorted(set(states))}
    summary = {
        "scan_id": int(scan_id), "operation_id": str(operation_id),
        "selected": len(rows), "completed": len(states),
        "concurrency_limit": MAX_CONCURRENCY,
        "request_budget": MAX_REQUESTS_PER_SCAN,
        "requests_attempted": request_budget.used,
        "completeness": counts,
    }
    logger.info("brand_redirect_stage_summary %s", json.dumps(summary, separators=(",", ":")))
    return summary


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1 or not args[0].isdigit():
        raise SystemExit("Usage: python -u brand_redirect_worker.py <scan_id>")
    print(json.dumps(run(int(args[0])), separators=(",", ":")))


if __name__ == "__main__":
    main()
