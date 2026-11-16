"""Execute one explicitly approved Brand Redirect monitoring campaign."""

import json
import logging
import sys
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

from authorization_policy import SCOPE_STATUS_ACTIVE
from brand_redirect_intelligence import (
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


_CAMPAIGN_FIELDS = """
    NULLIF(BTRIM(scope.monitoring_purpose), '') IS NOT NULL
    AND COALESCE(cardinality(scope.eligible_discovery_sources), 0) > 0
    AND scope.eligible_discovery_sources <@ ARRAY['brand_tld', 'brand_pattern']::text[]
    AND scope.max_requests_per_scan BETWEEN 1 AND 100000
"""


def _active_campaigns(cur):
    cur.execute(f"""
        SELECT scope.id, scope.scope_domain, scope.include_subdomains,
               scope.excluded_domains, scope.eligible_discovery_sources,
               scope.max_requests_per_scan, scope.monitoring_purpose
          FROM active_scan_scopes scope
         WHERE scope.testing_level = %s
           AND scope.status = %s
           AND (scope.expires_at IS NULL OR scope.expires_at > CURRENT_TIMESTAMP)
           AND ({_CAMPAIGN_FIELDS})
         ORDER BY scope.id
         LIMIT 2
    """, (BRAND_REDIRECT_SCOPE, SCOPE_STATUS_ACTIVE))
    return cur.fetchall()


def select_targets(scan_id, *, include_campaign=False):
    """Select Candidates by campaign scope and configured discovery sources.

    An incomplete legacy Brand Redirect scope is not a campaign and grants no
    requests. Multiple active campaigns fail closed until orchestration can
    account for their separate budgets without ambiguity.
    """
    conn = get_conn()
    try:
        cur = conn.cursor()
        require_running_scan(cur, scan_id)
        campaigns = _active_campaigns(cur)
        if len(campaigns) != 1:
            conn.rollback()
            return ([], None) if include_campaign else []
        campaign = campaigns[0]
        campaign_id, _root, _subs, exclusions, sources, request_budget, _purpose = campaign
        classification = reporting_asset_class_sql("d.domain", "d.ownership_status")
        cur.execute(f"""
            SELECT DISTINCT d.id, d.domain
              FROM scan_results sr
              JOIN domains d ON d.id = sr.domain_id
              JOIN active_scan_scopes scope ON scope.id = %s
             WHERE sr.scan_id = %s
               AND ({classification}) = 'CANDIDATE'
               AND NOT COALESCE(
                   'manually rejected' = ANY(d.confidence_reasons), FALSE
               )
               AND scope.testing_level = %s
               AND scope.status = %s
               AND (scope.expires_at IS NULL OR scope.expires_at > CURRENT_TIMESTAMP)
               AND ({_CAMPAIGN_FIELDS})
               AND NOT EXISTS (
                    SELECT 1 FROM unnest(scope.excluded_domains) excluded(domain)
                     WHERE LOWER(TRIM(TRAILING '.' FROM d.domain))
                               = LOWER(TRIM(TRAILING '.' FROM excluded.domain))
                        OR RIGHT(LOWER(TRIM(TRAILING '.' FROM d.domain)),
                                 LENGTH(LOWER(TRIM(TRAILING '.' FROM excluded.domain))) + 1)
                               = '.' || LOWER(TRIM(TRAILING '.' FROM excluded.domain))
               )
               AND NOT EXISTS (
                    SELECT 1 FROM active_scan_scopes revoked
                     WHERE revoked.testing_level = %s
                       AND revoked.status = 'REVOKED'
                       AND (
                            LOWER(TRIM(TRAILING '.' FROM d.domain)) = revoked.scope_domain
                            OR (revoked.include_subdomains AND RIGHT(
                                LOWER(TRIM(TRAILING '.' FROM d.domain)),
                                LENGTH(revoked.scope_domain) + 1
                            ) = '.' || revoked.scope_domain)
                       )
               )
               AND EXISTS (
                    SELECT 1 FROM domain_sources source
                     WHERE source.scan_id = sr.scan_id
                       AND source.domain_id = sr.domain_id
                       AND source.source = ANY(scope.eligible_discovery_sources)
                       AND LOWER(TRIM(TRAILING '.' FROM BTRIM(source.seed)))
                           = scope.scope_domain
               )
             ORDER BY d.id
             LIMIT %s
        """, (campaign_id, scan_id, BRAND_REDIRECT_SCOPE,
              SCOPE_STATUS_ACTIVE, BRAND_REDIRECT_SCOPE, request_budget))
        selected = []
        for domain_id, domain in cur.fetchall():
            hostname = normalize_hostname(domain, require_fqdn=True)
            if hostname:
                selected.append((domain_id, domain, f"https://{hostname}/"))
        conn.rollback()
        return (selected, campaign) if include_campaign else selected
    finally:
        conn.close()


class _RequestBudget:
    """Thread-safe campaign-wide request counter for one scan operation."""

    def __init__(self, limit):
        self.limit = min(MAX_REQUESTS_PER_SCAN, max(0, int(limit)))
        self.used = 0
        self.lock = threading.Lock()

    def reserve(self):
        with self.lock:
            if self.used >= self.limit:
                raise RequestBudgetExceeded("campaign request budget exhausted")
            self.used += 1


def _run_target(row, scan_id, operation_id, campaign, request_budget):
    domain_id, domain, initial_url = row
    campaign_id, campaign_root, _subs, _excluded, sources, request_limit, purpose = campaign
    conn = get_conn()
    try:
        cur = conn.cursor()
        candidate_class = reporting_asset_class_sql(
            "candidate.domain", "candidate.ownership_status"
        )

        def authorize(origin):
            # Redirect destinations are not required to be owned or separately
            # scoped. They remain subject to the approved campaign exclusions,
            # explicit manual rejection, current Candidate grant, and the
            # observer's independent URL/IP safety checks.
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
            cur.execute(f"""
                SELECT 1
                  FROM scans scan
                  JOIN scan_results sr
                    ON sr.scan_id = scan.id AND sr.domain_id = %s
                  JOIN domains candidate ON candidate.id = sr.domain_id
                  JOIN active_scan_scopes scope ON scope.id = %s
                 WHERE scan.id = %s AND scan.status = 'RUNNING'
                   AND ({candidate_class}) = 'CANDIDATE'
                   AND NOT COALESCE(
                       'manually rejected' = ANY(candidate.confidence_reasons), FALSE
                   )
                   AND scope.testing_level = %s AND scope.status = %s
                   AND (scope.expires_at IS NULL OR scope.expires_at > CURRENT_TIMESTAMP)
                   AND ({_CAMPAIGN_FIELDS})
                   AND EXISTS (
                        SELECT 1 FROM domain_sources source
                         WHERE source.scan_id = sr.scan_id
                           AND source.domain_id = sr.domain_id
                           AND source.source = ANY(scope.eligible_discovery_sources)
                           AND LOWER(TRIM(TRAILING '.' FROM BTRIM(source.seed)))
                               = scope.scope_domain
                   )
                   AND NOT EXISTS (
                        SELECT 1 FROM unnest(scope.excluded_domains) excluded(domain)
                         WHERE LOWER(TRIM(TRAILING '.' FROM excluded.domain)) = %s
                            OR RIGHT(%s, LENGTH(LOWER(TRIM(TRAILING '.' FROM excluded.domain))) + 1)
                               = '.' || LOWER(TRIM(TRAILING '.' FROM excluded.domain))
                   )
                   AND NOT EXISTS (
                        SELECT 1 FROM active_scan_scopes revoked
                         WHERE revoked.testing_level = %s
                           AND revoked.status = 'REVOKED'
                           AND (
                                %s = revoked.scope_domain
                                OR (revoked.include_subdomains AND RIGHT(
                                    %s, LENGTH(revoked.scope_domain) + 1
                                ) = '.' || revoked.scope_domain)
                           )
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM domains rejected_destination
                        WHERE LOWER(TRIM(TRAILING '.' FROM rejected_destination.domain)) = %s
                          AND COALESCE(
                              'manually rejected' = ANY(rejected_destination.confidence_reasons),
                              FALSE
                          )
                   )
                 LIMIT 1
            """, (domain_id, campaign_id, scan_id, BRAND_REDIRECT_SCOPE,
                  SCOPE_STATUS_ACTIVE, target_host, target_host, BRAND_REDIRECT_SCOPE,
                  target_host, target_host, target_host))
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
            "campaign_id": campaign_id,
            "campaign_scope": campaign_root,
            "campaign_purpose": purpose,
            "eligible_discovery_sources": list(sources or ()),
            "campaign_request_budget": int(request_limit),
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
    rows, campaign = select_targets(scan_id, include_campaign=True)
    operation_id = uuid.uuid4()
    if campaign is None:
        return {
            "scan_id": int(scan_id), "operation_id": str(operation_id),
            "selected": 0, "completed": 0,
            "disabled_reason": "no single complete, active brand-monitoring campaign is configured",
        }
    campaign_budget = int(campaign[5])
    if not rows:
        return {
            "scan_id": int(scan_id), "operation_id": str(operation_id),
            "selected": 0, "completed": 0,
            "request_budget": campaign_budget,
            "disabled_reason": "no current Candidate members match the campaign discovery sources and scope",
        }

    request_budget = _RequestBudget(campaign_budget)
    with ThreadPoolExecutor(
        max_workers=MAX_CONCURRENCY,
        thread_name_prefix="brand-redirect",
    ) as executor:
        states = list(executor.map(
            lambda row: _run_target(
                row, scan_id, operation_id, campaign, request_budget
            ), rows
        ))
    counts = {state: states.count(state) for state in sorted(set(states))}
    summary = {
        "scan_id": int(scan_id), "operation_id": str(operation_id),
        "selected": len(rows), "completed": len(states),
        "concurrency_limit": MAX_CONCURRENCY,
        "request_budget": campaign_budget,
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
