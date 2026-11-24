"""Scan-scoped CSV bundle generation for historical reports."""

import csv
import io
import json
import tempfile
import zipfile
from decimal import Decimal

from ownership import reporting_asset_class_sql
from scan_diagnostics import api_diagnostics
from subdomain_takeover_reporting import all_hosts_sql, csv_export_values, evidence_cte


class ScanReportNotFound(LookupError):
    pass


class ScanReportNotReady(ValueError):
    pass


SCAN_REPORT_DATASETS = (
    ("dns.csv", "DNS", """SELECT d.id, d.domain, x.record_type, x.value
        FROM domain_dns x JOIN domains d ON d.id = x.domain_id
       WHERE x.scan_id = %s AND EXISTS (
           SELECT 1 FROM scan_results sr WHERE sr.scan_id = x.scan_id
             AND sr.domain_id = x.domain_id)
       ORDER BY d.domain, x.record_type, x.value""",
     ("domain_id", "domain", "record_type", "value"), None),
    ("http.csv", "HTTP observations", """SELECT d.id, d.domain, ds.ip, ds.has_ip,
               ds.http_observation_status, ds.http_status, ds.http_live,
               ds.http_reason, ds.final_url, ds.final_status, ds.title,
               ds.reverse_dns,
               ds.http_redirect_evidence->>'first_hop_destination',
               CASE
                   WHEN ds.http_redirect_evidence->>'completion_status' = 'COMPLETE'
                    AND NULLIF(ds.http_redirect_evidence->>'verified_terminal_url', '') IS NOT NULL
                   THEN ds.http_redirect_evidence->>'verified_terminal_url'
                   ELSE NULL
               END AS verified_terminal_destination,
               CASE
                   WHEN ds.http_redirect_evidence->>'completion_status' = 'COMPLETE'
                    AND NULLIF(ds.http_redirect_evidence->>'verified_terminal_url', '') IS NOT NULL
                   THEN 'VERIFIED'
                   WHEN ds.http_redirect_evidence IS NULL
                     OR NOT (ds.http_redirect_evidence ? 'completion_status')
                   THEN 'UNKNOWN'
                   ELSE 'UNVERIFIED'
               END AS terminal_verification_status,
               COALESCE(ds.http_redirect_evidence->>'completion_status', 'UNKNOWN')
                   AS redirect_completeness,
               ds.http_redirect_evidence->>'stop_reason'
        FROM domain_states ds JOIN domains d ON d.id = ds.domain_id
       WHERE ds.scan_id = %s AND EXISTS (
           SELECT 1 FROM scan_results sr WHERE sr.scan_id = ds.scan_id
             AND sr.domain_id = ds.domain_id)
       ORDER BY d.domain""",
     ("domain_id", "domain", "ip", "has_ip", "http_observation_status",
      "http_status", "http_live", "http_reason", "final_url", "final_status",
      "title", "reverse_dns", "first_hop_destination", "terminal_destination",
      "terminal_verification_status", "redirect_completeness",
      "redirect_stop_reason"), None),
    ("tls.csv", "TLS certificate observations", """SELECT d.id, d.domain,
               c.expiry_date, c.days_to_expiry, c.cert_status
        FROM domain_cert c JOIN domains d ON d.id = c.domain_id
       WHERE c.scan_id = %s AND EXISTS (
           SELECT 1 FROM scan_results sr WHERE sr.scan_id = c.scan_id
             AND sr.domain_id = c.domain_id)
       ORDER BY d.domain, c.expiry_date NULLS LAST""",
     ("domain_id", "domain", "expiry_date", "days_to_expiry", "cert_status"), None),
    ("infrastructure.csv", "Provider and ASN observations", """SELECT d.id, d.domain,
               'ASN' AS observation_type, a.asn AS value, a.ip, a.org AS detail
        FROM domain_asn a JOIN domains d ON d.id = a.domain_id
       WHERE a.scan_id = %s AND EXISTS (
           SELECT 1 FROM scan_results sr WHERE sr.scan_id = a.scan_id
             AND sr.domain_id = a.domain_id)
        UNION ALL
        SELECT d.id, d.domain, 'PROVIDER' AS observation_type,
               p.provider AS value, NULL AS ip, NULL AS detail
        FROM domain_provider p JOIN domains d ON d.id = p.domain_id
       WHERE p.scan_id = %s AND EXISTS (
           SELECT 1 FROM scan_results sr WHERE sr.scan_id = p.scan_id
             AND sr.domain_id = p.domain_id)
       ORDER BY domain, observation_type, value""",
     ("domain_id", "domain", "observation_type", "value", "ip", "detail"), None),
    ("technology-labels.csv", "Technology labels", """SELECT d.id, d.domain, t.tech
        FROM domain_tech t JOIN domains d ON d.id = t.domain_id
       WHERE t.scan_id = %s AND EXISTS (
           SELECT 1 FROM scan_results sr WHERE sr.scan_id = t.scan_id
             AND sr.domain_id = t.domain_id)
       ORDER BY d.domain, t.tech""",
     ("domain_id", "domain", "technology"), None),
    ("ports.csv", "Port observations", """SELECT d.id, d.domain, p.port,
               p.service, sp.risk AS sensitive_port_risk,
               sp.description AS sensitive_port_description
        FROM domain_ports p JOIN domains d ON d.id = p.domain_id
        LEFT JOIN sensitive_ports sp ON sp.port = p.port
       WHERE p.scan_id = %s AND EXISTS (
           SELECT 1 FROM scan_results sr WHERE sr.scan_id = p.scan_id
             AND sr.domain_id = p.domain_id)
       ORDER BY d.domain, p.port""",
     ("domain_id", "domain", "port", "service", "sensitive_port_risk",
      "sensitive_port_description"), None),
    ("findings.csv", "Security findings", """SELECT d.id, d.domain, f.finding,
               f.severity, f.evidence
        FROM domain_findings f JOIN domains d ON d.id = f.domain_id
       WHERE f.scan_id = %s AND EXISTS (
           SELECT 1 FROM scan_results sr WHERE sr.scan_id = f.scan_id
             AND sr.domain_id = f.domain_id)
       ORDER BY d.domain, f.severity, f.finding""",
     ("domain_id", "domain", "finding", "severity", "evidence"), None),
    ("risk.csv", "Persisted scan risk", """SELECT d.id, d.domain, r.risk_score,
               r.reasons
        FROM domain_risk r JOIN domains d ON d.id = r.domain_id
       WHERE r.scan_id = %s AND EXISTS (
           SELECT 1 FROM scan_results sr WHERE sr.scan_id = r.scan_id
             AND sr.domain_id = r.domain_id)
       ORDER BY d.domain""",
     ("domain_id", "domain", "risk_score", "reasons"), None),
    ("dns-security.csv", "DNS Security assessments", """SELECT d.id, d.domain,
               x.check_key, x.target_identity, x.record_type, x.outcome,
               x.severity, x.confidence, x.evidence, x.remediation, x.checked_at
        FROM dns_security_checks x JOIN domains d ON d.id = x.domain_id
       WHERE x.scan_id = %s AND EXISTS (
           SELECT 1 FROM scan_results sr WHERE sr.scan_id = x.scan_id
             AND sr.domain_id = x.domain_id)
       ORDER BY d.domain, x.check_key, x.target_identity, x.record_type""",
     ("domain_id", "domain", "check_key", "target", "record_type", "outcome",
      "severity", "confidence", "evidence_json", "remediation", "checked_at"),
     "public.dns_security_checks"),
    ("technology-observations.csv", "Structured technology observations", """SELECT
               d.id, d.domain, x.technology, x.version, x.confidence,
               x.evidence_type, x.sanitized_evidence, x.observed_url,
               x.detector_version, x.created_at
        FROM domain_technology_observations x
        JOIN domains d ON d.id = x.domain_id
       WHERE x.scan_id = %s AND EXISTS (
           SELECT 1 FROM scan_results sr WHERE sr.scan_id = x.scan_id
             AND sr.domain_id = x.domain_id)
       ORDER BY d.domain, x.technology, x.created_at""",
      ("domain_id", "domain", "technology", "version", "confidence",
      "evidence_type", "sanitized_evidence", "observed_url", "detector_version",
      "created_at"), "public.domain_technology_observations"),
    ("brand-redirects.csv", "Brand Redirect Intelligence observations", """WITH
        brand_source_pairs AS (
            SELECT DISTINCT scan_id, domain_id, source, BTRIM(seed) AS seed
              FROM domain_sources
             WHERE scan_id = %s
               AND source IN ('brand_tld', 'brand_pattern')
        ), brand_provenance AS (
            SELECT scan_id, domain_id,
                   ARRAY_AGG(DISTINCT source ORDER BY source) AS sources,
                   JSONB_AGG(JSONB_BUILD_OBJECT('source', source, 'seed', seed)
                             ORDER BY source, seed) AS seed_attributions
              FROM brand_source_pairs
             GROUP BY scan_id, domain_id
        )
        SELECT br.id, br.scan_id, br.operation_id, br.observed_at,
               d.domain, COALESCE(bp.sources, ARRAY[]::text[]),
               COALESCE(bp.seed_attributions, '[]'::jsonb),
               br.evidence->>'http_observation_status', br.completeness,
               CASE
                   WHEN br.completeness IN ('COMPLETE', 'NO_REDIRECT')
                    AND NULLIF(br.evidence->>'verified_final_url', '') IS NOT NULL
                   THEN 'VERIFIED' ELSE 'UNVERIFIED'
               END AS terminal_verification_status,
               br.evidence #>> '{observed_hops,0,reported_destination_url}'
                   AS first_hop_destination,
               CASE
                   WHEN br.completeness IN ('COMPLETE', 'NO_REDIRECT')
                    AND NULLIF(br.evidence->>'verified_final_url', '') IS NOT NULL
                   THEN br.evidence->>'verified_final_url' ELSE NULL
               END AS terminal_destination,
               CASE
                   WHEN br.completeness = 'NO_REDIRECT'
                    AND NULLIF(br.evidence->>'verified_final_url', '') IS NOT NULL
                   THEN 'VERIFIED_NO_REDIRECT'
                   WHEN br.completeness = 'COMPLETE'
                    AND NULLIF(br.evidence->>'verified_final_url', '') IS NOT NULL
                    AND CASE WHEN JSONB_TYPEOF(br.evidence->'observed_hops') = 'array'
                             THEN JSONB_ARRAY_LENGTH(br.evidence->'observed_hops') > 0
                             ELSE FALSE END
                   THEN 'VERIFIED_REDIRECT_CHAIN'
                   WHEN br.completeness IN ('COMPLETE', 'NO_REDIRECT')
                    AND NULLIF(br.evidence->>'verified_final_url', '') IS NOT NULL
                   THEN 'VERIFIED_OBSERVATION'
                   ELSE 'INCOMPLETE_OR_UNVERIFIED'
               END AS classification,
               COALESCE(NULLIF(br.evidence->>'stop_reason', ''),
                   CASE WHEN br.completeness NOT IN ('COMPLETE', 'NO_REDIRECT')
                        THEN br.completeness ELSE NULL END) AS failure_or_stop_reason,
               br.evidence
          FROM brand_redirect_observations br
          JOIN domains d ON d.id = br.domain_id
          LEFT JOIN brand_provenance bp
            ON bp.scan_id = br.scan_id AND bp.domain_id = br.domain_id
         WHERE br.scan_id = %s AND EXISTS (
             SELECT 1 FROM scan_results sr
              WHERE sr.scan_id = br.scan_id AND sr.domain_id = br.domain_id)
         ORDER BY d.domain, br.observed_at, br.id""",
     ("observation_id", "scan_id", "operation_id", "observed_at", "source_domain",
      "discovery_sources", "associated_seed_brand_json", "observation_status",
      "verification_completeness",
      "terminal_verification_status", "first_hop_destination", "terminal_destination",
      "classification", "failure_or_stop_reason", "evidence_json"),
     "public.brand_redirect_observations"),
    ("subdomain-takeover.csv", "Subdomain Takeover evidence",
     all_hosts_sql(evidence_cte(reporting_asset_class_sql("d.domain", "d.ownership_status"))),
     ("scan_id", "hostname", "cname_destination", "provider", "finding_category",
      "evidence_categories_json", "confidence", "verification_status", "dns_evidence_json",
      "provider_evidence_json", "observation_timestamp", "classification_as_of",
      "evidence_basis"),
     "public.dns_security_checks"),
)


def _csv_value(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        value = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    if hasattr(value, "isoformat"):
        value = value.isoformat()
    # Keep numeric cells numeric (notably legitimate negative scores/durations).
    # For text, prefix an apostrophe when spreadsheet software could interpret
    # the first non-whitespace character as a formula operator.
    if isinstance(value, (bool, int, float, Decimal)):
        return value
    if isinstance(value, str):
        significant = value.lstrip(" \t\r\n")
        if value.startswith(("\t", "\r", "\n")) or significant.startswith(("=", "+", "-", "@")):
            return "'" + value
    return value


def _write_csv_member(archive, filename, headers, rows):
    with archive.open(filename, "w") as raw:
        text = io.TextIOWrapper(raw, encoding="utf-8", newline="")
        writer = csv.writer(text, lineterminator="\r\n")
        writer.writerow(headers)
        count = 0
        for row in rows:
            writer.writerow([_csv_value(value) for value in row])
            count += 1
        text.flush()
        text.detach()
    return count


def _query_rows(conn, query, params, cursor_name):
    """Yield in bounded batches using a PostgreSQL server-side cursor."""
    cur = conn.cursor(name=cursor_name)
    cur.itersize = 500
    try:
        cur.execute(query, params)
        while True:
            batch = cur.fetchmany(500)
            if not batch:
                break
            yield from batch
    finally:
        cur.close()


def _subdomain_takeover_export_rows(rows, scan_id):
    """Flatten the shared grouped read model while retaining each observation."""
    for row in rows:
        yield csv_export_values(row, scan_id)


def _brand_redirect_attempts(diagnostics):
    attempts = diagnostics.get("attempts") if isinstance(diagnostics, dict) else None
    if not isinstance(attempts, list):
        return []
    return [attempt for attempt in attempts if isinstance(attempt, dict)
            and attempt.get("stage") == "Brand Redirect Intelligence"]


def _brand_redirect_coverage(attempts, observation_stats, schema_available):
    """Describe persisted BRI evidence without treating absence as a clean result."""
    records, verified, verified_redirects, verified_no_redirect, incomplete = observation_stats
    if not schema_available:
        return ("SCHEMA_UNAVAILABLE",
                "brand_redirect_observations is not installed; no observation result can be inferred.")
    if not attempts:
        if records:
            return ("OBSERVATIONS_WITHOUT_STAGE_DIAGNOSTICS",
                    f"Persisted observations: {records}; stage eligibility and target totals are unknown.")
        return ("STAGE_NOT_RECORDED",
                "No BRI stage attempt or persisted observations are recorded; eligibility is unknown.")

    attempt = attempts[-1]
    summary = attempt.get("worker_summary")
    selected = summary.get("selected") if isinstance(summary, dict) else None
    completed = summary.get("completed") if isinstance(summary, dict) else None
    selected = selected if isinstance(selected, int) and not isinstance(selected, bool) else None
    completed = completed if isinstance(completed, int) and not isinstance(completed, bool) else None
    detail = (f"selected_targets={selected if selected is not None else 'UNKNOWN'}; "
              f"worker_completed={completed if completed is not None else 'UNKNOWN'}; "
              f"stage_attempts={len(attempts)}; "
              f"observations={records}; verified={verified}; "
              f"verified_redirect_chains={verified_redirects}; "
              f"verified_no_redirect={verified_no_redirect}; incomplete_or_unverified={incomplete}.")

    if selected == 0 and records == 0:
        return ("NO_ELIGIBLE_TARGETS",
                detail + " The scheduled worker selected no current-scan eligible candidates.")
    if selected == 0 and records:
        return "INCONSISTENT_STAGE_AND_OBSERVATION_COUNTS", detail
    if selected is not None and selected > 0 and records == 0:
        return "ELIGIBLE_BUT_NOT_ASSESSED", detail
    if selected is not None and selected > records:
        return "ELIGIBLE_BUT_NOT_FULLY_ASSESSED", detail
    if incomplete:
        state = "MIXED_VERIFIED_AND_INCOMPLETE" if verified else "INCOMPLETE_OR_UNVERIFIED_OBSERVATIONS"
        return state, detail
    if len(attempts) > 1:
        return "MULTIPLE_STAGE_ATTEMPTS_EVIDENCE_AGGREGATED", detail
    if records and verified_redirects == 0 and verified_no_redirect == records:
        return "ASSESSED_WITH_NO_REDIRECT_FINDINGS", detail
    if verified_redirects:
        return "ASSESSED_WITH_VERIFIED_REDIRECT_OBSERVATIONS", detail
    if records:
        return "ASSESSED_WITH_VERIFIED_OBSERVATIONS", detail
    return "ELIGIBILITY_UNKNOWN_NO_OBSERVATIONS", detail


def build_scan_report(conn, scan_id):
    """Return a spooled ZIP report containing only one finalized scan's evidence."""
    cur = conn.cursor()
    cur.execute("""
        SELECT s.id, s.status, s.scan_time, s.started_at, s.completed_at,
               s.seed, s.stage_diagnostics, COUNT(DISTINCT sr.domain_id)
          FROM scans s
          LEFT JOIN scan_results sr ON sr.scan_id = s.id
         WHERE s.id = %s
         GROUP BY s.id, s.status, s.scan_time, s.started_at,
                  s.completed_at, s.seed, s.stage_diagnostics
    """, (scan_id,))
    scan = cur.fetchone()
    cur.close()
    if scan is None:
        raise ScanReportNotFound()
    if scan[1] != "SUCCEEDED" or scan[4] is None:
        raise ScanReportNotReady()
    if scan[7] == 0:
        raise ScanReportNotReady("No historical scan membership is available")

    diagnostics = api_diagnostics(scan[6], scan[1])
    classification_sql = reporting_asset_class_sql("d.domain", "d.ownership_status")
    spool = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024, mode="w+b")
    try:
        coverage = [
            ("scan membership", scan[7], "AVAILABLE", "Membership is scoped to this scan."),
            ("domain states", 0, "UNKNOWN", "No rows are treated as unknown unless scan-scoped records exist."),
        ]
        with zipfile.ZipFile(spool, "w", compression=zipfile.ZIP_DEFLATED,
                             allowZip64=True) as archive:
            _write_csv_member(archive, "scan-summary.csv", (
                "scan_id", "status", "scan_time", "started_at", "completed_at",
                "seed", "asset_count", "stage_diagnostics_available", "scan_outcome_json",
            ), [(
                scan[0], scan[1], scan[2], scan[3], scan[4], scan[5], scan[7],
                diagnostics is not None,
                diagnostics.get("scan_outcome") if diagnostics else None,
            )])

            asset_query = f"""WITH membership AS (
                    SELECT sr.domain_id,
                           STRING_AGG(DISTINCT sr.seed, ';' ORDER BY sr.seed) AS seeds
                      FROM scan_results sr WHERE sr.scan_id = %s
                     GROUP BY sr.domain_id
                ), brand_source_pairs AS (
                    SELECT DISTINCT scan_id, domain_id, source, BTRIM(seed) AS seed
                      FROM domain_sources
                     WHERE scan_id = %s
                       AND source IN ('brand_tld', 'brand_pattern')
                ), brand_provenance AS (
                    SELECT scan_id, domain_id,
                           ARRAY_AGG(DISTINCT source ORDER BY source) AS sources,
                           JSONB_AGG(JSONB_BUILD_OBJECT('source', source, 'seed', seed)
                                     ORDER BY source, seed) AS seed_attributions
                      FROM brand_source_pairs
                     GROUP BY scan_id, domain_id
                )
                SELECT m.domain_id, d.domain, m.seeds, d.is_known,
                       d.ownership_status AS ownership_status_at_export,
                       {classification_sql} AS effective_asset_class_at_export,
                       (ds.domain_id IS NOT NULL) AS scan_state_record_available,
                       ds.ip, ds.has_ip, ds.http_observation_status,
                       ds.http_status, ds.http_live, ds.http_reason,
                       ds.final_url, ds.final_status, ds.title, ds.reverse_dns,
                       dr.risk_score AS persisted_scan_risk_score,
                       dr.reasons AS persisted_scan_risk_reasons,
                       COALESCE(bp.sources, ARRAY[]::text[]) AS brand_discovery_sources,
                       COALESCE(bp.seed_attributions, '[]'::jsonb)
                           AS brand_discovery_seed_attributions
                  FROM membership m JOIN domains d ON d.id = m.domain_id
                  LEFT JOIN domain_states ds
                    ON ds.domain_id = m.domain_id AND ds.scan_id = %s
                  LEFT JOIN domain_risk dr
                    ON dr.domain_id = m.domain_id AND dr.scan_id = %s
                  LEFT JOIN brand_provenance bp
                    ON bp.domain_id = m.domain_id AND bp.scan_id = %s
                 ORDER BY d.domain, d.id"""
            asset_headers = (
                "domain_id", "domain", "scan_seed_attributions", "is_known",
                "ownership_status_at_export", "effective_asset_class_at_export",
                "scan_state_record_available",
                "scan_ip", "scan_has_ip", "scan_http_observation_status",
                "scan_http_status", "scan_http_live", "scan_http_reason",
                "scan_final_url", "scan_final_status", "scan_title", "scan_reverse_dns",
                "persisted_scan_risk_score", "persisted_scan_risk_reasons",
                "brand_discovery_sources", "brand_discovery_seed_attributions_json",
            )
            assets_count = _write_csv_member(
                archive, "assets.csv", asset_headers,
                _query_rows(conn, asset_query,
                            (scan_id, scan_id, scan_id, scan_id, scan_id),
                            f"scan_report_assets_{scan_id}"),
            )
            cur = conn.cursor()
            cur.execute("""SELECT COUNT(DISTINCT ds.domain_id)
                FROM domain_states ds
                WHERE ds.scan_id = %s AND EXISTS (
                    SELECT 1 FROM scan_results sr
                     WHERE sr.scan_id = ds.scan_id AND sr.domain_id = ds.domain_id)
            """, (scan_id,))
            state_count = cur.fetchone()[0]
            cur.close()
            coverage[1] = (
                "domain states", state_count,
                "AVAILABLE_WITH_ROWS" if state_count else "NO_PERSISTED_ROWS",
                "Only domain_states rows for this scan are exported; missing rows remain blank.",
            )

            optional_tables = set()
            probe = conn.cursor()
            try:
                probe.execute("SELECT to_regclass(%s), to_regclass(%s), to_regclass(%s)",
                              ("public.dns_security_checks",
                               "public.domain_technology_observations",
                               "public.brand_redirect_observations"))
                detected_tables = probe.fetchone() or (None, None, None)
                optional_tables.update(name for name, exists in zip(
                    ("public.dns_security_checks", "public.domain_technology_observations",
                     "public.brand_redirect_observations"),
                    detected_tables,
                ) if exists is not None)
            finally:
                probe.close()

            brand_redirect_count = 0
            for index, (filename, label, query, headers, optional_table) in enumerate(
                SCAN_REPORT_DATASETS
            ):
                if optional_table and optional_table not in optional_tables:
                    _write_csv_member(archive, filename, headers, ())
                    if filename != "brand-redirects.csv":
                        coverage.append((label, "", "SCHEMA_UNAVAILABLE",
                                         "The optional evidence table is not installed."))
                    continue
                query_params = ((scan_id, scan_id) if filename in {
                    "infrastructure.csv", "brand-redirects.csv",
                    "subdomain-takeover.csv",
                } else (scan_id,))
                rows = _query_rows(
                    conn, query, query_params, f"scan_report_{scan_id}_{index}"
                )
                if filename == "subdomain-takeover.csv":
                    rows = _subdomain_takeover_export_rows(rows, scan_id)
                count = _write_csv_member(archive, filename, headers, rows)
                if filename == "brand-redirects.csv":
                    brand_redirect_count = count
                    continue
                state = "AVAILABLE_WITH_ROWS" if count else "NO_PERSISTED_ROWS"
                note = ("Rows are scoped to this scan." if count else
                        "No rows were persisted; this does not prove the operation completed or found nothing.")
                coverage.append((label, count, state, note))

            if "public.brand_redirect_observations" in optional_tables:
                probe = conn.cursor()
                try:
                    probe.execute("""SELECT COUNT(*),
                               COUNT(*) FILTER (WHERE completeness IN ('COMPLETE', 'NO_REDIRECT')
                                   AND NULLIF(evidence->>'verified_final_url', '') IS NOT NULL),
                               COUNT(*) FILTER (WHERE completeness = 'COMPLETE'
                                   AND NULLIF(evidence->>'verified_final_url', '') IS NOT NULL
                                   AND CASE WHEN JSONB_TYPEOF(evidence->'observed_hops') = 'array'
                                            THEN JSONB_ARRAY_LENGTH(evidence->'observed_hops') > 0
                                            ELSE FALSE END),
                               COUNT(*) FILTER (WHERE completeness = 'NO_REDIRECT'
                                   AND NULLIF(evidence->>'verified_final_url', '') IS NOT NULL),
                               COUNT(*) FILTER (WHERE completeness NOT IN ('COMPLETE', 'NO_REDIRECT')
                                   OR NULLIF(evidence->>'verified_final_url', '') IS NULL)
                          FROM brand_redirect_observations br
                         WHERE br.scan_id = %s AND EXISTS (
                               SELECT 1 FROM scan_results sr
                                WHERE sr.scan_id = br.scan_id AND sr.domain_id = br.domain_id)
                    """, (scan_id,))
                    observation_stats = probe.fetchone() or (0, 0, 0, 0, 0)
                finally:
                    probe.close()
                status, interpretation = _brand_redirect_coverage(
                    _brand_redirect_attempts(diagnostics), observation_stats,
                    schema_available=True,
                )
                coverage.append(("Brand Redirect Intelligence", brand_redirect_count,
                                 status, interpretation))
            else:
                status, interpretation = _brand_redirect_coverage(
                    _brand_redirect_attempts(diagnostics), (0, 0, 0, 0, 0),
                    schema_available=False,
                )
                coverage.append(("Brand Redirect Intelligence", "", status, interpretation))

            stage_rows = []
            if diagnostics and isinstance(diagnostics.get("attempts"), list):
                for attempt in diagnostics["attempts"]:
                    worker_summary = attempt.get("worker_summary")
                    stage_rows.append((
                        attempt.get("stage"), attempt.get("order"), attempt.get("attempt"),
                        attempt.get("status"), attempt.get("started_at"),
                        attempt.get("completed_at"), attempt.get("duration_seconds"),
                        attempt.get("error_category"), worker_summary,
                    ))
            _write_csv_member(archive, "stage-attempts.csv", (
                "stage", "stage_order", "attempt", "status", "started_at",
                "completed_at", "duration_seconds", "error_category", "worker_summary_json",
            ), stage_rows)
            _write_csv_member(archive, "coverage.csv", (
                "evidence_category", "record_count", "availability", "interpretation",
            ), coverage)
        spool.seek(0)
        return spool
    except Exception:
        spool.close()
        raise


ADHOC_CAMPAIGN_CSV_HEADERS = (
    "campaign_id", "check_id", "source_scan_id", "campaign_status",
    "assessment_date", "dataset_revision", "created_at", "started_at",
    "completed_at", "campaign_failure_code", "domain",
    "target_status", "target_skip_reason_code", "selected_at", "target_started_at",
    "target_completed_at", "execution_status", "evidence_status", "evaluation_status",
    "classification", "failure_code", "result_skip_reason_code", "observations_json",
    "lifecycle_json", "cve_intelligence_json", "observed_at", "persisted_at",
    "result_dataset_revision",
)


def write_adhoc_campaign_csv(stream, campaign, results):
    writer = csv.writer(stream, lineterminator="\r\n")
    writer.writerow(ADHOC_CAMPAIGN_CSV_HEADERS)
    for result in results:
        writer.writerow([_csv_value(value) for value in [
            campaign.get("campaign_id"), campaign.get("check_id"),
            campaign.get("source_scan_id"), campaign.get("status"),
            campaign.get("assessment_date"), campaign.get("dataset_revision"),
            campaign.get("created_at"), campaign.get("started_at"),
            campaign.get("completed_at"), campaign.get("failure_code"),
            result.get("domain"),
            result.get("target_status"), result.get("skip_reason_code"),
            result.get("selected_at"), result.get("started_at"),
            result.get("completed_at"), result.get("execution_status"),
            result.get("evidence_status"), result.get("evaluation_status"),
            result.get("classification"), result.get("failure_code"),
            result.get("result_skip_reason_code"), _csv_value(result.get("observations")),
            _csv_value(result.get("lifecycle")), _csv_value(result.get("cve_intelligence")),
            result.get("observed_at"), result.get("persisted_at"),
            result.get("dataset_revision"),
        ]])
