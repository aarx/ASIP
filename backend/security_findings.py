"""Read-only, scan-scoped aggregation of existing security evidence."""

from risk_engine import get_asset_exposure_keywords


ENVIRONMENT_KEYWORDS = {
    "DEV", "TEST", "UAT", "QA", "STAGE", "STAGING", "SANDBOX",
    "PREPROD", "PRE-PROD", "NONPROD", "NON-PROD", "LAB", "DEMO",
}
ROLE_KEYWORDS = {"ADMIN"}


def _asset_cte(classification_sql):
    return f"""
        WITH assets AS (
            SELECT DISTINCT d.id AS domain_id, d.domain,
                   ({classification_sql}) AS asset_class,
                   (SELECT dp.provider
                      FROM domain_provider dp
                     WHERE dp.domain_id = d.id AND dp.scan_id = %s
                     ORDER BY dp.provider NULLS LAST LIMIT 1) AS provider
              FROM scan_results sr
              JOIN domains d ON d.id = sr.domain_id
             WHERE sr.scan_id = %s
               AND ({classification_sql}) IN ('KNOWN', 'SHADOW')
        ), records AS (
            SELECT
                'domain_findings:' || df.scan_id::text || ':' || a.domain_id::text || ':' || df.finding AS finding_id,
                'domain_findings' AS source, df.finding AS source_record_id,
                df.scan_id, a.domain_id, a.domain AS asset_domain, a.asset_class,
                'FINDING' AS category, df.finding AS title, df.finding AS finding_type,
                df.severity AS severity, NULL::text AS source_outcome,
                NULL::text AS confidence, NULL::text AS verification_state,
                jsonb_build_object('source_evidence', df.evidence) AS evidence,
                NULL::text AS recommended_action, NULL::timestamptz AS observed_at,
                a.provider,
                jsonb_build_array('Source-recorded finding; independent verification state is unavailable.') AS limitations
              FROM domain_findings df JOIN assets a ON a.domain_id = df.domain_id
             WHERE df.scan_id = %s

            UNION ALL

            SELECT
                'dns_security_checks:' || c.id::text, 'dns_security_checks', c.id::text,
                c.scan_id, a.domain_id, a.domain, a.asset_class,
                CASE c.outcome
                    WHEN 'CONFIRMED_ISSUE' THEN 'FINDING'
                    WHEN 'INFORMATIONAL' THEN 'EXPOSURE_SIGNAL'
                    ELSE 'NEEDS_VERIFICATION'
                END,
                c.check_key || ' — ' || c.outcome, c.check_key, c.severity,
                c.outcome, c.confidence, c.outcome, c.evidence,
                c.remediation, c.checked_at, a.provider,
                jsonb_build_array('DNS outcome preserves the assessment result; it does not assert exploitability.')
              FROM dns_security_checks c JOIN assets a ON a.domain_id = c.domain_id
             WHERE c.scan_id = %s
               AND c.outcome NOT IN ('CLEAR', 'NOT_CHECKED')

            UNION ALL

            SELECT
                'domain_cert:' || dc.scan_id::text || ':' || a.domain_id::text,
                'domain_cert', a.domain_id::text, dc.scan_id, a.domain_id, a.domain,
                a.asset_class, 'NEEDS_VERIFICATION',
                'Certificate status: ' || dc.cert_status, 'certificate_status',
                NULL::text, dc.cert_status, NULL::text, dc.cert_status,
                jsonb_build_object('cert_status', dc.cert_status,
                                   'expiry_date', dc.expiry_date,
                                   'days_to_expiry_at_scan', dc.days_to_expiry),
                'Review the certificate validity and expiry for this scan.',
                NULL::timestamptz, a.provider,
                jsonb_build_array('Expiry and days-to-expiry are recorded at scan time; no current recalculation is implied.')
              FROM domain_cert dc JOIN assets a ON a.domain_id = dc.domain_id
             WHERE dc.scan_id = %s
               AND LOWER(COALESCE(dc.cert_status, '')) IN ('expired', 'critical', 'warning')

            UNION ALL

            SELECT
                'domain_ports:' || dp.scan_id::text || ':' || a.domain_id::text || ':' || dp.port::text,
                'domain_ports', dp.port::text, dp.scan_id, a.domain_id, a.domain,
                a.asset_class, 'EXPOSURE_SIGNAL',
                'Sensitive service observed on port ' || dp.port::text,
                'sensitive_port', NULL::text, NULL::text, NULL::text, NULL::text,
                jsonb_build_object('port', dp.port, 'service', dp.service,
                                   'description', sp.description, 'source_risk', sp.risk),
                'Validate whether this observed service is expected and appropriately protected.',
                NULL::timestamptz, a.provider,
                jsonb_build_array('An open sensitive port is an exposure observation, not a confirmed vulnerability.')
              FROM domain_ports dp
              JOIN sensitive_ports sp ON sp.port = dp.port
              JOIN assets a ON a.domain_id = dp.domain_id
             WHERE dp.scan_id = %s

            UNION ALL

            SELECT
                'redirect:' || ds.scan_id::text || ':' || a.domain_id::text,
                'redirect_review', a.domain_id::text, ds.scan_id, a.domain_id,
                a.domain, a.asset_class, 'NEEDS_VERIFICATION',
                'Cross-host HTTP redirect review', 'cross_host_http_redirect',
                NULL::text, NULL::text, NULL::text,
                COALESCE(ds.http_redirect_evidence->>'completion_status', 'LEGACY_UNKNOWN'),
                jsonb_build_object('http_status', ds.http_status,
                                   'observed_destination', NULLIF(ds.http_redirect_evidence->>'first_hop_destination', ''),
                                   'legacy_final_url', CASE WHEN ds.http_redirect_evidence IS NULL THEN ds.final_url ELSE NULL END,
                                   'redirect_evidence', jsonb_build_object(
                                       'completion_status', ds.http_redirect_evidence->>'completion_status',
                                       'stop_reason', ds.http_redirect_evidence->>'stop_reason',
                                       'first_hop_location', ds.http_redirect_evidence->>'first_hop_location',
                                       'first_hop_destination', ds.http_redirect_evidence->>'first_hop_destination',
                                       'verified_terminal_url', ds.http_redirect_evidence->>'verified_terminal_url'
                                   )),
                'Review the recorded redirect destination and verify that it is intentional.',
                NULL::timestamptz, a.provider,
                jsonb_build_array('Redirect evidence may be unresolved or legacy-unverified; it is not a compromise conclusion.')
              FROM domain_states ds JOIN assets a ON a.domain_id = ds.domain_id
             WHERE ds.scan_id = %s
               AND ds.http_observation_status = 'RESPONDED'
               AND ds.http_status BETWEEN 300 AND 399
               AND (NULLIF(TRIM(ds.http_redirect_evidence->>'first_hop_destination'), '') IS NOT NULL
                    OR (ds.http_redirect_evidence IS NULL AND NULLIF(TRIM(ds.final_url), '') IS NOT NULL))
               AND LOWER(TRIM(TRAILING '.' FROM substring(
                           COALESCE(NULLIF(ds.http_redirect_evidence->>'first_hop_destination', ''), ds.final_url, '')
                           FROM '^[a-zA-Z][a-zA-Z0-9+.-]*://([^/:?#]+)'
                       ))) <> LOWER(TRIM(TRAILING '.' FROM a.domain))

            UNION ALL

            SELECT
                'naming:' || %s::text || ':' || a.domain_id::text || ':' || k.keyword,
                'naming_indicator', k.keyword, %s, a.domain_id, a.domain,
                a.asset_class, 'EXPOSURE_SIGNAL',
                'Inferred hostname indicator: ' || UPPER(k.keyword),
                'hostname_naming_indicator', NULL::text, NULL::text, NULL::text,
                'INFERRED', jsonb_build_object('keyword', UPPER(k.keyword), 'basis', 'hostname substring'),
                'Confirm the asset purpose with its owner; hostname text is not verified environment or role.',
                NULL::timestamptz, a.provider,
                jsonb_build_array('Inferred from a broad hostname substring; it does not establish asset purpose or vulnerability.')
              FROM assets a
              CROSS JOIN (VALUES
                ('dev'), ('test'), ('uat'), ('qa'), ('admin'), ('mail'), ('temp'),
                ('stage'), ('staging'), ('sandbox'), ('preprod'), ('pre-prod'),
                ('nonprod'), ('non-prod'), ('lab'), ('demo')
              ) AS k(keyword)
             WHERE POSITION(k.keyword IN LOWER(a.domain)) > 0
               AND NOT (k.keyword = 'stage' AND POSITION('staging' IN LOWER(a.domain)) > 0)

            UNION ALL

            SELECT
                'shadow:' || %s::text || ':' || a.domain_id::text,
                'shadow_asset', a.domain_id::text, %s, a.domain_id, a.domain,
                a.asset_class, 'EXPOSURE_SIGNAL', 'Shadow asset inventory signal',
                'shadow_asset', NULL::text, NULL::text, NULL::text, 'INFERRED',
                jsonb_build_object('first_seen_scan', d.first_seen_scan),
                'Confirm whether this discovered asset is documented and has an accountable owner.',
                NULL::timestamptz, a.provider,
                jsonb_build_array('Shadow is an inventory classification, not a vulnerability or proof of unauthorized ownership.')
              FROM assets a JOIN domains d ON d.id = a.domain_id
             WHERE a.asset_class = 'SHADOW'
        )
    """


def normalize_security_record(row):
    """Convert a normalized SQL row to the stable API record contract."""
    (finding_id, source, source_record_id, scan_id, domain_id, domain,
     asset_class, category, title, finding_type, severity, source_outcome,
     confidence, verification_state, evidence, recommended_action, observed_at,
     provider, limitations) = row
    keywords = get_asset_exposure_keywords(domain)
    environment = [k for k in keywords if k in ENVIRONMENT_KEYWORDS]
    roles = [k for k in keywords if k in ROLE_KEYWORDS]
    limitations = list(limitations or [])
    if environment or roles:
        limitations.append("Environment and role labels are inferred from hostname substrings, not verified attributes.")
    why_by_source = {
        "domain_findings": "A source-recorded finding merits review; this read model does not add an independent verification claim.",
        "dns_security_checks": "The recorded DNS assessment outcome may warrant validation; it does not by itself establish exploitability.",
        "domain_cert": "A recorded certificate warning or expiry condition merits certificate review at the scan timestamp.",
        "domain_ports": "A sensitive service observation can inform exposure review; an open port is not itself a vulnerability.",
        "redirect_review": "A cross-host redirect can be intentional, but its destination and verification state merit review.",
        "naming_indicator": "A hostname keyword is contextual inventory intelligence and does not verify the asset purpose.",
        "shadow_asset": "Shadow classification identifies an inventory discrepancy for ownership review, not a vulnerability.",
    }
    if recommended_action is None and source == "domain_findings":
        recommended_action = "Review the source evidence and validate the finding before remediation."
    return {
        "finding_id": finding_id,
        "category": category,
        "source": source,
        "source_record_id": source_record_id,
        "scan_id": scan_id,
        "asset_domain": domain,
        "asset_class": asset_class,
        "title": title,
        "finding_type": finding_type,
        "why_it_matters": why_by_source.get(source),
        "severity": severity,
        "source_outcome": source_outcome,
        "confidence": confidence,
        "verification_state": verification_state,
        "evidence": evidence,
        "recommended_action": recommended_action,
        "observed_at": observed_at,
        "environment_indicators": environment,
        "role_indicators": roles,
        "indicators_inferred": bool(environment or roles),
        "provider": provider,
        "limitations": limitations,
    }


def normalized_findings_cte(classification_sql):
    return _asset_cte(classification_sql)


def base_query_params(scan_id):
    # One scan_id for provider/asset membership and each scan-scoped source arm.
    return [scan_id] * 11
