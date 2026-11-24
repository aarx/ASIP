"""Shared scan-scoped Subdomain Takeover evidence read model."""

import json


def evidence_cte(classification_sql):
    classification = classification_sql
    return f"""
            WITH evidence AS (
                SELECT d.id AS domain_id, d.domain AS hostname,
                       CASE
                         WHEN (EXISTS (SELECT 1 FROM jsonb_array_elements(
                              CASE WHEN jsonb_typeof(c.evidence->'chain')='array'
                                   THEN c.evidence->'chain' ELSE '[]'::jsonb END) x
                              WHERE x->>'state'='not_checked_authorization')
                           OR c.evidence->>'verification_status'='NOT_CHECKED_AUTHORIZATION')
                           AND EXISTS (SELECT 1 FROM jsonb_array_elements(
                              CASE WHEN jsonb_typeof(c.evidence->'chain')='array'
                                   THEN c.evidence->'chain' ELSE '[]'::jsonb END) x
                              WHERE NULLIF(x->>'provider','') IS NOT NULL)
                           THEN 'UNVERIFIED_PROVIDER_ASSOCIATION'
                         WHEN c.evidence->>'verification_status'='NOT_CHECKED_AUTHORIZATION'
                           OR EXISTS (SELECT 1 FROM jsonb_array_elements(
                              CASE WHEN jsonb_typeof(c.evidence->'chain')='array'
                                   THEN c.evidence->'chain' ELSE '[]'::jsonb END) x
                              WHERE x->>'state'='not_checked_authorization')
                           THEN 'UNKNOWN'
                         WHEN c.evidence->>'verification_status'='VERIFIED_DNS_NEGATIVE'
                           OR EXISTS (SELECT 1 FROM jsonb_array_elements(
                              CASE WHEN jsonb_typeof(c.evidence->'chain')='array'
                                   THEN c.evidence->'chain' ELSE '[]'::jsonb END) x
                              WHERE x->>'state'='potential_exposure')
                           THEN 'DNS_NEGATIVE_SIGNAL'
                         WHEN EXISTS (SELECT 1 FROM jsonb_array_elements(
                              CASE WHEN jsonb_typeof(c.evidence->'chain')='array'
                                   THEN c.evidence->'chain' ELSE '[]'::jsonb END) x
                              WHERE NULLIF(x->>'provider','') IS NOT NULL)
                           THEN 'UNVERIFIED_PROVIDER_ASSOCIATION'
                         ELSE 'UNKNOWN' END AS evidence_category,
                       CASE
                         WHEN c.evidence->>'verification_status'='NOT_CHECKED_AUTHORIZATION'
                           OR EXISTS (SELECT 1 FROM jsonb_array_elements(
                              CASE WHEN jsonb_typeof(c.evidence->'chain')='array'
                                   THEN c.evidence->'chain' ELSE '[]'::jsonb END) x
                              WHERE x->>'state'='not_checked_authorization')
                           THEN 'NOT_CHECKED_AUTHORIZATION'
                         WHEN c.evidence->>'verification_status'='VERIFIED_DNS_NEGATIVE'
                           THEN 'VERIFIED_DNS_NEGATIVE'
                         WHEN EXISTS (SELECT 1 FROM jsonb_array_elements(
                              CASE WHEN jsonb_typeof(c.evidence->'chain')='array'
                                   THEN c.evidence->'chain' ELSE '[]'::jsonb END) x
                              WHERE x->>'state'='potential_exposure')
                           THEN 'UNVERIFIED_LEGACY_EVIDENCE'
                         ELSE 'UNVERIFIED' END AS verification_status,
                       c.confidence,
                       COALESCE(c.evidence->>'cname_destination', (
                           SELECT x->>'target' FROM jsonb_array_elements(
                             CASE WHEN jsonb_typeof(c.evidence->'chain')='array'
                                  THEN c.evidence->'chain' ELSE '[]'::jsonb END) x
                            WHERE x ? 'target' LIMIT 1)) AS cname_destination,
                       COALESCE((SELECT string_agg(DISTINCT x->>'provider', ', ' ORDER BY x->>'provider')
                           FROM jsonb_array_elements(CASE WHEN jsonb_typeof(c.evidence->'chain')='array'
                                THEN c.evidence->'chain' ELSE '[]'::jsonb END) x
                          WHERE NULLIF(x->>'provider','') IS NOT NULL), NULL) AS provider,
                       c.checked_at AS observed_at,
                       jsonb_build_object('source','dns_security_checks','source_outcome',c.outcome,
                         'evidence_category',CASE
                           WHEN (EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(c.evidence->'chain')='array' THEN c.evidence->'chain' ELSE '[]'::jsonb END) x WHERE x->>'state'='not_checked_authorization') OR c.evidence->>'verification_status'='NOT_CHECKED_AUTHORIZATION') AND EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(c.evidence->'chain')='array' THEN c.evidence->'chain' ELSE '[]'::jsonb END) x WHERE NULLIF(x->>'provider','') IS NOT NULL) THEN 'UNVERIFIED_PROVIDER_ASSOCIATION'
                           WHEN c.evidence->>'verification_status'='NOT_CHECKED_AUTHORIZATION' OR EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(c.evidence->'chain')='array' THEN c.evidence->'chain' ELSE '[]'::jsonb END) x WHERE x->>'state'='not_checked_authorization') THEN 'UNKNOWN'
                           WHEN c.evidence->>'verification_status'='VERIFIED_DNS_NEGATIVE' OR EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(c.evidence->'chain')='array' THEN c.evidence->'chain' ELSE '[]'::jsonb END) x WHERE x->>'state'='potential_exposure') THEN 'DNS_NEGATIVE_SIGNAL'
                           WHEN EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(c.evidence->'chain')='array' THEN c.evidence->'chain' ELSE '[]'::jsonb END) x WHERE NULLIF(x->>'provider','') IS NOT NULL) THEN 'UNVERIFIED_PROVIDER_ASSOCIATION' ELSE 'UNKNOWN' END,
                         'verification_status',CASE
                           WHEN c.evidence->>'verification_status'='NOT_CHECKED_AUTHORIZATION' OR EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(c.evidence->'chain')='array' THEN c.evidence->'chain' ELSE '[]'::jsonb END) x WHERE x->>'state'='not_checked_authorization') THEN 'NOT_CHECKED_AUTHORIZATION'
                           WHEN c.evidence->>'verification_status'='VERIFIED_DNS_NEGATIVE' THEN 'VERIFIED_DNS_NEGATIVE'
                           WHEN EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(c.evidence->'chain')='array' THEN c.evidence->'chain' ELSE '[]'::jsonb END) x WHERE x->>'state'='potential_exposure') THEN 'UNVERIFIED_LEGACY_EVIDENCE'
                           ELSE 'UNVERIFIED' END,
                         'confidence',c.confidence,'target',c.target_identity,'evidence',c.evidence,
                         'rationale',CASE
                           WHEN (c.evidence->>'verification_status'='NOT_CHECKED_AUTHORIZATION' OR EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(c.evidence->'chain')='array' THEN c.evidence->'chain' ELSE '[]'::jsonb END) x WHERE x->>'state'='not_checked_authorization')) AND EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(c.evidence->'chain')='array' THEN c.evidence->'chain' ELSE '[]'::jsonb END) x WHERE NULLIF(x->>'provider','') IS NOT NULL) THEN 'Provider association was observed, but destination verification was blocked by authorization.'
                           WHEN c.evidence->>'verification_status'='VERIFIED_DNS_NEGATIVE' THEN 'Recorded terminal DNS responses support a DNS-negative signal; this does not confirm takeover.'
                           WHEN EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(c.evidence->'chain')='array' THEN c.evidence->'chain' ELSE '[]'::jsonb END) x WHERE x->>'state'='potential_exposure') THEN 'Legacy potential-exposure evidence lacks raw terminal response categories.'
                           ELSE 'Available evidence does not establish a dangling DNS condition.' END,
                         'observed_at',c.checked_at) AS observation
                  FROM dns_security_checks c JOIN domains d ON d.id=c.domain_id
                 WHERE c.scan_id=%s AND c.check_key='cname_health'
                   AND c.outcome IN ('POTENTIAL_EXPOSURE','NOT_CHECKED','CONFIRMED_ISSUE')
                   AND EXISTS (SELECT 1 FROM scan_results sr WHERE sr.scan_id=c.scan_id AND sr.domain_id=c.domain_id)
                   AND d.scannable IS TRUE AND ({classification}) IN ('KNOWN','SHADOW')
                UNION ALL
                SELECT d.id,d.domain,
                       CASE WHEN lower(f.finding)='dangling_dns' THEN 'PROVIDER_SPECIFIC_CANDIDATE' ELSE 'UNKNOWN' END,
                       CASE WHEN lower(f.finding)='dangling_dns' THEN 'FINGERPRINT_CANDIDATE' ELSE 'UNVERIFIED_PROVIDER_RESPONSE' END,
                       NULL::text,NULL::text,NULL::text,NULL::timestamptz,
                       jsonb_build_object('source','domain_findings','finding',f.finding,'severity',f.severity,
                         'evidence_category',CASE WHEN lower(f.finding)='dangling_dns' THEN 'PROVIDER_SPECIFIC_CANDIDATE' ELSE 'UNKNOWN' END,
                         'verification_status',CASE WHEN lower(f.finding)='dangling_dns' THEN 'FINGERPRINT_CANDIDATE' ELSE 'UNVERIFIED_PROVIDER_RESPONSE' END,
                         'rationale',CASE WHEN lower(f.finding)='dangling_dns' THEN 'Existing provider-specific fingerprint finding; takeover confirmation is not implied.' ELSE 'Existing suspicious DNS response signal; it is not a provider fingerprint confirmation.' END,
                         'evidence',jsonb_build_object('raw_evidence',f.evidence))
                  FROM domain_findings f JOIN domains d ON d.id=f.domain_id
                 WHERE f.scan_id=%s AND lower(f.finding) IN ('dangling_dns','suspicious_dns')
                   AND EXISTS (SELECT 1 FROM scan_results sr WHERE sr.scan_id=f.scan_id AND sr.domain_id=f.domain_id)
                   AND d.scannable IS TRUE AND ({classification}) IN ('KNOWN','SHADOW')
            ), grouped AS (
                SELECT domain_id,hostname,array_agg(DISTINCT evidence_category) AS categories,
                       string_agg(DISTINCT provider, ', ' ORDER BY provider) FILTER (WHERE provider IS NOT NULL) AS provider,
                       (array_agg(confidence ORDER BY observed_at DESC NULLS LAST))[1] AS confidence,
                       (array_agg(cname_destination ORDER BY observed_at DESC NULLS LAST))[1] AS cname_destination,
                       string_agg(DISTINCT verification_status, ', ' ORDER BY verification_status) AS verification_status,
                       max(observed_at) AS observed_at,
                       jsonb_agg(observation ORDER BY observed_at DESC NULLS LAST) AS observations
                  FROM evidence GROUP BY domain_id,hostname
            ), classified AS (
                SELECT *, CASE WHEN 'PROVIDER_SPECIFIC_CANDIDATE'=ANY(categories) THEN 'PROVIDER_SPECIFIC_CANDIDATE'
                               WHEN 'DNS_NEGATIVE_SIGNAL'=ANY(categories) THEN 'DNS_NEGATIVE_SIGNAL'
                               WHEN 'UNVERIFIED_PROVIDER_ASSOCIATION'=ANY(categories) THEN 'UNVERIFIED_PROVIDER_ASSOCIATION'
                               ELSE 'UNKNOWN' END AS finding_category
                  FROM grouped
            )"""


def filtered_hosts_sql(cte, where, *, limit_offset=False, include_classification_time=False):
    suffix = " LIMIT %s OFFSET %s" if limit_offset else ""
    classification_time = (
        ", CURRENT_TIMESTAMP AS classification_as_of"
        if include_classification_time else ""
    )
    return cte + f"""
        SELECT domain_id, hostname, cname_destination, provider,
               finding_category, confidence, verification_status,
               observed_at, observations, categories{classification_time}
          FROM classified
         WHERE {where}
         ORDER BY hostname COLLATE "C" ASC, domain_id ASC{suffix}
    """


def all_hosts_sql(cte):
    return cte + """
        SELECT domain_id, hostname, cname_destination, provider,
               finding_category, confidence, verification_status,
               observed_at, observations, categories,
               CURRENT_TIMESTAMP AS classification_as_of
          FROM classified
         WHERE TRUE
         ORDER BY hostname COLLATE "C" ASC, domain_id ASC
    """


def csv_export_values(row, scan_id):
    """Flatten one grouped row without inventing absent historical evidence."""
    observations = row[8] or []
    if isinstance(observations, str):
        try:
            observations = json.loads(observations)
        except (TypeError, ValueError):
            observations = []
    observations = observations if isinstance(observations, list) else []
    observations = [item for item in observations if isinstance(item, dict)]
    dns_evidence = [item for item in observations
                    if item.get("source") == "dns_security_checks"]
    provider_evidence = [item for item in observations
        if item.get("source") == "domain_findings"
        or item.get("evidence_category") == "UNVERIFIED_PROVIDER_ASSOCIATION"]
    evidence_basis = sorted({str(item.get("source")) for item in observations
                             if item.get("source")})
    return (
        scan_id, row[1], row[2], row[3], row[4], row[9], row[5],
        row[6] or "UNVERIFIED", dns_evidence, provider_evidence, row[7],
        row[10] if len(row) > 10 else None, evidence_basis,
    )
