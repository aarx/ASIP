"""Read-only, retained Brand Discovery inventory.

Membership is recorded provenance, not an assertion that an old scan succeeded.
Classification uses the current reporting rules against the persisted domain row;
it is not a reconstruction of ownership at discovery time.
"""

from ownership import reporting_asset_class_sql


IDENTITY_SQL = "LOWER(TRIM(TRAILING '.' FROM BTRIM(d.domain)))"
CLASS_SQL = reporting_asset_class_sql("d.domain", "d.ownership_status")
HISTORY_CTE = f"""
WITH evidence AS (
    SELECT {IDENTITY_SQL} AS identity, d.id AS domain_id, d.domain,
           d.ownership_status, ds.scan_id, ds.source, s.scan_time, s.status
      FROM domain_sources ds
      JOIN domains d ON d.id = ds.domain_id
      JOIN scans s ON s.id = ds.scan_id
     WHERE ds.source IN ('brand_tld', 'brand_pattern')
       AND NULLIF({IDENTITY_SQL}, '') IS NOT NULL
), identities AS (
    SELECT identity, MIN(scan_id) AS first_evidence_scan_id,
           MAX(scan_id) AS last_evidence_scan_id,
           MIN(scan_time) AS first_evidence_at,
           MAX(scan_time) AS last_evidence_at,
           COUNT(*) AS source_associations,
           COUNT(DISTINCT scan_id) AS retained_scan_count,
           ARRAY_AGG(DISTINCT source ORDER BY source) AS discovery_sources
      FROM evidence GROUP BY identity
), latest AS (
    SELECT DISTINCT ON (identity) identity, domain_id, domain,
           ownership_status, scan_id AS latest_source_scan_id
      FROM evidence
     ORDER BY identity, scan_id DESC, domain_id DESC, domain
), inventory AS (
    SELECT i.*, l.domain_id, l.domain, l.ownership_status,
           l.latest_source_scan_id,
           CASE WHEN ({CLASS_SQL}) IN ('CANDIDATE', 'EXTERNAL')
                THEN 'NEEDS_VERIFICATION'
                WHEN ({CLASS_SQL}) IN ('KNOWN', 'SHADOW')
                THEN ({CLASS_SQL}) ELSE 'UNKNOWN' END AS review_class,
           ({CLASS_SQL}) AS asset_class
      FROM identities i JOIN latest l USING (identity)
      JOIN domains d ON d.id = l.domain_id
)
"""


def history_summary(cursor):
    cursor.execute(HISTORY_CTE + """
        SELECT review_class, COUNT(*) FROM inventory GROUP BY review_class
    """)
    counts = {name: 0 for name in
              ("NEEDS_VERIFICATION", "KNOWN", "SHADOW", "UNKNOWN")}
    counts.update(cursor.fetchall())
    cursor.execute("""
        SELECT COUNT(*), COUNT(DISTINCT ds.scan_id),
               MIN(ds.scan_id), MAX(ds.scan_id),
               MIN(s.scan_time), MAX(s.scan_time),
               COUNT(DISTINCT ds.scan_id) FILTER (WHERE s.status = 'SUCCEEDED'),
               COUNT(DISTINCT ds.scan_id) FILTER (WHERE s.status = 'UNKNOWN')
          FROM domain_sources ds JOIN scans s ON s.id = ds.scan_id
         WHERE ds.source IN ('brand_tld', 'brand_pattern')
    """)
    associations, scans, first_id, last_id, first_at, last_at, succeeded, legacy = cursor.fetchone()
    return {
        "scope": "retained_brand_source_history",
        "source_filter": ["brand_tld", "brand_pattern"],
        "normalization": "lowercase, trim surrounding whitespace and trailing dots; deduplicate by normalized hostname",
        "classification_basis": "current persisted ownership and current reporting rules; not ownership at historical observation time",
        "total": sum(counts.values()),
        "counts": {"needs_verification": counts["NEEDS_VERIFICATION"],
                   "known": counts["KNOWN"], "shadow": counts["SHADOW"],
                   "unknown": counts["UNKNOWN"]},
        "retention": {
            "source_associations": associations,
            "scan_count": scans,
            "succeeded_scan_count": succeeded,
            "legacy_unknown_status_scan_count": legacy,
            "other_status_scan_count": scans - succeeded - legacy,
            "first_evidence_scan_id": first_id,
            "last_evidence_scan_id": last_id,
            "first_evidence_at": first_at,
            "last_evidence_at": last_at,
            "limitation": "Only retained domain_sources rows are counted; legacy UNKNOWN scan status does not establish scan success. Earlier or deleted evidence cannot be reconstructed.",
        },
    }


def history_assets(cursor, *, page, limit, classification=None, search=None,
                   sort_by="domain", sort_dir="asc"):
    field = {"domain": "identity", "first_seen": "first_evidence_scan_id",
             "last_seen": "last_evidence_scan_id"}[sort_by]
    direction = "ASC" if sort_dir == "asc" else "DESC"
    where = "WHERE (%s IS NULL OR review_class = %s) AND (%s IS NULL OR POSITION(%s IN identity) > 0)"
    search_value = search.lower() if search else None
    params = (classification, classification, search_value, search_value)
    cursor.execute(HISTORY_CTE + f" SELECT COUNT(*) FROM inventory {where}", params)
    total = cursor.fetchone()[0]
    cursor.execute(HISTORY_CTE + f"""
        SELECT identity, domain, ownership_status, asset_class, review_class,
               first_evidence_scan_id, last_evidence_scan_id,
               first_evidence_at, last_evidence_at, source_associations,
               retained_scan_count, discovery_sources, latest_source_scan_id
          FROM inventory {where}
         ORDER BY {field} {direction}, identity ASC, domain_id ASC
         LIMIT %s OFFSET %s
    """, params + (limit, (page - 1) * limit))
    names = ("identity", "domain", "ownership_status", "asset_class", "review_class",
             "first_evidence_scan_id", "last_evidence_scan_id", "first_evidence_at",
             "last_evidence_at", "source_associations", "retained_scan_count",
             "discovery_sources", "latest_source_scan_id")
    return {"scope": "retained_brand_source_history", "page": page, "limit": limit,
            "count": total, "classification": classification, "search": search,
            "sort_by": sort_by, "sort_dir": sort_dir,
            "assets": [dict(zip(names, row)) for row in cursor.fetchall()]}
