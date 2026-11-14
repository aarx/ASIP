"""Read-only identity population for retained-scan Asset Inventory."""

from ownership import reporting_asset_class_sql


def identity_sql(expression="d.domain"):
    raw = f"LOWER(BTRIM({expression}))"
    dns = (
        r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
        r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.?$"
    )
    return f"CASE WHEN {raw} ~ '{dns}' AND LENGTH(TRIM(TRAILING '.' FROM {raw})) <= 253 " \
           f"THEN TRIM(TRAILING '.' FROM {raw}) ELSE {raw} END"


def retained_inventory_cte():
    classification = reporting_asset_class_sql("d.domain", "d.ownership_status")
    identity = identity_sql()
    return f"""
      WITH membership AS (
        SELECT sr.scan_id, d.id AS domain_id, d.domain, d.is_known,
               d.ownership_status, s.scan_time, s.status AS scan_status,
               {identity} AS identity_key,
               ({classification}) AS asset_class,
               ROW_NUMBER() OVER (
                 PARTITION BY {identity}
                 ORDER BY s.scan_time DESC NULLS LAST, sr.scan_id DESC, d.id DESC
               ) AS evidence_rank,
               MIN(s.scan_time) OVER (PARTITION BY {identity}) AS first_observed_at,
               MAX(s.scan_time) OVER (PARTITION BY {identity}) AS last_observed_at
          FROM scan_results sr
          JOIN scans s ON s.id = sr.scan_id
          JOIN domains d ON d.id = sr.domain_id
      ), identity_scan_counts AS (
        SELECT identity_key, COUNT(DISTINCT scan_id) AS retained_scan_count
          FROM membership GROUP BY identity_key
      ), latest AS (
        SELECT m.*, isc.retained_scan_count,
               EXISTS (SELECT 1 FROM membership cur
                        WHERE cur.identity_key=m.identity_key
                          AND cur.scan_id=(SELECT MAX(id) FROM scans WHERE status='SUCCEEDED')) AS current_scan_member,
               cs.id AS current_scan_id
          FROM membership m
          JOIN identity_scan_counts isc USING (identity_key)
          LEFT JOIN scans cs ON cs.status='SUCCEEDED'
                            AND cs.id=(SELECT MAX(id) FROM scans WHERE status='SUCCEEDED')
         WHERE m.evidence_rank=1
      ), enriched AS (
        SELECT l.*, ds.ip, ds.has_ip,
               CASE WHEN ds.http_observation_status='RESPONDED' THEN TRUE
                    WHEN ds.http_observation_status='NO_RESPONSE' THEN FALSE
                    ELSE NULL END AS http_live,
               COALESCE(ds.http_observation_status, 'UNKNOWN') AS http_observation_status,
               CASE WHEN ds.http_observation_status='RESPONDED'
                          AND ds.http_status BETWEEN 100 AND 599
                    THEN ds.http_status ELSE NULL END AS http_status,
               ds.title, ds.final_url, ds.final_status, ds.http_redirect_evidence,
               COALESCE(dp.provider, 'Unknown') AS provider, da.asn,
               dr.risk_score, dr.reasons AS risk_reasons,
               COALESCE((SELECT json_agg(json_build_object('source',x.source,'seed',x.seed)
                                         ORDER BY x.source,x.seed)
                           FROM domain_sources x WHERE x.scan_id=l.scan_id
                            AND x.domain_id=l.domain_id), '[]'::json) AS provenance,
               (ds.domain_id IS NOT NULL) AS state_available,
               (dp.domain_id IS NOT NULL) AS provider_available,
               (da.domain_id IS NOT NULL) AS asn_available,
               (dr.domain_id IS NOT NULL) AS risk_available
          FROM latest l
          LEFT JOIN domain_states ds ON ds.domain_id=l.domain_id AND ds.scan_id=l.scan_id
          LEFT JOIN domain_provider dp ON dp.domain_id=l.domain_id AND dp.scan_id=l.scan_id
          LEFT JOIN domain_asn da ON da.domain_id=l.domain_id AND da.scan_id=l.scan_id
          LEFT JOIN domain_risk dr ON dr.domain_id=l.domain_id AND dr.scan_id=l.scan_id
      )
    """


def historical_identity_lookup_sql():
    """Resolve one requested identity with a single safely bound input value."""
    return retained_inventory_cte() + f"""
      SELECT e.domain, e.scan_id, e.scan_time, e.scan_status,
             e.current_scan_member, e.identity_key
        FROM enriched e
        CROSS JOIN (SELECT %s::text AS domain) requested
       WHERE e.identity_key={identity_sql('requested.domain')}
    """


def scan_identity_lookup_sql():
    """Resolve a requested identity only when it is a member of one scan."""
    return f"""
      SELECT d.domain
        FROM scan_results sr
        JOIN domains d ON d.id=sr.domain_id
        CROSS JOIN (SELECT %s::text AS domain) requested
       WHERE sr.scan_id=%s
         AND {identity_sql('d.domain')}={identity_sql('requested.domain')}
       ORDER BY d.id LIMIT 1
    """


def normalize_historical_http_payload(http_payload):
    """Keep HTTP state and code semantics separate for retained evidence."""
    http = dict(http_payload or {})
    observation = (http.get("observation_status") or "UNKNOWN").upper()
    status = http.get("status")
    valid_status = isinstance(status, int) and 100 <= status <= 599
    if observation != "RESPONDED" or not valid_status:
        http["status"] = None
    if observation == "UNKNOWN":
        http["live"] = None
    elif observation == "NO_RESPONSE":
        http["live"] = False
    return http


def list_retained_assets(cursor, *, page, limit, filters, sort_by, sort_dir):
    """Apply filters/count/order/page in SQL against the one-row identity CTE."""
    clauses, params = [], []
    mapping = {
        "search": ("POSITION(LOWER(%s) IN LOWER(domain)) > 0", lambda x: x.strip()),
        "ownership": ("UPPER(ownership_status)=UPPER(%s)", str),
        "asset_class": ("asset_class=UPPER(%s)", str),
        "provider": ("LOWER(COALESCE(provider,''))=LOWER(%s)", str),
        "http_observation_status": ("http_observation_status=UPPER(%s)", str),
        "http_status": ("http_status=%s", int),
        "http_status_group": ("http_status BETWEEN %s AND %s", None),
    }
    for key, value in filters.items():
        if value is None:
            continue
        if key == "discovery_source":
            if value == "brand_union":
                clauses.append("EXISTS (SELECT 1 FROM domain_sources src WHERE src.domain_id=e.domain_id AND src.scan_id=e.scan_id AND src.source IN ('brand_tld','brand_pattern'))")
            else:
                clauses.append("EXISTS (SELECT 1 FROM domain_sources src WHERE src.domain_id=e.domain_id AND src.scan_id=e.scan_id AND src.source=%s)")
                params.append(value)
        elif key == "exposure_keyword":
            keyword = value.strip().lower()
            if keyword == "stage":
                clauses.append("(LOWER(domain) LIKE %s AND LOWER(domain) NOT LIKE %s)")
                params.extend(("%stage%", "%staging%"))
            else:
                clauses.append("LOWER(domain) LIKE %s")
                params.append(f"%{keyword}%")
        if key in ("has_ip", "http_live"):
            clauses.append(f"{key}=%s")
            params.append(value)
        elif key == "priority":
            clauses.append("CASE WHEN risk_score >= 8 THEN 'High' WHEN risk_score >= 6 THEN 'Elevated' WHEN risk_score >= 4 THEN 'Review' WHEN risk_score IS NOT NULL THEN 'Low' END= %s")
            params.append(value.title())
        elif key in ("risk_min", "risk_max"):
            clauses.append("risk_score " + (">=" if key == "risk_min" else "<=") + " %s")
            params.append(value)
        elif key == "risk_positive":
            clauses.append("risk_score " + ("> 0" if value else "<= 0 AND risk_score IS NOT NULL"))
        elif key in mapping:
            sql, transform = mapping[key]
            if key == "http_status_group":
                lower = int(value[0]) * 100
                clauses.append(sql)
                params.extend((lower, lower + 99))
            else:
                clauses.append(sql)
                params.append(transform(value))
    if any(filters.get(k) is not None for k in ("has_ip", "http_live", "http_status", "http_status_group")):
        clauses.append("asset_class IN ('KNOWN','SHADOW')")
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    sort_expr = {
        "domain": "identity_key",
        "priority": "CASE WHEN risk_score >= 8 THEN 3 WHEN risk_score >= 6 THEN 2 WHEN risk_score >= 4 THEN 1 WHEN risk_score IS NOT NULL THEN 0 END",
        "risk_score": "risk_score",
    }[sort_by]
    direction = "DESC" if sort_dir == "desc" else "ASC"
    cursor.execute(retained_inventory_cte() + f"SELECT COUNT(*) FROM enriched e{where}", tuple(params))
    total = cursor.fetchone()[0]
    cursor.execute(retained_inventory_cte() + f"""
      SELECT identity_key, domain, current_scan_member, current_scan_id,
             asset_class, ownership_status, is_known, first_observed_at,
             last_observed_at, scan_id, scan_time, scan_status,
             ip, has_ip, http_live, http_observation_status, http_status,
             title, final_url, final_status, provider, asn, risk_score, risk_reasons,
             provenance, state_available, provider_available, asn_available,
             risk_available, retained_scan_count
        FROM enriched e{where}
       ORDER BY {sort_expr} {direction} NULLS LAST, identity_key ASC, domain ASC
       LIMIT %s OFFSET %s
    """, tuple(params) + (limit, (page-1)*limit))
    names = ("identity_key", "domain", "current_scan_member", "current_scan_id",
             "asset_class", "ownership_status", "is_known", "first_observed_at",
             "last_observed_at", "latest_evidence_scan_id", "latest_evidence_at",
             "latest_evidence_scan_status", "ip", "has_ip", "http_live",
             "http_observation_status", "http_status", "title", "final_url",
             "final_status", "provider", "asn", "risk_score", "risk_reasons", "provenance",
             "state_available", "provider_available", "asn_available",
             "risk_available", "retained_scan_count")
    return total, [dict(zip(names, row)) for row in cursor.fetchall()]
