"""Separate, passive CVE assessment over stored scan evidence.

This module never performs network I/O. The CLI is the only execution entry
point; HTTP integrations below this layer are read-only.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import uuid
from urllib.parse import urlparse

from php_cve_intelligence import PHP_CVE_ADVISORIES, evaluate_php_cve_applicability
from apache_version_evidence import parse_apache_server_header
from ownership import reporting_asset_class_sql, trusted_boundary_sql
from authorization_policy import (
    CAPD_HTTP_HEADER_VERIFY,
    active_scope_exclusion_sql,
)


CHECKS_PATH = Path(__file__).with_name("capd_checks.json")
MAX_TARGETS = 1000
MAX_PAGE_SIZE = 200
RESULT_STATUSES = frozenset({
    "POTENTIAL_MATCH", "INSUFFICIENT_EVIDENCE", "NOT_APPLICABLE", "UNSUPPORTED", "ERROR",
})
MATCH_CLASSIFICATIONS = frozenset({
    "VERSION_MATCHED", "PRODUCT_MATCHED_VERSION_UNKNOWN", "SERVICE_CANDIDATE",
    "NOT_APPLICABLE", "INSUFFICIENT_EVIDENCE",
})
CONFIDENCE_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}
FORBIDDEN_SERVICE_ALIASES = frozenset({"http", "https", "web", "www", "tcp", "ssl", "tls"})
CHECK_FIELDS = frozenset({
    "check_id", "check_revision", "cve_id", "vendor", "product", "canonical_product",
    "platform", "category", "enabled", "version_scheme", "affected_ranges",
    "required_evidence", "verification_method", "advisory_reference",
    "source_updated_at", "last_reviewed_at", "coverage", "limitations", "service_aliases",
})


class CapdError(ValueError):
    """Invalid check, run request, or CAPD state."""


def _version_tuple(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d+\.\d+\.\d+", value):
        return None
    return tuple(int(part) for part in value.split("."))


def load_checks(path=None):
    """Load and validate inert JSON check definitions; no code is evaluated."""
    path = CHECKS_PATH if path is None else path
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CapdError("CAPD check catalog could not be loaded") from exc
    if not isinstance(payload, dict) or payload.get("catalog_schema_version") != 1:
        raise CapdError("Unsupported CAPD catalog schema version")
    checks = payload.get("checks")
    if not isinstance(checks, list):
        raise CapdError("CAPD checks must be a list")
    validated = {}
    for item in checks:
        if not isinstance(item, dict):
            raise CapdError("Invalid CAPD check definition")
        if set(item) - CHECK_FIELDS:
            raise CapdError("CAPD check contains unsupported fields")
        check_id = item.get("check_id")
        if not isinstance(check_id, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,120}", check_id):
            raise CapdError("Invalid CAPD check identifier")
        if check_id in validated:
            raise CapdError("Duplicate CAPD check identifier")
        required_text = ("check_revision", "cve_id", "vendor", "product", "canonical_product",
                         "category", "advisory_reference", "last_reviewed_at")
        if any(not isinstance(item.get(key), str) or not item[key].strip() for key in required_text):
            raise CapdError("CAPD check is missing required versioned advisory metadata")
        if not re.fullmatch(r"\d+\.\d+\.\d+", item["check_revision"]):
            raise CapdError("CAPD check revision must use semantic version syntax")
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", item["cve_id"]):
            raise CapdError("Invalid CAPD CVE identifier")
        if item["canonical_product"] != item["canonical_product"].strip().lower():
            raise CapdError("Canonical product must use normalized lowercase text")
        advisory = urlparse(item["advisory_reference"])
        if advisory.scheme != "https" or not advisory.netloc:
            raise CapdError("CAPD advisory reference must be an HTTPS URL")
        for date_field in ("last_reviewed_at", "source_updated_at"):
            value = item.get(date_field)
            if value is not None:
                try:
                    date.fromisoformat(value)
                except (TypeError, ValueError) as exc:
                    raise CapdError(f"Invalid CAPD {date_field}") from exc
        if not isinstance(item.get("enabled"), bool):
            raise CapdError("CAPD check enabled state is required")
        if item.get("version_scheme") not in {"php_semver3", "numeric_dotted3"}:
            raise CapdError("Unsupported CAPD version comparison scheme")
        required = item.get("required_evidence")
        if not isinstance(required, dict) or set(required) - {
            "technology_labels", "structured_sources", "evidence_types", "minimum_detection_confidence"
        }:
            raise CapdError("CAPD check required evidence fields are invalid")
        if any(not isinstance(required.get(key), list) or not required[key]
               or any(not isinstance(value, str) or not value.strip() for value in required[key])
               for key in ("technology_labels", "structured_sources", "evidence_types")):
            raise CapdError("CAPD check requires exact technology labels")
        if required.get("minimum_detection_confidence") not in CONFIDENCE_RANK:
            raise CapdError("CAPD check has invalid minimum confidence")
        if item.get("verification_method") != "PASSIVE_VERSION_RANGE_MATCH":
            raise CapdError("Only passive CAPD checks are supported")
        if not isinstance(item.get("affected_ranges"), list) or not item["affected_ranges"]:
            raise CapdError("CAPD check requires affected version ranges")
        for version_range in item["affected_ranges"]:
            if not isinstance(version_range, dict):
                raise CapdError("Invalid affected version range")
            branch = version_range.get("branch")
            fixed = version_range.get("fixed")
            if branch is not None and not re.fullmatch(r"\d+\.\d+", str(branch)):
                raise CapdError("Invalid version branch")
            if _version_tuple(fixed) is None:
                raise CapdError("Invalid fixed version")
        service_aliases = item.get("service_aliases", [])
        if not isinstance(service_aliases, list) or any(
            not isinstance(alias, str) or alias.strip().lower() in FORBIDDEN_SERVICE_ALIASES
            for alias in service_aliases
        ):
            raise CapdError("Service aliases must be specific product evidence")
        validated[check_id] = item
    return payload["catalog_schema_version"], validated


def get_check(check_id, *, include_disabled=True):
    _schema, checks = load_checks()
    item = checks.get(str(check_id))
    if item is None or (not include_disabled and not item["enabled"]):
        raise CapdError("CAPD check not found or disabled")
    return item


def public_check(item):
    return {
        key: item.get(key)
        for key in (
            "check_id", "check_revision", "cve_id", "vendor", "product", "platform",
            "category", "affected_ranges", "version_scheme", "required_evidence",
            "verification_method", "advisory_reference", "source_updated_at",
            "last_reviewed_at", "enabled", "coverage", "limitations",
        )
    }


def _latest_scan_id(cur):
    cur.execute("SELECT id FROM scans WHERE status = %s ORDER BY id DESC LIMIT 1", ("SUCCEEDED",))
    row = cur.fetchone()
    return row[0] if row else None


def _validate_source_scan(cur, scan_id=None):
    selected = _latest_scan_id(cur) if scan_id is None else int(scan_id)
    if selected is None:
        raise CapdError("No successful inventory scan exists")
    cur.execute("SELECT id, status, completed_at FROM scans WHERE id = %s", (selected,))
    row = cur.fetchone()
    if row is None:
        raise CapdError("Source inventory scan not found")
    if row[1] != "SUCCEEDED":
        raise CapdError("Source inventory scan must be SUCCEEDED")
    return {"scan_id": row[0], "status": row[1], "completed_at": _iso(row[2])}


def _eligibility_sql(testing_level="ADHOC_CHECK"):
    return (
        reporting_asset_class_sql("d.domain", "d.ownership_status"),
        trusted_boundary_sql("d.domain"),
        active_scope_exclusion_sql("d", testing_level),
    )


def _eligibility_summary(cur, scan_id, testing_level="ADHOC_CHECK"):
    class_sql, boundary_sql, exclusion_sql = _eligibility_sql(testing_level)
    cur.execute(f"""
        WITH members AS (
            SELECT DISTINCT sr.domain_id, d.ownership_status, d.scannable,
                   d.confidence_reasons, ({class_sql}) AS asset_class,
                   ({boundary_sql}) AS trusted,
                   ({exclusion_sql}) AS excluded
              FROM scan_results sr JOIN domains d ON d.id = sr.domain_id
             WHERE sr.scan_id = %s
        )
        SELECT COUNT(*),
               COUNT(*) FILTER (WHERE asset_class IN ('KNOWN','SHADOW')),
               COUNT(*) FILTER (WHERE asset_class IN ('KNOWN','SHADOW') AND scannable IS TRUE),
               COUNT(*) FILTER (WHERE asset_class IN ('KNOWN','SHADOW')
                                  AND ownership_status = 'CONFIRMED' AND scannable IS TRUE
                                  AND trusted AND NOT COALESCE('manually rejected' = ANY(confidence_reasons), FALSE)
                                  AND NOT excluded)
          FROM members
    """, (scan_id,))
    total_members, organizational, scannable_org, eligible = cur.fetchone()
    cur.execute(f"""
        WITH members AS (
            SELECT DISTINCT sr.domain_id, d.ownership_status, d.scannable,
                   d.confidence_reasons, ({class_sql}) AS asset_class,
                   ({boundary_sql}) AS trusted,
                   ({exclusion_sql}) AS excluded
              FROM scan_results sr JOIN domains d ON d.id = sr.domain_id
             WHERE sr.scan_id = %s
        )
        SELECT CASE
                 WHEN asset_class IS NULL OR asset_class NOT IN ('KNOWN','SHADOW') THEN 'OUTSIDE_ORGANIZATIONAL_CLASS'
                 WHEN ownership_status IS DISTINCT FROM 'CONFIRMED' THEN 'OWNERSHIP_NOT_CONFIRMED'
                 WHEN scannable IS DISTINCT FROM TRUE THEN 'NOT_SCANNABLE'
                 WHEN trusted IS DISTINCT FROM TRUE THEN 'OUTSIDE_TRUSTED_BOUNDARY'
                 WHEN COALESCE('manually rejected' = ANY(confidence_reasons), FALSE) THEN 'MANUALLY_REJECTED'
                 WHEN excluded IS DISTINCT FROM FALSE THEN 'OPERATION_SCOPE_EXCLUDED'
                 ELSE 'ELIGIBLE'
               END AS reason,
               COUNT(*)
          FROM members
         GROUP BY reason
         ORDER BY reason
    """, (scan_id,))
    skipped_by_reason = {reason: count for reason, count in cur.fetchall() if reason != "ELIGIBLE"}
    return {
        "scan_members": total_members,
        "organizational_members": organizational,
        "scannable_organizational_members": scannable_org,
        "eligible_targets": eligible,
        "excluded_or_ineligible": total_members - eligible,
        "skipped_by_reason": skipped_by_reason,
    }


def _select_targets(cur, scan_id, limit, testing_level="ADHOC_CHECK"):
    class_sql, boundary_sql, exclusion_sql = _eligibility_sql(testing_level)
    cur.execute(f"""
        SELECT DISTINCT d.id, d.domain, ({class_sql}) AS asset_class
          FROM scan_results sr JOIN domains d ON d.id = sr.domain_id
         WHERE sr.scan_id = %s
           AND d.ownership_status = 'CONFIRMED'
           AND d.scannable IS TRUE
           AND ({class_sql}) IN ('KNOWN','SHADOW')
           AND ({boundary_sql})
           AND NOT COALESCE('manually rejected' = ANY(d.confidence_reasons), FALSE)
           AND NOT ({exclusion_sql})
         ORDER BY d.domain, d.id
         LIMIT %s
    """, (scan_id, int(limit)))
    # These fields document that this exact row passed the inventory
    # eligibility query. They are not a substitute for a fresh operation-level
    # authorization check before any future live CAPD request.
    return [{"domain_id": row[0], "domain": row[1], "asset_class": row[2],
             "scannable": True, "inventory_eligible": True} for row in cur.fetchall()]


def preview_targets(conn, check_id, *, scan_id=None, limit=MAX_TARGETS):
    check = get_check(check_id, include_disabled=False)
    limit = _bounded_limit(limit)
    cur = conn.cursor()
    cur.execute("SET TRANSACTION READ ONLY")
    cur.execute("SET LOCAL statement_timeout = 10000")
    cur.execute("SET LOCAL lock_timeout = 1000")
    scan = _validate_source_scan(cur, scan_id)
    summary = _eligibility_summary(cur, scan["scan_id"])
    targets = _select_targets(cur, scan["scan_id"], limit)
    evidence_by_domain = _load_evidence(cur, scan["scan_id"], targets, check)
    relevance, target_relevance = _relevance_summary(check, targets, evidence_by_domain)
    relevance["eligible_inventory_assets"] = summary["eligible_targets"]
    relevance["selected_inventory_assets"] = len(targets)
    return {
        "check": public_check(check), "source_scan": scan, "selection": summary,
        "target_limit": limit, "selected_count": len(targets),
        "truncated": summary["eligible_targets"] > len(targets),
        "relevance": relevance, "targets": target_relevance,
    }


def preview_product_targets(conn, product, *, scan_id=None, limit=MAX_TARGETS):
    """Read-only, service-specific inventory preview; never performs requests."""
    normalized = str(product or "").strip().lower()
    if normalized != "apache":
        raise CapdError("Unsupported CAPD product preview")
    limit = _bounded_limit(limit)
    cur = conn.cursor()
    cur.execute("SET TRANSACTION READ ONLY")
    cur.execute("SET LOCAL statement_timeout = 10000")
    cur.execute("SET LOCAL lock_timeout = 1000")
    scan = _validate_source_scan(cur, scan_id)
    selection = _eligibility_summary(
        cur, scan["scan_id"], CAPD_HTTP_HEADER_VERIFY
    )
    targets = _select_targets(
        cur, scan["scan_id"], limit, CAPD_HTTP_HEADER_VERIFY
    )
    product_definition = {
        "required_evidence": {
            "technology_labels": ["apache"],
            "structured_sources": ["domain_technology_observations"],
            "evidence_types": ["server_header"],
            "minimum_detection_confidence": "medium",
        },
        "service_aliases": ["apache", "httpd", "apache-httpd"],
    }
    evidence = _load_evidence(cur, scan["scan_id"], targets, product_definition)
    rows = []
    candidate_counts = {"product_matched_candidates": 0, "version_known_candidates": 0,
                        "version_unknown_candidates": 0, "service_only_candidates": 0,
                        "insufficient_evidence": 0}
    for target in targets:
        records = evidence.get(target["domain_id"], [])
        products = [row for row in records if str(row.get("technology") or "").lower() == "apache"]
        parsed_versions = []
        for record in products:
            if record.get("source") != "domain_technology_observations" or record.get("evidence_type") != "server_header":
                continue
            parsed = parse_apache_server_header(str(record.get("evidence") or ""))
            if (parsed["outcome"] == "VERSION_IDENTIFIED"
                    and parsed["version"] == record.get("version")
                    and record.get("confidence") == "high"):
                parsed_versions.append((record, parsed))
        services = [row for row in records if row.get("source") == "domain_ports"]
        if products:
            candidate_counts["product_matched_candidates"] += 1
            if parsed_versions:
                candidate_counts["version_known_candidates"] += 1
                classification = "VERSION_KNOWN"
                outcome = "VERSION_IDENTIFIED"
                version = parsed_versions[0][1]["version"]
                selected_evidence = [item[0] for item in parsed_versions]
            else:
                candidate_counts["version_unknown_candidates"] += 1
                classification = "VERSION_UNKNOWN"
                outcome = "PRODUCT_IDENTIFIED_VERSION_UNKNOWN"
                version = None
                selected_evidence = products
        elif services:
            candidate_counts["service_only_candidates"] += 1
            classification = "SERVICE_ONLY_CANDIDATE"
            outcome = "INSUFFICIENT_EVIDENCE"
            version = None
            selected_evidence = services
        else:
            candidate_counts["insufficient_evidence"] += 1
            continue
        rows.append({**target, "classification": classification, "outcome": outcome,
                     "version": version, "evidence": selected_evidence})
    truncated = selection["eligible_targets"] > len(targets)
    populations = {
        "eligible_inventory_total": selection["eligible_targets"],
        "selected_inventory_total": len(targets),
        "candidate_counts_scope": "SELECTED_INVENTORY",
        "candidate_counts_complete": not truncated,
        "truncated": truncated,
        "selected_candidate_counts": candidate_counts,
        "excluded_targets": selection["skipped_by_reason"],
    }
    return {
        "product": "Apache HTTP Server", "source_scan": scan, "selection": selection,
        "populations": populations,
        "version_verification_preview": {
            "enabled": False, "network_requests": 0, "database_writes": 0,
            "request": "One bounded GET to the already-observed approved origin; redirects disabled.",
            "authorization_required": "CAPD_HTTP_HEADER_VERIFY plus signed local approval and current per-target revalidation.",
            "targets": "Apache product-matched candidates only; generic HTTP services are excluded.",
        },
        "targets": rows,
    }


def _bounded_limit(value):
    try:
        limit = int(value)
    except (TypeError, ValueError) as exc:
        raise CapdError("Target limit must be an integer") from exc
    if limit < 1 or limit > MAX_TARGETS:
        raise CapdError(f"Target limit must be between 1 and {MAX_TARGETS}")
    return limit


def _load_evidence(cur, scan_id, targets, check):
    if not targets:
        return {}
    ids = [item["domain_id"] for item in targets]
    required = check["required_evidence"]
    labels = [str(label).strip().lower() for label in required["technology_labels"]]
    output = {domain_id: [] for domain_id in ids}
    cur.execute("""
        SELECT domain_id, technology, version, confidence, evidence_type,
               sanitized_evidence, observed_url, detector_version, created_at
          FROM domain_technology_observations
         WHERE scan_id = %s AND domain_id = ANY(%s)
         ORDER BY domain_id, technology, version NULLS FIRST, evidence_type, id
    """, (scan_id, ids))
    for row in cur.fetchall():
        output[row[0]].append({
            "source": "domain_technology_observations", "technology": row[1],
            "version": row[2], "confidence": row[3], "evidence_type": row[4],
            "evidence": row[5], "observed_url": row[6], "detector_version": row[7],
            "persisted_at": _iso(row[8]),
        })
    legacy_labels = set(labels)
    cur.execute("""
        SELECT domain_id, tech FROM domain_tech
         WHERE scan_id = %s AND domain_id = ANY(%s)
         ORDER BY domain_id, tech
    """, (scan_id, ids))
    present = {(domain_id, str(item["technology"]).strip().lower())
               for domain_id, records in output.items() for item in records}
    for domain_id, technology in cur.fetchall():
        normalized = str(technology or "").strip().lower()
        if normalized in legacy_labels and (domain_id, normalized) not in present:
            output[domain_id].append({
                "source": "domain_tech", "technology": normalized, "version": None,
                "confidence": "none", "evidence_type": "legacy_label",
                "evidence": "Legacy scan-scoped technology label; no version evidence.",
                "observed_url": None, "detector_version": None, "persisted_at": None,
            })
    service_aliases = {str(value).strip().lower() for value in check.get("service_aliases", [])}
    if service_aliases:
        cur.execute("""
            SELECT domain_id, port, service FROM domain_ports
             WHERE scan_id = %s AND domain_id = ANY(%s)
             ORDER BY domain_id, port, service
        """, (scan_id, ids))
        for domain_id, port, service in cur.fetchall():
            if str(service or "").strip().lower() in service_aliases:
                output[domain_id].append({
                    "source": "domain_ports", "service": service, "port": port,
                    "technology": None, "version": None, "confidence": "low",
                    "evidence_type": "service_name", "evidence": "Stored port service label; product is unverified.",
                    "observed_url": None, "detector_version": None, "persisted_at": None,
                })
    return output


def _php_candidate(check, version, assessment_date):
    evaluated = evaluate_php_cve_applicability(
        "php", version, PHP_CVE_ADVISORIES, assessment_date
    )
    return next((item for item in evaluated["candidates"] if item.get("cve_id") == check["cve_id"]), None)


def _version_candidate(check, version):
    parsed = _version_tuple(version)
    if parsed is None:
        return "INSUFFICIENT_EVIDENCE", "INSUFFICIENT_EVIDENCE", "Reported version is absent or not supported by the declared comparison scheme."
    ranges = check["affected_ranges"]
    branch_ranges = [item for item in ranges if not item.get("branch") or parsed[:2] == tuple(int(part) for part in item["branch"].split("."))]
    if not branch_ranges:
        return "INSUFFICIENT_EVIDENCE", "INSUFFICIENT_EVIDENCE", "The product version branch is not covered by this check definition."
    if check["canonical_product"] == "php":
        candidate = _php_candidate(check, version, date.today())
        if candidate is None:
            return "UNSUPPORTED", "INSUFFICIENT_EVIDENCE", "No matching local advisory evaluation is available."
        status = candidate["applicability_status"]
        if status == "potentially_affected":
            return "POTENTIAL_MATCH", "VERSION_MATCHED", candidate["explanation_code"]
        if status == "not_affected_by_version":
            return "NOT_APPLICABLE", "NOT_APPLICABLE", candidate["explanation_code"]
        return "INSUFFICIENT_EVIDENCE", "INSUFFICIENT_EVIDENCE", candidate["explanation_code"]
    for item in branch_ranges:
        lower = _version_tuple(item.get("introduced")) if item.get("introduced") else None
        upper = _version_tuple(item.get("fixed")) if item.get("fixed") else None
        if (lower is None or parsed >= lower) and (upper is None or parsed < upper):
            return "POTENTIAL_MATCH", "VERSION_MATCHED", "Reported version falls inside the declared affected range."
    return "NOT_APPLICABLE", "NOT_APPLICABLE", "Reported version is outside the declared affected ranges."


def _evidence_identity(records, domain_id):
    canonical = json.dumps(records, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256((str(domain_id) + ":" + canonical).encode("utf-8")).hexdigest()


def _relevance_summary(check, targets, evidence_by_domain):
    product_assets, service_assets, version_assets = set(), set(), set()
    no_relevant_assets, potential_assets = set(), set()
    target_relevance = []
    required = check["required_evidence"]
    labels = {str(label).strip().lower() for label in required["technology_labels"]}
    acceptable_sources = set(required.get("structured_sources", []))
    acceptable_types = set(required.get("evidence_types", []))
    minimum = required.get("minimum_detection_confidence", "none")
    for target in targets:
        records = evidence_by_domain.get(target["domain_id"], [])
        product_records = [record for record in records
                           if str(record.get("technology") or "").strip().lower() in labels]
        service_records = [record for record in records if record.get("source") == "domain_ports"]
        versions = [record for record in product_records
                    if record.get("source") in acceptable_sources
                    and record.get("evidence_type") in acceptable_types
                    and CONFIDENCE_RANK.get(str(record.get("confidence") or "none").lower(), 0)
                        >= CONFIDENCE_RANK.get(minimum, 0)
                    and record.get("version")]
        product = bool(product_records)
        service = bool(service_records) and not product
        version = any(_version_candidate(check, record.get("version"))[1] == "VERSION_MATCHED"
                      for record in versions)
        assessment_error = False
        try:
            assessments = _assess_asset(check, target, records)
        except Exception:
            assessments = []
            assessment_error = True
        potential = any(item["result_status"] == "POTENTIAL_MATCH" for item in assessments)
        if product:
            product_assets.add(target["domain_id"])
        if service and not product:
            service_assets.add(target["domain_id"])
        if version:
            version_assets.add(target["domain_id"])
        if not product and not service:
            no_relevant_assets.add(target["domain_id"])
        if potential:
            potential_assets.add(target["domain_id"])
        if assessment_error:
            relevance_class = "ASSESSMENT_ERROR"
        elif potential:
            relevance_class = "POTENTIAL_CVE_MATCH"
        elif version:
            relevance_class = "VERSION_MATCHED_CANDIDATE"
        elif product:
            relevance_class = "PRODUCT_MATCHED_CANDIDATE"
        elif service:
            relevance_class = "SERVICE_CANDIDATE"
        else:
            relevance_class = "NO_RELEVANT_PRODUCT_OR_SERVICE_EVIDENCE"
        target_relevance.append({
            **target,
            "relevance": relevance_class,
            "product": check["product"] if product else None,
            "version": versions[0].get("version") if versions else None,
            "result_statuses": sorted({item["result_status"] for item in assessments})
                               if assessments else (["ERROR"] if assessment_error else ["INSUFFICIENT_EVIDENCE"]),
        })
    return ({
        "product_matched_candidate_assets": len(product_assets),
        "service_candidate_assets": len(service_assets),
        "version_matched_candidate_assets": len(version_assets),
        "assets_without_relevant_product_or_service_evidence": len(no_relevant_assets),
        "potential_cve_match_assets": len(potential_assets),
    }, target_relevance)


def _assess_asset(check, target, records):
    labels = {str(label).strip().lower() for label in check["required_evidence"]["technology_labels"]}
    acceptable_sources = set(check["required_evidence"].get("structured_sources", []))
    acceptable_types = set(check["required_evidence"].get("evidence_types", []))
    minimum = check["required_evidence"].get("minimum_detection_confidence", "none")
    product_records = [record for record in records if str(record.get("technology") or "").lower() in labels]
    service_records = [record for record in records if record.get("source") == "domain_ports"]
    usable_versions = [
        record for record in product_records
        if record.get("source") in acceptable_sources
        and record.get("evidence_type") in acceptable_types
        and CONFIDENCE_RANK.get(str(record.get("confidence") or "none").lower(), 0)
            >= CONFIDENCE_RANK.get(minimum, 0)
        and record.get("version")
    ]
    if usable_versions:
        # One result per observed service/product/version identity. Preserve all
        # supporting rows in evidence without multiplying duplicate detections.
        grouped = {}
        for record in usable_versions:
            key = (
                record.get("source"), record.get("technology"), record.get("version"),
                record.get("evidence_type"), record.get("observed_url"),
                record.get("service"), record.get("port"),
            )
            grouped.setdefault(key, []).append(record)
        evaluated = []
        for records_for_service in grouped.values():
            record = max(
                records_for_service,
                key=lambda value: CONFIDENCE_RANK.get(str(value.get("confidence") or "none").lower(), 0),
            )
            status, candidate_class, explanation = _version_candidate(check, record["version"])
            evaluated.append((record, records_for_service, status, candidate_class, explanation))
        return [{
            "domain_id": target["domain_id"], "domain": target["domain"],
            "asset_class": target["asset_class"], "product": check["product"],
            "version": record["version"], "detection_confidence": record["confidence"],
            "match_confidence": "medium" if status == "POTENTIAL_MATCH" else None,
            "result_status": status, "candidate_classification": candidate_class,
            "evidence": records_for_service, "explanation": explanation,
            "limitations": list(check.get("limitations", [])),
        } for record, records_for_service, status, candidate_class, explanation in evaluated]
    if product_records:
        return [{
            "domain_id": target["domain_id"], "domain": target["domain"],
            "asset_class": target["asset_class"], "product": check["product"],
            "version": next((record.get("version") for record in product_records if record.get("version")), None),
            "detection_confidence": max(
                (record.get("confidence") for record in product_records),
                key=lambda value: CONFIDENCE_RANK.get(str(value).lower(), 0), default=None,
            ),
            "match_confidence": None, "result_status": "INSUFFICIENT_EVIDENCE",
            "candidate_classification": "PRODUCT_MATCHED_VERSION_UNKNOWN",
            "evidence": product_records,
            "explanation": "Product evidence exists, but no version observation meets this check's evidence requirements.",
            "limitations": list(check.get("limitations", [])),
        }]
    if service_records:
        return [{
            "domain_id": target["domain_id"], "domain": target["domain"],
            "asset_class": target["asset_class"], "product": None, "version": None,
            "detection_confidence": "low", "match_confidence": None,
            "result_status": "INSUFFICIENT_EVIDENCE",
            "candidate_classification": "SERVICE_CANDIDATE", "evidence": service_records,
            "explanation": "Stored service metadata is a candidate only; it does not establish the checked product.",
            "limitations": list(check.get("limitations", [])),
        }]
    return [{
        "domain_id": target["domain_id"], "domain": target["domain"],
        "asset_class": target["asset_class"], "product": None, "version": None,
        "detection_confidence": None, "match_confidence": None,
        "result_status": "INSUFFICIENT_EVIDENCE",
        "candidate_classification": "INSUFFICIENT_EVIDENCE", "evidence": [],
        "explanation": "Available scan evidence cannot determine whether the checked product is present.",
        "limitations": list(check.get("limitations", [])) + ["No product/version observation is not evidence that the component is absent."],
    }]


def _iso(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat() if value.tzinfo else value.replace(tzinfo=timezone.utc).isoformat()
    return str(value)


def _result_payload(row):
    return {
        "result_id": row[0], "run_id": str(row[1]), "domain_id": row[2],
        "domain": row[3], "asset_class": row[4], "result_status": row[5],
        "candidate_classification": row[6], "product": row[7], "version": row[8],
        "detection_confidence": row[9], "match_confidence": row[10],
        "evidence": row[11], "explanation": row[12], "limitations": row[13],
        "assessed_at": _iso(row[14]),
    }


def execute_passive(conn, check_id, *, scan_id=None, limit=MAX_TARGETS, dry_run=False):
    """Preview or persist one passive run. This function performs no network I/O."""
    check = get_check(check_id, include_disabled=False)
    limit = _bounded_limit(limit)
    cur = conn.cursor()
    if dry_run:
        cur.execute("SET TRANSACTION READ ONLY")
        cur.execute("SET LOCAL statement_timeout = 10000")
        cur.execute("SET LOCAL lock_timeout = 1000")
    source_scan = _validate_source_scan(cur, scan_id)
    selection = _eligibility_summary(cur, source_scan["scan_id"])
    preview = _select_targets(cur, source_scan["scan_id"], limit)
    selection_summary = {
        **selection,
        "selected_targets": len(preview),
        "eligible_not_selected_due_to_limit": max(0, selection["eligible_targets"] - len(preview)),
        "no_active_network_authorization_required": True,
        "classification_semantics": "Effective KNOWN/SHADOW at CAPD selection time; not a historical ownership snapshot.",
    }
    if dry_run:
        evidence_by_domain = _load_evidence(cur, source_scan["scan_id"], preview, check)
        relevance, target_relevance = _relevance_summary(check, preview, evidence_by_domain)
        relevance["eligible_inventory_assets"] = selection["eligible_targets"]
        relevance["selected_inventory_assets"] = len(preview)
        selection_summary["relevance"] = relevance
        return {
            "dry_run": True, "check": public_check(check), "source_scan": source_scan,
            "selection": selection_summary, "relevance": relevance,
            "targets": target_relevance,
            "network_requests": 0,
        }

    run_id = str(uuid.uuid4())
    cur.execute("""
        INSERT INTO capd_runs(
            run_id, check_id, check_revision, cve_id, check_definition, source_scan_id,
            execution_mode, status, target_limit, eligible_target_count,
            selected_target_count, skipped_target_count, selection_summary
        ) VALUES (%s,%s,%s,%s,%s::jsonb,%s,'PASSIVE','RUNNING',%s,%s,%s,%s,%s::jsonb)
    """, (
        run_id, check["check_id"], check["check_revision"], check["cve_id"],
        json.dumps(check), source_scan["scan_id"], limit, selection["eligible_targets"], len(preview),
        selection["excluded_or_ineligible"] + selection_summary["eligible_not_selected_due_to_limit"],
        json.dumps(selection_summary),
    ))
    conn.commit()
    try:
        # Re-select after run creation: the preview is never treated as a grant.
        fresh_scan = _validate_source_scan(cur, source_scan["scan_id"])
        fresh_summary = _eligibility_summary(cur, fresh_scan["scan_id"])
        targets = _select_targets(cur, fresh_scan["scan_id"], limit)
        evidence_by_domain = _load_evidence(cur, fresh_scan["scan_id"], targets, check)
        fresh_relevance, _target_relevance = _relevance_summary(check, targets, evidence_by_domain)
        fresh_relevance["eligible_inventory_assets"] = fresh_summary["eligible_targets"]
        fresh_relevance["selected_inventory_assets"] = len(targets)
        counts = {status: 0 for status in sorted(RESULT_STATUSES)}
        inserted = 0
        for target in targets:
            cur.execute("SAVEPOINT capd_target")
            try:
                assessments = _assess_asset(check, target, evidence_by_domain.get(target["domain_id"], []))
                seen = set()
                for result in assessments:
                    identity = _evidence_identity(result["evidence"], target["domain_id"])
                    if identity in seen:
                        continue
                    seen.add(identity)
                    cur.execute("""
                        INSERT INTO capd_results(
                            run_id, domain_id, domain_snapshot, asset_class_snapshot,
                            evidence_identity, result_status, candidate_classification,
                            product, version, detection_confidence, match_confidence,
                            evidence, explanation, limitations
                        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s::jsonb)
                        ON CONFLICT (run_id, domain_id, evidence_identity) DO NOTHING
                    """, (
                        run_id, target["domain_id"], target["domain"], target["asset_class"], identity,
                        result["result_status"], result["candidate_classification"], result["product"],
                        result["version"], result["detection_confidence"], result["match_confidence"],
                        json.dumps(result["evidence"]), result["explanation"], json.dumps(result["limitations"]),
                    ))
                    if cur.rowcount:
                        counts[result["result_status"]] += 1
                        inserted += 1
                cur.execute("RELEASE SAVEPOINT capd_target")
            except Exception:
                # A failed row write can abort the current PostgreSQL transaction.
                # Roll back only this target before storing a sanitized error result.
                cur.execute("ROLLBACK TO SAVEPOINT capd_target")
                identity = _evidence_identity([], target["domain_id"])
                cur.execute("""
                    INSERT INTO capd_results(
                        run_id,domain_id,domain_snapshot,asset_class_snapshot,evidence_identity,
                        result_status,candidate_classification,evidence,explanation,limitations
                    ) VALUES (%s,%s,%s,%s,%s,'ERROR','INSUFFICIENT_EVIDENCE',%s::jsonb,
                              %s,%s::jsonb)
                    ON CONFLICT (run_id,domain_id,evidence_identity) DO NOTHING
                """, (
                    run_id, target["domain_id"], target["domain"], target["asset_class"], identity,
                    json.dumps([]), "CAPD could not evaluate this target.",
                    json.dumps(["Target evidence evaluation failed."]),
                ))
                error_inserted = cur.rowcount
                cur.execute("RELEASE SAVEPOINT capd_target")
                counts["ERROR"] += int(error_inserted == 1)
                inserted += int(error_inserted == 1)
        status = "PARTIAL" if counts["ERROR"] or len(targets) < fresh_summary["eligible_targets"] else "SUCCEEDED"
        run_selection = {
            **fresh_summary,
            "relevance": fresh_relevance,
            "selected_targets": len(targets),
            "eligible_not_selected_due_to_limit": max(0, fresh_summary["eligible_targets"] - len(targets)),
            "no_active_network_authorization_required": True,
            "classification_semantics": "Effective KNOWN/SHADOW at CAPD selection time; not a historical ownership snapshot.",
        }
        cur.execute("""
            UPDATE capd_runs SET status=%s, completed_at=CURRENT_TIMESTAMP,
                eligible_target_count=%s, selected_target_count=%s,
                skipped_target_count=%s, selection_summary=%s::jsonb, counts=%s::jsonb
             WHERE run_id=%s
        """, (
            status, fresh_summary["eligible_targets"], len(targets),
            fresh_summary["excluded_or_ineligible"] + max(0, fresh_summary["eligible_targets"] - len(targets)),
            json.dumps(run_selection), json.dumps(counts), run_id,
        ))
        conn.commit()
        return {
            "run_id": run_id, "status": status, "check": public_check(check),
            "source_scan": fresh_scan, "selection": run_selection,
            "relevance": fresh_relevance, "counts": counts,
            "results_persisted": inserted, "network_requests": 0,
        }
    except Exception:
        conn.rollback()
        cur.execute("""
            UPDATE capd_runs SET status='FAILED', completed_at=CURRENT_TIMESTAMP,
                   error_code='CAPD_PASSIVE_EXECUTION_FAILED'
             WHERE run_id=%s AND status='RUNNING'
        """, (run_id,))
        conn.commit()
        raise


def _pagination(page, limit):
    try:
        page, limit = int(page), int(limit)
    except (TypeError, ValueError) as exc:
        raise CapdError("page and limit must be integers") from exc
    if page < 1 or limit < 1:
        raise CapdError("page and limit must be positive")
    return page, min(limit, MAX_PAGE_SIZE)


def list_runs(conn, *, page=1, limit=50, check_id=None, cve_id=None, status=None,
              sort_by="started_at", sort_dir="desc"):
    page, limit = _pagination(page, limit)
    if status and status not in {"RUNNING", "SUCCEEDED", "PARTIAL", "FAILED"}:
        raise CapdError("Invalid CAPD run status")
    conditions, params = [], []
    if check_id:
        get_check(check_id)
        conditions.append("check_id = %s")
        params.append(check_id)
    if cve_id:
        _schema, checks = load_checks()
        if cve_id not in {item["cve_id"] for item in checks.values()}:
            raise CapdError("Invalid CAPD CVE filter")
        conditions.append("cve_id = %s")
        params.append(cve_id)
    if status:
        conditions.append("status = %s")
        params.append(status)
    sort_fields = {"run_id": "run_id", "check_id": "check_id", "source_scan_id": "source_scan_id",
                   "status": "status", "started_at": "started_at", "completed_at": "completed_at"}
    if sort_by not in sort_fields or sort_dir not in {"asc", "desc"}:
        raise CapdError("Invalid CAPD run sort")
    order = sort_fields[sort_by] + " " + sort_dir.upper() + " NULLS LAST, run_id DESC"
    where = " WHERE " + " AND ".join(conditions) if conditions else ""
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM capd_runs" + where, tuple(params))
    total = cur.fetchone()[0]
    cur.execute(f"""
        SELECT run_id,check_id,check_revision,cve_id,check_definition,source_scan_id,execution_mode,status,
               started_at,completed_at,target_limit,eligible_target_count,selected_target_count,
               skipped_target_count,selection_summary,counts,error_code
          FROM capd_runs
    """ + where + f" ORDER BY {order} LIMIT %s OFFSET %s",
                tuple(params + [limit, (page - 1) * limit]))
    runs = [_run_payload(row) for row in cur.fetchall()]
    for item in runs:
        item.pop("check_definition", None)
    return {"page": page, "limit": limit, "total": total, "runs": runs}


def _run_payload(row):
    keys = (
        "run_id", "check_id", "check_revision", "cve_id", "check_definition", "source_scan_id", "execution_mode",
        "status", "started_at", "completed_at", "target_limit", "eligible_target_count",
        "selected_target_count", "skipped_target_count", "selection_summary", "counts", "error_code",
    )
    data = dict(zip(keys, row))
    data["run_id"] = str(data["run_id"])
    data["started_at"] = _iso(data["started_at"])
    data["completed_at"] = _iso(data["completed_at"])
    return data


def get_run(conn, run_id):
    try:
        parsed = str(uuid.UUID(str(run_id)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise CapdError("Invalid CAPD run ID") from exc
    cur = conn.cursor()
    cur.execute("""
        SELECT run_id,check_id,check_revision,cve_id,check_definition,source_scan_id,execution_mode,status,
               started_at,completed_at,target_limit,eligible_target_count,selected_target_count,
               skipped_target_count,selection_summary,counts,error_code
          FROM capd_runs WHERE run_id=%s
    """, (parsed,))
    row = cur.fetchone()
    if row is None:
        raise CapdError("CAPD run not found")
    result = _run_payload(row)
    result["check"] = public_check(result.pop("check_definition"))
    return result


def list_results(conn, run_id, *, page=1, limit=50, result_status=None,
                 sort_by="domain", sort_dir="asc"):
    run = get_run(conn, run_id)
    page, limit = _pagination(page, limit)
    if result_status:
        result_status = str(result_status).strip().upper()
        if result_status not in RESULT_STATUSES:
            raise CapdError("Invalid CAPD result status")
    sort_fields = {"domain": "domain_snapshot", "result_status": "result_status",
                   "product": "product", "version": "version",
                   "confidence": "detection_confidence", "assessed_at": "assessed_at"}
    if sort_by not in sort_fields or sort_dir not in {"asc", "desc"}:
        raise CapdError("Invalid CAPD result sort")
    order = sort_fields[sort_by] + " " + sort_dir.upper() + " NULLS LAST, domain_id ASC, id ASC"
    where = " WHERE run_id=%s"
    params = [run["run_id"]]
    if result_status:
        where += " AND result_status=%s"
        params.append(result_status)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM capd_results" + where, tuple(params))
    total = cur.fetchone()[0]
    cur.execute(f"""
        SELECT id,run_id,domain_id,domain_snapshot,asset_class_snapshot,result_status,
               candidate_classification,product,version,detection_confidence,match_confidence,
               evidence,explanation,limitations,assessed_at
          FROM capd_results
    """ + where + f" ORDER BY {order} LIMIT %s OFFSET %s",
                tuple(params + [limit, (page - 1) * limit]))
    return {
        "run": {key: run[key] for key in ("run_id", "check_id", "check_revision", "cve_id", "source_scan_id", "status")},
        "page": page, "limit": limit, "total": total,
        "results": [_result_payload(row) for row in cur.fetchall()],
    }
