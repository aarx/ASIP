"""Offline, evidence-backed PHP CVE applicability intelligence.

The dataset is deliberately small and versioned in source control.  A match
means only that a reported PHP version falls within a vendor-published range;
it does not verify the runtime, a vendor backport, configuration, reachability,
or exploitability.
"""

from dataclasses import dataclass
from datetime import date
import re


PHP_CVE_DATASET_REVISION = "2026-10-28"
PHP_CVE_COVERAGE = "partial"
PHP_ADVISORY_RELEASE_SOURCE_URL = "https://www.php.net/archive/2026.php"


@dataclass(frozen=True)
class PHPVersionRange:
    branch: str
    upper_bound: tuple[int, int, int]
    upper_inclusive: bool
    fixed_version: str
    range_text: str
    lower_bound: tuple[int, int, int] | None = None
    lower_inclusive: bool = True

    def matches(self, version):
        if version[:2] != tuple(int(part) for part in self.branch.split(".")):
            return False
        if self.lower_bound is not None:
            if self.lower_inclusive and version < self.lower_bound:
                return False
            if not self.lower_inclusive and version <= self.lower_bound:
                return False
        if self.upper_inclusive:
            return version <= self.upper_bound
        return version < self.upper_bound


@dataclass(frozen=True)
class PHPAdvisory:
    cve_id: str
    product: str
    publication_date: str
    source_url: str
    severity: str
    verification_status: str
    affected_ranges: tuple[PHPVersionRange, ...]
    applicability_conditions: tuple[str, ...]


def _version(value):
    return tuple(int(part) for part in value.split("."))


def _branch_range(branch, fixed_version):
    return PHPVersionRange(
        branch=branch,
        upper_bound=_version(fixed_version),
        upper_inclusive=False,
        fixed_version=fixed_version,
        range_text=f"< {fixed_version} (PHP {branch} branch)",
    )


_PHP_8_2_35 = _branch_range("8.2", "8.2.35")
_PHP_8_3_36 = _branch_range("8.3", "8.3.36")
_PHP_8_4_27 = _branch_range("8.4", "8.4.27")
_PHP_8_5_12 = _branch_range("8.5", "8.5.12")
_VERIFIED_RANGES = (_PHP_8_2_35, _PHP_8_3_36, _PHP_8_4_27, _PHP_8_5_12)

_OOM_SOURCE_URL = (
    "https://github.com/php/php-src/security/advisories/"
    "GHSA-w8hw-w9fx-j79w"
)
_STALE_STATE_SOURCE_URL = (
    "https://github.com/php/php-src/security/advisories/"
    "GHSA-6wmf-4rv5-p3rp"
)
_COMMON_CONDITIONS = (
    "A reported version is not proof of the installed or unpatched runtime.",
    "Vendor backported patches and deployment-specific reachability require "
    "independent verification.",
)

PHP_CVE_ADVISORIES = (
    PHPAdvisory(
        cve_id="CVE-2026-109618",
        product="PHP",
        publication_date="2026-10-21",
        source_url=_OOM_SOURCE_URL,
        severity="critical",
        verification_status="verified_vendor_advisory_range",
        affected_ranges=_VERIFIED_RANGES,
        applicability_conditions=_COMMON_CONDITIONS + (
            "The vendor advisory describes confirmed mod_php exposure and "
            "conditional exposure for other SAPIs.",
        ),
    ),
    PHPAdvisory(
        cve_id="CVE-2026-109619",
        product="PHP",
        publication_date="2026-10-21",
        source_url=_STALE_STATE_SOURCE_URL,
        severity="critical",
        verification_status="verified_vendor_advisory_range",
        affected_ranges=_VERIFIED_RANGES,
        applicability_conditions=_COMMON_CONDITIONS + (
            "Successful exploitation requires a producer and consumer of "
            "stale request-owned state in a persistent worker.",
        ),
    ),
)


_VERSION_RE = re.compile(r"^\s*(\d+)\.(\d+)\.(\d+)\s*$")


def _assessment_date(value):
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        return date.fromisoformat(value)
    raise TypeError("assessment_date must be a date or ISO date string")


def _candidate(
    *,
    advisory,
    reported_version,
    status,
    affected_version_range,
    fixed_version,
    evidence_confidence,
    patch_status,
    explanation_code,
):
    return {
        "cve_id": advisory.cve_id,
        "applicability_status": status,
        "reported_version": reported_version,
        "affected_version_range": affected_version_range,
        "fixed_version": fixed_version,
        "source_url": advisory.source_url,
        "dataset_revision": PHP_CVE_DATASET_REVISION,
        "evidence_confidence": evidence_confidence,
        "patch_status": patch_status,
        "explanation_code": explanation_code,
    }


def evaluate_php_cve_applicability(
    technology,
    reported_version,
    advisory_dataset=PHP_CVE_ADVISORIES,
    assessment_date=None,
):
    """Evaluate PHP CVE candidates without network or database access."""
    assessed = _assessment_date(assessment_date or date.today())
    result = {
        "assessment_date": assessed.isoformat(),
        "dataset_revision": PHP_CVE_DATASET_REVISION,
        "coverage": PHP_CVE_COVERAGE,
        "candidates": [],
    }
    if str(technology or "").strip().lower() != "php":
        result["coverage"] = "not_applicable"
        return result

    version_text = str(reported_version or "").strip()
    match = _VERSION_RE.fullmatch(version_text)
    parsed_version = (
        tuple(int(part) for part in match.groups()) if match else None
    )
    seen_cves = set()

    for advisory in advisory_dataset:
        if advisory.cve_id in seen_cves:
            continue
        seen_cves.add(advisory.cve_id)

        if not match:
            code = "php_version_absent" if not version_text else "php_version_malformed"
            result["candidates"].append(_candidate(
                advisory=advisory,
                reported_version=reported_version,
                status="insufficient_evidence",
                affected_version_range=None,
                fixed_version=None,
                evidence_confidence="insufficient",
                patch_status="unknown",
                explanation_code=code,
            ))
            continue

        matching_branch = [
            item for item in advisory.affected_ranges
            if parsed_version[:2] == tuple(
                int(part) for part in item.branch.split(".")
            )
        ]
        if not matching_branch:
            result["candidates"].append(_candidate(
                advisory=advisory,
                reported_version=reported_version,
                status="insufficient_evidence",
                affected_version_range=None,
                fixed_version=None,
                evidence_confidence="insufficient",
                patch_status="unknown",
                explanation_code="php_branch_not_covered_by_dataset",
            ))
            continue

        matched_range = next(
            (item for item in matching_branch if item.matches(parsed_version)),
            None,
        )
        if matched_range:
            result["candidates"].append(_candidate(
                advisory=advisory,
                reported_version=reported_version,
                status="potentially_affected",
                affected_version_range=matched_range.range_text,
                fixed_version=matched_range.fixed_version,
                evidence_confidence="high_version_range_match",
                patch_status="unknown",
                explanation_code="php_version_within_verified_affected_range",
            ))
        else:
            fixed_versions = sorted({
                item.fixed_version for item in matching_branch
            })
            result["candidates"].append(_candidate(
                advisory=advisory,
                reported_version=reported_version,
                status="not_affected_by_version",
                affected_version_range=None,
                fixed_version=fixed_versions[-1] if fixed_versions else None,
                evidence_confidence="high_version_range_match",
                patch_status="unknown",
                explanation_code="php_reported_version_at_or_above_verified_fix",
            ))

    return result
