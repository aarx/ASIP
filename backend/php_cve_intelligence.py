"""Offline PHP CVE applicability compatibility adapter.

The public PHP classes and evaluator remain stable while the pure comparison
and advisory model are shared with future product-specific catalogs.
"""

from dataclasses import dataclass
from datetime import date

from advisory_catalog import (
    AdvisoryRecord,
    VersionRange,
    evaluate_advisory_catalog,
)


PHP_CVE_DATASET_REVISION = "2026-10-28"
PHP_CVE_COVERAGE = "partial"
PHP_ADVISORY_RELEASE_SOURCE_URL = "https://www.php.net/archive/2026.php"


@dataclass(frozen=True)
class PHPVersionRange(VersionRange):
    """Backward-compatible public name for PHP version ranges."""


@dataclass(frozen=True)
class PHPAdvisory(AdvisoryRecord):
    """Backward-compatible public name for PHP advisory records."""


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
        advisory_id="CVE-2026-109618",
        vendor="PHP",
        canonical_technology="php",
        updated_date="2026-10-21",
        dataset_revision=PHP_CVE_DATASET_REVISION,
        coverage=PHP_CVE_COVERAGE,
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
        advisory_id="CVE-2026-109619",
        vendor="PHP",
        canonical_technology="php",
        updated_date="2026-10-21",
        dataset_revision=PHP_CVE_DATASET_REVISION,
        coverage=PHP_CVE_COVERAGE,
    ),
)


_LEGACY_CANDIDATE_FIELDS = (
    "cve_id",
    "applicability_status",
    "reported_version",
    "affected_version_range",
    "fixed_version",
    "source_url",
    "dataset_revision",
    "evidence_confidence",
    "patch_status",
    "explanation_code",
)


def _assessment_date(value):
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        return date.fromisoformat(value)
    raise TypeError("assessment_date must be a date or ISO date string")


def evaluate_php_cve_applicability(
    technology,
    reported_version,
    advisory_dataset=PHP_CVE_ADVISORIES,
    assessment_date=None,
):
    """Evaluate PHP candidates while preserving the existing result contract."""
    assessed = _assessment_date(assessment_date or date.today())
    if str(technology or "").strip().lower() != "php":
        return {
            "assessment_date": assessed.isoformat(),
            "dataset_revision": PHP_CVE_DATASET_REVISION,
            "coverage": "not_applicable",
            "candidates": [],
        }

    evaluated = evaluate_advisory_catalog(
        "php",
        reported_version,
        advisory_dataset,
        dataset_revision=PHP_CVE_DATASET_REVISION,
        assessment_date=assessed,
        coverage=PHP_CVE_COVERAGE,
    )
    return {
        "assessment_date": evaluated["assessment_date"],
        "dataset_revision": PHP_CVE_DATASET_REVISION,
        "coverage": PHP_CVE_COVERAGE,
        "candidates": [
            {key: candidate[key] for key in _LEGACY_CANDIDATE_FIELDS}
            for candidate in evaluated["candidates"]
        ],
    }
