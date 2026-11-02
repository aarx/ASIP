"""Small, offline advisory catalog primitives.

The catalog intentionally evaluates reported technology observations only.  It
does not verify an installed runtime, vendor backport, configuration,
reachability, or exploitability, and it has no database or network dependency.
"""

from dataclasses import dataclass
from datetime import date
import re


@dataclass(frozen=True)
class ProductIdentity:
    """Canonical identity for an exact detector technology label."""

    canonical_technology: str
    vendor: str
    product: str


PRODUCT_IDENTITIES = {
    "php": ProductIdentity("php", "PHP", "PHP"),
    "apache": ProductIdentity(
        "apache_http_server", "Apache Software Foundation", "Apache HTTP Server"
    ),
    "nginx": ProductIdentity("nginx", "NGINX", "Nginx"),
    "microsoft-iis": ProductIdentity("microsoft_iis", "Microsoft", "Microsoft IIS"),
    "tomcat": ProductIdentity(
        "apache_tomcat", "Apache Software Foundation", "Apache Tomcat"
    ),
}


def normalize_product_label(label):
    """Map only known detector labels; return ``None`` for unknown labels."""
    normalized = str(label or "").strip().lower()
    return PRODUCT_IDENTITIES.get(normalized)


@dataclass(frozen=True)
class VersionRange:
    """A documented numeric version range for one advisory.

    ``branch`` is optional.  Bounds are optional individually so a range may
    be one-sided, but a range with neither bound is incomplete and cannot
    produce an applicability conclusion.
    """

    branch: str | None
    upper_bound: tuple[int, ...] | None
    upper_inclusive: bool
    fixed_version: str | None
    range_text: str
    lower_bound: tuple[int, ...] | None = None
    lower_inclusive: bool = True
    comparator: str = "numeric"

    def branch_matches(self, version):
        if not self.branch:
            return True
        branch = tuple(int(part) for part in self.branch.split("."))
        return tuple(version[:len(branch)]) == branch

    @property
    def is_complete(self):
        return self.lower_bound is not None or self.upper_bound is not None

    def matches(self, version):
        if not self.branch_matches(version) or not self.is_complete:
            return False
        if self.lower_bound is not None:
            if self.lower_inclusive and version < self.lower_bound:
                return False
            if not self.lower_inclusive and version <= self.lower_bound:
                return False
        if self.upper_bound is not None:
            if self.upper_inclusive:
                return version <= self.upper_bound
            return version < self.upper_bound
        return True


@dataclass(frozen=True)
class AdvisoryRecord:
    """Immutable advisory metadata and documented affected ranges."""

    cve_id: str | None
    product: str
    publication_date: str | None
    source_url: str
    severity: str
    verification_status: str
    affected_ranges: tuple[VersionRange, ...]
    applicability_conditions: tuple[str, ...]
    advisory_id: str | None = None
    vendor: str | None = None
    canonical_technology: str | None = None
    updated_date: str | None = None
    dataset_revision: str | None = None
    coverage: str = "partial"
    patch_status: str = "unknown"

    @property
    def identity(self):
        return self.advisory_id or self.cve_id


_PHP_VERSION_RE = re.compile(r"^\s*(\d+)\.(\d+)\.(\d+)\s*$")
VERSION_COMPARATORS = {}


def _parse_php_version(value):
    match = _PHP_VERSION_RE.fullmatch(str(value or ""))
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


VERSION_COMPARATORS["php"] = _parse_php_version


def get_version_comparator(canonical_technology):
    """Return the explicitly supported comparator for a canonical product."""
    return VERSION_COMPARATORS.get(canonical_technology)


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
    explanation_code,
    dataset_revision,
):
    return {
        "advisory_id": advisory.identity,
        "cve_id": advisory.cve_id,
        "applicability_status": status,
        "reported_version": reported_version,
        "affected_version_range": affected_version_range,
        "fixed_version": fixed_version,
        "source_url": advisory.source_url,
        "dataset_revision": dataset_revision,
        "evidence_confidence": evidence_confidence,
        "patch_status": advisory.patch_status,
        "explanation_code": explanation_code,
    }


def _insufficient_candidate(
    advisory, reported_version, code, dataset_revision
):
    return _candidate(
        advisory=advisory,
        reported_version=reported_version,
        status="insufficient_evidence",
        affected_version_range=None,
        fixed_version=None,
        evidence_confidence="insufficient",
        explanation_code=code,
        dataset_revision=dataset_revision,
    )


def evaluate_advisory_catalog(
    technology,
    reported_version,
    advisory_dataset,
    dataset_revision,
    assessment_date=None,
    coverage="partial",
):
    """Evaluate a local advisory dataset without network or database access.

    Only products with an explicitly registered comparator are evaluated.  A
    known product without a comparator returns ``unsupported`` coverage rather
    than making a version claim.
    """
    assessed = _assessment_date(assessment_date or date.today())
    result = {
        "assessment_date": assessed.isoformat(),
        "dataset_revision": dataset_revision,
        "coverage": coverage,
        "candidates": [],
    }
    identity = normalize_product_label(technology)
    if identity is None:
        result["coverage"] = "not_applicable"
        result["explanation_code"] = "unknown_product"
        return result

    comparator = get_version_comparator(identity.canonical_technology)
    if comparator is None:
        result["coverage"] = "unsupported"
        result["explanation_code"] = "unsupported_product_comparator"
        return result

    parsed_version = comparator(reported_version)
    prefix = identity.canonical_technology
    seen_advisories = set()
    for advisory in advisory_dataset:
        if advisory.identity in seen_advisories:
            continue
        seen_advisories.add(advisory.identity)

        advisory_product = advisory.canonical_technology
        if advisory_product and advisory_product != identity.canonical_technology:
            continue

        if parsed_version is None:
            code = f"{prefix}_version_absent" if not str(reported_version or "").strip() else f"{prefix}_version_malformed"
            result["candidates"].append(
                _insufficient_candidate(
                    advisory, reported_version, code, dataset_revision
                )
            )
            continue

        branch_ranges = [
            item for item in advisory.affected_ranges
            if item.branch_matches(parsed_version)
        ]
        if not branch_ranges:
            result["candidates"].append(
                _insufficient_candidate(
                    advisory,
                    reported_version,
                    f"{prefix}_branch_not_covered_by_dataset",
                    dataset_revision,
                )
            )
            continue

        ranges_complete = all(item.is_complete for item in branch_ranges)
        verified = advisory.verification_status == "verified_vendor_advisory_range"
        matched_range = next(
            (item for item in branch_ranges if item.matches(parsed_version)),
            None,
        )
        if not verified or not ranges_complete:
            result["candidates"].append(
                _insufficient_candidate(
                    advisory,
                    reported_version,
                    f"{prefix}_advisory_range_incomplete",
                    dataset_revision,
                )
            )
            continue

        if matched_range:
            result["candidates"].append(_candidate(
                advisory=advisory,
                reported_version=reported_version,
                status="potentially_affected",
                affected_version_range=matched_range.range_text,
                fixed_version=matched_range.fixed_version,
                evidence_confidence="high_version_range_match",
                explanation_code=f"{prefix}_version_within_verified_affected_range",
                dataset_revision=dataset_revision,
            ))
            continue

        fixed_versions = sorted({
            item.fixed_version
            for item in branch_ranges
            if item.fixed_version is not None
        })
        result["candidates"].append(_candidate(
            advisory=advisory,
            reported_version=reported_version,
            status="not_affected_by_version",
            affected_version_range=None,
            fixed_version=fixed_versions[-1] if fixed_versions else None,
            evidence_confidence="high_version_range_match",
            explanation_code=f"{prefix}_reported_version_at_or_above_verified_fix",
            dataset_revision=dataset_revision,
        ))

    return result
