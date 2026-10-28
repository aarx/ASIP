"""Offline PHP release-branch lifecycle intelligence.

The policy data is intentionally versioned in source control.  It is used
only to describe the support state of a reported PHP release branch; it does
not verify the installed runtime or make an exploitability determination.
"""

from dataclasses import dataclass
from datetime import date
import re


PHP_SUPPORTED_SOURCE_URL = "https://www.php.net/supported-versions.php"
PHP_EOL_SOURCE_URL = "https://www.php.net/eol.php"
PHP_POLICY_DATASET_REVISION = "2026-10-28"


@dataclass(frozen=True)
class PHPReleasePolicy:
    branch: str
    initial_release: date | None
    active_support_until: date | None
    security_support_until: date | None
    end_of_life: date
    source_url: str


def _d(value):
    return date.fromisoformat(value) if value else None


# Dates are copied from the official PHP lifecycle pages identified above.
# Older branches have an official EOL date but no published active/security
# split in the source used here, so those fields remain intentionally null.
PHP_RELEASE_POLICIES = (
    PHPReleasePolicy(
        "8.5", _d("2025-11-20"), _d("2027-12-31"), _d("2029-12-31"),
        _d("2029-12-31"), PHP_SUPPORTED_SOURCE_URL,
    ),
    PHPReleasePolicy(
        "8.4", _d("2024-11-21"), _d("2026-12-31"), _d("2028-12-31"),
        _d("2028-12-31"), PHP_SUPPORTED_SOURCE_URL,
    ),
    PHPReleasePolicy(
        "8.3", _d("2023-11-23"), _d("2025-12-31"), _d("2027-12-31"),
        _d("2027-12-31"), PHP_SUPPORTED_SOURCE_URL,
    ),
    PHPReleasePolicy(
        "8.2", _d("2022-12-08"), _d("2024-12-31"), _d("2026-12-31"),
        _d("2026-12-31"), PHP_SUPPORTED_SOURCE_URL,
    ),
    PHPReleasePolicy(
        "8.1", None, None, None, _d("2025-12-31"), PHP_EOL_SOURCE_URL,
    ),
    PHPReleasePolicy(
        "8.0", None, None, None, _d("2023-11-26"), PHP_EOL_SOURCE_URL,
    ),
    PHPReleasePolicy(
        "7.4", None, None, None, _d("2022-11-28"), PHP_EOL_SOURCE_URL,
    ),
    PHPReleasePolicy(
        "7.3", None, None, None, _d("2021-12-06"), PHP_EOL_SOURCE_URL,
    ),
    PHPReleasePolicy(
        "7.2", None, None, None, _d("2020-11-30"), PHP_EOL_SOURCE_URL,
    ),
    PHPReleasePolicy(
        "7.1", None, None, None, _d("2019-12-01"), PHP_EOL_SOURCE_URL,
    ),
    PHPReleasePolicy(
        "7.0", None, None, None, _d("2019-01-10"), PHP_EOL_SOURCE_URL,
    ),
    PHPReleasePolicy(
        "5.6", None, None, None, _d("2018-12-31"), PHP_EOL_SOURCE_URL,
    ),
    PHPReleasePolicy(
        "5.5", None, None, None, _d("2016-07-21"), PHP_EOL_SOURCE_URL,
    ),
    PHPReleasePolicy(
        "5.4", None, None, None, _d("2015-09-03"), PHP_EOL_SOURCE_URL,
    ),
    PHPReleasePolicy(
        "5.3", None, None, None, _d("2014-08-14"), PHP_EOL_SOURCE_URL,
    ),
    PHPReleasePolicy(
        "5.2", None, None, None, _d("2011-01-06"), PHP_EOL_SOURCE_URL,
    ),
    PHPReleasePolicy(
        "5.1", None, None, None, _d("2006-08-24"), PHP_EOL_SOURCE_URL,
    ),
    PHPReleasePolicy(
        "5.0", None, None, None, _d("2005-09-05"), PHP_EOL_SOURCE_URL,
    ),
    PHPReleasePolicy(
        "4.4", None, None, None, _d("2008-08-07"), PHP_EOL_SOURCE_URL,
    ),
    PHPReleasePolicy(
        "4.3", None, None, None, _d("2005-03-31"), PHP_EOL_SOURCE_URL,
    ),
    PHPReleasePolicy(
        "4.2", None, None, None, _d("2002-09-06"), PHP_EOL_SOURCE_URL,
    ),
    PHPReleasePolicy(
        "4.1", None, None, None, _d("2002-03-12"), PHP_EOL_SOURCE_URL,
    ),
    PHPReleasePolicy(
        "4.0", None, None, None, _d("2001-06-23"), PHP_EOL_SOURCE_URL,
    ),
    PHPReleasePolicy(
        "3.0", None, None, None, _d("2000-10-20"), PHP_EOL_SOURCE_URL,
    ),
)

_POLICY_BY_BRANCH = {item.branch: item for item in PHP_RELEASE_POLICIES}
_VERSION_RE = re.compile(r"^\s*(\d+)\.(\d+)(?:\.\d+)?\s*$")


def _assessment_date(value):
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        return date.fromisoformat(value)
    raise TypeError("assessment_date must be a date or ISO date string")


def _result(
    *,
    status,
    branch,
    policy,
    assessed,
    explanation_code,
    source_url=None,
):
    return {
        "status": status,
        "matched_release_branch": branch,
        "active_support_until": (
            policy.active_support_until.isoformat()
            if policy and policy.active_support_until else None
        ),
        "security_support_until": (
            policy.security_support_until.isoformat()
            if policy and policy.security_support_until else None
        ),
        "end_of_life": policy.end_of_life.isoformat() if policy else None,
        "source_url": source_url or (policy.source_url if policy else None),
        "dataset_revision": PHP_POLICY_DATASET_REVISION,
        "assessment_date": assessed.isoformat(),
        "explanation_code": explanation_code,
    }


def evaluate_php_lifecycle(technology, version, assessment_date):
    """Evaluate a reported PHP branch using only the local policy dataset."""
    assessed = _assessment_date(assessment_date)
    normalized_technology = str(technology or "").strip().lower()
    if normalized_technology != "php":
        return _result(
            status="unknown",
            branch=None,
            policy=None,
            assessed=assessed,
            explanation_code="non_php_observation",
        )

    version_text = str(version or "")
    match = _VERSION_RE.fullmatch(version_text)
    if not match:
        return _result(
            status="unknown",
            branch=None,
            policy=None,
            assessed=assessed,
            explanation_code=(
                "php_version_absent" if not version_text.strip()
                else "php_version_unrecognized"
            ),
            source_url=PHP_SUPPORTED_SOURCE_URL,
        )

    branch = f"{int(match.group(1))}.{int(match.group(2))}"
    policy = _POLICY_BY_BRANCH.get(branch)
    if policy is None:
        return _result(
            status="unknown",
            branch=branch,
            policy=None,
            assessed=assessed,
            explanation_code="php_release_branch_unrecognized",
            source_url=PHP_SUPPORTED_SOURCE_URL,
        )

    if policy.initial_release and assessed < policy.initial_release:
        return _result(
            status="unknown",
            branch=branch,
            policy=policy,
            assessed=assessed,
            explanation_code="php_assessment_before_release",
        )

    if policy.active_support_until and assessed <= policy.active_support_until:
        status = "active_support"
        explanation_code = "php_active_support"
    elif (
        policy.security_support_until
        and assessed <= policy.security_support_until
    ):
        status = "security_support"
        explanation_code = "php_security_support"
    elif assessed >= policy.end_of_life:
        status = "end_of_life"
        explanation_code = "php_end_of_life"
    else:
        status = "unknown"
        explanation_code = "php_policy_dates_incomplete"

    return _result(
        status=status,
        branch=branch,
        policy=policy,
        assessed=assessed,
        explanation_code=explanation_code,
    )
