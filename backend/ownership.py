import re


OWNERSHIP_CONFIRMED = "CONFIRMED"
OWNERSHIP_CANDIDATE = "CANDIDATE"
OWNERSHIP_EXTERNAL = "EXTERNAL"

OWNERSHIP_STATUSES = frozenset({
    OWNERSHIP_CONFIRMED,
    OWNERSHIP_CANDIDATE,
    OWNERSHIP_EXTERNAL,
})

_DNS_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DNS_NAME_RE = re.compile(rf"^(?:{_DNS_LABEL})(?:\.{_DNS_LABEL})*$")
_DNS_NAME_SQL_RE = (
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.?$"
)


def normalize_hostname(value):
    """Canonicalize a DNS hostname, returning None for malformed input."""
    if not isinstance(value, str):
        return None
    hostname = value.strip().lower()
    if hostname.endswith("."):
        hostname = hostname[:-1]
    if len(hostname) > 253 or not _DNS_NAME_RE.fullmatch(hostname):
        return None
    return hostname


def _normalize_domain(value):
    """Compatibility wrapper for callers that expect an empty string."""
    return normalize_hostname(value) or ""


def _split_values(values):
    if isinstance(values, str):
        values = values.split(",")
    return {
        normalized
        for value in (values or ())
        if (normalized := normalize_hostname(value))
    }


def is_within_trusted_boundary(domain, trusted_domains):
    domain = normalize_hostname(domain)
    if domain is None:
        return False
    return any(
        domain == seed or domain.endswith("." + seed)
        for seed in _split_values(trusted_domains)
    )


def is_within_confirmed_root(domain, seeds):
    """Compatibility alias for the original seed-root matcher."""
    return is_within_trusted_boundary(domain, seeds)


def load_trusted_domains(cursor):
    """Read the operator-maintained trusted boundary from both inventories."""
    cursor.execute(
        """
        SELECT domain FROM seed_domains
        UNION
        SELECT domain FROM known_domains
        """
    )
    return _split_values(row[0] for row in cursor.fetchall())


def trusted_boundary_sql(domain_expression):
    """SQL predicate matching a valid hostname against both trusted tables."""
    candidate_raw = f"LOWER(BTRIM({domain_expression}))"
    candidate = f"TRIM(TRAILING '.' FROM {candidate_raw})"
    root_raw = "LOWER(BTRIM(trusted_root.domain))"
    root = f"TRIM(TRAILING '.' FROM {root_raw})"
    return f"""
        (
            {candidate_raw} ~ '{_DNS_NAME_SQL_RE}'
            AND LENGTH({candidate}) <= 253
            AND EXISTS (
                SELECT 1
                FROM (
                    SELECT domain FROM seed_domains
                    UNION ALL
                    SELECT domain FROM known_domains
                ) trusted_root
                WHERE {root_raw} ~ '{_DNS_NAME_SQL_RE}'
                  AND LENGTH({root}) <= 253
                  AND (
                      {candidate} = {root}
                      OR RIGHT({candidate}, LENGTH({root}) + 1) = '.' || {root}
                  )
            )
        )
    """


def ownership_for_discovery(
    domain, sources, seeds, is_known=False, trusted_domains=None,
):
    """Classify from trusted roots, never from discovery-source similarity.

    ``trusted_domains`` is the authoritative database inventory. The legacy
    ``seeds`` argument remains supported for old callers that have not yet
    been moved to inventory-backed classification.
    """
    if normalize_hostname(domain) is None:
        return OWNERSHIP_CANDIDATE
    roots = seeds if trusted_domains is None else trusted_domains
    if (
        (is_known and trusted_domains is None)
        or is_within_trusted_boundary(domain, roots)
    ):
        return OWNERSHIP_CONFIRMED

    return OWNERSHIP_CANDIDATE


def normalize_ownership_status(value):
    status = (value or "").strip().upper()
    if status not in OWNERSHIP_STATUSES:
        raise ValueError(f"Invalid ownership status: {value}")
    return status
