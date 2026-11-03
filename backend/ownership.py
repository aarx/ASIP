from dataclasses import dataclass
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


@dataclass(frozen=True)
class TrustedDomainBoundary:
    """Separate trusted seed namespaces from exact documented hosts."""

    seed_domains: frozenset
    known_domains: frozenset


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
    if isinstance(trusted_domains, TrustedDomainBoundary):
        if domain in trusted_domains.known_domains:
            return True
        seed_domains = trusted_domains.seed_domains
    else:
        # Compatibility for callers passing a seed-root collection directly.
        seed_domains = _split_values(trusted_domains)
    return any(
        domain == seed or domain.endswith("." + seed)
        for seed in seed_domains
    )


def is_within_confirmed_root(domain, seeds):
    """Compatibility alias for the original seed-root matcher."""
    return is_within_trusted_boundary(domain, seeds)


def load_trusted_domains(cursor):
    """Load trusted seed namespaces and exact documented hosts separately."""
    cursor.execute("SELECT domain FROM seed_domains")
    seed_domains = _split_values(row[0] for row in cursor.fetchall())
    cursor.execute("SELECT domain FROM known_domains")
    known_domains = _split_values(row[0] for row in cursor.fetchall())
    return TrustedDomainBoundary(
        seed_domains=frozenset(seed_domains),
        known_domains=frozenset(known_domains),
    )


def trusted_boundary_sql(domain_expression):
    """SQL predicate matching seed descendants or exact known hosts."""
    candidate_raw = f"LOWER(BTRIM({domain_expression}))"
    candidate = f"TRIM(TRAILING '.' FROM {candidate_raw})"
    seed_raw = "LOWER(BTRIM(seed_root.domain))"
    seed_root = f"TRIM(TRAILING '.' FROM {seed_raw})"
    known_raw = "LOWER(BTRIM(known_host.domain))"
    known_host = f"TRIM(TRAILING '.' FROM {known_raw})"
    return f"""
        (
            {candidate_raw} ~ '{_DNS_NAME_SQL_RE}'
            AND LENGTH({candidate}) <= 253
            AND (
                EXISTS (
                    SELECT 1
                    FROM seed_domains seed_root
                    WHERE {seed_raw} ~ '{_DNS_NAME_SQL_RE}'
                      AND LENGTH({seed_root}) <= 253
                      AND (
                          {candidate} = {seed_root}
                          OR RIGHT({candidate}, LENGTH({seed_root}) + 1) = '.' || {seed_root}
                      )
                )
                OR EXISTS (
                    SELECT 1
                    FROM known_domains known_host
                    WHERE {known_raw} ~ '{_DNS_NAME_SQL_RE}'
                      AND LENGTH({known_host}) <= 253
                      AND {candidate} = {known_host}
                  )
            )
        )
    """


def ownership_for_discovery(
    domain, sources, seeds, is_known=False, trusted_domains=None,
):
    """Classify from trusted roots, never from discovery-source similarity.

    ``trusted_domains`` carries seed namespaces and exact known hosts. The
    legacy ``seeds`` argument remains supported as a seed-root collection.
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
