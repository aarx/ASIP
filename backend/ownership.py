OWNERSHIP_CONFIRMED = "CONFIRMED"
OWNERSHIP_CANDIDATE = "CANDIDATE"
OWNERSHIP_EXTERNAL = "EXTERNAL"

OWNERSHIP_STATUSES = frozenset({
    OWNERSHIP_CONFIRMED,
    OWNERSHIP_CANDIDATE,
    OWNERSHIP_EXTERNAL,
})

def _normalize_domain(value):
    return (value or "").strip().lower().rstrip(".")


def _split_values(values):
    if isinstance(values, str):
        values = values.split(",")
    return {
        normalized
        for value in (values or ())
        if (normalized := _normalize_domain(value))
    }


def is_within_confirmed_root(domain, seeds):
    domain = _normalize_domain(domain)
    return any(
        domain == seed or domain.endswith("." + seed)
        for seed in _split_values(seeds)
    )


def ownership_for_discovery(domain, sources, seeds, is_known=False):
    """Classify discovery from approved namespace/inventory evidence only."""
    if is_known or is_within_confirmed_root(domain, seeds):
        return OWNERSHIP_CONFIRMED

    return OWNERSHIP_CANDIDATE


def normalize_ownership_status(value):
    status = (value or "").strip().upper()
    if status not in OWNERSHIP_STATUSES:
        raise ValueError(f"Invalid ownership status: {value}")
    return status
