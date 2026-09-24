def explicit_t2_authorization_sql(domain_alias="d"):
    """Return the current explicit/manual T2 authorization SQL predicate."""
    return (
        f"{domain_alias}.scannable IS TRUE "
        f"AND {domain_alias}.validation_source = 'manual'"
    )
