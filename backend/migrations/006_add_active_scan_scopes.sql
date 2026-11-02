BEGIN;

CREATE TABLE IF NOT EXISTS active_scan_scopes (
    id BIGSERIAL PRIMARY KEY,
    scope_domain TEXT NOT NULL,
    include_subdomains BOOLEAN NOT NULL,
    testing_level TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    approved_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    expires_at TIMESTAMPTZ,
    excluded_domains TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    revoked_by TEXT,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT,
    CONSTRAINT active_scan_scopes_domain_format CHECK (
        scope_domain = lower(btrim(scope_domain))
        AND scope_domain ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
        AND length(scope_domain) BETWEEN 1 AND 253
    ),
    CONSTRAINT active_scan_scopes_testing_level CHECK (
        testing_level IN ('TECHNOLOGY_HTTP', 'PORT_SCAN', 'ADHOC_CHECK')
    ),
    CONSTRAINT active_scan_scopes_status CHECK (
        status IN ('ACTIVE', 'REVOKED')
    ),
    CONSTRAINT active_scan_scopes_expiry CHECK (
        expires_at IS NULL OR expires_at > approved_at
    ),
    CONSTRAINT active_scan_scopes_revocation_metadata CHECK (
        (status = 'ACTIVE' AND revoked_by IS NULL AND revoked_at IS NULL)
        OR
        (status = 'REVOKED' AND revoked_by IS NOT NULL AND revoked_at IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS active_scan_scopes_active_lookup_idx
    ON active_scan_scopes(status, testing_level, expires_at);

CREATE INDEX IF NOT EXISTS active_scan_scopes_domain_idx
    ON active_scan_scopes(scope_domain);

COMMIT;
