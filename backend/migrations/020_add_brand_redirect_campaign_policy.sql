BEGIN;

ALTER TABLE public.active_scan_scopes
    ADD COLUMN IF NOT EXISTS monitoring_purpose text,
    ADD COLUMN IF NOT EXISTS eligible_discovery_sources text[],
    ADD COLUMN IF NOT EXISTS max_requests_per_scan integer;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'public.active_scan_scopes'::regclass
           AND conname = 'active_scan_scopes_brand_campaign_policy'
    ) THEN
        ALTER TABLE public.active_scan_scopes
            ADD CONSTRAINT active_scan_scopes_brand_campaign_policy CHECK (
                testing_level <> 'BRAND_REDIRECT_OBSERVATION'
                OR status = 'REVOKED'
                OR (
                    NULLIF(BTRIM(monitoring_purpose), '') IS NOT NULL
                    AND COALESCE(cardinality(eligible_discovery_sources), 0) > 0
                    AND eligible_discovery_sources
                        <@ ARRAY['brand_tld', 'brand_pattern']::text[]
                    AND max_requests_per_scan BETWEEN 1 AND 100000
                )
            ) NOT VALID;
    END IF;

    IF to_regclass('public.brand_redirect_observations') IS NULL THEN
        RAISE EXCEPTION
            'Migration 020 requires migration 018 brand_redirect_observations';
    END IF;

    ALTER TABLE public.brand_redirect_observations
        DROP CONSTRAINT IF EXISTS brand_redirect_observations_completeness_check;
    ALTER TABLE public.brand_redirect_observations
        ADD CONSTRAINT brand_redirect_observations_completeness_check CHECK (
            completeness IN (
                'COMPLETE', 'NO_REDIRECT', 'STOPPED_AT_AUTHORIZATION_BOUNDARY',
                'TIMEOUT', 'ERROR', 'REDIRECT_LOOP', 'MAX_REDIRECT_HOPS',
                'REQUEST_BUDGET_EXHAUSTED'
            )
        );
END $$;

COMMIT;
