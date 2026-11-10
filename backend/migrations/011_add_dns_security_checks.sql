BEGIN;

DO $$
DECLARE
    constraint_definition text;
BEGIN
    SELECT pg_get_constraintdef(oid)
      INTO constraint_definition
      FROM pg_constraint
     WHERE conrelid = 'public.active_scan_scopes'::regclass
       AND conname = 'active_scan_scopes_testing_level';

    IF constraint_definition IS NULL THEN
        RAISE EXCEPTION
            'active_scan_scopes_testing_level constraint is missing';
    END IF;

    IF constraint_definition NOT LIKE '%DNS_SECURITY%' THEN
        ALTER TABLE public.active_scan_scopes
            DROP CONSTRAINT active_scan_scopes_testing_level;

        ALTER TABLE public.active_scan_scopes
            ADD CONSTRAINT active_scan_scopes_testing_level CHECK (
                testing_level IN (
                    'TECHNOLOGY_HTTP',
                    'PORT_SCAN',
                    'ADHOC_CHECK',
                    'HTTP_TLS_OBSERVATION',
                    'DNS_SECURITY'
                )
            );
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS public.dns_security_checks (
    id BIGSERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
    domain_id INTEGER NOT NULL REFERENCES public.domains(id) ON DELETE CASCADE,
    check_key TEXT NOT NULL CHECK (length(check_key) BETWEEN 1 AND 80),
    target_identity TEXT NOT NULL DEFAULT '' CHECK (length(target_identity) <= 253),
    record_type TEXT NOT NULL DEFAULT '' CHECK (
        record_type IN ('', 'A', 'AAAA', 'CNAME', 'MX', 'TXT')
    ),
    outcome TEXT NOT NULL CHECK (outcome IN (
        'CONFIRMED_ISSUE', 'POTENTIAL_EXPOSURE', 'WARNING',
        'INFORMATIONAL', 'CLEAR', 'NOT_CHECKED', 'INCONCLUSIVE'
    )),
    severity TEXT NOT NULL DEFAULT 'INFO' CHECK (
        severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN')
    ),
    confidence TEXT NOT NULL DEFAULT 'UNKNOWN' CHECK (
        confidence IN ('HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')
    ),
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (
        jsonb_typeof(evidence) = 'object' AND pg_column_size(evidence) <= 8192
    ),
    remediation TEXT CHECK (remediation IS NULL OR length(remediation) <= 1000),
    checked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Also upgrade an already-created disposable/dev copy of the original draft
-- schema. Production has not applied this migration yet.
ALTER TABLE public.dns_security_checks
    ADD COLUMN IF NOT EXISTS record_type TEXT;
UPDATE public.dns_security_checks SET record_type = '' WHERE record_type IS NULL;
ALTER TABLE public.dns_security_checks
    ALTER COLUMN record_type SET DEFAULT '',
    ALTER COLUMN record_type SET NOT NULL;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'public.dns_security_checks'::regclass
           AND conname = 'dns_security_checks_scan_domain_key'
    ) THEN
        ALTER TABLE public.dns_security_checks
            DROP CONSTRAINT dns_security_checks_scan_domain_key;
    END IF;
END $$;

ALTER TABLE public.dns_security_checks
    DROP CONSTRAINT IF EXISTS dns_security_checks_record_type_check;
ALTER TABLE public.dns_security_checks
    ADD CONSTRAINT dns_security_checks_record_type_check CHECK (
        record_type IN ('', 'A', 'AAAA', 'CNAME', 'MX', 'TXT')
    );

CREATE UNIQUE INDEX IF NOT EXISTS dns_security_checks_identity_uq
    ON public.dns_security_checks(
        scan_id, domain_id, check_key, target_identity, record_type
    );

CREATE INDEX IF NOT EXISTS dns_security_checks_scan_outcome_idx
    ON public.dns_security_checks(scan_id, outcome, severity);

COMMIT;
