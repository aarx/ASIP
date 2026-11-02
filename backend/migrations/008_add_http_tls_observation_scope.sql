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

    IF constraint_definition NOT LIKE '%TECHNOLOGY_HTTP%'
       OR constraint_definition NOT LIKE '%PORT_SCAN%'
       OR constraint_definition NOT LIKE '%ADHOC_CHECK%' THEN
        RAISE EXCEPTION
            'active_scan_scopes_testing_level constraint is incompatible';
    END IF;

    IF constraint_definition NOT LIKE '%HTTP_TLS_OBSERVATION%' THEN
        ALTER TABLE public.active_scan_scopes
            DROP CONSTRAINT active_scan_scopes_testing_level;

        ALTER TABLE public.active_scan_scopes
            ADD CONSTRAINT active_scan_scopes_testing_level CHECK (
                testing_level IN (
                    'TECHNOLOGY_HTTP',
                    'PORT_SCAN',
                    'ADHOC_CHECK',
                    'HTTP_TLS_OBSERVATION'
                )
            );
    END IF;
END $$;

COMMIT;
