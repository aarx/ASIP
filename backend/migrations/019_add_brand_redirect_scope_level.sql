BEGIN;

DO $$
DECLARE
    constraint_definition text;
    allowed_levels text[];
    allowed_sql text;
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

    IF constraint_definition NOT LIKE '%BRAND_REDIRECT_OBSERVATION%' THEN
        SELECT array_agg(captured[1] ORDER BY ordinality)
          INTO allowed_levels
          FROM regexp_matches(
              constraint_definition, '''([^'']+)''', 'g'
          ) WITH ORDINALITY AS extracted(captured, ordinality);
        allowed_levels := array_append(
            allowed_levels, 'BRAND_REDIRECT_OBSERVATION'
        );
        SELECT string_agg(quote_literal(value), ', ' ORDER BY ordinality)
          INTO allowed_sql
          FROM unnest(allowed_levels) WITH ORDINALITY AS levels(value, ordinality);

        ALTER TABLE public.active_scan_scopes
            DROP CONSTRAINT active_scan_scopes_testing_level;

        EXECUTE 'ALTER TABLE public.active_scan_scopes '
            || 'ADD CONSTRAINT active_scan_scopes_testing_level CHECK '
            || '(testing_level IN (' || allowed_sql || '))';
    END IF;
END $$;

COMMIT;
