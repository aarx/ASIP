BEGIN;

ALTER TABLE public.scans
    ADD COLUMN IF NOT EXISTS dns_security_target_ids INTEGER[];

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conrelid = 'public.scans'::regclass
           AND conname = 'scans_dns_security_target_ids_limit'
    ) THEN
        ALTER TABLE public.scans
            ADD CONSTRAINT scans_dns_security_target_ids_limit CHECK (
                dns_security_target_ids IS NULL
                OR (
                    array_ndims(dns_security_target_ids) = 1
                    AND cardinality(dns_security_target_ids) BETWEEN 1 AND 3
                    AND array_position(dns_security_target_ids, NULL) IS NULL
                    AND 0 < ALL(dns_security_target_ids)
                )
            );
    END IF;
END $$;

COMMIT;
