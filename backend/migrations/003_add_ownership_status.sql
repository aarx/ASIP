BEGIN;

ALTER TABLE domains
    ADD COLUMN IF NOT EXISTS ownership_status TEXT NOT NULL DEFAULT 'CONFIRMED';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'domains_ownership_status_check'
          AND conrelid = 'domains'::regclass
    ) THEN
        ALTER TABLE domains
            ADD CONSTRAINT domains_ownership_status_check
            CHECK (ownership_status IN ('CONFIRMED', 'CANDIDATE', 'EXTERNAL'));
    END IF;
END
$$;

COMMIT;
