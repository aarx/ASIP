BEGIN;

ALTER TABLE public.scans
    ADD COLUMN IF NOT EXISTS stage_diagnostics jsonb;

COMMIT;
