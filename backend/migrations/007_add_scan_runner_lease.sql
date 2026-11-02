BEGIN;

ALTER TABLE public.scans
    ADD COLUMN IF NOT EXISTS runner_token text,
    ADD COLUMN IF NOT EXISTS heartbeat_at timestamptz,
    ADD COLUMN IF NOT EXISTS failure_reason text;

CREATE INDEX IF NOT EXISTS idx_scans_running_heartbeat
    ON public.scans (status, heartbeat_at)
    WHERE status = 'RUNNING';

COMMIT;
