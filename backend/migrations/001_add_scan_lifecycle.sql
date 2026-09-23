BEGIN;

ALTER TABLE public.scans
    ADD COLUMN status text NOT NULL DEFAULT 'UNKNOWN';

ALTER TABLE public.scans
    ADD CONSTRAINT scans_status_check
    CHECK (status IN ('UNKNOWN', 'RUNNING', 'SUCCEEDED', 'FAILED'));

ALTER TABLE public.scans
    ADD CONSTRAINT scans_status_completed_at_check
    CHECK (
        status = 'UNKNOWN'
        OR (status = 'RUNNING' AND completed_at IS NULL)
        OR (
            status IN ('SUCCEEDED', 'FAILED')
            AND completed_at IS NOT NULL
        )
    );

CREATE INDEX idx_scans_succeeded_id_desc
    ON public.scans (id DESC)
    WHERE status = 'SUCCEEDED';

COMMIT;
