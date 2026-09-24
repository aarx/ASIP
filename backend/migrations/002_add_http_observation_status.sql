BEGIN;

ALTER TABLE public.domain_states
    ADD COLUMN http_observation_status text NOT NULL DEFAULT 'UNKNOWN';

ALTER TABLE public.domain_states
    ADD CONSTRAINT domain_states_http_observation_status_check
    CHECK (
        http_observation_status IN (
            'RESPONDED',
            'NO_RESPONSE',
            'FAILED',
            'UNKNOWN'
        )
    );

COMMIT;
