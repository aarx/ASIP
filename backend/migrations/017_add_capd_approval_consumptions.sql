BEGIN;

CREATE TABLE public.capd_approval_consumptions (
    run_id uuid PRIMARY KEY,
    approval_sha256 text NOT NULL UNIQUE
        CHECK (approval_sha256 ~ '^[0-9a-f]{64}$'),
    check_id text NOT NULL CHECK (btrim(check_id) <> ''),
    check_revision text NOT NULL CHECK (btrim(check_revision) <> ''),
    source_scan_id integer NOT NULL REFERENCES public.scans(id),
    domain_id integer NOT NULL REFERENCES public.domains(id),
    domain_snapshot text NOT NULL CHECK (btrim(domain_snapshot) <> ''),
    origin text NOT NULL CHECK (btrim(origin) <> ''),
    http_method text NOT NULL CHECK (http_method = 'GET'),
    request_budget smallint NOT NULL CHECK (request_budget = 1),
    operator_uid integer NOT NULL CHECK (operator_uid > 0),
    operator_name text NOT NULL CHECK (btrim(operator_name) <> ''),
    authorization_receipt jsonb NOT NULL
        CHECK (jsonb_typeof(authorization_receipt) = 'object'),
    consumed_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_capd_approval_consumptions_consumed_at
    ON public.capd_approval_consumptions (consumed_at DESC);

COMMIT;
