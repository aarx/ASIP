--
-- PostgreSQL database dump
--

\restrict QSjqkZUNzRfbJdmIDeQZoLE0BGNDuREOTn2FqvvufRpcjKof19XC5dtHet9XlhP

-- Dumped from database version 15.17 (Debian 15.17-1.pgdg13+1)
-- Dumped by pg_dump version 15.17 (Debian 15.17-1.pgdg13+1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: cert_expiry; Type: TABLE; Schema: public; Owner: asm
--

CREATE TABLE public.cert_expiry (
    domain_id integer NOT NULL,
    scan_id integer NOT NULL,
    expiry_date timestamp without time zone,
    days_to_expiry integer
);


ALTER TABLE public.cert_expiry OWNER TO asm;

--
-- Name: domain_asn; Type: TABLE; Schema: public; Owner: asm
--

CREATE TABLE public.domain_asn (
    scan_id integer,
    domain_id integer,
    asn text,
    ip text,
    org text
);


ALTER TABLE public.domain_asn OWNER TO asm;

--
-- Name: domain_cert; Type: TABLE; Schema: public; Owner: asm
--

CREATE TABLE public.domain_cert (
    domain_id integer,
    scan_id integer,
    expiry_date date,
    days_to_expiry integer,
    cert_status text
);


ALTER TABLE public.domain_cert OWNER TO asm;

--
-- Name: domain_dns; Type: TABLE; Schema: public; Owner: asm
--

CREATE TABLE public.domain_dns (
    id integer NOT NULL,
    domain_id integer,
    scan_id integer,
    record_type text,
    value text
);


ALTER TABLE public.domain_dns OWNER TO asm;

--
-- Name: domain_dns_id_seq; Type: SEQUENCE; Schema: public; Owner: asm
--

CREATE SEQUENCE public.domain_dns_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.domain_dns_id_seq OWNER TO asm;

--
-- Name: domain_dns_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: asm
--

ALTER SEQUENCE public.domain_dns_id_seq OWNED BY public.domain_dns.id;


--
-- Name: domain_findings; Type: TABLE; Schema: public; Owner: asm
--

CREATE TABLE public.domain_findings (
    id integer NOT NULL,
    domain_id integer,
    scan_id integer,
    finding text,
    severity text,
    evidence text
);


ALTER TABLE public.domain_findings OWNER TO asm;

--
-- Name: domain_findings_id_seq; Type: SEQUENCE; Schema: public; Owner: asm
--

CREATE SEQUENCE public.domain_findings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.domain_findings_id_seq OWNER TO asm;

--
-- Name: domain_findings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: asm
--

ALTER SEQUENCE public.domain_findings_id_seq OWNED BY public.domain_findings.id;


--
-- Name: domain_ports; Type: TABLE; Schema: public; Owner: asm
--

CREATE TABLE public.domain_ports (
    scan_id integer,
    domain_id integer,
    port integer,
    service text
);


ALTER TABLE public.domain_ports OWNER TO asm;

--
-- Name: domain_provider; Type: TABLE; Schema: public; Owner: asm
--

CREATE TABLE public.domain_provider (
    scan_id integer,
    domain_id integer,
    provider text
);


ALTER TABLE public.domain_provider OWNER TO asm;

--
-- Name: domain_risk; Type: TABLE; Schema: public; Owner: asm
--

CREATE TABLE public.domain_risk (
    domain_id integer NOT NULL,
    scan_id integer NOT NULL,
    risk_score integer,
    reasons text
);


ALTER TABLE public.domain_risk OWNER TO asm;

--
-- Name: domain_san; Type: TABLE; Schema: public; Owner: asm
--

CREATE TABLE public.domain_san (
    domain_id integer NOT NULL,
    scan_id integer NOT NULL
);


ALTER TABLE public.domain_san OWNER TO asm;

--
-- Name: domain_sources; Type: TABLE; Schema: public; Owner: asm
--

CREATE TABLE public.domain_sources (
    domain_id integer,
    scan_id integer,
    source text,
    seed text
);


ALTER TABLE public.domain_sources OWNER TO asm;

--
-- Name: domain_states; Type: TABLE; Schema: public; Owner: asm
--

CREATE TABLE public.domain_states (
    scan_id integer,
    domain_id integer,
    ip text,
    has_ip boolean,
    http_status integer,
    http_live boolean,
    reverse_dns text,
    http_reason text,
    final_url text,
    final_status integer,
    title text,
    http_observation_status text DEFAULT 'UNKNOWN'::text NOT NULL
);


ALTER TABLE public.domain_states OWNER TO asm;

--
-- Name: domain_tech; Type: TABLE; Schema: public; Owner: asm
--

CREATE TABLE public.domain_tech (
    scan_id integer,
    domain_id integer,
    tech text
);


ALTER TABLE public.domain_tech OWNER TO asm;

--
-- Name: domain_validation_log; Type: TABLE; Schema: public; Owner: asm
--

CREATE TABLE public.domain_validation_log (
    domain text,
    status text,
    source text,
    created_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.domain_validation_log OWNER TO asm;

--
-- Name: domains; Type: TABLE; Schema: public; Owner: asm
--

CREATE TABLE public.domains (
    id integer NOT NULL,
    domain text,
    first_seen_scan integer,
    last_seen_scan integer,
    is_known boolean DEFAULT false,
    source text DEFAULT 'seed'::text,
    enrichment_status text DEFAULT 'pending'::text,
    san_processed boolean DEFAULT false,
    port_done boolean DEFAULT false,
    tech_done boolean DEFAULT false,
    asn_done boolean DEFAULT false,
    provider_done boolean DEFAULT false,
    scannable boolean DEFAULT false,
    confidence_score integer DEFAULT 0,
    confidence_label text DEFAULT 'low'::text,
    confidence_reasons text[],
    validation_source text,
    first_seen_at timestamp without time zone,
    last_seen_at timestamp without time zone,
    ownership_status text DEFAULT 'CONFIRMED'::text NOT NULL
);


ALTER TABLE public.domains OWNER TO asm;

--
-- Name: domains_id_seq; Type: SEQUENCE; Schema: public; Owner: asm
--

CREATE SEQUENCE public.domains_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.domains_id_seq OWNER TO asm;

--
-- Name: domains_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: asm
--

ALTER SEQUENCE public.domains_id_seq OWNED BY public.domains.id;


--
-- Name: known_domains; Type: TABLE; Schema: public; Owner: asm
--

CREATE TABLE public.known_domains (
    id integer NOT NULL,
    domain text,
    source text,
    added_at timestamp without time zone DEFAULT now()
);


ALTER TABLE public.known_domains OWNER TO asm;

--
-- Name: known_domains_id_seq; Type: SEQUENCE; Schema: public; Owner: asm
--

CREATE SEQUENCE public.known_domains_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.known_domains_id_seq OWNER TO asm;

--
-- Name: known_domains_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: asm
--

ALTER SEQUENCE public.known_domains_id_seq OWNED BY public.known_domains.id;


--
-- Name: scan_results; Type: TABLE; Schema: public; Owner: asm
--

CREATE TABLE public.scan_results (
    scan_id integer,
    domain_id integer,
    seed text
);


ALTER TABLE public.scan_results OWNER TO asm;

--
-- Name: scans; Type: TABLE; Schema: public; Owner: asm
--

CREATE TABLE public.scans (
    id integer NOT NULL,
    scan_time timestamp without time zone DEFAULT now(),
    seed text,
    started_at timestamp without time zone,
    completed_at timestamp without time zone,
    status text DEFAULT 'UNKNOWN'::text NOT NULL
);


ALTER TABLE public.scans OWNER TO asm;

--
-- Name: scans_id_seq; Type: SEQUENCE; Schema: public; Owner: asm
--

CREATE SEQUENCE public.scans_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.scans_id_seq OWNER TO asm;

--
-- Name: scans_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: asm
--

ALTER SEQUENCE public.scans_id_seq OWNED BY public.scans.id;


--
-- Name: seed_domains; Type: TABLE; Schema: public; Owner: asm
--

CREATE TABLE public.seed_domains (
    id integer NOT NULL,
    domain text
);


ALTER TABLE public.seed_domains OWNER TO asm;

--
-- Name: seed_domains_id_seq; Type: SEQUENCE; Schema: public; Owner: asm
--

CREATE SEQUENCE public.seed_domains_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.seed_domains_id_seq OWNER TO asm;

--
-- Name: seed_domains_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: asm
--

ALTER SEQUENCE public.seed_domains_id_seq OWNED BY public.seed_domains.id;


--
-- Name: sensitive_ports; Type: TABLE; Schema: public; Owner: asm
--

CREATE TABLE public.sensitive_ports (
    port integer NOT NULL,
    risk integer DEFAULT 5,
    description text
);


ALTER TABLE public.sensitive_ports OWNER TO asm;

--
-- Name: domain_dns id; Type: DEFAULT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.domain_dns ALTER COLUMN id SET DEFAULT nextval('public.domain_dns_id_seq'::regclass);


--
-- Name: domain_findings id; Type: DEFAULT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.domain_findings ALTER COLUMN id SET DEFAULT nextval('public.domain_findings_id_seq'::regclass);


--
-- Name: domains id; Type: DEFAULT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.domains ALTER COLUMN id SET DEFAULT nextval('public.domains_id_seq'::regclass);


--
-- Name: known_domains id; Type: DEFAULT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.known_domains ALTER COLUMN id SET DEFAULT nextval('public.known_domains_id_seq'::regclass);


--
-- Name: scans id; Type: DEFAULT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.scans ALTER COLUMN id SET DEFAULT nextval('public.scans_id_seq'::regclass);


--
-- Name: seed_domains id; Type: DEFAULT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.seed_domains ALTER COLUMN id SET DEFAULT nextval('public.seed_domains_id_seq'::regclass);


--
-- Name: cert_expiry cert_expiry_pkey; Type: CONSTRAINT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.cert_expiry
    ADD CONSTRAINT cert_expiry_pkey PRIMARY KEY (domain_id, scan_id);


--
-- Name: domain_dns domain_dns_pkey; Type: CONSTRAINT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.domain_dns
    ADD CONSTRAINT domain_dns_pkey PRIMARY KEY (id);


--
-- Name: domain_findings domain_findings_domain_id_scan_id_finding_key; Type: CONSTRAINT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.domain_findings
    ADD CONSTRAINT domain_findings_domain_id_scan_id_finding_key UNIQUE (domain_id, scan_id, finding);


--
-- Name: domain_findings domain_findings_pkey; Type: CONSTRAINT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.domain_findings
    ADD CONSTRAINT domain_findings_pkey PRIMARY KEY (id);


--
-- Name: domain_risk domain_risk_pkey; Type: CONSTRAINT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.domain_risk
    ADD CONSTRAINT domain_risk_pkey PRIMARY KEY (domain_id, scan_id);


--
-- Name: domain_san domain_san_pkey; Type: CONSTRAINT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.domain_san
    ADD CONSTRAINT domain_san_pkey PRIMARY KEY (domain_id, scan_id);


--
-- Name: domain_sources domain_sources_domain_id_scan_id_source_seed_key; Type: CONSTRAINT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.domain_sources
    ADD CONSTRAINT domain_sources_domain_id_scan_id_source_seed_key UNIQUE (domain_id, scan_id, source, seed);


--
-- Name: domains domains_domain_key; Type: CONSTRAINT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.domains
    ADD CONSTRAINT domains_domain_key UNIQUE (domain);


--
-- Name: domains domains_pkey; Type: CONSTRAINT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.domains
    ADD CONSTRAINT domains_pkey PRIMARY KEY (id);


--
-- Name: known_domains known_domains_domain_key; Type: CONSTRAINT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.known_domains
    ADD CONSTRAINT known_domains_domain_key UNIQUE (domain);


--
-- Name: known_domains known_domains_pkey; Type: CONSTRAINT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.known_domains
    ADD CONSTRAINT known_domains_pkey PRIMARY KEY (id);


--
-- Name: scan_results scan_results_scan_id_domain_id_seed_key; Type: CONSTRAINT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.scan_results
    ADD CONSTRAINT scan_results_scan_id_domain_id_seed_key UNIQUE (scan_id, domain_id, seed);


--
-- Name: scans scans_pkey; Type: CONSTRAINT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.scans
    ADD CONSTRAINT scans_pkey PRIMARY KEY (id);


--
-- Name: scans scans_status_check; Type: CHECK CONSTRAINT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.scans
    ADD CONSTRAINT scans_status_check CHECK ((status = ANY (ARRAY['UNKNOWN'::text, 'RUNNING'::text, 'SUCCEEDED'::text, 'FAILED'::text])));


--
-- Name: scans scans_status_completed_at_check; Type: CHECK CONSTRAINT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.scans
    ADD CONSTRAINT scans_status_completed_at_check CHECK (((status = 'UNKNOWN'::text) OR ((status = 'RUNNING'::text) AND (completed_at IS NULL)) OR ((status = ANY (ARRAY['SUCCEEDED'::text, 'FAILED'::text])) AND (completed_at IS NOT NULL))));


--
-- Name: seed_domains seed_domains_domain_key; Type: CONSTRAINT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.seed_domains
    ADD CONSTRAINT seed_domains_domain_key UNIQUE (domain);


--
-- Name: seed_domains seed_domains_pkey; Type: CONSTRAINT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.seed_domains
    ADD CONSTRAINT seed_domains_pkey PRIMARY KEY (id);


--
-- Name: sensitive_ports sensitive_ports_pkey; Type: CONSTRAINT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.sensitive_ports
    ADD CONSTRAINT sensitive_ports_pkey PRIMARY KEY (port);


--
-- Name: domain_asn unique_domain_asn; Type: CONSTRAINT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.domain_asn
    ADD CONSTRAINT unique_domain_asn UNIQUE (domain_id, scan_id);


--
-- Name: domain_cert unique_domain_cert; Type: CONSTRAINT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.domain_cert
    ADD CONSTRAINT unique_domain_cert UNIQUE (domain_id, scan_id);


--
-- Name: domain_dns unique_domain_dns; Type: CONSTRAINT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.domain_dns
    ADD CONSTRAINT unique_domain_dns UNIQUE (domain_id, scan_id, record_type, value);


--
-- Name: domain_ports unique_domain_port; Type: CONSTRAINT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.domain_ports
    ADD CONSTRAINT unique_domain_port UNIQUE (domain_id, port, scan_id);


--
-- Name: domain_provider unique_domain_provider; Type: CONSTRAINT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.domain_provider
    ADD CONSTRAINT unique_domain_provider UNIQUE (domain_id, scan_id);


--
-- Name: domain_states unique_domain_scan; Type: CONSTRAINT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.domain_states
    ADD CONSTRAINT unique_domain_scan UNIQUE (domain_id, scan_id);


--
-- Name: domain_states domain_states_http_observation_status_check; Type: CONSTRAINT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.domain_states
    ADD CONSTRAINT domain_states_http_observation_status_check CHECK ((http_observation_status = ANY (ARRAY['RESPONDED'::text, 'NO_RESPONSE'::text, 'FAILED'::text, 'UNKNOWN'::text])));


--
-- Name: domains domains_ownership_status_check; Type: CHECK CONSTRAINT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.domains
    ADD CONSTRAINT domains_ownership_status_check CHECK ((ownership_status = ANY (ARRAY['CONFIRMED'::text, 'CANDIDATE'::text, 'EXTERNAL'::text])));


--
-- Name: domain_tech unique_domain_tech; Type: CONSTRAINT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.domain_tech
    ADD CONSTRAINT unique_domain_tech UNIQUE (domain_id, scan_id, tech);


--
-- Name: scan_results unique_scan_domain; Type: CONSTRAINT; Schema: public; Owner: asm
--

ALTER TABLE ONLY public.scan_results
    ADD CONSTRAINT unique_scan_domain UNIQUE (scan_id, domain_id);


--
-- Name: idx_domain_asn_scan; Type: INDEX; Schema: public; Owner: asm
--

CREATE INDEX idx_domain_asn_scan ON public.domain_asn USING btree (scan_id);


--
-- Name: idx_domain_ports_scan; Type: INDEX; Schema: public; Owner: asm
--

CREATE INDEX idx_domain_ports_scan ON public.domain_ports USING btree (scan_id);


--
-- Name: idx_domain_states_scan; Type: INDEX; Schema: public; Owner: asm
--

CREATE INDEX idx_domain_states_scan ON public.domain_states USING btree (scan_id);


--
-- Name: idx_domains_domain; Type: INDEX; Schema: public; Owner: asm
--

CREATE INDEX idx_domains_domain ON public.domains USING btree (domain);


--
-- Name: idx_known_domains_domain; Type: INDEX; Schema: public; Owner: asm
--

CREATE INDEX idx_known_domains_domain ON public.known_domains USING btree (domain);


--
-- Name: idx_scans_succeeded_id_desc; Type: INDEX; Schema: public; Owner: asm
--

CREATE INDEX idx_scans_succeeded_id_desc ON public.scans USING btree (id DESC) WHERE (status = 'SUCCEEDED'::text);


--
-- Name: active_scan_scopes; Type: TABLE; Schema: public; Owner: asm
--

CREATE TABLE public.active_scan_scopes (
    id bigserial PRIMARY KEY,
    scope_domain text NOT NULL,
    include_subdomains boolean NOT NULL,
    testing_level text NOT NULL,
    approved_by text NOT NULL,
    approved_at timestamp with time zone NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status text NOT NULL DEFAULT 'ACTIVE',
    expires_at timestamp with time zone,
    excluded_domains text[] NOT NULL DEFAULT ARRAY[]::text[],
    monitoring_purpose text,
    eligible_discovery_sources text[],
    max_requests_per_scan integer,
    revoked_by text,
    revoked_at timestamp with time zone,
    revocation_reason text,
    CONSTRAINT active_scan_scopes_domain_format CHECK (
        scope_domain = lower(btrim(scope_domain))
        AND scope_domain ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
        AND length(scope_domain) BETWEEN 1 AND 253
    ),
    CONSTRAINT active_scan_scopes_testing_level CHECK (
        testing_level IN (
            'TECHNOLOGY_HTTP', 'PORT_SCAN', 'ADHOC_CHECK',
            'HTTP_TLS_OBSERVATION', 'DNS_SECURITY', 'ASN_METADATA',
            'CAPD_HTTP_HEADER_VERIFY', 'BRAND_REDIRECT_OBSERVATION'
        )
    ),
    CONSTRAINT active_scan_scopes_status CHECK (status IN ('ACTIVE', 'REVOKED')),
    CONSTRAINT active_scan_scopes_expiry CHECK (
        expires_at IS NULL OR expires_at > approved_at
    ),
    CONSTRAINT active_scan_scopes_revocation_metadata CHECK (
        (status = 'ACTIVE' AND revoked_by IS NULL AND revoked_at IS NULL)
        OR
        (status = 'REVOKED' AND revoked_by IS NOT NULL AND revoked_at IS NOT NULL)
    ),
    CONSTRAINT active_scan_scopes_brand_campaign_policy CHECK (
        testing_level <> 'BRAND_REDIRECT_OBSERVATION'
        OR status = 'REVOKED'
        OR (
            NULLIF(BTRIM(monitoring_purpose), '') IS NOT NULL
            AND COALESCE(cardinality(eligible_discovery_sources), 0) > 0
            AND eligible_discovery_sources <@ ARRAY['brand_tld', 'brand_pattern']::text[]
            AND max_requests_per_scan BETWEEN 1 AND 100000
        )
    )
);

ALTER TABLE public.active_scan_scopes OWNER TO asm;

CREATE INDEX active_scan_scopes_active_lookup_idx
    ON public.active_scan_scopes USING btree (status, testing_level, expires_at);

CREATE INDEX active_scan_scopes_domain_idx
    ON public.active_scan_scopes USING btree (scope_domain);


--
-- PostgreSQL database dump complete
--

\unrestrict QSjqkZUNzRfbJdmIDeQZoLE0BGNDuREOTn2FqvvufRpcjKof19XC5dtHet9XlhP

