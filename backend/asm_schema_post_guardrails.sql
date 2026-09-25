--
-- PostgreSQL database dump
--

\restrict 9cyTDUJCNpIRnriRbM3Ygn0OT0EplRuchLgK4qS2SLLLVEAeeKTGVe3u70qWbjd

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
    completed_at timestamp without time zone
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
-- Data for Name: cert_expiry; Type: TABLE DATA; Schema: public; Owner: asm
--

COPY public.cert_expiry (domain_id, scan_id, expiry_date, days_to_expiry) FROM stdin;
\.


--
-- Data for Name: domain_asn; Type: TABLE DATA; Schema: public; Owner: asm
--

COPY public.domain_asn (scan_id, domain_id, asn, ip, org) FROM stdin;
1	8	AS55836	49.44.175.16	AS55836 Reliance Jio Infocomm Limited
1	9	AS55836	49.44.175.10	AS55836 Reliance Jio Infocomm Limited
1	10	AS14618	98.82.42.139	AS14618 Amazon.com, Inc.
1	12	AS16276	146.59.149.209	AS16276 OVH SAS
1	13	AS24940	88.198.55.147	AS24940 Hetzner Online GmbH
1	14	AS16509	44.232.173.249	AS16509 Amazon.com, Inc.
1	15	AS16509	18.224.83.222	AS16509 Amazon.com, Inc.
1	17	AS16509	13.248.169.48	AS16509 Amazon.com, Inc.
1	20	AS8560	88.208.252.9	AS8560 IONOS SE
1	21	AS16509	108.158.245.116	AS16509 Amazon.com, Inc.
1	22	AS45102	47.242.94.198	AS45102 Alibaba (US) Technology Co., Ltd.
1	23	AS16509	54.215.31.113	AS16509 Amazon.com, Inc.
1	24	AS14061	162.243.117.188	AS14061 DigitalOcean, LLC
1	25	AS13335	172.67.72.194	AS13335 Cloudflare, Inc.
1	27	AS46606	66.147.242.96	AS46606 Unified Layer
1	28	AS16509	76.223.67.189	AS16509 Amazon.com, Inc.
1	29	AS7859	216.92.209.88	AS7859 pair Networks
1	30	AS16509	18.224.83.222	AS16509 Amazon.com, Inc.
1	31		139.104.232.65	
1	32		139.104.232.66	
1	33	AS26347	173.236.214.24	AS26347 New Dream Network, LLC
1	34	AS16509	18.224.83.222	AS16509 Amazon.com, Inc.
1	35	AS16509	52.40.138.92	AS16509 Amazon.com, Inc.
1	38	AS16509	44.245.73.38	AS16509 Amazon.com, Inc.
1	39	AS16509	18.66.102.99	AS16509 Amazon.com, Inc.
1	40	AS16509	3.175.86.5	AS16509 Amazon.com, Inc.
1	41	AS16509	18.66.102.9	AS16509 Amazon.com, Inc.
1	52	AS54330	139.104.36.49	AS54330 Disney Worldwide Services, Inc.
1	53	AS36863	192.195.67.80	AS36863 American Broadcasting Companies, Inc.
1	55	AS16509	44.253.167.177	AS16509 Amazon.com, Inc.
1	58	AS16509	52.40.138.92	AS16509 Amazon.com, Inc.
1	60	AS36863	192.195.67.80	AS36863 American Broadcasting Companies, Inc.
1	61	AS13335	104.18.116.121	AS13335 Cloudflare, Inc.
1	62	AS36863	192.195.67.10	AS36863 American Broadcasting Companies, Inc.
1	65	AS16509	44.245.73.38	AS16509 Amazon.com, Inc.
1	68	AS55836	49.44.175.16	AS55836 Reliance Jio Infocomm Limited
1	70	AS55836	184.85.220.95	AS55836 Reliance Jio Infocomm Limited
1	71	AS55836	49.44.175.9	AS55836 Reliance Jio Infocomm Limited
1	79	AS14618	18.205.77.36	AS14618 Amazon.com, Inc.
1	83		172.24.74.81	
1	86		10.102.125.155	
1	87	AS36863	192.195.67.81	AS36863 American Broadcasting Companies, Inc.
1	88	AS16509	18.164.237.51	AS16509 Amazon.com, Inc.
1	90	AS14618	3.218.80.165	AS14618 Amazon.com, Inc.
1	92	AS14618	3.212.204.30	AS14618 Amazon.com, Inc.
1	98	AS14618	75.101.163.207	AS14618 Amazon.com, Inc.
1	99	AS14061	24.144.66.46	AS14061 DigitalOcean, LLC
1	100	AS36863	192.195.67.81	AS36863 American Broadcasting Companies, Inc.
1	102	AS16509	44.253.167.177	AS16509 Amazon.com, Inc.
1	103	AS54113	151.101.106.137	AS54113 Fastly, Inc.
1	104	AS54113	151.101.106.217	AS54113 Fastly, Inc.
1	105	AS54113	151.101.106.137	AS54113 Fastly, Inc.
1	106	AS54113	151.101.106.217	AS54113 Fastly, Inc.
1	112		192.195.63.65	
1	113	AS16509	44.253.167.177	AS16509 Amazon.com, Inc.
1	120	AS36863	192.195.67.22	AS36863 American Broadcasting Companies, Inc.
1	122	AS8075	40.71.70.250	AS8075 Microsoft Corporation
1	123	AS8075	40.71.70.250	AS8075 Microsoft Corporation
1	124	AS14618	72.44.37.156	AS14618 Amazon.com, Inc.
1	129	AS55836	184.85.220.71	AS55836 Reliance Jio Infocomm Limited
1	130	AS55836	184.85.220.97	AS55836 Reliance Jio Infocomm Limited
1	136	AS54330	204.87.172.6	AS54330 Disney Worldwide Services, Inc.
1	137	AS54330	204.87.172.6	AS54330 Disney Worldwide Services, Inc.
1	139	AS16509	52.84.150.42	AS16509 Amazon.com, Inc.
1	140		72.2.116.92	
1	142	AS16509	76.223.54.146	AS16509 Amazon.com, Inc.
1	145	AS14618	54.165.131.183	AS14618 Amazon.com, Inc.
1	146		139.104.232.35	
1	148		139.104.232.30	
1	149		139.104.232.31	
1	150		139.104.232.32	
1	151		139.104.232.13	
1	152	AS54113	151.101.106.217	AS54113 Fastly, Inc.
1	153	AS54113	151.101.106.217	AS54113 Fastly, Inc.
1	154	AS16509	52.40.138.92	AS16509 Amazon.com, Inc.
1	156	AS16509	44.253.167.177	AS16509 Amazon.com, Inc.
1	157	AS16509	15.197.148.33	AS16509 Amazon.com, Inc.
1	158	AS396982	34.174.221.135	AS396982 Google LLC
1	160	AS36863	192.195.67.81	AS36863 American Broadcasting Companies, Inc.
1	171	AS55836	49.44.119.26	AS55836 Reliance Jio Infocomm Limited
1	172	AS16509	52.40.138.92	AS16509 Amazon.com, Inc.
1	173	AS16509	44.253.167.177	AS16509 Amazon.com, Inc.
1	179	AS36863	192.195.67.33	AS36863 American Broadcasting Companies, Inc.
1	180		68.71.212.241	
1	181	AS8075	40.71.70.250	AS8075 Microsoft Corporation
1	195	AS16509	44.253.167.177	AS16509 Amazon.com, Inc.
1	197		192.195.63.64	
1	198	AS16509	15.156.104.222	AS16509 Amazon.com, Inc.
1	199	AS19574	165.160.15.20	AS19574 Corporation Service Company
1	202		209.34.85.149	
1	203	AS14618	54.205.246.153	AS14618 Amazon.com, Inc.
1	207		139.104.232.44	
1	208	AS16509	44.245.73.38	AS16509 Amazon.com, Inc.
1	213	AS16509	108.158.245.4	AS16509 Amazon.com, Inc.
1	215	AS14618	34.195.213.174	AS14618 Amazon.com, Inc.
1	216	AS16509	99.86.30.39	AS16509 Amazon.com, Inc.
1	218	AS2914	204.202.134.76	AS2914 NTT America, Inc.
1	219	AS2914	204.202.134.77	AS2914 NTT America, Inc.
1	220	AS2914	204.202.134.78	AS2914 NTT America, Inc.
1	221	AS36863	192.195.67.129	AS36863 American Broadcasting Companies, Inc.
1	222	AS8075	52.150.35.231	AS8075 Microsoft Corporation
1	223	AS14618	44.206.52.255	AS14618 Amazon.com, Inc.
1	235	AS16509	44.245.73.38	AS16509 Amazon.com, Inc.
1	238	AS396982	35.197.121.119	AS396982 Google LLC
1	239		139.104.232.57	
1	244	AS29736	192.195.66.83	AS29736 Disney Worldwide Services, Inc.
1	253	AS16509	18.164.217.118	AS16509 Amazon.com, Inc.
1	254	AS16509	3.160.188.51	AS16509 Amazon.com, Inc.
1	255	AS16509	99.84.152.57	AS16509 Amazon.com, Inc.
1	258	AS209242	216.198.53.11	AS209242 Cloudflare London, LLC
1	260	AS16509	66.117.22.190	AS16509 Amazon.com, Inc.
1	267	AS16509	13.248.169.48	AS16509 Amazon.com, Inc.
1	268	AS46475	208.115.240.122	AS46475 Limestone Networks, Inc.
1	279	AS8075	52.147.216.119	AS8075 Microsoft Corporation
1	280	AS8075	52.147.216.119	AS8075 Microsoft Corporation
1	284		139.104.232.100	
1	285		139.104.232.107	
1	288	AS32475	67.212.182.149	AS32475 Internap Holding LLC
1	292	AS8075	20.127.42.140	AS8075 Microsoft Corporation
1	293	AS55836	49.44.50.75	AS55836 Reliance Jio Infocomm Limited
1	294	AS16509	66.117.22.113	AS16509 Amazon.com, Inc.
1	295	AS16509	44.245.73.38	AS16509 Amazon.com, Inc.
1	299	AS16509	108.158.245.59	AS16509 Amazon.com, Inc.
1	305	AS16509	52.40.138.92	AS16509 Amazon.com, Inc.
3	8	AS55836	49.44.95.153	AS55836 Reliance Jio Infocomm Limited
3	9	AS55836	49.44.175.32	AS55836 Reliance Jio Infocomm Limited
3	10	AS14618	98.82.42.139	AS14618 Amazon.com, Inc.
3	12	AS16276	146.59.149.209	AS16276 OVH SAS
3	13	AS24940	88.198.55.147	AS24940 Hetzner Online GmbH
3	14	AS16509	52.40.42.113	AS16509 Amazon.com, Inc.
3	15	AS16509	18.224.83.222	AS16509 Amazon.com, Inc.
3	17	AS16509	76.223.54.146	AS16509 Amazon.com, Inc.
3	20	AS8560	88.208.252.9	AS8560 IONOS SE
3	21	AS16509	13.225.103.113	AS16509 Amazon.com, Inc.
3	22	AS45102	47.242.94.198	AS45102 Alibaba (US) Technology Co., Ltd.
3	23	AS16509	54.215.31.113	AS16509 Amazon.com, Inc.
3	24	AS14061	162.243.117.188	AS14061 DigitalOcean, LLC
3	25	AS13335	172.67.72.194	AS13335 Cloudflare, Inc.
3	27	AS46606	66.147.242.96	AS46606 Unified Layer
3	28	AS16509	3.33.130.190	AS16509 Amazon.com, Inc.
3	29	AS7859	216.92.209.88	AS7859 pair Networks
3	30	AS16509	18.224.83.222	AS16509 Amazon.com, Inc.
3	31		139.104.232.65	
3	32		139.104.232.66	
3	33	AS26347	173.236.214.24	AS26347 New Dream Network, LLC
3	34	AS16509	18.224.83.222	AS16509 Amazon.com, Inc.
3	35	AS14618	13.217.182.13	AS14618 Amazon.com, Inc.
3	38	AS14618	100.49.209.37	AS14618 Amazon.com, Inc.
3	39	AS16509	18.66.102.117	AS16509 Amazon.com, Inc.
3	40	AS16509	18.66.102.117	AS16509 Amazon.com, Inc.
3	41	AS16509	18.66.102.117	AS16509 Amazon.com, Inc.
3	52	AS8137	139.104.64.14	AS8137 Disney Worldwide Services, Inc.
3	53	AS36863	192.195.67.80	AS36863 American Broadcasting Companies, Inc.
3	55	AS16509	54.70.112.205	AS16509 Amazon.com, Inc.
3	58	AS16509	54.70.112.205	AS16509 Amazon.com, Inc.
3	60	AS36863	192.195.67.80	AS36863 American Broadcasting Companies, Inc.
3	61	AS13335	104.18.117.121	AS13335 Cloudflare, Inc.
3	62	AS36863	192.195.67.10	AS36863 American Broadcasting Companies, Inc.
3	65	AS16509	52.43.57.102	AS16509 Amazon.com, Inc.
3	68	AS55836	49.44.175.8	AS55836 Reliance Jio Infocomm Limited
3	70	AS55836	184.85.220.73	AS55836 Reliance Jio Infocomm Limited
3	71	AS55836	49.44.175.9	AS55836 Reliance Jio Infocomm Limited
3	79	AS14618	18.210.153.8	AS14618 Amazon.com, Inc.
3	83		172.24.74.81	
3	86		10.102.125.155	
3	87	AS36863	192.195.67.81	AS36863 American Broadcasting Companies, Inc.
3	88	AS16509	18.164.237.97	AS16509 Amazon.com, Inc.
3	90	AS14618	54.243.116.183	AS14618 Amazon.com, Inc.
3	92	AS14618	44.196.164.156	AS14618 Amazon.com, Inc.
3	98	AS14618	75.101.163.207	AS14618 Amazon.com, Inc.
3	99	AS14061	24.144.66.46	AS14061 DigitalOcean, LLC
3	100	AS36863	192.195.67.81	AS36863 American Broadcasting Companies, Inc.
3	102	AS14618	100.49.209.37	AS14618 Amazon.com, Inc.
3	103	AS54113	151.101.106.137	AS54113 Fastly, Inc.
3	104	AS54113	151.101.106.217	AS54113 Fastly, Inc.
3	105	AS54113	151.101.106.137	AS54113 Fastly, Inc.
3	106	AS54113	151.101.106.217	AS54113 Fastly, Inc.
3	112		192.195.63.65	
3	113	AS16509	54.190.118.130	AS16509 Amazon.com, Inc.
3	120	AS36863	192.195.67.22	AS36863 American Broadcasting Companies, Inc.
3	122	AS8075	40.71.70.250	AS8075 Microsoft Corporation
3	123	AS8075	40.71.70.250	AS8075 Microsoft Corporation
3	124	AS14618	72.44.37.156	AS14618 Amazon.com, Inc.
3	129	AS55836	184.85.220.71	AS55836 Reliance Jio Infocomm Limited
3	130	AS55836	184.85.220.86	AS55836 Reliance Jio Infocomm Limited
3	136	AS54330	204.87.172.6	AS54330 Disney Worldwide Services, Inc.
3	137	AS54330	204.87.172.6	AS54330 Disney Worldwide Services, Inc.
3	139	AS16509	52.84.150.57	AS16509 Amazon.com, Inc.
3	140		72.2.116.92	
3	142	AS16509	76.223.54.146	AS16509 Amazon.com, Inc.
3	145	AS14618	52.44.244.98	AS14618 Amazon.com, Inc.
3	146		139.104.232.35	
3	148		139.104.232.30	
3	149		139.104.232.31	
3	150		139.104.232.32	
3	151		139.104.232.13	
3	152	AS54113	151.101.106.217	AS54113 Fastly, Inc.
3	153	AS54113	151.101.106.217	AS54113 Fastly, Inc.
3	154	AS16509	54.70.112.205	AS16509 Amazon.com, Inc.
3	156	AS16509	52.43.57.102	AS16509 Amazon.com, Inc.
3	157	AS16509	3.33.130.190	AS16509 Amazon.com, Inc.
3	158	AS396982	34.174.221.135	AS396982 Google LLC
3	160	AS36863	192.195.67.81	AS36863 American Broadcasting Companies, Inc.
3	171	AS55836	49.44.95.143	AS55836 Reliance Jio Infocomm Limited
3	172	AS16509	54.190.118.130	AS16509 Amazon.com, Inc.
3	173	AS16509	54.190.118.130	AS16509 Amazon.com, Inc.
3	179	AS36863	192.195.67.33	AS36863 American Broadcasting Companies, Inc.
3	180		68.71.212.241	
3	181	AS8075	40.71.70.250	AS8075 Microsoft Corporation
3	195	AS14618	100.49.209.37	AS14618 Amazon.com, Inc.
3	197		192.195.63.64	
3	198	AS16509	3.96.22.179	AS16509 Amazon.com, Inc.
3	199	AS19574	165.160.15.20	AS19574 Corporation Service Company
3	202		209.34.85.149	
3	203	AS14618	52.0.158.81	AS14618 Amazon.com, Inc.
3	207		139.104.232.44	
3	208	AS16509	54.70.112.205	AS16509 Amazon.com, Inc.
3	213	AS16509	108.158.245.6	AS16509 Amazon.com, Inc.
3	215	AS14618	3.218.217.30	AS14618 Amazon.com, Inc.
3	216	AS16509	99.86.30.39	AS16509 Amazon.com, Inc.
3	218	AS2914	204.202.134.76	AS2914 NTT America, Inc.
3	219	AS2914	204.202.134.77	AS2914 NTT America, Inc.
3	220	AS2914	204.202.134.78	AS2914 NTT America, Inc.
3	221	AS36863	192.195.67.129	AS36863 American Broadcasting Companies, Inc.
3	222	AS8075	52.150.35.231	AS8075 Microsoft Corporation
3	223	AS14618	100.30.242.112	AS14618 Amazon.com, Inc.
3	235	AS16509	54.70.112.205	AS16509 Amazon.com, Inc.
3	238	AS396982	35.197.121.119	AS396982 Google LLC
3	239		139.104.232.57	
3	244	AS29736	192.195.66.83	AS29736 Disney Worldwide Services, Inc.
3	253	AS16509	18.164.217.118	AS16509 Amazon.com, Inc.
3	254	AS16509	99.84.152.104	AS16509 Amazon.com, Inc.
3	255	AS16509	99.84.152.6	AS16509 Amazon.com, Inc.
3	258	AS209242	216.198.53.11	AS209242 Cloudflare London, LLC
3	260	AS16509	66.117.22.113	AS16509 Amazon.com, Inc.
3	267	AS16509	13.248.169.48	AS16509 Amazon.com, Inc.
3	268	AS46475	208.115.240.122	AS46475 Limestone Networks, Inc.
3	279	AS8075	52.147.216.119	AS8075 Microsoft Corporation
3	280	AS8075	52.147.216.119	AS8075 Microsoft Corporation
3	284		139.104.232.100	
3	285		139.104.232.107	
3	288	AS32475	67.212.182.149	AS32475 Internap Holding LLC
3	292	AS8075	20.127.42.140	AS8075 Microsoft Corporation
3	293	AS55836	49.44.175.11	AS55836 Reliance Jio Infocomm Limited
3	294	AS16509	66.117.22.113	AS16509 Amazon.com, Inc.
3	295	AS16509	54.190.118.130	AS16509 Amazon.com, Inc.
3	299	AS16509	13.225.103.63	AS16509 Amazon.com, Inc.
3	305	AS16509	54.190.118.130	AS16509 Amazon.com, Inc.
3	1686	AS55836	49.44.50.82	AS55836 Reliance Jio Infocomm Limited
3	1884	AS16509	54.190.118.130	AS16509 Amazon.com, Inc.
3	1938	AS53578	192.147.170.20	AS53578 Disney Worldwide Services, Inc.
3	1942	AS55836	184.85.220.78	AS55836 Reliance Jio Infocomm Limited
3	1948	AS16509	54.190.118.130	AS16509 Amazon.com, Inc.
3	1960	AS14618	13.217.182.13	AS14618 Amazon.com, Inc.
3	2016	AS2914	204.202.137.92	AS2914 NTT America, Inc.
3	2033		199.181.134.92	
3	2072	AS55836	49.44.50.67	AS55836 Reliance Jio Infocomm Limited
\.


--
-- Data for Name: domain_cert; Type: TABLE DATA; Schema: public; Owner: asm
--

COPY public.domain_cert (domain_id, scan_id, expiry_date, days_to_expiry, cert_status) FROM stdin;
38	3	2026-11-04	191	healthy
113	3	2026-11-04	191	healthy
9	3	2026-11-04	191	healthy
153	3	2026-12-12	229	healthy
58	3	2026-11-04	191	healthy
1942	3	2026-11-04	191	healthy
61	3	2020-10-14	-2021	expired
35	3	2026-11-04	191	healthy
21	3	2026-11-04	191	healthy
1884	3	2026-10-05	161	healthy
106	3	2026-12-12	229	healthy
68	3	2026-12-22	239	healthy
154	3	2026-11-04	191	healthy
70	3	2026-07-19	82	healthy
139	3	2027-03-03	310	healthy
129	3	2026-05-23	25	warning
65	3	2026-11-04	191	healthy
1948	3	2026-11-04	191	healthy
130	3	2026-05-23	25	warning
1960	3	2026-11-04	191	healthy
41	3	\N	\N	no_cert
71	3	2026-06-17	50	healthy
295	3	2026-10-05	161	healthy
260	3	2026-08-13	108	healthy
299	3	2026-11-04	191	healthy
235	3	2026-11-04	191	healthy
293	3	2026-12-22	239	healthy
258	3	2027-02-03	282	healthy
294	3	2027-03-12	319	healthy
305	3	2026-11-04	191	healthy
173	3	2026-11-04	191	healthy
172	3	2026-11-04	191	healthy
102	3	2026-10-05	161	healthy
156	3	2026-11-04	191	healthy
171	3	2026-06-21	54	healthy
195	3	2026-11-04	191	healthy
105	3	2027-04-01	338	healthy
103	3	2026-11-04	191	healthy
104	3	2026-11-04	191	healthy
55	3	2026-11-04	191	healthy
213	3	2026-08-06	101	healthy
2072	3	2026-12-22	239	healthy
253	3	2026-08-06	101	healthy
216	3	2026-08-06	101	healthy
208	3	2026-11-04	191	healthy
124	3	2027-04-25	362	healthy
254	3	\N	\N	no_cert
92	3	2026-07-30	94	healthy
40	3	2026-10-01	157	healthy
255	3	\N	\N	no_cert
292	3	2024-02-01	-816	expired
39	3	2026-10-01	157	healthy
288	3	2026-03-19	-40	expired
123	3	2025-10-03	-206	expired
88	3	2026-08-06	101	healthy
203	3	2026-08-13	108	healthy
99	3	2026-06-11	45	healthy
152	3	2026-12-12	229	healthy
181	3	2024-11-07	-537	expired
179	3	2027-03-10	317	healthy
122	3	2025-10-03	-206	expired
221	3	2026-09-12	138	healthy
90	3	2026-10-01	157	healthy
79	3	2026-07-15	79	healthy
215	3	2026-10-07	163	healthy
145	3	\N	\N	no_cert
\.


--
-- Data for Name: domain_dns; Type: TABLE DATA; Schema: public; Owner: asm
--

COPY public.domain_dns (id, domain_id, scan_id, record_type, value) FROM stdin;
281	8	3	A	49.44.95.153
282	8	3	A	49.44.95.152
283	8	3	CNAME	a-abc.seabc.akadns.net
284	10	3	A	52.201.53.166
285	10	3	A	98.82.42.139
286	12	3	A	146.59.149.209
287	13	3	A	88.198.55.147
288	14	3	A	44.232.173.249
289	14	3	A	52.40.42.113
290	15	3	A	18.224.83.222
291	17	3	A	13.248.169.48
292	17	3	A	76.223.54.146
293	20	3	A	88.208.252.9
294	22	3	A	47.242.94.198
295	23	3	A	54.215.31.113
296	24	3	A	162.243.117.188
297	25	3	A	104.26.6.66
298	25	3	A	172.67.72.194
299	25	3	A	104.26.7.66
300	9	3	A	49.44.175.10
301	9	3	A	49.44.175.32
302	9	3	CNAME	a.oscar.abc.com.edgesuite.net
303	31	3	A	139.104.232.65
304	32	3	A	139.104.232.66
305	35	3	A	54.70.112.205
306	35	3	A	52.43.57.102
307	35	3	A	54.190.118.130
308	38	3	A	54.70.112.205
309	38	3	A	54.190.118.130
310	38	3	A	52.43.57.102
311	58	3	A	54.197.191.132
312	58	3	A	100.49.209.37
313	58	3	A	13.217.182.13
314	1686	3	A	49.44.175.32
315	1686	3	A	49.44.175.10
316	1686	3	CNAME	a.static.abc.com.edgesuite.net
317	60	3	A	192.195.67.80
318	61	3	A	104.18.117.121
319	61	3	A	104.18.115.121
320	61	3	A	104.18.114.121
321	61	3	A	104.18.118.121
322	61	3	A	104.18.116.121
323	61	3	CNAME	abccom.typepad.com
324	1884	3	A	13.217.182.13
325	1884	3	A	54.197.191.132
326	1884	3	A	100.49.209.37
327	39	3	A	18.66.102.117
328	39	3	A	18.66.102.44
329	39	3	A	18.66.102.9
330	39	3	A	18.66.102.99
331	39	3	CNAME	abc-prod-mashery-varnish.aws.seabc.go.com
332	79	3	A	18.210.153.8
333	79	3	CNAME	socialize.gigya.com
334	41	3	A	18.66.102.99
335	41	3	A	18.66.102.117
336	41	3	A	18.66.102.44
337	41	3	A	18.66.102.9
338	41	3	CNAME	prod-abc-msh.aws.seabc.go.com
339	62	3	A	192.195.67.10
340	65	3	A	54.70.112.205
341	65	3	A	52.43.57.102
342	65	3	A	54.190.118.130
343	68	3	A	49.44.50.80
344	68	3	CNAME	cdn.disney.edgesuite.net
345	83	3	A	172.24.74.81
346	86	3	A	10.102.125.155
347	87	3	A	192.195.67.81
348	90	3	A	54.152.97.113
349	90	3	A	54.243.116.183
350	90	3	CNAME	dev.galaxy.go.com
351	92	3	A	44.196.164.156
352	92	3	A	50.17.227.109
353	92	3	CNAME	dev.netbox.go.com
354	106	3	A	151.101.106.217
355	106	3	CNAME	dwtsvote.votenow.tv
356	112	3	A	192.195.63.65
357	113	3	A	100.49.209.37
358	113	3	A	13.217.182.13
359	113	3	A	54.197.191.132
360	21	3	A	13.225.103.113
361	21	3	A	13.225.103.38
362	21	3	A	13.225.103.54
363	21	3	A	13.225.103.63
364	52	3	A	139.104.64.14
365	52	3	A	139.104.36.49
366	53	3	A	192.195.67.80
367	120	3	A	192.195.67.22
368	120	3	CNAME	emx.x100net.com
369	122	3	A	40.71.70.250
370	122	3	CNAME	etsprod.go.com
371	123	3	A	40.71.70.250
372	123	3	CNAME	etsdev.go.com
373	124	3	A	72.44.37.156
374	129	3	A	184.85.220.71
375	129	3	A	184.85.220.70
376	129	3	CNAME	fcast.cdn.abc.com.edgesuite.net
377	130	3	A	184.85.220.97
378	130	3	A	184.85.220.86
379	130	3	CNAME	fcast.qa.cdn.abc.com.edgesuite.net
380	136	3	A	204.87.172.6
381	136	3	CNAME	ftp3.abc.com
382	137	3	A	204.87.172.6
383	139	3	A	52.84.150.62
384	139	3	A	52.84.150.57
385	139	3	A	52.84.150.53
386	139	3	A	52.84.150.42
387	139	3	CNAME	gambit-api.fantasy.espn.com
388	140	3	A	72.2.116.92
389	142	3	A	13.248.169.48
390	142	3	A	76.223.54.146
391	145	3	A	52.44.244.98
392	145	3	A	54.165.131.183
393	145	3	CNAME	gksrv.xlontech.net
394	146	3	A	139.104.232.35
395	148	3	A	139.104.232.30
396	149	3	A	139.104.232.31
397	150	3	A	139.104.232.32
398	151	3	A	139.104.232.13
399	152	3	A	151.101.106.217
400	152	3	CNAME	idolvote-test.votenow.tv
401	153	3	A	151.101.106.217
402	153	3	CNAME	idolvote.votenow.tv
403	154	3	A	54.197.191.132
404	154	3	A	100.49.209.37
405	154	3	A	13.217.182.13
406	27	3	A	66.147.242.96
407	28	3	A	3.33.130.190
408	28	3	A	15.197.148.33
409	29	3	A	216.92.209.88
410	30	3	A	18.224.83.222
411	33	3	A	173.236.214.24
412	34	3	A	18.224.83.222
413	70	3	A	184.85.220.73
414	70	3	A	184.85.220.95
415	70	3	CNAME	cdn.mktg.abc.com.akamaized.net
416	71	3	A	49.44.50.74
417	71	3	CNAME	cdn-video.seabc.akadns.net
418	222	3	A	52.150.35.231
419	222	3	CNAME	remotesupport.go.com
420	223	3	A	100.30.242.112
421	223	3	A	44.212.149.54
422	223	3	CNAME	reset.go.com
423	235	3	A	54.70.112.205
424	235	3	A	54.190.118.130
425	235	3	A	52.43.57.102
426	239	3	A	139.104.232.57
427	239	3	CNAME	secureaccess.abc.go.com
428	244	3	A	192.195.66.83
429	267	3	A	13.248.169.48
430	267	3	A	76.223.54.146
431	268	3	A	208.115.240.122
432	1938	3	A	192.147.170.20
433	1942	3	A	184.85.220.87
434	1942	3	A	184.85.220.78
435	1942	3	CNAME	matterhorn.disney.com
436	1948	3	A	54.197.191.132
437	1948	3	A	13.217.182.13
438	1948	3	A	100.49.209.37
439	1960	3	A	54.197.191.132
440	1960	3	A	100.49.209.37
441	1960	3	A	13.217.182.13
442	2016	3	A	204.202.137.92
443	2016	3	A	204.202.134.45
444	279	3	A	52.147.216.119
445	279	3	CNAME	vdigate.go.com
446	280	3	A	52.147.216.119
447	280	3	CNAME	vdigate1.go.com
448	284	3	A	139.104.232.100
449	284	3	CNAME	vdigate3.go.com
450	285	3	A	139.104.232.107
451	285	3	CNAME	vdigate3qa.go.com
452	288	3	A	67.212.182.149
453	288	3	CNAME	vdigate5.go.com
454	292	3	A	20.127.42.140
455	292	3	CNAME	vdigateqa.go.com
456	293	3	A	49.44.175.27
457	293	3	A	49.44.175.11
458	293	3	CNAME	vp2.abc.com.edgesuite.net
459	294	3	A	66.117.22.113
460	294	3	A	66.117.22.191
461	294	3	A	66.117.22.190
462	294	3	CNAME	abc.com.sc.omtrdc.net
463	295	3	A	54.190.118.130
464	295	3	A	54.70.112.205
465	295	3	A	52.43.57.102
466	2033	3	A	199.181.134.92
467	254	3	A	99.84.152.6
468	254	3	A	99.84.152.57
469	254	3	A	99.84.152.48
470	254	3	A	99.84.152.104
471	254	3	CNAME	d2vq7wimz061cj.cloudfront.net
472	255	3	A	99.84.152.57
473	255	3	A	99.84.152.48
474	255	3	A	99.84.152.104
475	255	3	A	99.84.152.6
476	255	3	CNAME	d2vq7wimz061cj.cloudfront.net
477	258	3	A	216.198.53.11
478	258	3	A	216.198.54.11
479	258	3	CNAME	supportabc.zendesk.com
480	260	3	A	66.117.22.191
481	260	3	A	66.117.22.113
482	260	3	A	66.117.22.190
483	260	3	CNAME	abc.com.ssl.sc.omtrdc.net
484	299	3	A	13.225.103.54
485	299	3	A	13.225.103.63
486	299	3	A	13.225.103.113
487	299	3	A	13.225.103.38
488	299	3	CNAME	d2iwv1xxkqpmiz.cloudfront.net
489	305	3	A	13.217.182.13
490	305	3	A	54.197.191.132
491	305	3	A	100.49.209.37
492	2072	3	A	49.44.175.16
493	2072	3	A	49.44.175.24
494	2072	3	CNAME	www.datgpodcast.abc.com.edgesuite.net
495	156	3	A	54.197.191.132
496	156	3	A	13.217.182.13
497	156	3	A	100.49.209.37
498	157	3	A	3.33.130.190
499	157	3	A	15.197.148.33
500	158	3	A	34.174.221.135
501	160	3	A	192.195.67.81
502	171	3	A	49.44.95.151
503	171	3	A	49.44.95.143
504	171	3	CNAME	ll-media.seabc.akadns.net
505	172	3	A	100.49.209.37
506	172	3	A	13.217.182.13
507	172	3	A	54.197.191.132
508	238	3	A	35.197.121.119
509	173	3	A	54.70.112.205
510	173	3	A	54.190.118.130
511	173	3	A	52.43.57.102
512	40	3	A	3.175.86.5
513	40	3	A	3.175.86.14
514	40	3	A	3.175.86.50
515	40	3	A	3.175.86.116
516	40	3	CNAME	prod-abc-msh.aws.seabc.go.com
517	55	3	A	100.49.209.37
518	55	3	A	54.197.191.132
519	55	3	A	13.217.182.13
520	98	3	A	75.101.163.207
521	99	3	A	24.144.66.46
522	100	3	A	192.195.67.81
523	102	3	A	52.43.57.102
524	102	3	A	54.190.118.130
525	102	3	A	54.70.112.205
526	102	3	CNAME	abc.go.com
527	103	3	A	151.101.106.137
528	103	3	CNAME	dwtsvote-live-test.votenow.tv
529	104	3	A	151.101.106.217
530	104	3	CNAME	dwtsvote-live.votenow.tv
531	105	3	A	151.101.106.137
532	105	3	CNAME	dwtsvote-test.votenow.tv
533	179	3	A	192.195.67.33
534	180	3	A	68.71.212.241
535	180	3	CNAME	media.abc.go.com
536	181	3	A	40.71.70.250
537	181	3	CNAME	mediapulsepoc2.go.com
538	195	3	A	100.49.209.37
539	195	3	A	54.197.191.132
540	195	3	A	13.217.182.13
541	197	3	A	192.195.63.64
542	198	3	A	3.96.111.237
543	198	3	A	3.96.22.179
544	199	3	A	165.160.15.20
545	199	3	A	165.160.13.20
546	202	3	A	209.34.85.149
547	203	3	A	52.0.158.81
548	203	3	A	3.213.171.250
549	203	3	CNAME	netbox.go.com
550	207	3	A	139.104.232.44
551	207	3	CNAME	nyoffair.go.com
552	208	3	A	100.49.209.37
553	208	3	A	13.217.182.13
554	208	3	A	54.197.191.132
555	253	3	A	18.164.217.122
556	253	3	A	18.164.217.118
557	253	3	A	18.164.217.42
558	253	3	A	18.164.217.16
559	253	3	CNAME	ds0wo5bna2uoo.cloudfront.net
560	213	3	A	108.158.245.6
561	213	3	A	108.158.245.4
562	213	3	A	108.158.245.19
563	213	3	A	108.158.245.18
564	213	3	CNAME	d1wk1so0oejvku.cloudfront.net
565	88	3	A	18.164.237.51
566	88	3	A	18.164.237.7
567	88	3	A	18.164.237.97
568	88	3	A	18.164.237.90
569	88	3	CNAME	d2bret3vw7vy2b.cloudfront.net
570	215	3	A	184.73.202.181
571	215	3	A	3.218.217.30
572	215	3	A	52.44.31.214
573	215	3	CNAME	abc-qa.api.mashery.com
574	218	3	A	204.202.134.76
575	216	3	A	99.86.30.55
576	216	3	A	99.86.30.39
577	216	3	A	99.86.30.107
578	216	3	A	99.86.30.77
579	216	3	CNAME	d2dd9u6m86m0tp.cloudfront.net
580	219	3	A	204.202.134.77
581	220	3	A	204.202.134.78
582	221	3	A	192.195.67.129
\.


--
-- Data for Name: domain_findings; Type: TABLE DATA; Schema: public; Owner: asm
--

COPY public.domain_findings (id, domain_id, scan_id, finding, severity, evidence) FROM stdin;
\.


--
-- Data for Name: domain_ports; Type: TABLE DATA; Schema: public; Owner: asm
--

COPY public.domain_ports (scan_id, domain_id, port, service) FROM stdin;
3	8	80	http
3	8	443	https
3	9	80	http
3	9	443	https
3	21	80	http
3	21	443	https
3	35	80	http
3	35	443	https
3	38	80	http
3	38	443	https
3	39	80	http
3	39	443	https
3	40	80	http
3	40	443	https
3	41	80	http
3	41	443	https
3	52	80	http
3	55	80	http
3	55	443	https
3	58	80	http
3	58	443	https
3	61	80	http
3	61	443	https
3	61	8080	http-proxy
3	61	8443	https-alt
3	65	80	http
3	65	443	https
3	68	80	http
3	68	443	https
3	70	80	http
3	70	443	https
3	71	80	http
3	71	443	https
3	79	80	http
3	79	443	https
3	88	80	http
3	88	443	https
3	90	80	http
3	90	443	https
3	92	80	http
3	92	443	https
3	99	80	http
3	99	443	https
3	102	80	http
3	102	443	https
3	103	80	http
3	103	443	https
3	104	80	http
3	104	443	https
3	105	80	http
3	105	443	https
3	106	80	http
3	106	443	https
3	113	80	http
3	113	443	https
3	122	80	http
3	122	443	https
3	123	80	http
3	123	443	https
3	124	443	https
3	129	80	http
3	129	443	https
3	130	80	http
3	130	443	https
3	139	80	http
3	139	443	https
3	145	80	http
3	152	80	http
3	152	443	https
3	153	80	http
3	153	443	https
3	154	80	http
3	154	443	https
3	156	80	http
3	156	443	https
3	171	80	http
3	171	443	https
3	172	80	http
3	172	443	https
3	173	80	http
3	173	443	https
3	179	80	http
3	179	443	https
3	181	80	http
3	181	443	https
3	195	80	http
3	195	443	https
3	203	80	http
3	203	443	https
3	208	80	http
3	208	443	https
3	213	80	http
3	213	443	https
3	215	80	http
3	215	443	https
3	216	80	http
3	216	443	https
3	221	80	http
3	221	443	https
3	223	80	http
3	223	443	https
3	235	80	http
3	235	443	https
3	253	80	http
3	253	443	https
3	254	80	http
3	254	443	https
3	255	80	http
3	255	443	https
3	258	80	http
3	258	443	https
3	258	8080	http-proxy
3	258	8443	https-alt
3	260	80	http
3	260	443	https
3	288	80	http
3	288	443	https
3	292	443	https
3	293	80	http
3	293	443	https
3	294	80	http
3	294	443	https
3	295	80	http
3	295	443	https
3	299	80	http
3	299	443	https
3	305	80	http
3	305	443	https
3	1686	80	http
3	1686	443	https
3	1884	80	http
3	1884	443	https
3	1938	22	ssh
3	1938	53	domain
3	1938	80	http
3	1938	110	pop3
3	1938	143	imap
3	1938	389	ldap
3	1938	443	https
3	1938	1521	oracle
3	1938	3000	ppp
3	1938	3306	mysql
3	1938	3389	ms-wbt-server
3	1938	5000	upnp
3	1938	5432	postgresql
3	1938	5900	vnc
3	1938	5985	wsman
3	1938	5986	wsmans
3	1938	6379	redis
3	1938	7001	afs3-callback
3	1938	7002	afs3-prserver
3	1938	8000	http-alt
3	1938	8080	http-proxy
3	1938	8443	https-alt
3	1938	8888	sun-answerbook
3	1938	11211	memcache
3	1938	27017	mongod
3	1942	80	http
3	1942	443	https
3	1948	80	http
3	1948	443	https
3	1960	80	http
3	1960	443	https
3	2072	80	http
3	2072	443	https
\.


--
-- Data for Name: domain_provider; Type: TABLE DATA; Schema: public; Owner: asm
--

COPY public.domain_provider (scan_id, domain_id, provider) FROM stdin;
3	8	Other
3	9	Other
3	10	AWS
3	12	Other
3	13	Other
3	14	AWS
3	15	AWS
3	17	AWS
3	20	Other
3	21	AWS
3	22	Other
3	23	AWS
3	24	Other
3	25	Cloudflare
3	27	Other
3	28	AWS
3	29	Other
3	30	AWS
3	31	Other
3	32	Other
3	33	Other
3	34	AWS
3	35	AWS
3	38	AWS
3	39	AWS
3	40	AWS
3	41	AWS
3	52	Other
3	53	Other
3	55	AWS
3	58	AWS
3	60	Other
3	61	Cloudflare
3	62	Other
3	65	AWS
3	68	Other
3	70	Other
3	71	Other
3	79	AWS
3	83	Other
3	86	Other
3	87	Other
3	88	AWS
3	90	AWS
3	92	AWS
3	98	AWS
3	99	Other
3	100	Other
3	102	AWS
3	103	Other
3	104	Other
3	105	Other
3	106	Other
3	112	Other
3	113	AWS
3	120	Other
3	122	Azure
3	123	Azure
3	124	AWS
3	129	Other
3	130	Other
3	136	Other
3	137	Other
3	139	AWS
3	140	Other
3	142	AWS
3	145	AWS
3	146	Other
3	148	Other
3	149	Other
3	150	Other
3	151	Other
3	152	Other
3	153	Other
3	154	AWS
3	156	AWS
3	157	AWS
3	158	GCP
3	160	Other
3	171	Other
3	172	AWS
3	173	AWS
3	179	Other
3	180	Other
3	181	Azure
3	195	AWS
3	197	Other
3	198	AWS
3	199	Other
3	202	Other
3	203	AWS
3	207	Other
3	208	AWS
3	213	AWS
3	215	AWS
3	216	AWS
3	218	Other
3	219	Other
3	220	Other
3	221	Other
3	222	Azure
3	223	AWS
3	235	AWS
3	238	GCP
3	239	Other
3	244	Other
3	253	AWS
3	254	AWS
3	255	AWS
3	258	Cloudflare
3	260	AWS
3	267	AWS
3	268	Other
3	279	Azure
3	280	Azure
3	284	Other
3	285	Other
3	288	Other
3	292	Azure
3	293	Other
3	294	AWS
3	295	AWS
3	299	AWS
3	305	AWS
3	1686	Other
3	1884	AWS
3	1938	Other
3	1942	Other
3	1948	AWS
3	1960	AWS
3	2016	Other
3	2033	Other
3	2072	Other
\.


--
-- Data for Name: domain_risk; Type: TABLE DATA; Schema: public; Owner: asm
--

COPY public.domain_risk (domain_id, scan_id, risk_score, reasons) FROM stdin;
8	3	4	no_http,sensitive_port_exposed,infra_only_exposure
10	3	1	unknown_stack
12	3	1	unknown_stack
13	3	1	unknown_stack
14	3	1	unknown_stack
15	3	1	unknown_stack
17	3	1	unknown_stack
20	3	1	unknown_stack
22	3	1	no_http
23	3	1	unknown_stack
9	3	3	sensitive_port_exposed,web_entrypoint_present
31	3	1	no_http
32	3	1	no_http
35	3	3	sensitive_port_exposed,web_entrypoint_present
38	3	3	sensitive_port_exposed,web_entrypoint_present
58	3	3	sensitive_port_exposed,web_entrypoint_present
1686	3	4	no_http,sensitive_port_exposed,infra_only_exposure
60	3	1	no_http
61	3	3	sensitive_port_exposed,web_entrypoint_present
1884	3	3	sensitive_port_exposed,web_entrypoint_present
39	3	3	sensitive_port_exposed,web_entrypoint_present
79	3	3	sensitive_port_exposed,web_entrypoint_present
41	3	3	sensitive_port_exposed,web_entrypoint_present
62	3	1	no_http
65	3	3	sensitive_port_exposed,web_entrypoint_present
68	3	3	sensitive_port_exposed,web_entrypoint_present
83	3	1	no_http
86	3	1	no_http
87	3	1	no_http
90	3	3	sensitive_port_exposed,web_entrypoint_present
92	3	3	sensitive_port_exposed,web_entrypoint_present
106	3	3	sensitive_port_exposed,web_entrypoint_present
112	3	1	no_http
113	3	3	sensitive_port_exposed,web_entrypoint_present
21	3	3	sensitive_port_exposed,web_entrypoint_present
52	3	4	no_http,sensitive_port_exposed,infra_only_exposure
53	3	1	no_http
24	3	1	unknown_stack
25	3	1	unknown_stack
120	3	1	no_http
122	3	3	sensitive_port_exposed,web_entrypoint_present
123	3	3	sensitive_port_exposed,web_entrypoint_present
124	3	3	sensitive_port_exposed,web_entrypoint_present
129	3	3	sensitive_port_exposed,web_entrypoint_present
130	3	3	sensitive_port_exposed,web_entrypoint_present
136	3	1	no_http
137	3	1	no_http
139	3	3	sensitive_port_exposed,web_entrypoint_present
140	3	1	no_http
145	3	3	sensitive_port_exposed,web_entrypoint_present
146	3	1	no_http
148	3	1	no_http
149	3	1	no_http
150	3	1	no_http
151	3	1	no_http
152	3	3	sensitive_port_exposed,web_entrypoint_present
153	3	3	sensitive_port_exposed,web_entrypoint_present
154	3	3	sensitive_port_exposed,web_entrypoint_present
142	3	1	unknown_stack
27	3	1	unknown_stack
28	3	1	unknown_stack
29	3	1	unknown_stack
30	3	1	unknown_stack
33	3	1	unknown_stack
34	3	1	unknown_stack
70	3	3	sensitive_port_exposed,web_entrypoint_present
71	3	3	sensitive_port_exposed,web_entrypoint_present
222	3	1	no_http
223	3	4	no_http,sensitive_port_exposed,infra_only_exposure
235	3	3	sensitive_port_exposed,web_entrypoint_present
239	3	1	no_http
244	3	1	no_http
1938	3	5	no_http,sensitive_port_exposed,critical_port_exposed,infra_only_exposure,high_risk_unknown_service
1942	3	3	sensitive_port_exposed,web_entrypoint_present
1948	3	3	sensitive_port_exposed,web_entrypoint_present
1960	3	3	sensitive_port_exposed,web_entrypoint_present
2016	3	1	no_http
267	3	1	unknown_stack
268	3	1	unknown_stack
279	3	1	no_http
280	3	1	no_http
284	3	1	no_http
285	3	1	no_http
288	3	3	sensitive_port_exposed,web_entrypoint_present
292	3	3	sensitive_port_exposed,web_entrypoint_present
293	3	3	sensitive_port_exposed,web_entrypoint_present
294	3	3	sensitive_port_exposed,web_entrypoint_present
295	3	3	sensitive_port_exposed,web_entrypoint_present
2033	3	1	no_http
254	3	3	sensitive_port_exposed,web_entrypoint_present
255	3	3	sensitive_port_exposed,web_entrypoint_present
258	3	3	sensitive_port_exposed,web_entrypoint_present
260	3	3	sensitive_port_exposed,web_entrypoint_present
299	3	3	sensitive_port_exposed,web_entrypoint_present
305	3	3	sensitive_port_exposed,web_entrypoint_present
2072	3	3	sensitive_port_exposed,web_entrypoint_present
156	3	3	sensitive_port_exposed,web_entrypoint_present
157	3	1	unknown_stack
158	3	1	unknown_stack
238	3	1	unknown_stack
160	3	1	no_http
171	3	3	sensitive_port_exposed,web_entrypoint_present
172	3	3	sensitive_port_exposed,web_entrypoint_present
173	3	3	sensitive_port_exposed,web_entrypoint_present
40	3	3	sensitive_port_exposed,web_entrypoint_present
55	3	3	sensitive_port_exposed,web_entrypoint_present
98	3	1	no_http
99	3	3	sensitive_port_exposed,web_entrypoint_present
100	3	1	no_http
102	3	3	sensitive_port_exposed,web_entrypoint_present
103	3	3	sensitive_port_exposed,web_entrypoint_present
104	3	3	sensitive_port_exposed,web_entrypoint_present
105	3	3	sensitive_port_exposed,web_entrypoint_present
179	3	3	sensitive_port_exposed,web_entrypoint_present
180	3	1	no_http
181	3	3	sensitive_port_exposed,web_entrypoint_present
195	3	3	sensitive_port_exposed,web_entrypoint_present
198	3	1	unknown_stack
199	3	1	unknown_stack
197	3	1	no_http
202	3	1	no_http
203	3	3	sensitive_port_exposed,web_entrypoint_present
207	3	1	no_http
208	3	3	sensitive_port_exposed,web_entrypoint_present
253	3	3	sensitive_port_exposed,web_entrypoint_present
213	3	3	sensitive_port_exposed,web_entrypoint_present
88	3	3	sensitive_port_exposed,web_entrypoint_present
215	3	3	sensitive_port_exposed,web_entrypoint_present
218	3	1	no_http
216	3	3	sensitive_port_exposed,web_entrypoint_present
219	3	1	no_http
220	3	1	no_http
221	3	3	sensitive_port_exposed,web_entrypoint_present
\.


--
-- Data for Name: domain_san; Type: TABLE DATA; Schema: public; Owner: asm
--

COPY public.domain_san (domain_id, scan_id) FROM stdin;
8	3
9	3
10	3
12	3
13	3
14	3
15	3
17	3
20	3
21	3
22	3
23	3
24	3
25	3
27	3
28	3
29	3
30	3
31	3
32	3
33	3
34	3
35	3
38	3
39	3
40	3
41	3
52	3
53	3
55	3
58	3
60	3
61	3
62	3
65	3
68	3
70	3
71	3
79	3
83	3
86	3
87	3
88	3
90	3
92	3
98	3
99	3
100	3
102	3
103	3
104	3
105	3
106	3
112	3
113	3
120	3
122	3
123	3
124	3
129	3
130	3
136	3
137	3
139	3
140	3
142	3
145	3
146	3
148	3
149	3
150	3
151	3
152	3
153	3
154	3
156	3
157	3
158	3
160	3
171	3
172	3
173	3
179	3
180	3
181	3
195	3
197	3
198	3
199	3
202	3
203	3
207	3
208	3
213	3
215	3
216	3
218	3
219	3
220	3
221	3
222	3
223	3
235	3
238	3
239	3
244	3
253	3
254	3
255	3
258	3
260	3
267	3
268	3
279	3
280	3
284	3
285	3
288	3
292	3
293	3
294	3
295	3
299	3
305	3
1686	3
1884	3
1938	3
1942	3
1948	3
1960	3
2016	3
2033	3
2072	3
1	3
2	3
3	3
4	3
5	3
6	3
7	3
11	3
16	3
18	3
19	3
26	3
36	3
37	3
42	3
43	3
44	3
45	3
46	3
47	3
48	3
49	3
50	3
51	3
54	3
56	3
57	3
59	3
63	3
64	3
66	3
67	3
69	3
72	3
73	3
74	3
75	3
76	3
77	3
78	3
80	3
81	3
82	3
84	3
89	3
91	3
93	3
94	3
95	3
96	3
97	3
107	3
108	3
109	3
110	3
111	3
114	3
115	3
116	3
117	3
118	3
119	3
121	3
126	3
127	3
128	3
131	3
132	3
133	3
134	3
135	3
138	3
141	3
143	3
144	3
147	3
155	3
161	3
162	3
163	3
164	3
165	3
166	3
167	3
168	3
169	3
170	3
174	3
175	3
177	3
178	3
183	3
184	3
185	3
186	3
187	3
188	3
189	3
190	3
191	3
192	3
193	3
194	3
200	3
201	3
204	3
205	3
206	3
209	3
210	3
211	3
212	3
214	3
217	3
224	3
225	3
226	3
227	3
228	3
229	3
230	3
231	3
232	3
233	3
234	3
236	3
237	3
240	3
241	3
242	3
243	3
245	3
246	3
247	3
248	3
249	3
250	3
251	3
252	3
256	3
257	3
259	3
261	3
262	3
264	3
265	3
266	3
269	3
270	3
271	3
272	3
273	3
274	3
275	3
276	3
277	3
278	3
281	3
282	3
283	3
286	3
287	3
289	3
290	3
291	3
296	3
297	3
298	3
303	3
306	3
313	3
314	3
315	3
317	3
320	3
323	3
324	3
325	3
326	3
327	3
328	3
329	3
330	3
331	3
332	3
333	3
334	3
335	3
336	3
337	3
338	3
339	3
340	3
342	3
343	3
344	3
345	3
457	3
530	3
573	3
595	3
596	3
597	3
598	3
599	3
600	3
601	3
602	3
984	3
996	3
998	3
1009	3
1156	3
1291	3
1292	3
1295	3
1296	3
1297	3
1673	3
1679	3
1680	3
1681	3
1682	3
1683	3
1687	3
1694	3
1706	3
1715	3
1716	3
1717	3
1725	3
1731	3
1738	3
1745	3
1753	3
1767	3
1770	3
1771	3
1773	3
1775	3
1777	3
1792	3
1796	3
1820	3
1822	3
1831	3
1842	3
1843	3
1847	3
1849	3
1854	3
1858	3
1859	3
1862	3
1863	3
1864	3
1870	3
1871	3
1875	3
1883	3
1886	3
1889	3
1890	3
1892	3
1893	3
1916	3
1918	3
1923	3
1925	3
1929	3
1930	3
1931	3
1934	3
1935	3
1936	3
1940	3
1943	3
1952	3
1956	3
1965	3
1974	3
1981	3
1982	3
1988	3
1989	3
1996	3
1997	3
1998	3
2004	3
2006	3
2010	3
2013	3
2015	3
2021	3
2022	3
2048	3
2049	3
2051	3
2053	3
2056	3
2057	3
2059	3
2060	3
2061	3
2063	3
2086	3
971	3
4518	3
4519	3
4520	3
4521	3
4522	3
4523	3
4524	3
4525	3
4526	3
4527	3
4528	3
4529	3
4530	3
4531	3
4532	3
4533	3
4534	3
4535	3
4536	3
4537	3
4538	3
4539	3
4540	3
4541	3
4542	3
4543	3
4544	3
4545	3
4546	3
4547	3
4548	3
4549	3
4550	3
4552	3
4553	3
4554	3
4555	3
4556	3
4557	3
4558	3
4559	3
4560	3
4561	3
4563	3
4565	3
4566	3
4567	3
4568	3
4569	3
4570	3
4571	3
4572	3
4573	3
4574	3
4577	3
4579	3
4582	3
4584	3
4585	3
4587	3
4591	3
4592	3
4594	3
4595	3
4596	3
4598	3
4601	3
4603	3
4604	3
4606	3
4611	3
4612	3
4613	3
4614	3
\.


--
-- Data for Name: domain_sources; Type: TABLE DATA; Schema: public; Owner: asm
--

COPY public.domain_sources (domain_id, scan_id, source, seed) FROM stdin;
2	11	brand_pattern	alico.com
3	11	brand_pattern	alico.com
4	11	brand_pattern	alico.com
5	11	brand_pattern	alico.com
6	11	brand_pattern	alico.com
7	11	brand_pattern	alico.com
8	11	brand_tld	alico.com
9	11	brand_tld	alico.com
10	11	brand_tld	alico.com
11	11	brand_tld	alico.com
12	11	findomain	alico.com
12	11	brand_tld	alico.com
12	11	assetfinder	alico.com
13	11	brand_tld	alico.com
14	11	brand_tld	alico.com
15	11	brand_tld	alico.com
16	11	brand_tld	alico.com
17	11	brand_tld	alico.com
18	11	brand_pattern	alico.com
19	11	brand_pattern	alico.com
20	11	brand_pattern	alico.com
21	11	brand_pattern	alico.com
22	11	brand_pattern	alico.com
23	11	brand_pattern	alico.com
24	11	assetfinder	alico.com
24	11	subfinder	alico.com
25	11	assetfinder	alico.com
25	11	subfinder	alico.com
26	11	subfinder	alico.com
27	11	subfinder	alico.com
28	11	assetfinder	alico.com
28	11	subfinder	alico.com
29	11	assetfinder	alico.com
29	11	subfinder	alico.com
30	11	assetfinder	alico.com
30	11	subfinder	alico.com
31	11	assetfinder	alico.com
31	11	findomain	alico.com
31	11	subfinder	alico.com
32	11	assetfinder	alico.com
32	11	subfinder	alico.com
33	11	assetfinder	alico.com
33	11	subfinder	alico.com
34	11	brand_pattern	alico.com
35	11	brand_pattern	alico.com
36	11	brand_pattern	alico.com
37	11	brand_pattern	alico.com
38	11	assetfinder	alico.com
38	11	subfinder	alico.com
39	11	brand_pattern	alico.com
40	11	brand_pattern	alico.com
41	11	assetfinder	alico.com
41	11	subfinder	alico.com
42	11	brand_pattern	alico.com
43	11	subfinder	alico.com
44	11	brand_pattern	alico.com
45	11	brand_pattern	alico.com
46	11	brand_pattern	alico.com
47	11	assetfinder	alico.com
47	11	subfinder	alico.com
48	11	assetfinder	alico.com
48	11	subfinder	alico.com
49	11	assetfinder	alico.com
49	11	subfinder	alico.com
50	11	subfinder	alico.com
51	11	assetfinder	alico.com
51	11	subfinder	alico.com
52	11	assetfinder	alico.com
52	11	subfinder	alico.com
53	11	subfinder	alico.com
55	12	brand_ct	alico.com
56	12	brand_ct	alico.com
57	12	brand_ct	alico.com
58	12	brand_ct	alico.com
59	12	brand_ct	alico.com
60	12	brand_ct	alico.com
61	12	brand_ct	alico.com
62	12	brand_ct	alico.com
63	12	brand_ct	alico.com
2	12	brand_pattern	alico.com
3	12	brand_pattern	alico.com
66	12	brand_ct	alico.com
4	12	brand_pattern	alico.com
5	12	brand_pattern	alico.com
6	12	brand_pattern	alico.com
7	12	brand_pattern	alico.com
8	12	brand_tld	alico.com
9	12	brand_tld	alico.com
10	12	brand_tld	alico.com
11	12	brand_tld	alico.com
12	12	assetfinder	alico.com
12	12	brand_tld	alico.com
13	12	brand_tld	alico.com
14	12	brand_tld	alico.com
15	12	brand_tld	alico.com
16	12	brand_tld	alico.com
80	12	brand_ct	alico.com
17	12	brand_tld	alico.com
18	12	brand_pattern	alico.com
19	12	brand_pattern	alico.com
20	12	brand_pattern	alico.com
21	12	brand_pattern	alico.com
22	12	brand_pattern	alico.com
23	12	brand_pattern	alico.com
88	12	brand_ct	alico.com
24	12	assetfinder	alico.com
24	12	subfinder	alico.com
24	12	findomain	alico.com
25	12	assetfinder	alico.com
25	12	subfinder	alico.com
26	12	subfinder	alico.com
26	12	findomain	alico.com
92	12	brand_ct	alico.com
93	12	brand_ct	alico.com
27	12	subfinder	alico.com
95	12	brand_ct	alico.com
96	12	brand_ct	alico.com
97	12	brand_ct	alico.com
28	12	assetfinder	alico.com
28	12	subfinder	alico.com
99	12	subfinder	alico.com
99	12	findomain	alico.com
100	12	brand_ct	alico.com
29	12	assetfinder	alico.com
29	12	subfinder	alico.com
30	12	assetfinder	alico.com
30	12	subfinder	alico.com
30	12	findomain	alico.com
31	12	assetfinder	alico.com
31	12	subfinder	alico.com
31	12	findomain	alico.com
104	12	brand_ct	alico.com
105	12	brand_ct	alico.com
106	12	subfinder	alico.com
106	12	findomain	alico.com
107	12	brand_ct	alico.com
108	12	brand_ct	alico.com
109	12	brand_ct	alico.com
110	12	brand_ct	alico.com
111	12	brand_ct	alico.com
112	12	brand_ct	alico.com
113	12	brand_ct	alico.com
32	12	assetfinder	alico.com
32	12	subfinder	alico.com
32	12	findomain	alico.com
115	12	subfinder	alico.com
115	12	findomain	alico.com
33	12	assetfinder	alico.com
33	12	subfinder	alico.com
33	12	findomain	alico.com
117	12	subfinder	alico.com
34	12	brand_pattern	alico.com
35	12	brand_pattern	alico.com
36	12	brand_pattern	alico.com
37	12	brand_pattern	alico.com
122	12	subfinder	alico.com
123	12	brand_ct	alico.com
124	12	brand_ct	alico.com
125	12	brand_ct	alico.com
126	12	brand_ct	alico.com
127	12	brand_ct	alico.com
128	12	brand_ct	alico.com
129	12	brand_ct	alico.com
38	12	assetfinder	alico.com
38	12	subfinder	alico.com
39	12	brand_pattern	alico.com
40	12	brand_pattern	alico.com
41	12	assetfinder	alico.com
41	12	subfinder	alico.com
134	12	subfinder	alico.com
134	12	findomain	alico.com
135	12	subfinder	alico.com
135	12	findomain	alico.com
136	12	brand_ct	alico.com
137	12	subfinder	alico.com
137	12	findomain	alico.com
42	12	brand_pattern	alico.com
43	12	subfinder	alico.com
43	12	findomain	alico.com
44	12	brand_pattern	alico.com
141	12	subfinder	alico.com
141	12	findomain	alico.com
142	12	subfinder	alico.com
142	12	findomain	alico.com
143	12	subfinder	alico.com
143	12	findomain	alico.com
144	12	brand_ct	alico.com
145	12	subfinder	alico.com
145	12	findomain	alico.com
146	12	subfinder	alico.com
146	12	findomain	alico.com
147	12	subfinder	alico.com
148	12	brand_ct	alico.com
149	12	subfinder	alico.com
149	12	findomain	alico.com
150	12	subfinder	alico.com
150	12	findomain	alico.com
151	12	subfinder	alico.com
151	12	findomain	alico.com
45	12	brand_pattern	alico.com
46	12	brand_pattern	alico.com
154	12	subfinder	alico.com
155	12	brand_ct	alico.com
47	12	assetfinder	alico.com
47	12	subfinder	alico.com
47	12	findomain	alico.com
48	12	assetfinder	alico.com
48	12	subfinder	alico.com
48	12	findomain	alico.com
49	12	assetfinder	alico.com
49	12	subfinder	alico.com
49	12	findomain	alico.com
159	12	brand_ct	alico.com
160	12	brand_ct	alico.com
50	12	subfinder	alico.com
162	12	brand_ct	alico.com
163	12	brand_ct	alico.com
164	12	brand_ct	alico.com
165	12	brand_ct	alico.com
51	12	assetfinder	alico.com
51	12	subfinder	alico.com
52	12	assetfinder	alico.com
52	12	subfinder	alico.com
168	12	brand_ct	alico.com
169	12	brand_ct	alico.com
170	12	brand_ct	alico.com
53	12	subfinder	alico.com
55	13	brand_ct	alico.com
56	13	brand_ct	alico.com
57	13	brand_ct	alico.com
58	13	brand_ct	alico.com
59	13	brand_ct	alico.com
60	13	brand_ct	alico.com
61	13	brand_ct	alico.com
62	13	brand_ct	alico.com
63	13	brand_ct	alico.com
2	13	brand_pattern	alico.com
3	13	brand_pattern	alico.com
66	13	brand_ct	alico.com
4	13	brand_pattern	alico.com
5	13	brand_pattern	alico.com
6	13	brand_pattern	alico.com
7	13	brand_pattern	alico.com
8	13	brand_tld	alico.com
9	13	brand_tld	alico.com
10	13	brand_tld	alico.com
11	13	brand_tld	alico.com
12	13	assetfinder	alico.com
12	13	brand_tld	alico.com
12	13	findomain	alico.com
13	13	brand_tld	alico.com
14	13	brand_tld	alico.com
15	13	brand_tld	alico.com
16	13	brand_tld	alico.com
80	13	brand_ct	alico.com
17	13	brand_tld	alico.com
18	13	brand_pattern	alico.com
19	13	brand_pattern	alico.com
20	13	brand_pattern	alico.com
21	13	brand_pattern	alico.com
22	13	brand_pattern	alico.com
23	13	brand_pattern	alico.com
88	13	brand_ct	alico.com
24	13	assetfinder	alico.com
24	13	subfinder	alico.com
24	13	findomain	alico.com
25	13	assetfinder	alico.com
25	13	subfinder	alico.com
26	13	assetfinder	alico.com
26	13	subfinder	alico.com
26	13	findomain	alico.com
92	13	brand_ct	alico.com
93	13	brand_ct	alico.com
27	13	assetfinder	alico.com
27	13	subfinder	alico.com
95	13	brand_ct	alico.com
96	13	brand_ct	alico.com
97	13	brand_ct	alico.com
218	13	assetfinder	alico.com
219	13	assetfinder	alico.com
28	13	assetfinder	alico.com
28	13	subfinder	alico.com
99	13	assetfinder	alico.com
99	13	subfinder	alico.com
99	13	findomain	alico.com
100	13	brand_ct	alico.com
29	13	assetfinder	alico.com
29	13	subfinder	alico.com
30	13	assetfinder	alico.com
30	13	subfinder	alico.com
30	13	findomain	alico.com
31	13	assetfinder	alico.com
31	13	subfinder	alico.com
31	13	findomain	alico.com
104	13	brand_ct	alico.com
105	13	brand_ct	alico.com
106	13	assetfinder	alico.com
106	13	subfinder	alico.com
106	13	findomain	alico.com
107	13	brand_ct	alico.com
108	13	brand_ct	alico.com
109	13	brand_ct	alico.com
110	13	brand_ct	alico.com
111	13	brand_ct	alico.com
112	13	brand_ct	alico.com
113	13	brand_ct	alico.com
32	13	assetfinder	alico.com
32	13	subfinder	alico.com
32	13	findomain	alico.com
115	13	assetfinder	alico.com
115	13	subfinder	alico.com
115	13	findomain	alico.com
33	13	assetfinder	alico.com
33	13	subfinder	alico.com
33	13	findomain	alico.com
117	13	assetfinder	alico.com
117	13	subfinder	alico.com
34	13	brand_pattern	alico.com
35	13	brand_pattern	alico.com
36	13	brand_pattern	alico.com
37	13	brand_pattern	alico.com
122	13	assetfinder	alico.com
122	13	subfinder	alico.com
123	13	brand_ct	alico.com
124	13	brand_ct	alico.com
125	13	brand_ct	alico.com
126	13	brand_ct	alico.com
127	13	brand_ct	alico.com
128	13	brand_ct	alico.com
251	13	assetfinder	alico.com
129	13	brand_ct	alico.com
38	13	assetfinder	alico.com
38	13	subfinder	alico.com
39	13	brand_pattern	alico.com
40	13	brand_pattern	alico.com
41	13	assetfinder	alico.com
41	13	subfinder	alico.com
134	13	assetfinder	alico.com
134	13	subfinder	alico.com
134	13	findomain	alico.com
135	13	assetfinder	alico.com
135	13	subfinder	alico.com
135	13	findomain	alico.com
136	13	brand_ct	alico.com
137	13	assetfinder	alico.com
137	13	subfinder	alico.com
137	13	findomain	alico.com
42	13	brand_pattern	alico.com
43	13	assetfinder	alico.com
43	13	subfinder	alico.com
43	13	findomain	alico.com
44	13	brand_pattern	alico.com
141	13	assetfinder	alico.com
141	13	subfinder	alico.com
141	13	findomain	alico.com
142	13	assetfinder	alico.com
142	13	subfinder	alico.com
142	13	findomain	alico.com
143	13	assetfinder	alico.com
143	13	subfinder	alico.com
143	13	findomain	alico.com
144	13	brand_ct	alico.com
145	13	assetfinder	alico.com
145	13	subfinder	alico.com
145	13	findomain	alico.com
146	13	assetfinder	alico.com
146	13	subfinder	alico.com
146	13	findomain	alico.com
147	13	subfinder	alico.com
148	13	brand_ct	alico.com
149	13	assetfinder	alico.com
149	13	subfinder	alico.com
149	13	findomain	alico.com
150	13	assetfinder	alico.com
150	13	subfinder	alico.com
150	13	findomain	alico.com
151	13	assetfinder	alico.com
151	13	subfinder	alico.com
151	13	findomain	alico.com
45	13	brand_pattern	alico.com
46	13	brand_pattern	alico.com
154	13	assetfinder	alico.com
154	13	subfinder	alico.com
155	13	brand_ct	alico.com
47	13	assetfinder	alico.com
47	13	subfinder	alico.com
47	13	findomain	alico.com
48	13	assetfinder	alico.com
48	13	subfinder	alico.com
48	13	findomain	alico.com
49	13	assetfinder	alico.com
49	13	subfinder	alico.com
49	13	findomain	alico.com
159	13	brand_ct	alico.com
160	13	brand_ct	alico.com
50	13	subfinder	alico.com
162	13	brand_ct	alico.com
163	13	brand_ct	alico.com
164	13	brand_ct	alico.com
165	13	brand_ct	alico.com
51	13	assetfinder	alico.com
51	13	subfinder	alico.com
52	13	assetfinder	alico.com
52	13	subfinder	alico.com
168	13	brand_ct	alico.com
169	13	brand_ct	alico.com
170	13	brand_ct	alico.com
53	13	subfinder	alico.com
55	14	brand_ct	alico.com
56	14	brand_ct	alico.com
57	14	brand_ct	alico.com
58	14	brand_ct	alico.com
59	14	brand_ct	alico.com
60	14	brand_ct	alico.com
61	14	brand_ct	alico.com
62	14	brand_ct	alico.com
63	14	brand_ct	alico.com
2	14	brand_pattern	alico.com
3	14	brand_pattern	alico.com
66	14	brand_ct	alico.com
4	14	brand_pattern	alico.com
5	14	brand_pattern	alico.com
6	14	brand_pattern	alico.com
7	14	brand_pattern	alico.com
8	14	brand_tld	alico.com
9	14	brand_tld	alico.com
10	14	brand_tld	alico.com
11	14	brand_tld	alico.com
12	14	findomain	alico.com
12	14	assetfinder	alico.com
12	14	brand_tld	alico.com
13	14	brand_tld	alico.com
14	14	brand_tld	alico.com
15	14	brand_tld	alico.com
16	14	brand_tld	alico.com
80	14	brand_ct	alico.com
17	14	brand_tld	alico.com
18	14	brand_pattern	alico.com
19	14	brand_pattern	alico.com
20	14	brand_pattern	alico.com
21	14	brand_pattern	alico.com
22	14	brand_pattern	alico.com
23	14	brand_pattern	alico.com
88	14	brand_ct	alico.com
24	14	findomain	alico.com
24	14	assetfinder	alico.com
24	14	subfinder	alico.com
25	14	assetfinder	alico.com
25	14	subfinder	alico.com
26	14	findomain	alico.com
26	14	assetfinder	alico.com
26	14	subfinder	alico.com
92	14	brand_ct	alico.com
93	14	brand_ct	alico.com
27	14	assetfinder	alico.com
27	14	subfinder	alico.com
95	14	brand_ct	alico.com
96	14	brand_ct	alico.com
97	14	brand_ct	alico.com
218	14	assetfinder	alico.com
219	14	assetfinder	alico.com
28	14	assetfinder	alico.com
28	14	subfinder	alico.com
99	14	findomain	alico.com
99	14	assetfinder	alico.com
99	14	subfinder	alico.com
100	14	brand_ct	alico.com
29	14	assetfinder	alico.com
29	14	subfinder	alico.com
30	14	findomain	alico.com
30	14	assetfinder	alico.com
30	14	subfinder	alico.com
31	14	findomain	alico.com
31	14	assetfinder	alico.com
31	14	subfinder	alico.com
104	14	brand_ct	alico.com
105	14	brand_ct	alico.com
106	14	findomain	alico.com
106	14	assetfinder	alico.com
106	14	subfinder	alico.com
107	14	brand_ct	alico.com
108	14	brand_ct	alico.com
109	14	brand_ct	alico.com
110	14	brand_ct	alico.com
111	14	brand_ct	alico.com
112	14	brand_ct	alico.com
113	14	brand_ct	alico.com
32	14	findomain	alico.com
32	14	assetfinder	alico.com
32	14	subfinder	alico.com
115	14	findomain	alico.com
115	14	assetfinder	alico.com
115	14	subfinder	alico.com
33	14	findomain	alico.com
33	14	assetfinder	alico.com
33	14	subfinder	alico.com
117	14	assetfinder	alico.com
117	14	subfinder	alico.com
34	14	brand_pattern	alico.com
35	14	brand_pattern	alico.com
36	14	brand_pattern	alico.com
37	14	brand_pattern	alico.com
122	14	assetfinder	alico.com
122	14	subfinder	alico.com
123	14	brand_ct	alico.com
124	14	brand_ct	alico.com
125	14	brand_ct	alico.com
126	14	brand_ct	alico.com
127	14	brand_ct	alico.com
128	14	brand_ct	alico.com
251	14	assetfinder	alico.com
129	14	brand_ct	alico.com
38	14	assetfinder	alico.com
38	14	subfinder	alico.com
39	14	brand_pattern	alico.com
40	14	brand_pattern	alico.com
41	14	assetfinder	alico.com
41	14	subfinder	alico.com
134	14	findomain	alico.com
134	14	assetfinder	alico.com
134	14	subfinder	alico.com
135	14	findomain	alico.com
135	14	assetfinder	alico.com
135	14	subfinder	alico.com
136	14	brand_ct	alico.com
137	14	findomain	alico.com
137	14	assetfinder	alico.com
137	14	subfinder	alico.com
42	14	brand_pattern	alico.com
43	14	findomain	alico.com
43	14	assetfinder	alico.com
43	14	subfinder	alico.com
44	14	brand_pattern	alico.com
141	14	findomain	alico.com
141	14	assetfinder	alico.com
141	14	subfinder	alico.com
142	14	findomain	alico.com
142	14	assetfinder	alico.com
142	14	subfinder	alico.com
143	14	findomain	alico.com
143	14	assetfinder	alico.com
143	14	subfinder	alico.com
144	14	brand_ct	alico.com
145	14	findomain	alico.com
145	14	assetfinder	alico.com
145	14	subfinder	alico.com
146	14	findomain	alico.com
146	14	assetfinder	alico.com
146	14	subfinder	alico.com
147	14	subfinder	alico.com
148	14	brand_ct	alico.com
149	14	findomain	alico.com
149	14	assetfinder	alico.com
149	14	subfinder	alico.com
150	14	findomain	alico.com
150	14	assetfinder	alico.com
150	14	subfinder	alico.com
151	14	findomain	alico.com
151	14	assetfinder	alico.com
151	14	subfinder	alico.com
45	14	brand_pattern	alico.com
46	14	brand_pattern	alico.com
154	14	assetfinder	alico.com
154	14	subfinder	alico.com
155	14	brand_ct	alico.com
47	14	findomain	alico.com
47	14	assetfinder	alico.com
47	14	subfinder	alico.com
48	14	findomain	alico.com
48	14	assetfinder	alico.com
48	14	subfinder	alico.com
49	14	findomain	alico.com
49	14	assetfinder	alico.com
49	14	subfinder	alico.com
159	14	brand_ct	alico.com
160	14	brand_ct	alico.com
50	14	subfinder	alico.com
162	14	brand_ct	alico.com
163	14	brand_ct	alico.com
164	14	brand_ct	alico.com
165	14	brand_ct	alico.com
51	14	assetfinder	alico.com
51	14	subfinder	alico.com
52	14	assetfinder	alico.com
52	14	subfinder	alico.com
168	14	brand_ct	alico.com
169	14	brand_ct	alico.com
170	14	brand_ct	alico.com
53	14	subfinder	alico.com
55	15	brand_ct	alico.com
56	15	brand_ct	alico.com
57	15	brand_ct	alico.com
58	15	brand_ct	alico.com
59	15	brand_ct	alico.com
60	15	brand_ct	alico.com
61	15	brand_ct	alico.com
62	15	brand_ct	alico.com
63	15	brand_ct	alico.com
2	15	brand_pattern	alico.com
3	15	brand_pattern	alico.com
66	15	brand_ct	alico.com
4	15	brand_pattern	alico.com
5	15	brand_pattern	alico.com
6	15	brand_pattern	alico.com
7	15	brand_pattern	alico.com
8	15	brand_tld	alico.com
9	15	brand_tld	alico.com
10	15	brand_tld	alico.com
11	15	brand_tld	alico.com
12	15	findomain	alico.com
12	15	brand_tld	alico.com
12	15	assetfinder	alico.com
13	15	brand_tld	alico.com
14	15	brand_tld	alico.com
15	15	brand_tld	alico.com
16	15	brand_tld	alico.com
80	15	brand_ct	alico.com
17	15	brand_tld	alico.com
18	15	brand_pattern	alico.com
19	15	brand_pattern	alico.com
20	15	brand_pattern	alico.com
21	15	brand_pattern	alico.com
22	15	brand_pattern	alico.com
23	15	brand_pattern	alico.com
88	15	brand_ct	alico.com
24	15	subfinder	alico.com
24	15	findomain	alico.com
24	15	assetfinder	alico.com
25	15	subfinder	alico.com
25	15	assetfinder	alico.com
26	15	subfinder	alico.com
26	15	findomain	alico.com
92	15	brand_ct	alico.com
93	15	brand_ct	alico.com
27	15	subfinder	alico.com
95	15	brand_ct	alico.com
96	15	brand_ct	alico.com
97	15	brand_ct	alico.com
28	15	subfinder	alico.com
28	15	assetfinder	alico.com
99	15	subfinder	alico.com
99	15	findomain	alico.com
100	15	brand_ct	alico.com
29	15	subfinder	alico.com
29	15	assetfinder	alico.com
30	15	subfinder	alico.com
30	15	findomain	alico.com
30	15	assetfinder	alico.com
31	15	subfinder	alico.com
31	15	findomain	alico.com
31	15	assetfinder	alico.com
104	15	brand_ct	alico.com
105	15	brand_ct	alico.com
106	15	subfinder	alico.com
106	15	findomain	alico.com
107	15	brand_ct	alico.com
108	15	brand_ct	alico.com
109	15	brand_ct	alico.com
110	15	brand_ct	alico.com
111	15	brand_ct	alico.com
112	15	brand_ct	alico.com
113	15	brand_ct	alico.com
32	15	subfinder	alico.com
32	15	findomain	alico.com
32	15	assetfinder	alico.com
115	15	subfinder	alico.com
115	15	findomain	alico.com
33	15	subfinder	alico.com
33	15	findomain	alico.com
33	15	assetfinder	alico.com
117	15	subfinder	alico.com
34	15	brand_pattern	alico.com
35	15	brand_pattern	alico.com
36	15	brand_pattern	alico.com
37	15	brand_pattern	alico.com
122	15	subfinder	alico.com
123	15	brand_ct	alico.com
124	15	brand_ct	alico.com
125	15	brand_ct	alico.com
126	15	brand_ct	alico.com
127	15	brand_ct	alico.com
128	15	brand_ct	alico.com
129	15	brand_ct	alico.com
38	15	subfinder	alico.com
38	15	assetfinder	alico.com
39	15	brand_pattern	alico.com
40	15	brand_pattern	alico.com
41	15	subfinder	alico.com
41	15	assetfinder	alico.com
134	15	subfinder	alico.com
134	15	findomain	alico.com
135	15	subfinder	alico.com
135	15	findomain	alico.com
136	15	brand_ct	alico.com
137	15	subfinder	alico.com
137	15	findomain	alico.com
42	15	brand_pattern	alico.com
43	15	subfinder	alico.com
43	15	findomain	alico.com
44	15	brand_pattern	alico.com
141	15	subfinder	alico.com
141	15	findomain	alico.com
142	15	subfinder	alico.com
142	15	findomain	alico.com
143	15	subfinder	alico.com
143	15	findomain	alico.com
144	15	brand_ct	alico.com
145	15	subfinder	alico.com
145	15	findomain	alico.com
146	15	subfinder	alico.com
146	15	findomain	alico.com
147	15	subfinder	alico.com
148	15	brand_ct	alico.com
149	15	subfinder	alico.com
149	15	findomain	alico.com
150	15	subfinder	alico.com
150	15	findomain	alico.com
151	15	subfinder	alico.com
151	15	findomain	alico.com
45	15	brand_pattern	alico.com
46	15	brand_pattern	alico.com
154	15	subfinder	alico.com
155	15	brand_ct	alico.com
47	15	subfinder	alico.com
47	15	findomain	alico.com
47	15	assetfinder	alico.com
48	15	subfinder	alico.com
48	15	findomain	alico.com
48	15	assetfinder	alico.com
49	15	subfinder	alico.com
49	15	findomain	alico.com
49	15	assetfinder	alico.com
159	15	brand_ct	alico.com
160	15	brand_ct	alico.com
50	15	subfinder	alico.com
162	15	brand_ct	alico.com
163	15	brand_ct	alico.com
164	15	brand_ct	alico.com
165	15	brand_ct	alico.com
51	15	subfinder	alico.com
51	15	assetfinder	alico.com
52	15	subfinder	alico.com
52	15	assetfinder	alico.com
168	15	brand_ct	alico.com
169	15	brand_ct	alico.com
170	15	brand_ct	alico.com
53	15	subfinder	alico.com
55	16	brand_ct	alico.com
56	16	brand_ct	alico.com
57	16	brand_ct	alico.com
58	16	brand_ct	alico.com
59	16	brand_ct	alico.com
60	16	brand_ct	alico.com
61	16	brand_ct	alico.com
62	16	brand_ct	alico.com
63	16	brand_ct	alico.com
2	16	brand_pattern	alico.com
3	16	brand_pattern	alico.com
66	16	brand_ct	alico.com
4	16	brand_pattern	alico.com
5	16	brand_pattern	alico.com
6	16	brand_pattern	alico.com
7	16	brand_pattern	alico.com
8	16	brand_tld	alico.com
9	16	brand_tld	alico.com
10	16	brand_tld	alico.com
11	16	brand_tld	alico.com
12	16	brand_tld	alico.com
12	16	assetfinder	alico.com
13	16	brand_tld	alico.com
14	16	brand_tld	alico.com
15	16	brand_tld	alico.com
16	16	brand_tld	alico.com
80	16	brand_ct	alico.com
17	16	brand_tld	alico.com
18	16	brand_pattern	alico.com
19	16	brand_pattern	alico.com
20	16	brand_pattern	alico.com
21	16	brand_pattern	alico.com
22	16	brand_pattern	alico.com
23	16	brand_pattern	alico.com
88	16	brand_ct	alico.com
24	16	subfinder	alico.com
24	16	assetfinder	alico.com
24	16	findomain	alico.com
25	16	subfinder	alico.com
25	16	assetfinder	alico.com
26	16	subfinder	alico.com
26	16	assetfinder	alico.com
26	16	findomain	alico.com
92	16	brand_ct	alico.com
93	16	brand_ct	alico.com
27	16	subfinder	alico.com
27	16	assetfinder	alico.com
95	16	brand_ct	alico.com
96	16	brand_ct	alico.com
97	16	brand_ct	alico.com
218	16	assetfinder	alico.com
219	16	assetfinder	alico.com
28	16	subfinder	alico.com
28	16	assetfinder	alico.com
99	16	subfinder	alico.com
99	16	assetfinder	alico.com
99	16	findomain	alico.com
100	16	brand_ct	alico.com
29	16	subfinder	alico.com
29	16	assetfinder	alico.com
30	16	subfinder	alico.com
30	16	assetfinder	alico.com
30	16	findomain	alico.com
31	16	subfinder	alico.com
31	16	assetfinder	alico.com
31	16	findomain	alico.com
104	16	brand_ct	alico.com
105	16	brand_ct	alico.com
106	16	subfinder	alico.com
106	16	assetfinder	alico.com
106	16	findomain	alico.com
107	16	brand_ct	alico.com
108	16	brand_ct	alico.com
109	16	brand_ct	alico.com
110	16	brand_ct	alico.com
111	16	brand_ct	alico.com
112	16	brand_ct	alico.com
113	16	brand_ct	alico.com
32	16	subfinder	alico.com
32	16	assetfinder	alico.com
32	16	findomain	alico.com
115	16	subfinder	alico.com
115	16	assetfinder	alico.com
115	16	findomain	alico.com
33	16	subfinder	alico.com
33	16	assetfinder	alico.com
33	16	findomain	alico.com
117	16	subfinder	alico.com
117	16	assetfinder	alico.com
34	16	brand_pattern	alico.com
35	16	brand_pattern	alico.com
36	16	brand_pattern	alico.com
37	16	brand_pattern	alico.com
122	16	subfinder	alico.com
122	16	assetfinder	alico.com
123	16	brand_ct	alico.com
124	16	brand_ct	alico.com
125	16	brand_ct	alico.com
126	16	brand_ct	alico.com
127	16	brand_ct	alico.com
128	16	brand_ct	alico.com
251	16	assetfinder	alico.com
129	16	brand_ct	alico.com
38	16	subfinder	alico.com
38	16	assetfinder	alico.com
39	16	brand_pattern	alico.com
40	16	brand_pattern	alico.com
41	16	subfinder	alico.com
41	16	assetfinder	alico.com
134	16	subfinder	alico.com
134	16	assetfinder	alico.com
134	16	findomain	alico.com
135	16	subfinder	alico.com
135	16	assetfinder	alico.com
135	16	findomain	alico.com
136	16	brand_ct	alico.com
137	16	subfinder	alico.com
137	16	assetfinder	alico.com
137	16	findomain	alico.com
42	16	brand_pattern	alico.com
43	16	subfinder	alico.com
43	16	assetfinder	alico.com
43	16	findomain	alico.com
44	16	brand_pattern	alico.com
141	16	subfinder	alico.com
141	16	assetfinder	alico.com
141	16	findomain	alico.com
142	16	subfinder	alico.com
142	16	assetfinder	alico.com
142	16	findomain	alico.com
143	16	subfinder	alico.com
143	16	assetfinder	alico.com
143	16	findomain	alico.com
144	16	brand_ct	alico.com
145	16	subfinder	alico.com
145	16	assetfinder	alico.com
145	16	findomain	alico.com
146	16	subfinder	alico.com
146	16	assetfinder	alico.com
146	16	findomain	alico.com
147	16	subfinder	alico.com
148	16	brand_ct	alico.com
149	16	subfinder	alico.com
149	16	assetfinder	alico.com
149	16	findomain	alico.com
150	16	subfinder	alico.com
150	16	assetfinder	alico.com
150	16	findomain	alico.com
151	16	subfinder	alico.com
151	16	assetfinder	alico.com
151	16	findomain	alico.com
45	16	brand_pattern	alico.com
46	16	brand_pattern	alico.com
154	16	subfinder	alico.com
154	16	assetfinder	alico.com
155	16	brand_ct	alico.com
47	16	subfinder	alico.com
47	16	assetfinder	alico.com
47	16	findomain	alico.com
48	16	subfinder	alico.com
48	16	assetfinder	alico.com
48	16	findomain	alico.com
49	16	subfinder	alico.com
49	16	assetfinder	alico.com
49	16	findomain	alico.com
159	16	brand_ct	alico.com
160	16	brand_ct	alico.com
50	16	subfinder	alico.com
162	16	brand_ct	alico.com
163	16	brand_ct	alico.com
164	16	brand_ct	alico.com
165	16	brand_ct	alico.com
51	16	subfinder	alico.com
51	16	assetfinder	alico.com
52	16	subfinder	alico.com
52	16	assetfinder	alico.com
168	16	brand_ct	alico.com
169	16	brand_ct	alico.com
170	16	brand_ct	alico.com
53	16	subfinder	alico.com
55	17	brand_ct	alico.com
56	17	brand_ct	alico.com
57	17	brand_ct	alico.com
58	17	brand_ct	alico.com
59	17	brand_ct	alico.com
60	17	brand_ct	alico.com
61	17	brand_ct	alico.com
62	17	brand_ct	alico.com
63	17	brand_ct	alico.com
2	17	brand_pattern	alico.com
3	17	brand_pattern	alico.com
66	17	brand_ct	alico.com
4	17	brand_pattern	alico.com
5	17	brand_pattern	alico.com
6	17	brand_pattern	alico.com
7	17	brand_pattern	alico.com
8	17	brand_tld	alico.com
9	17	brand_tld	alico.com
10	17	brand_tld	alico.com
11	17	brand_tld	alico.com
12	17	findomain	alico.com
12	17	brand_tld	alico.com
12	17	assetfinder	alico.com
13	17	brand_tld	alico.com
14	17	brand_tld	alico.com
15	17	brand_tld	alico.com
16	17	brand_tld	alico.com
80	17	brand_ct	alico.com
17	17	brand_tld	alico.com
18	17	brand_pattern	alico.com
19	17	brand_pattern	alico.com
20	17	brand_pattern	alico.com
21	17	brand_pattern	alico.com
22	17	brand_pattern	alico.com
23	17	brand_pattern	alico.com
88	17	brand_ct	alico.com
24	17	subfinder	alico.com
24	17	findomain	alico.com
24	17	assetfinder	alico.com
25	17	subfinder	alico.com
25	17	assetfinder	alico.com
26	17	subfinder	alico.com
26	17	findomain	alico.com
26	17	assetfinder	alico.com
92	17	brand_ct	alico.com
93	17	brand_ct	alico.com
27	17	subfinder	alico.com
27	17	assetfinder	alico.com
95	17	brand_ct	alico.com
96	17	brand_ct	alico.com
97	17	brand_ct	alico.com
218	17	assetfinder	alico.com
219	17	assetfinder	alico.com
28	17	subfinder	alico.com
28	17	assetfinder	alico.com
99	17	subfinder	alico.com
99	17	findomain	alico.com
99	17	assetfinder	alico.com
100	17	brand_ct	alico.com
29	17	subfinder	alico.com
29	17	assetfinder	alico.com
30	17	subfinder	alico.com
30	17	findomain	alico.com
30	17	assetfinder	alico.com
31	17	subfinder	alico.com
31	17	findomain	alico.com
31	17	assetfinder	alico.com
104	17	brand_ct	alico.com
105	17	brand_ct	alico.com
106	17	subfinder	alico.com
106	17	findomain	alico.com
106	17	assetfinder	alico.com
107	17	brand_ct	alico.com
108	17	brand_ct	alico.com
109	17	brand_ct	alico.com
110	17	brand_ct	alico.com
111	17	brand_ct	alico.com
112	17	brand_ct	alico.com
113	17	brand_ct	alico.com
32	17	subfinder	alico.com
32	17	findomain	alico.com
32	17	assetfinder	alico.com
115	17	subfinder	alico.com
115	17	findomain	alico.com
115	17	assetfinder	alico.com
33	17	subfinder	alico.com
33	17	findomain	alico.com
33	17	assetfinder	alico.com
117	17	subfinder	alico.com
117	17	assetfinder	alico.com
34	17	brand_pattern	alico.com
35	17	brand_pattern	alico.com
36	17	brand_pattern	alico.com
37	17	brand_pattern	alico.com
122	17	subfinder	alico.com
122	17	assetfinder	alico.com
123	17	brand_ct	alico.com
124	17	brand_ct	alico.com
125	17	brand_ct	alico.com
126	17	brand_ct	alico.com
127	17	brand_ct	alico.com
128	17	brand_ct	alico.com
251	17	assetfinder	alico.com
129	17	brand_ct	alico.com
38	17	subfinder	alico.com
38	17	assetfinder	alico.com
39	17	brand_pattern	alico.com
40	17	brand_pattern	alico.com
41	17	subfinder	alico.com
41	17	assetfinder	alico.com
134	17	subfinder	alico.com
134	17	findomain	alico.com
134	17	assetfinder	alico.com
135	17	subfinder	alico.com
135	17	findomain	alico.com
135	17	assetfinder	alico.com
136	17	brand_ct	alico.com
137	17	subfinder	alico.com
137	17	findomain	alico.com
137	17	assetfinder	alico.com
42	17	brand_pattern	alico.com
43	17	subfinder	alico.com
43	17	findomain	alico.com
43	17	assetfinder	alico.com
44	17	brand_pattern	alico.com
141	17	subfinder	alico.com
141	17	findomain	alico.com
141	17	assetfinder	alico.com
142	17	subfinder	alico.com
142	17	findomain	alico.com
142	17	assetfinder	alico.com
143	17	subfinder	alico.com
143	17	findomain	alico.com
143	17	assetfinder	alico.com
144	17	brand_ct	alico.com
145	17	subfinder	alico.com
145	17	findomain	alico.com
145	17	assetfinder	alico.com
146	17	subfinder	alico.com
146	17	findomain	alico.com
146	17	assetfinder	alico.com
147	17	subfinder	alico.com
148	17	brand_ct	alico.com
149	17	subfinder	alico.com
149	17	findomain	alico.com
149	17	assetfinder	alico.com
150	17	subfinder	alico.com
150	17	findomain	alico.com
150	17	assetfinder	alico.com
151	17	subfinder	alico.com
151	17	findomain	alico.com
151	17	assetfinder	alico.com
45	17	brand_pattern	alico.com
46	17	brand_pattern	alico.com
154	17	subfinder	alico.com
154	17	assetfinder	alico.com
155	17	brand_ct	alico.com
47	17	subfinder	alico.com
47	17	findomain	alico.com
47	17	assetfinder	alico.com
48	17	subfinder	alico.com
48	17	findomain	alico.com
48	17	assetfinder	alico.com
49	17	subfinder	alico.com
49	17	findomain	alico.com
49	17	assetfinder	alico.com
159	17	brand_ct	alico.com
160	17	brand_ct	alico.com
50	17	subfinder	alico.com
162	17	brand_ct	alico.com
163	17	brand_ct	alico.com
164	17	brand_ct	alico.com
165	17	brand_ct	alico.com
51	17	subfinder	alico.com
51	17	assetfinder	alico.com
52	17	subfinder	alico.com
52	17	assetfinder	alico.com
168	17	brand_ct	alico.com
169	17	brand_ct	alico.com
170	17	brand_ct	alico.com
53	17	subfinder	alico.com
55	18	brand_ct	alico.com
56	18	brand_ct	alico.com
57	18	brand_ct	alico.com
58	18	brand_ct	alico.com
59	18	brand_ct	alico.com
60	18	brand_ct	alico.com
61	18	brand_ct	alico.com
62	18	brand_ct	alico.com
63	18	brand_ct	alico.com
2	18	brand_pattern	alico.com
3	18	brand_pattern	alico.com
66	18	brand_ct	alico.com
4	18	brand_pattern	alico.com
5	18	brand_pattern	alico.com
6	18	brand_pattern	alico.com
7	18	brand_pattern	alico.com
8	18	brand_tld	alico.com
9	18	brand_tld	alico.com
10	18	brand_tld	alico.com
11	18	brand_tld	alico.com
12	18	brand_tld	alico.com
12	18	findomain	alico.com
12	18	assetfinder	alico.com
13	18	brand_tld	alico.com
14	18	brand_tld	alico.com
15	18	brand_tld	alico.com
16	18	brand_tld	alico.com
80	18	brand_ct	alico.com
17	18	brand_tld	alico.com
18	18	brand_pattern	alico.com
19	18	brand_pattern	alico.com
20	18	brand_pattern	alico.com
21	18	brand_pattern	alico.com
22	18	brand_pattern	alico.com
23	18	brand_pattern	alico.com
88	18	brand_ct	alico.com
24	18	findomain	alico.com
24	18	assetfinder	alico.com
24	18	subfinder	alico.com
25	18	assetfinder	alico.com
25	18	subfinder	alico.com
26	18	findomain	alico.com
26	18	subfinder	alico.com
92	18	brand_ct	alico.com
93	18	brand_ct	alico.com
27	18	subfinder	alico.com
95	18	brand_ct	alico.com
96	18	brand_ct	alico.com
97	18	brand_ct	alico.com
28	18	assetfinder	alico.com
28	18	subfinder	alico.com
99	18	findomain	alico.com
100	18	brand_ct	alico.com
29	18	assetfinder	alico.com
29	18	subfinder	alico.com
30	18	findomain	alico.com
30	18	assetfinder	alico.com
30	18	subfinder	alico.com
31	18	findomain	alico.com
31	18	assetfinder	alico.com
31	18	subfinder	alico.com
104	18	brand_ct	alico.com
105	18	brand_ct	alico.com
106	18	findomain	alico.com
107	18	brand_ct	alico.com
108	18	brand_ct	alico.com
109	18	brand_ct	alico.com
110	18	brand_ct	alico.com
111	18	brand_ct	alico.com
112	18	brand_ct	alico.com
113	18	brand_ct	alico.com
32	18	findomain	alico.com
32	18	assetfinder	alico.com
32	18	subfinder	alico.com
115	18	findomain	alico.com
33	18	findomain	alico.com
33	18	assetfinder	alico.com
33	18	subfinder	alico.com
34	18	brand_pattern	alico.com
35	18	brand_pattern	alico.com
36	18	brand_pattern	alico.com
37	18	brand_pattern	alico.com
123	18	brand_ct	alico.com
124	18	brand_ct	alico.com
125	18	brand_ct	alico.com
126	18	brand_ct	alico.com
127	18	brand_ct	alico.com
128	18	brand_ct	alico.com
129	18	brand_ct	alico.com
38	18	assetfinder	alico.com
38	18	subfinder	alico.com
39	18	brand_pattern	alico.com
40	18	brand_pattern	alico.com
41	18	assetfinder	alico.com
41	18	subfinder	alico.com
134	18	findomain	alico.com
135	18	findomain	alico.com
136	18	brand_ct	alico.com
137	18	findomain	alico.com
42	18	brand_pattern	alico.com
43	18	findomain	alico.com
43	18	subfinder	alico.com
44	18	brand_pattern	alico.com
141	18	findomain	alico.com
142	18	findomain	alico.com
143	18	findomain	alico.com
144	18	brand_ct	alico.com
145	18	findomain	alico.com
146	18	findomain	alico.com
148	18	brand_ct	alico.com
149	18	findomain	alico.com
150	18	findomain	alico.com
151	18	findomain	alico.com
45	18	brand_pattern	alico.com
46	18	brand_pattern	alico.com
155	18	brand_ct	alico.com
47	18	findomain	alico.com
47	18	assetfinder	alico.com
47	18	subfinder	alico.com
48	18	findomain	alico.com
48	18	assetfinder	alico.com
48	18	subfinder	alico.com
49	18	findomain	alico.com
49	18	assetfinder	alico.com
49	18	subfinder	alico.com
159	18	brand_ct	alico.com
160	18	brand_ct	alico.com
50	18	subfinder	alico.com
162	18	brand_ct	alico.com
163	18	brand_ct	alico.com
164	18	brand_ct	alico.com
165	18	brand_ct	alico.com
51	18	assetfinder	alico.com
51	18	subfinder	alico.com
52	18	assetfinder	alico.com
52	18	subfinder	alico.com
168	18	brand_ct	alico.com
169	18	brand_ct	alico.com
170	18	brand_ct	alico.com
53	18	subfinder	alico.com
902	21	subfinder	sigmamind.ai
902	21	assetfinder	sigmamind.ai
903	21	subfinder	sigmamind.ai
903	21	assetfinder	sigmamind.ai
903	21	findomain	sigmamind.ai
904	21	subfinder	sigmamind.ai
904	21	assetfinder	sigmamind.ai
904	21	findomain	sigmamind.ai
905	21	subfinder	sigmamind.ai
905	21	assetfinder	sigmamind.ai
905	21	findomain	sigmamind.ai
906	21	brand_pattern	sigmamind.ai
907	21	brand_pattern	sigmamind.ai
908	21	brand_pattern	sigmamind.ai
909	21	brand_pattern	sigmamind.ai
910	21	subfinder	sigmamind.ai
910	21	findomain	sigmamind.ai
911	21	brand_pattern	sigmamind.ai
912	21	brand_pattern	sigmamind.ai
913	21	subfinder	sigmamind.ai
913	21	assetfinder	sigmamind.ai
913	21	findomain	sigmamind.ai
914	21	brand_pattern	sigmamind.ai
915	21	brand_pattern	sigmamind.ai
916	21	brand_pattern	sigmamind.ai
917	21	brand_pattern	sigmamind.ai
918	21	brand_pattern	sigmamind.ai
919	21	brand_pattern	sigmamind.ai
920	21	brand_pattern	sigmamind.ai
921	21	brand_pattern	sigmamind.ai
922	21	brand_tld	sigmamind.ai
922	21	assetfinder	sigmamind.ai
922	21	findomain	sigmamind.ai
923	21	brand_tld	sigmamind.ai
924	21	brand_tld	sigmamind.ai
925	21	brand_tld	sigmamind.ai
926	21	brand_tld	sigmamind.ai
927	21	brand_tld	sigmamind.ai
928	21	brand_tld	sigmamind.ai
929	21	brand_tld	sigmamind.ai
930	21	brand_tld	sigmamind.ai
931	21	brand_tld	sigmamind.ai
932	21	brand_pattern	sigmamind.ai
933	21	brand_pattern	sigmamind.ai
934	21	brand_pattern	sigmamind.ai
935	21	brand_pattern	sigmamind.ai
936	21	brand_pattern	sigmamind.ai
937	21	brand_pattern	sigmamind.ai
938	21	brand_pattern	sigmamind.ai
939	21	brand_pattern	sigmamind.ai
940	21	subfinder	sigmamind.ai
940	21	findomain	sigmamind.ai
941	21	subfinder	sigmamind.ai
941	21	assetfinder	sigmamind.ai
941	21	findomain	sigmamind.ai
1	1	subfinder	sigmamind.ai
1	1	assetfinder	sigmamind.ai
2	1	findomain	sigmamind.ai
2	1	subfinder	sigmamind.ai
2	1	assetfinder	sigmamind.ai
3	1	findomain	sigmamind.ai
3	1	subfinder	sigmamind.ai
3	1	assetfinder	sigmamind.ai
4	1	findomain	sigmamind.ai
4	1	subfinder	sigmamind.ai
4	1	assetfinder	sigmamind.ai
5	1	brand_pattern	sigmamind.ai
6	1	brand_pattern	sigmamind.ai
7	1	brand_pattern	sigmamind.ai
8	1	brand_pattern	sigmamind.ai
9	1	findomain	sigmamind.ai
9	1	subfinder	sigmamind.ai
10	1	brand_pattern	sigmamind.ai
11	1	brand_pattern	sigmamind.ai
12	1	findomain	sigmamind.ai
12	1	subfinder	sigmamind.ai
12	1	assetfinder	sigmamind.ai
13	1	brand_pattern	sigmamind.ai
14	1	brand_pattern	sigmamind.ai
15	1	brand_pattern	sigmamind.ai
16	1	brand_pattern	sigmamind.ai
17	1	brand_pattern	sigmamind.ai
18	1	brand_pattern	sigmamind.ai
19	1	brand_pattern	sigmamind.ai
20	1	brand_pattern	sigmamind.ai
21	1	findomain	sigmamind.ai
21	1	brand_tld	sigmamind.ai
21	1	assetfinder	sigmamind.ai
22	1	brand_tld	sigmamind.ai
23	1	brand_tld	sigmamind.ai
24	1	brand_tld	sigmamind.ai
25	1	brand_tld	sigmamind.ai
26	1	brand_tld	sigmamind.ai
27	1	brand_tld	sigmamind.ai
28	1	brand_tld	sigmamind.ai
29	1	brand_tld	sigmamind.ai
30	1	brand_tld	sigmamind.ai
31	1	brand_pattern	sigmamind.ai
32	1	brand_pattern	sigmamind.ai
33	1	brand_pattern	sigmamind.ai
34	1	brand_pattern	sigmamind.ai
35	1	brand_pattern	sigmamind.ai
36	1	brand_pattern	sigmamind.ai
37	1	brand_pattern	sigmamind.ai
38	1	brand_pattern	sigmamind.ai
39	1	findomain	sigmamind.ai
39	1	subfinder	sigmamind.ai
40	1	findomain	sigmamind.ai
40	1	subfinder	sigmamind.ai
40	1	assetfinder	sigmamind.ai
43	2	assetfinder	xyz
44	2	assetfinder	xyz
45	2	assetfinder	xyz
46	2	assetfinder	xyz
47	2	assetfinder	xyz
48	2	assetfinder	xyz
49	2	assetfinder	xyz
50	2	assetfinder	xyz
51	2	assetfinder	xyz
52	2	assetfinder	xyz
53	2	assetfinder	xyz
54	2	assetfinder	xyz
55	2	assetfinder	xyz
56	2	assetfinder	xyz
57	2	assetfinder	xyz
58	2	assetfinder	xyz
59	2	assetfinder	xyz
60	2	assetfinder	xyz
61	2	assetfinder	xyz
62	2	assetfinder	xyz
63	2	assetfinder	xyz
64	2	assetfinder	xyz
65	2	assetfinder	xyz
66	2	assetfinder	xyz
67	2	assetfinder	xyz
68	2	assetfinder	xyz
69	2	assetfinder	xyz
70	2	assetfinder	xyz
71	2	assetfinder	xyz
72	2	assetfinder	xyz
73	2	assetfinder	xyz
74	2	assetfinder	xyz
75	2	assetfinder	xyz
76	2	assetfinder	xyz
77	2	assetfinder	xyz
78	2	assetfinder	xyz
79	2	assetfinder	xyz
80	2	assetfinder	xyz
81	2	assetfinder	xyz
82	2	assetfinder	xyz
83	2	assetfinder	xyz
84	2	assetfinder	xyz
85	2	assetfinder	xyz
86	2	assetfinder	xyz
87	2	assetfinder	xyz
88	2	assetfinder	xyz
89	2	assetfinder	xyz
90	2	assetfinder	xyz
91	2	assetfinder	xyz
92	2	assetfinder	xyz
93	2	assetfinder	xyz
94	2	assetfinder	xyz
95	2	assetfinder	xyz
96	2	assetfinder	xyz
97	2	assetfinder	xyz
98	2	assetfinder	xyz
99	2	assetfinder	xyz
100	2	assetfinder	xyz
101	2	assetfinder	xyz
102	2	assetfinder	xyz
103	2	assetfinder	xyz
104	2	assetfinder	xyz
105	2	assetfinder	xyz
106	2	assetfinder	xyz
107	2	assetfinder	xyz
108	2	assetfinder	xyz
109	2	assetfinder	xyz
110	2	assetfinder	xyz
111	2	assetfinder	xyz
112	2	assetfinder	xyz
113	2	assetfinder	xyz
114	2	assetfinder	xyz
115	2	assetfinder	xyz
116	2	assetfinder	xyz
117	2	assetfinder	xyz
118	2	assetfinder	xyz
119	2	assetfinder	xyz
120	2	assetfinder	xyz
121	2	assetfinder	xyz
122	2	assetfinder	xyz
123	2	assetfinder	xyz
124	2	assetfinder	xyz
125	2	assetfinder	xyz
126	2	assetfinder	xyz
127	2	assetfinder	xyz
128	2	assetfinder	xyz
129	2	assetfinder	xyz
130	2	assetfinder	xyz
131	2	assetfinder	xyz
132	2	assetfinder	xyz
133	2	assetfinder	xyz
134	2	assetfinder	xyz
135	2	assetfinder	xyz
136	2	assetfinder	xyz
137	2	assetfinder	xyz
138	2	assetfinder	xyz
139	2	assetfinder	xyz
140	2	assetfinder	xyz
141	2	assetfinder	xyz
142	2	assetfinder	xyz
143	2	assetfinder	xyz
144	2	assetfinder	xyz
145	2	assetfinder	xyz
146	2	assetfinder	xyz
147	2	assetfinder	xyz
148	2	assetfinder	xyz
149	2	assetfinder	xyz
150	2	assetfinder	xyz
151	2	assetfinder	xyz
152	2	assetfinder	xyz
153	2	assetfinder	xyz
154	2	assetfinder	xyz
155	2	assetfinder	xyz
156	2	assetfinder	xyz
157	2	assetfinder	xyz
158	2	assetfinder	xyz
159	2	assetfinder	xyz
160	2	assetfinder	xyz
161	2	assetfinder	xyz
162	2	assetfinder	xyz
163	2	assetfinder	xyz
164	2	assetfinder	xyz
165	2	assetfinder	xyz
166	2	assetfinder	xyz
167	2	assetfinder	xyz
168	2	assetfinder	xyz
169	2	assetfinder	xyz
170	2	assetfinder	xyz
171	2	assetfinder	xyz
172	2	assetfinder	xyz
173	2	assetfinder	xyz
174	2	assetfinder	xyz
175	2	assetfinder	xyz
176	2	assetfinder	xyz
177	2	assetfinder	xyz
178	2	assetfinder	xyz
179	2	assetfinder	xyz
180	2	assetfinder	xyz
181	2	assetfinder	xyz
182	2	assetfinder	xyz
183	2	assetfinder	xyz
184	2	assetfinder	xyz
185	2	assetfinder	xyz
186	2	assetfinder	xyz
187	2	assetfinder	xyz
188	2	assetfinder	xyz
189	2	assetfinder	xyz
190	2	assetfinder	xyz
191	2	assetfinder	xyz
192	2	assetfinder	xyz
193	2	assetfinder	xyz
194	2	assetfinder	xyz
195	2	assetfinder	xyz
196	2	assetfinder	xyz
197	2	assetfinder	xyz
198	2	assetfinder	xyz
199	2	assetfinder	xyz
200	2	assetfinder	xyz
201	2	assetfinder	xyz
202	2	assetfinder	xyz
203	2	assetfinder	xyz
204	2	assetfinder	xyz
205	2	assetfinder	xyz
206	2	assetfinder	xyz
207	2	assetfinder	xyz
208	2	assetfinder	xyz
209	2	assetfinder	xyz
210	2	assetfinder	xyz
211	2	assetfinder	xyz
212	2	assetfinder	xyz
213	2	assetfinder	xyz
214	2	assetfinder	xyz
215	2	assetfinder	xyz
216	2	assetfinder	xyz
217	2	assetfinder	xyz
218	2	assetfinder	xyz
219	2	assetfinder	xyz
220	2	assetfinder	xyz
221	2	assetfinder	xyz
222	2	assetfinder	xyz
223	2	assetfinder	xyz
224	2	assetfinder	xyz
225	2	assetfinder	xyz
226	2	assetfinder	xyz
227	2	assetfinder	xyz
228	2	assetfinder	xyz
229	2	assetfinder	xyz
230	2	assetfinder	xyz
231	2	assetfinder	xyz
232	2	assetfinder	xyz
233	2	assetfinder	xyz
234	2	assetfinder	xyz
235	2	assetfinder	xyz
236	2	assetfinder	xyz
237	2	assetfinder	xyz
238	2	assetfinder	xyz
239	2	assetfinder	xyz
240	2	assetfinder	xyz
241	2	assetfinder	xyz
242	2	assetfinder	xyz
243	2	assetfinder	xyz
244	2	assetfinder	xyz
245	2	assetfinder	xyz
246	2	assetfinder	xyz
247	2	assetfinder	xyz
248	2	assetfinder	xyz
249	2	assetfinder	xyz
250	2	assetfinder	xyz
251	2	assetfinder	xyz
252	2	assetfinder	xyz
253	2	assetfinder	xyz
254	2	assetfinder	xyz
255	2	assetfinder	xyz
256	2	assetfinder	xyz
257	2	assetfinder	xyz
258	2	assetfinder	xyz
259	2	assetfinder	xyz
260	2	assetfinder	xyz
261	2	assetfinder	xyz
262	2	assetfinder	xyz
263	2	assetfinder	xyz
264	2	assetfinder	xyz
265	2	assetfinder	xyz
266	2	assetfinder	xyz
267	2	assetfinder	xyz
268	2	assetfinder	xyz
269	2	assetfinder	xyz
270	2	assetfinder	xyz
271	2	assetfinder	xyz
272	2	assetfinder	xyz
273	2	assetfinder	xyz
274	2	assetfinder	xyz
275	2	assetfinder	xyz
276	2	assetfinder	xyz
277	2	assetfinder	xyz
278	2	assetfinder	xyz
279	2	assetfinder	xyz
280	2	assetfinder	xyz
281	2	assetfinder	xyz
282	2	assetfinder	xyz
283	2	assetfinder	xyz
284	2	assetfinder	xyz
285	2	assetfinder	xyz
286	2	assetfinder	xyz
287	2	assetfinder	xyz
288	2	assetfinder	xyz
289	2	assetfinder	xyz
290	2	assetfinder	xyz
291	2	assetfinder	xyz
292	2	assetfinder	xyz
293	2	assetfinder	xyz
294	2	assetfinder	xyz
295	2	assetfinder	xyz
296	2	assetfinder	xyz
297	2	assetfinder	xyz
298	2	assetfinder	xyz
299	2	assetfinder	xyz
300	2	assetfinder	xyz
301	2	assetfinder	xyz
302	2	assetfinder	xyz
303	2	assetfinder	xyz
304	2	assetfinder	xyz
305	2	assetfinder	xyz
306	2	assetfinder	xyz
307	2	assetfinder	xyz
308	2	assetfinder	xyz
309	2	assetfinder	xyz
310	2	assetfinder	xyz
311	2	assetfinder	xyz
312	2	assetfinder	xyz
313	2	assetfinder	xyz
314	2	assetfinder	xyz
315	2	assetfinder	xyz
316	2	assetfinder	xyz
317	2	assetfinder	xyz
318	2	assetfinder	xyz
319	2	assetfinder	xyz
320	2	assetfinder	xyz
321	2	assetfinder	xyz
322	2	assetfinder	xyz
323	2	assetfinder	xyz
324	2	assetfinder	xyz
325	2	assetfinder	xyz
326	2	assetfinder	xyz
327	2	assetfinder	xyz
328	2	assetfinder	xyz
329	2	assetfinder	xyz
330	2	assetfinder	xyz
331	2	assetfinder	xyz
332	2	assetfinder	xyz
333	2	assetfinder	xyz
334	2	assetfinder	xyz
335	2	assetfinder	xyz
336	2	assetfinder	xyz
337	2	assetfinder	xyz
338	2	assetfinder	xyz
339	2	assetfinder	xyz
340	2	assetfinder	xyz
341	2	assetfinder	xyz
342	2	assetfinder	xyz
343	2	assetfinder	xyz
344	2	assetfinder	xyz
345	2	assetfinder	xyz
346	2	assetfinder	xyz
347	2	assetfinder	xyz
348	2	assetfinder	xyz
349	2	assetfinder	xyz
350	2	assetfinder	xyz
351	2	assetfinder	xyz
352	2	assetfinder	xyz
353	2	assetfinder	xyz
354	2	assetfinder	xyz
355	2	assetfinder	xyz
356	2	assetfinder	xyz
357	2	assetfinder	xyz
358	2	assetfinder	xyz
359	2	assetfinder	xyz
360	2	assetfinder	xyz
361	2	assetfinder	xyz
362	2	assetfinder	xyz
363	2	assetfinder	xyz
364	2	assetfinder	xyz
365	2	assetfinder	xyz
366	2	assetfinder	xyz
367	2	assetfinder	xyz
368	2	assetfinder	xyz
369	2	assetfinder	xyz
370	2	assetfinder	xyz
371	2	assetfinder	xyz
372	2	assetfinder	xyz
373	2	assetfinder	xyz
374	2	assetfinder	xyz
375	2	assetfinder	xyz
376	2	assetfinder	xyz
377	2	assetfinder	xyz
378	2	assetfinder	xyz
379	2	assetfinder	xyz
380	2	assetfinder	xyz
381	2	assetfinder	xyz
382	2	assetfinder	xyz
383	2	assetfinder	xyz
384	2	assetfinder	xyz
385	2	assetfinder	xyz
386	2	assetfinder	xyz
387	2	assetfinder	xyz
388	2	assetfinder	xyz
389	2	assetfinder	xyz
390	2	assetfinder	xyz
391	2	assetfinder	xyz
392	2	assetfinder	xyz
393	2	assetfinder	xyz
394	2	assetfinder	xyz
395	2	assetfinder	xyz
396	2	assetfinder	xyz
397	2	assetfinder	xyz
398	2	assetfinder	xyz
399	2	assetfinder	xyz
400	2	assetfinder	xyz
401	2	assetfinder	xyz
402	2	assetfinder	xyz
403	2	assetfinder	xyz
404	2	assetfinder	xyz
405	2	assetfinder	xyz
406	2	assetfinder	xyz
407	2	assetfinder	xyz
408	2	assetfinder	xyz
409	2	assetfinder	xyz
410	2	assetfinder	xyz
411	2	assetfinder	xyz
412	2	assetfinder	xyz
413	2	assetfinder	xyz
414	2	assetfinder	xyz
415	2	assetfinder	xyz
416	2	assetfinder	xyz
417	2	assetfinder	xyz
418	2	assetfinder	xyz
419	2	assetfinder	xyz
420	2	assetfinder	xyz
421	2	assetfinder	xyz
422	2	assetfinder	xyz
423	2	assetfinder	xyz
424	2	assetfinder	xyz
425	2	assetfinder	xyz
426	2	assetfinder	xyz
427	2	assetfinder	xyz
428	2	assetfinder	xyz
429	2	assetfinder	xyz
430	2	assetfinder	xyz
431	2	assetfinder	xyz
432	2	assetfinder	xyz
433	2	assetfinder	xyz
434	2	assetfinder	xyz
435	2	assetfinder	xyz
436	2	assetfinder	xyz
437	2	assetfinder	xyz
438	2	assetfinder	xyz
439	2	assetfinder	xyz
440	2	assetfinder	xyz
441	2	assetfinder	xyz
442	2	assetfinder	xyz
443	2	assetfinder	xyz
444	2	assetfinder	xyz
445	2	assetfinder	xyz
446	2	assetfinder	xyz
447	2	assetfinder	xyz
448	2	assetfinder	xyz
449	2	assetfinder	xyz
450	2	assetfinder	xyz
451	2	assetfinder	xyz
452	2	assetfinder	xyz
453	2	assetfinder	xyz
454	2	assetfinder	xyz
455	2	assetfinder	xyz
456	2	assetfinder	xyz
457	2	assetfinder	xyz
458	2	assetfinder	xyz
459	2	assetfinder	xyz
460	2	assetfinder	xyz
461	2	assetfinder	xyz
462	2	assetfinder	xyz
463	2	assetfinder	xyz
464	2	assetfinder	xyz
465	2	assetfinder	xyz
466	2	assetfinder	xyz
467	2	assetfinder	xyz
468	2	assetfinder	xyz
469	2	assetfinder	xyz
470	2	assetfinder	xyz
471	2	assetfinder	xyz
472	2	assetfinder	xyz
473	2	assetfinder	xyz
474	2	assetfinder	xyz
475	2	assetfinder	xyz
476	2	assetfinder	xyz
477	2	assetfinder	xyz
478	2	assetfinder	xyz
479	2	assetfinder	xyz
480	2	assetfinder	xyz
481	2	assetfinder	xyz
482	2	assetfinder	xyz
483	2	assetfinder	xyz
484	2	assetfinder	xyz
485	2	assetfinder	xyz
486	2	assetfinder	xyz
487	2	assetfinder	xyz
488	2	assetfinder	xyz
489	2	assetfinder	xyz
490	2	assetfinder	xyz
491	2	assetfinder	xyz
492	2	assetfinder	xyz
493	2	assetfinder	xyz
494	2	assetfinder	xyz
495	2	assetfinder	xyz
496	2	assetfinder	xyz
497	2	assetfinder	xyz
498	2	assetfinder	xyz
499	2	assetfinder	xyz
500	2	assetfinder	xyz
501	2	assetfinder	xyz
502	2	assetfinder	xyz
503	2	assetfinder	xyz
504	2	assetfinder	xyz
505	2	assetfinder	xyz
506	2	assetfinder	xyz
507	2	assetfinder	xyz
508	2	assetfinder	xyz
509	2	assetfinder	xyz
510	2	assetfinder	xyz
511	2	assetfinder	xyz
512	2	assetfinder	xyz
513	2	assetfinder	xyz
514	2	assetfinder	xyz
515	2	assetfinder	xyz
516	2	assetfinder	xyz
517	2	assetfinder	xyz
518	2	assetfinder	xyz
519	2	assetfinder	xyz
520	2	assetfinder	xyz
521	2	assetfinder	xyz
522	2	assetfinder	xyz
523	2	assetfinder	xyz
524	2	assetfinder	xyz
525	2	assetfinder	xyz
526	2	assetfinder	xyz
527	2	assetfinder	xyz
528	2	assetfinder	xyz
529	2	assetfinder	xyz
530	2	assetfinder	xyz
531	2	assetfinder	xyz
532	2	assetfinder	xyz
533	2	assetfinder	xyz
534	2	assetfinder	xyz
535	2	assetfinder	xyz
536	2	assetfinder	xyz
537	2	assetfinder	xyz
538	2	assetfinder	xyz
539	2	assetfinder	xyz
540	2	assetfinder	xyz
541	2	assetfinder	xyz
542	2	assetfinder	xyz
543	2	assetfinder	xyz
544	2	assetfinder	xyz
545	2	assetfinder	xyz
546	2	assetfinder	xyz
547	2	assetfinder	xyz
548	2	assetfinder	xyz
549	2	assetfinder	xyz
550	2	assetfinder	xyz
551	2	assetfinder	xyz
552	2	assetfinder	xyz
553	2	assetfinder	xyz
554	2	assetfinder	xyz
555	2	assetfinder	xyz
556	2	assetfinder	xyz
557	2	assetfinder	xyz
558	2	assetfinder	xyz
559	2	assetfinder	xyz
560	2	assetfinder	xyz
561	2	assetfinder	xyz
562	2	assetfinder	xyz
563	2	assetfinder	xyz
564	2	assetfinder	xyz
565	2	assetfinder	xyz
566	2	assetfinder	xyz
567	2	assetfinder	xyz
568	2	assetfinder	xyz
569	2	assetfinder	xyz
570	2	assetfinder	xyz
571	2	assetfinder	xyz
572	2	assetfinder	xyz
573	2	assetfinder	xyz
574	2	assetfinder	xyz
575	2	assetfinder	xyz
576	2	assetfinder	xyz
577	2	assetfinder	xyz
578	2	assetfinder	xyz
579	2	assetfinder	xyz
580	2	assetfinder	xyz
581	2	assetfinder	xyz
582	2	assetfinder	xyz
583	2	assetfinder	xyz
584	2	assetfinder	xyz
585	2	assetfinder	xyz
586	2	assetfinder	xyz
587	2	assetfinder	xyz
588	2	assetfinder	xyz
589	2	assetfinder	xyz
590	2	assetfinder	xyz
591	2	assetfinder	xyz
592	2	assetfinder	xyz
593	2	assetfinder	xyz
594	2	assetfinder	xyz
595	2	assetfinder	xyz
596	2	assetfinder	xyz
597	2	assetfinder	xyz
598	2	assetfinder	xyz
599	2	assetfinder	xyz
600	2	assetfinder	xyz
601	2	assetfinder	xyz
602	2	assetfinder	xyz
603	2	assetfinder	xyz
604	2	assetfinder	xyz
605	2	assetfinder	xyz
606	2	assetfinder	xyz
607	2	assetfinder	xyz
608	2	assetfinder	xyz
609	2	assetfinder	xyz
610	2	assetfinder	xyz
611	2	assetfinder	xyz
612	2	assetfinder	xyz
613	2	assetfinder	xyz
614	2	assetfinder	xyz
615	2	assetfinder	xyz
616	2	assetfinder	xyz
617	2	assetfinder	xyz
618	2	assetfinder	xyz
619	2	assetfinder	xyz
620	2	assetfinder	xyz
621	2	assetfinder	xyz
622	2	assetfinder	xyz
623	2	assetfinder	xyz
624	2	assetfinder	xyz
625	2	assetfinder	xyz
626	2	assetfinder	xyz
627	2	assetfinder	xyz
628	2	assetfinder	xyz
629	2	assetfinder	xyz
630	2	assetfinder	xyz
631	2	assetfinder	xyz
632	2	assetfinder	xyz
633	2	assetfinder	xyz
634	2	assetfinder	xyz
635	2	assetfinder	xyz
636	2	assetfinder	xyz
637	2	assetfinder	xyz
638	2	assetfinder	xyz
639	2	assetfinder	xyz
640	2	assetfinder	xyz
641	2	assetfinder	xyz
642	2	assetfinder	xyz
643	2	assetfinder	xyz
644	2	assetfinder	xyz
645	2	assetfinder	xyz
646	2	assetfinder	xyz
647	2	assetfinder	xyz
648	2	assetfinder	xyz
649	2	assetfinder	xyz
650	2	assetfinder	xyz
651	2	assetfinder	xyz
652	2	assetfinder	xyz
653	2	assetfinder	xyz
654	2	assetfinder	xyz
655	2	assetfinder	xyz
656	2	assetfinder	xyz
657	2	assetfinder	xyz
658	2	assetfinder	xyz
659	2	assetfinder	xyz
660	2	assetfinder	xyz
661	2	assetfinder	xyz
662	2	assetfinder	xyz
663	2	assetfinder	xyz
664	2	assetfinder	xyz
665	2	assetfinder	xyz
666	2	assetfinder	xyz
667	2	assetfinder	xyz
668	2	assetfinder	xyz
669	2	assetfinder	xyz
670	2	assetfinder	xyz
671	2	assetfinder	xyz
672	2	assetfinder	xyz
673	2	assetfinder	xyz
674	2	assetfinder	xyz
675	2	assetfinder	xyz
676	2	assetfinder	xyz
677	2	assetfinder	xyz
678	2	assetfinder	xyz
679	2	assetfinder	xyz
680	2	assetfinder	xyz
681	2	assetfinder	xyz
682	2	assetfinder	xyz
683	2	assetfinder	xyz
684	2	assetfinder	xyz
685	2	assetfinder	xyz
686	2	assetfinder	xyz
687	2	assetfinder	xyz
688	2	assetfinder	xyz
689	2	assetfinder	xyz
690	2	assetfinder	xyz
691	2	assetfinder	xyz
692	2	assetfinder	xyz
693	2	assetfinder	xyz
694	2	assetfinder	xyz
695	2	assetfinder	xyz
696	2	assetfinder	xyz
697	2	assetfinder	xyz
698	2	assetfinder	xyz
699	2	assetfinder	xyz
700	2	assetfinder	xyz
700	2	subfinder	xyz
701	2	assetfinder	xyz
701	2	subfinder	xyz
702	2	assetfinder	xyz
702	2	subfinder	xyz
703	2	assetfinder	xyz
703	2	subfinder	xyz
704	2	assetfinder	xyz
704	2	subfinder	xyz
705	2	assetfinder	xyz
705	2	subfinder	xyz
706	2	assetfinder	xyz
706	2	subfinder	xyz
707	2	assetfinder	xyz
707	2	subfinder	xyz
708	2	assetfinder	xyz
708	2	subfinder	xyz
709	2	assetfinder	xyz
709	2	subfinder	xyz
710	2	assetfinder	xyz
710	2	subfinder	xyz
711	2	assetfinder	xyz
711	2	subfinder	xyz
712	2	assetfinder	xyz
712	2	subfinder	xyz
713	2	assetfinder	xyz
713	2	subfinder	xyz
714	2	assetfinder	xyz
714	2	subfinder	xyz
715	2	assetfinder	xyz
715	2	subfinder	xyz
716	2	assetfinder	xyz
716	2	subfinder	xyz
717	2	assetfinder	xyz
717	2	subfinder	xyz
718	2	assetfinder	xyz
718	2	subfinder	xyz
719	2	assetfinder	xyz
719	2	subfinder	xyz
720	2	assetfinder	xyz
720	2	subfinder	xyz
721	2	assetfinder	xyz
721	2	subfinder	xyz
722	2	assetfinder	xyz
722	2	subfinder	xyz
723	2	assetfinder	xyz
723	2	subfinder	xyz
724	2	assetfinder	xyz
724	2	subfinder	xyz
724	2	brand_ct	xyz
725	2	assetfinder	xyz
725	2	subfinder	xyz
725	2	brand_ct	xyz
726	2	assetfinder	xyz
726	2	subfinder	xyz
726	2	brand_ct	xyz
727	2	assetfinder	xyz
727	2	subfinder	xyz
727	2	brand_ct	xyz
728	2	assetfinder	xyz
728	2	subfinder	xyz
728	2	brand_ct	xyz
729	2	assetfinder	xyz
729	2	subfinder	xyz
729	2	brand_ct	xyz
730	2	assetfinder	xyz
730	2	subfinder	xyz
730	2	brand_ct	xyz
731	2	assetfinder	xyz
731	2	subfinder	xyz
731	2	brand_ct	xyz
732	2	assetfinder	xyz
732	2	subfinder	xyz
732	2	brand_ct	xyz
733	2	assetfinder	xyz
733	2	subfinder	xyz
733	2	brand_ct	xyz
734	2	assetfinder	xyz
734	2	subfinder	xyz
734	2	brand_ct	xyz
735	2	assetfinder	xyz
735	2	subfinder	xyz
735	2	brand_ct	xyz
736	2	assetfinder	xyz
736	2	subfinder	xyz
736	2	brand_ct	xyz
737	2	assetfinder	xyz
737	2	subfinder	xyz
737	2	brand_ct	xyz
738	2	assetfinder	xyz
738	2	subfinder	xyz
738	2	brand_ct	xyz
739	2	assetfinder	xyz
739	2	subfinder	xyz
739	2	brand_ct	xyz
740	2	assetfinder	xyz
740	2	subfinder	xyz
740	2	brand_ct	xyz
741	2	assetfinder	xyz
741	2	subfinder	xyz
741	2	brand_ct	xyz
742	2	assetfinder	xyz
742	2	subfinder	xyz
742	2	brand_ct	xyz
743	2	assetfinder	xyz
743	2	subfinder	xyz
743	2	brand_ct	xyz
744	2	assetfinder	xyz
744	2	subfinder	xyz
744	2	brand_ct	xyz
745	2	assetfinder	xyz
745	2	subfinder	xyz
745	2	brand_ct	xyz
746	2	assetfinder	xyz
746	2	subfinder	xyz
746	2	brand_ct	xyz
747	2	assetfinder	xyz
747	2	subfinder	xyz
747	2	brand_ct	xyz
748	2	assetfinder	xyz
748	2	subfinder	xyz
748	2	brand_ct	xyz
749	2	assetfinder	xyz
749	2	subfinder	xyz
749	2	brand_ct	xyz
750	2	assetfinder	xyz
750	2	subfinder	xyz
750	2	brand_ct	xyz
751	2	assetfinder	xyz
751	2	subfinder	xyz
751	2	brand_ct	xyz
752	2	assetfinder	xyz
752	2	subfinder	xyz
752	2	brand_ct	xyz
753	2	assetfinder	xyz
753	2	subfinder	xyz
753	2	brand_ct	xyz
754	2	assetfinder	xyz
754	2	subfinder	xyz
754	2	brand_ct	xyz
755	2	assetfinder	xyz
755	2	subfinder	xyz
755	2	brand_ct	xyz
756	2	assetfinder	xyz
756	2	subfinder	xyz
756	2	brand_ct	xyz
757	2	assetfinder	xyz
757	2	subfinder	xyz
757	2	brand_ct	xyz
758	2	assetfinder	xyz
758	2	subfinder	xyz
758	2	brand_ct	xyz
759	2	assetfinder	xyz
759	2	subfinder	xyz
759	2	brand_ct	xyz
760	2	assetfinder	xyz
760	2	subfinder	xyz
760	2	brand_ct	xyz
761	2	assetfinder	xyz
761	2	subfinder	xyz
761	2	brand_ct	xyz
762	2	assetfinder	xyz
762	2	subfinder	xyz
762	2	brand_ct	xyz
763	2	assetfinder	xyz
763	2	subfinder	xyz
763	2	brand_ct	xyz
764	2	assetfinder	xyz
764	2	subfinder	xyz
764	2	brand_ct	xyz
765	2	assetfinder	xyz
765	2	subfinder	xyz
765	2	brand_ct	xyz
766	2	assetfinder	xyz
766	2	subfinder	xyz
766	2	brand_ct	xyz
767	2	assetfinder	xyz
767	2	subfinder	xyz
767	2	brand_ct	xyz
768	2	assetfinder	xyz
768	2	subfinder	xyz
768	2	brand_ct	xyz
769	2	assetfinder	xyz
769	2	subfinder	xyz
769	2	brand_ct	xyz
770	2	assetfinder	xyz
770	2	subfinder	xyz
770	2	brand_ct	xyz
771	2	assetfinder	xyz
771	2	subfinder	xyz
771	2	brand_ct	xyz
772	2	assetfinder	xyz
772	2	subfinder	xyz
772	2	brand_ct	xyz
773	2	assetfinder	xyz
773	2	subfinder	xyz
773	2	brand_ct	xyz
774	2	assetfinder	xyz
774	2	subfinder	xyz
774	2	brand_ct	xyz
775	2	assetfinder	xyz
775	2	subfinder	xyz
775	2	brand_ct	xyz
776	2	assetfinder	xyz
776	2	subfinder	xyz
776	2	brand_ct	xyz
777	2	assetfinder	xyz
777	2	subfinder	xyz
777	2	brand_ct	xyz
778	2	assetfinder	xyz
778	2	subfinder	xyz
778	2	brand_ct	xyz
779	2	assetfinder	xyz
779	2	subfinder	xyz
779	2	brand_ct	xyz
780	2	assetfinder	xyz
780	2	subfinder	xyz
780	2	brand_ct	xyz
781	2	assetfinder	xyz
781	2	subfinder	xyz
781	2	brand_ct	xyz
782	2	assetfinder	xyz
782	2	subfinder	xyz
782	2	brand_ct	xyz
783	2	assetfinder	xyz
783	2	subfinder	xyz
783	2	brand_ct	xyz
784	2	assetfinder	xyz
784	2	subfinder	xyz
784	2	brand_ct	xyz
785	2	assetfinder	xyz
785	2	subfinder	xyz
785	2	brand_ct	xyz
786	2	assetfinder	xyz
786	2	subfinder	xyz
786	2	brand_ct	xyz
787	2	assetfinder	xyz
787	2	subfinder	xyz
787	2	brand_ct	xyz
788	2	assetfinder	xyz
788	2	subfinder	xyz
788	2	brand_ct	xyz
789	2	assetfinder	xyz
789	2	subfinder	xyz
789	2	brand_ct	xyz
790	2	assetfinder	xyz
790	2	subfinder	xyz
790	2	brand_ct	xyz
791	2	assetfinder	xyz
791	2	subfinder	xyz
791	2	brand_ct	xyz
792	2	assetfinder	xyz
792	2	subfinder	xyz
792	2	brand_ct	xyz
793	2	assetfinder	xyz
793	2	subfinder	xyz
793	2	brand_ct	xyz
794	2	assetfinder	xyz
794	2	subfinder	xyz
794	2	brand_ct	xyz
795	2	assetfinder	xyz
795	2	subfinder	xyz
795	2	brand_ct	xyz
796	2	assetfinder	xyz
796	2	subfinder	xyz
796	2	brand_ct	xyz
797	2	assetfinder	xyz
797	2	subfinder	xyz
797	2	brand_ct	xyz
798	2	assetfinder	xyz
798	2	subfinder	xyz
798	2	brand_ct	xyz
799	2	assetfinder	xyz
799	2	subfinder	xyz
799	2	brand_ct	xyz
800	2	assetfinder	xyz
800	2	subfinder	xyz
800	2	brand_ct	xyz
801	2	assetfinder	xyz
801	2	subfinder	xyz
801	2	brand_ct	xyz
802	2	assetfinder	xyz
802	2	subfinder	xyz
802	2	brand_ct	xyz
803	2	assetfinder	xyz
803	2	subfinder	xyz
803	2	brand_ct	xyz
804	2	assetfinder	xyz
804	2	subfinder	xyz
804	2	brand_ct	xyz
805	2	assetfinder	xyz
805	2	subfinder	xyz
805	2	brand_ct	xyz
806	2	assetfinder	xyz
806	2	subfinder	xyz
806	2	brand_ct	xyz
807	2	assetfinder	xyz
807	2	subfinder	xyz
807	2	brand_ct	xyz
808	2	assetfinder	xyz
808	2	subfinder	xyz
808	2	brand_ct	xyz
809	2	subfinder	xyz
809	2	brand_ct	xyz
810	2	assetfinder	xyz
810	2	subfinder	xyz
810	2	brand_ct	xyz
811	2	assetfinder	xyz
811	2	subfinder	xyz
811	2	brand_ct	xyz
812	2	assetfinder	xyz
812	2	subfinder	xyz
812	2	brand_ct	xyz
813	2	assetfinder	xyz
813	2	subfinder	xyz
813	2	brand_ct	xyz
814	2	assetfinder	xyz
814	2	subfinder	xyz
814	2	brand_ct	xyz
815	2	assetfinder	xyz
815	2	subfinder	xyz
815	2	brand_ct	xyz
816	2	assetfinder	xyz
816	2	subfinder	xyz
816	2	brand_ct	xyz
817	2	assetfinder	xyz
817	2	subfinder	xyz
817	2	brand_ct	xyz
818	2	assetfinder	xyz
818	2	subfinder	xyz
818	2	brand_ct	xyz
819	2	assetfinder	xyz
819	2	subfinder	xyz
819	2	brand_ct	xyz
820	2	assetfinder	xyz
820	2	subfinder	xyz
820	2	brand_ct	xyz
821	2	assetfinder	xyz
821	2	subfinder	xyz
821	2	brand_ct	xyz
822	2	assetfinder	xyz
822	2	subfinder	xyz
822	2	brand_ct	xyz
823	2	assetfinder	xyz
823	2	subfinder	xyz
823	2	brand_ct	xyz
824	2	assetfinder	xyz
824	2	subfinder	xyz
824	2	brand_ct	xyz
825	2	assetfinder	xyz
825	2	subfinder	xyz
825	2	brand_ct	xyz
826	2	assetfinder	xyz
826	2	subfinder	xyz
826	2	brand_ct	xyz
827	2	assetfinder	xyz
827	2	subfinder	xyz
827	2	brand_ct	xyz
828	2	assetfinder	xyz
828	2	subfinder	xyz
828	2	brand_ct	xyz
829	2	assetfinder	xyz
829	2	subfinder	xyz
829	2	brand_ct	xyz
830	2	assetfinder	xyz
830	2	subfinder	xyz
830	2	brand_ct	xyz
831	2	assetfinder	xyz
831	2	subfinder	xyz
831	2	brand_ct	xyz
832	2	assetfinder	xyz
832	2	subfinder	xyz
832	2	brand_ct	xyz
833	2	assetfinder	xyz
833	2	subfinder	xyz
833	2	brand_ct	xyz
834	2	assetfinder	xyz
834	2	subfinder	xyz
834	2	brand_ct	xyz
835	2	assetfinder	xyz
835	2	subfinder	xyz
835	2	brand_ct	xyz
836	2	subfinder	xyz
836	2	brand_ct	xyz
837	2	assetfinder	xyz
837	2	subfinder	xyz
837	2	brand_ct	xyz
838	2	assetfinder	xyz
838	2	subfinder	xyz
838	2	brand_ct	xyz
839	2	assetfinder	xyz
839	2	subfinder	xyz
839	2	brand_ct	xyz
840	2	assetfinder	xyz
840	2	subfinder	xyz
840	2	brand_ct	xyz
841	2	assetfinder	xyz
841	2	subfinder	xyz
841	2	brand_ct	xyz
842	2	assetfinder	xyz
842	2	subfinder	xyz
842	2	brand_ct	xyz
843	2	assetfinder	xyz
843	2	subfinder	xyz
843	2	brand_ct	xyz
844	2	assetfinder	xyz
844	2	subfinder	xyz
844	2	brand_ct	xyz
845	2	assetfinder	xyz
845	2	subfinder	xyz
845	2	brand_ct	xyz
846	2	assetfinder	xyz
846	2	subfinder	xyz
846	2	brand_ct	xyz
847	2	assetfinder	xyz
847	2	subfinder	xyz
847	2	brand_ct	xyz
848	2	assetfinder	xyz
849	2	assetfinder	xyz
849	2	subfinder	xyz
849	2	brand_ct	xyz
850	2	assetfinder	xyz
850	2	subfinder	xyz
850	2	brand_ct	xyz
851	2	assetfinder	xyz
851	2	subfinder	xyz
851	2	brand_ct	xyz
852	2	assetfinder	xyz
853	2	assetfinder	xyz
853	2	subfinder	xyz
853	2	brand_ct	xyz
854	2	assetfinder	xyz
854	2	subfinder	xyz
854	2	brand_ct	xyz
855	2	assetfinder	xyz
855	2	subfinder	xyz
855	2	brand_ct	xyz
856	2	assetfinder	xyz
856	2	subfinder	xyz
856	2	brand_ct	xyz
857	2	assetfinder	xyz
857	2	subfinder	xyz
857	2	brand_ct	xyz
858	2	assetfinder	xyz
858	2	subfinder	xyz
858	2	brand_ct	xyz
859	2	assetfinder	xyz
859	2	subfinder	xyz
859	2	brand_ct	xyz
860	2	assetfinder	xyz
860	2	subfinder	xyz
860	2	brand_ct	xyz
861	2	assetfinder	xyz
862	2	assetfinder	xyz
862	2	subfinder	xyz
862	2	brand_ct	xyz
863	2	assetfinder	xyz
863	2	subfinder	xyz
863	2	brand_ct	xyz
864	2	assetfinder	xyz
864	2	subfinder	xyz
864	2	brand_ct	xyz
865	2	assetfinder	xyz
865	2	subfinder	xyz
865	2	brand_ct	xyz
866	2	assetfinder	xyz
866	2	subfinder	xyz
866	2	brand_ct	xyz
867	2	assetfinder	xyz
867	2	subfinder	xyz
867	2	brand_ct	xyz
868	2	assetfinder	xyz
868	2	subfinder	xyz
868	2	brand_ct	xyz
869	2	assetfinder	xyz
869	2	subfinder	xyz
869	2	brand_ct	xyz
870	2	assetfinder	xyz
870	2	subfinder	xyz
870	2	brand_ct	xyz
871	2	assetfinder	xyz
871	2	subfinder	xyz
871	2	brand_ct	xyz
872	2	assetfinder	xyz
872	2	subfinder	xyz
872	2	brand_ct	xyz
873	2	assetfinder	xyz
873	2	subfinder	xyz
873	2	brand_ct	xyz
874	2	assetfinder	xyz
875	2	assetfinder	xyz
875	2	subfinder	xyz
875	2	brand_ct	xyz
876	2	assetfinder	xyz
876	2	subfinder	xyz
876	2	brand_ct	xyz
877	2	assetfinder	xyz
877	2	subfinder	xyz
877	2	brand_ct	xyz
878	2	assetfinder	xyz
878	2	subfinder	xyz
878	2	brand_ct	xyz
879	2	assetfinder	xyz
879	2	subfinder	xyz
879	2	brand_ct	xyz
880	2	assetfinder	xyz
880	2	subfinder	xyz
880	2	brand_ct	xyz
881	2	assetfinder	xyz
881	2	subfinder	xyz
881	2	brand_ct	xyz
882	2	assetfinder	xyz
882	2	subfinder	xyz
882	2	brand_ct	xyz
883	2	assetfinder	xyz
883	2	subfinder	xyz
883	2	brand_ct	xyz
884	2	assetfinder	xyz
884	2	subfinder	xyz
884	2	brand_ct	xyz
885	2	assetfinder	xyz
885	2	subfinder	xyz
885	2	brand_ct	xyz
886	2	assetfinder	xyz
886	2	subfinder	xyz
886	2	brand_ct	xyz
887	2	assetfinder	xyz
887	2	subfinder	xyz
887	2	brand_ct	xyz
888	2	assetfinder	xyz
888	2	subfinder	xyz
888	2	brand_ct	xyz
889	2	assetfinder	xyz
889	2	subfinder	xyz
889	2	brand_ct	xyz
890	2	assetfinder	xyz
890	2	subfinder	xyz
890	2	brand_ct	xyz
891	2	assetfinder	xyz
891	2	subfinder	xyz
891	2	brand_ct	xyz
892	2	assetfinder	xyz
892	2	subfinder	xyz
892	2	brand_ct	xyz
893	2	assetfinder	xyz
893	2	subfinder	xyz
893	2	brand_ct	xyz
894	2	assetfinder	xyz
894	2	subfinder	xyz
894	2	brand_ct	xyz
895	2	assetfinder	xyz
895	2	subfinder	xyz
895	2	brand_ct	xyz
896	2	assetfinder	xyz
896	2	subfinder	xyz
896	2	brand_ct	xyz
897	2	assetfinder	xyz
897	2	subfinder	xyz
897	2	brand_ct	xyz
898	2	assetfinder	xyz
898	2	subfinder	xyz
898	2	brand_ct	xyz
899	2	assetfinder	xyz
899	2	subfinder	xyz
899	2	brand_ct	xyz
900	2	assetfinder	xyz
900	2	subfinder	xyz
900	2	brand_ct	xyz
901	2	assetfinder	xyz
901	2	subfinder	xyz
901	2	brand_ct	xyz
902	2	assetfinder	xyz
902	2	subfinder	xyz
902	2	brand_ct	xyz
903	2	assetfinder	xyz
903	2	subfinder	xyz
903	2	brand_ct	xyz
904	2	assetfinder	xyz
904	2	subfinder	xyz
904	2	brand_ct	xyz
905	2	assetfinder	xyz
905	2	subfinder	xyz
905	2	brand_ct	xyz
906	2	assetfinder	xyz
906	2	subfinder	xyz
906	2	brand_ct	xyz
907	2	assetfinder	xyz
907	2	subfinder	xyz
907	2	brand_ct	xyz
908	2	assetfinder	xyz
908	2	subfinder	xyz
908	2	brand_ct	xyz
909	2	assetfinder	xyz
909	2	subfinder	xyz
909	2	brand_ct	xyz
910	2	assetfinder	xyz
910	2	subfinder	xyz
910	2	brand_ct	xyz
911	2	assetfinder	xyz
911	2	subfinder	xyz
911	2	brand_ct	xyz
912	2	assetfinder	xyz
912	2	subfinder	xyz
912	2	brand_ct	xyz
913	2	assetfinder	xyz
913	2	subfinder	xyz
913	2	brand_ct	xyz
914	2	assetfinder	xyz
914	2	subfinder	xyz
914	2	brand_ct	xyz
915	2	assetfinder	xyz
915	2	subfinder	xyz
915	2	brand_ct	xyz
916	2	assetfinder	xyz
916	2	subfinder	xyz
917	2	assetfinder	xyz
917	2	subfinder	xyz
917	2	brand_ct	xyz
918	2	assetfinder	xyz
918	2	subfinder	xyz
918	2	brand_ct	xyz
919	2	assetfinder	xyz
919	2	subfinder	xyz
919	2	brand_ct	xyz
920	2	assetfinder	xyz
920	2	subfinder	xyz
920	2	brand_ct	xyz
921	2	assetfinder	xyz
922	2	assetfinder	xyz
922	2	subfinder	xyz
922	2	brand_ct	xyz
923	2	assetfinder	xyz
923	2	subfinder	xyz
923	2	brand_ct	xyz
924	2	subfinder	xyz
925	2	brand_ct	xyz
926	2	assetfinder	xyz
926	2	subfinder	xyz
926	2	brand_ct	xyz
927	2	assetfinder	xyz
927	2	subfinder	xyz
927	2	brand_ct	xyz
928	2	assetfinder	xyz
928	2	subfinder	xyz
928	2	brand_ct	xyz
929	2	assetfinder	xyz
929	2	subfinder	xyz
929	2	brand_ct	xyz
930	2	assetfinder	xyz
930	2	subfinder	xyz
930	2	brand_ct	xyz
931	2	assetfinder	xyz
931	2	subfinder	xyz
931	2	brand_ct	xyz
932	2	assetfinder	xyz
932	2	subfinder	xyz
932	2	brand_ct	xyz
933	2	assetfinder	xyz
933	2	subfinder	xyz
933	2	brand_ct	xyz
934	2	assetfinder	xyz
934	2	subfinder	xyz
934	2	brand_ct	xyz
935	2	assetfinder	xyz
935	2	subfinder	xyz
935	2	brand_ct	xyz
936	2	assetfinder	xyz
936	2	subfinder	xyz
936	2	brand_ct	xyz
937	2	assetfinder	xyz
937	2	subfinder	xyz
937	2	brand_ct	xyz
938	2	assetfinder	xyz
938	2	subfinder	xyz
938	2	brand_ct	xyz
939	2	assetfinder	xyz
939	2	subfinder	xyz
939	2	brand_ct	xyz
940	2	assetfinder	xyz
940	2	subfinder	xyz
940	2	brand_ct	xyz
941	2	assetfinder	xyz
941	2	subfinder	xyz
941	2	brand_ct	xyz
942	2	assetfinder	xyz
942	2	subfinder	xyz
942	2	brand_ct	xyz
943	2	assetfinder	xyz
943	2	subfinder	xyz
943	2	brand_ct	xyz
944	2	assetfinder	xyz
944	2	subfinder	xyz
944	2	brand_ct	xyz
945	2	assetfinder	xyz
945	2	subfinder	xyz
945	2	brand_ct	xyz
946	2	assetfinder	xyz
946	2	subfinder	xyz
946	2	brand_ct	xyz
947	2	assetfinder	xyz
947	2	subfinder	xyz
947	2	brand_ct	xyz
948	2	assetfinder	xyz
948	2	subfinder	xyz
948	2	brand_ct	xyz
949	2	assetfinder	xyz
950	2	assetfinder	xyz
950	2	subfinder	xyz
950	2	brand_ct	xyz
951	2	assetfinder	xyz
951	2	subfinder	xyz
951	2	brand_ct	xyz
952	2	assetfinder	xyz
952	2	subfinder	xyz
952	2	brand_ct	xyz
953	2	assetfinder	xyz
953	2	subfinder	xyz
953	2	brand_ct	xyz
954	2	assetfinder	xyz
954	2	subfinder	xyz
954	2	brand_ct	xyz
955	2	assetfinder	xyz
956	2	assetfinder	xyz
956	2	subfinder	xyz
956	2	brand_ct	xyz
957	2	assetfinder	xyz
957	2	subfinder	xyz
957	2	brand_ct	xyz
958	2	assetfinder	xyz
958	2	subfinder	xyz
959	2	assetfinder	xyz
959	2	subfinder	xyz
959	2	brand_ct	xyz
960	2	assetfinder	xyz
960	2	subfinder	xyz
960	2	brand_ct	xyz
961	2	assetfinder	xyz
961	2	subfinder	xyz
961	2	brand_ct	xyz
962	2	assetfinder	xyz
962	2	subfinder	xyz
962	2	brand_ct	xyz
963	2	assetfinder	xyz
963	2	subfinder	xyz
963	2	brand_ct	xyz
964	2	assetfinder	xyz
964	2	subfinder	xyz
964	2	brand_ct	xyz
965	2	assetfinder	xyz
965	2	subfinder	xyz
965	2	brand_ct	xyz
966	2	assetfinder	xyz
966	2	subfinder	xyz
966	2	brand_ct	xyz
967	2	assetfinder	xyz
967	2	subfinder	xyz
967	2	brand_ct	xyz
968	2	assetfinder	xyz
968	2	subfinder	xyz
968	2	brand_ct	xyz
969	2	assetfinder	xyz
969	2	subfinder	xyz
969	2	brand_ct	xyz
970	2	assetfinder	xyz
970	2	subfinder	xyz
970	2	brand_ct	xyz
971	2	assetfinder	xyz
971	2	subfinder	xyz
971	2	brand_ct	xyz
972	2	assetfinder	xyz
972	2	subfinder	xyz
972	2	brand_ct	xyz
973	2	assetfinder	xyz
973	2	subfinder	xyz
973	2	brand_ct	xyz
974	2	assetfinder	xyz
974	2	subfinder	xyz
974	2	brand_ct	xyz
975	2	assetfinder	xyz
975	2	subfinder	xyz
975	2	brand_ct	xyz
976	2	assetfinder	xyz
976	2	subfinder	xyz
976	2	brand_ct	xyz
977	2	assetfinder	xyz
977	2	subfinder	xyz
977	2	brand_ct	xyz
978	2	assetfinder	xyz
978	2	subfinder	xyz
978	2	brand_ct	xyz
979	2	assetfinder	xyz
979	2	subfinder	xyz
979	2	brand_ct	xyz
980	2	assetfinder	xyz
980	2	subfinder	xyz
980	2	brand_ct	xyz
981	2	assetfinder	xyz
981	2	subfinder	xyz
981	2	brand_ct	xyz
982	2	assetfinder	xyz
982	2	subfinder	xyz
982	2	brand_ct	xyz
983	2	assetfinder	xyz
983	2	subfinder	xyz
983	2	brand_ct	xyz
984	2	assetfinder	xyz
984	2	subfinder	xyz
984	2	brand_ct	xyz
985	2	assetfinder	xyz
985	2	subfinder	xyz
985	2	brand_ct	xyz
986	2	assetfinder	xyz
986	2	subfinder	xyz
986	2	brand_ct	xyz
987	2	assetfinder	xyz
987	2	subfinder	xyz
987	2	brand_ct	xyz
988	2	assetfinder	xyz
988	2	subfinder	xyz
988	2	brand_ct	xyz
989	2	assetfinder	xyz
989	2	subfinder	xyz
989	2	brand_ct	xyz
990	2	assetfinder	xyz
990	2	subfinder	xyz
990	2	brand_ct	xyz
991	2	assetfinder	xyz
991	2	subfinder	xyz
991	2	brand_ct	xyz
992	2	assetfinder	xyz
992	2	subfinder	xyz
992	2	brand_ct	xyz
993	2	assetfinder	xyz
993	2	subfinder	xyz
993	2	brand_ct	xyz
994	2	assetfinder	xyz
994	2	subfinder	xyz
994	2	brand_ct	xyz
995	2	assetfinder	xyz
995	2	subfinder	xyz
995	2	brand_ct	xyz
996	2	assetfinder	xyz
996	2	subfinder	xyz
996	2	brand_ct	xyz
997	2	assetfinder	xyz
998	2	assetfinder	xyz
998	2	subfinder	xyz
998	2	brand_ct	xyz
999	2	assetfinder	xyz
999	2	subfinder	xyz
999	2	brand_ct	xyz
1000	2	assetfinder	xyz
1000	2	subfinder	xyz
1000	2	brand_ct	xyz
1001	2	assetfinder	xyz
1001	2	subfinder	xyz
1001	2	brand_ct	xyz
1002	2	assetfinder	xyz
1002	2	subfinder	xyz
1002	2	brand_ct	xyz
1003	2	assetfinder	xyz
1003	2	subfinder	xyz
1003	2	brand_ct	xyz
1004	2	assetfinder	xyz
1004	2	subfinder	xyz
1004	2	brand_ct	xyz
1005	2	assetfinder	xyz
1005	2	subfinder	xyz
1005	2	brand_ct	xyz
1006	2	assetfinder	xyz
1006	2	subfinder	xyz
1006	2	brand_ct	xyz
1007	2	assetfinder	xyz
1007	2	subfinder	xyz
1007	2	brand_ct	xyz
1008	2	assetfinder	xyz
1008	2	subfinder	xyz
1008	2	brand_ct	xyz
1009	2	assetfinder	xyz
1009	2	subfinder	xyz
1009	2	brand_ct	xyz
1010	2	assetfinder	xyz
1010	2	subfinder	xyz
1010	2	brand_ct	xyz
1011	2	assetfinder	xyz
1011	2	subfinder	xyz
1011	2	brand_ct	xyz
1012	2	assetfinder	xyz
1012	2	subfinder	xyz
1012	2	brand_ct	xyz
1013	2	assetfinder	xyz
1013	2	subfinder	xyz
1013	2	brand_ct	xyz
1014	2	assetfinder	xyz
1014	2	subfinder	xyz
1014	2	brand_ct	xyz
1015	2	assetfinder	xyz
1015	2	subfinder	xyz
1016	2	assetfinder	xyz
1016	2	subfinder	xyz
1016	2	brand_ct	xyz
1017	2	assetfinder	xyz
1017	2	subfinder	xyz
1017	2	brand_ct	xyz
1018	2	assetfinder	xyz
1018	2	subfinder	xyz
1018	2	brand_ct	xyz
1019	2	assetfinder	xyz
1019	2	subfinder	xyz
1019	2	brand_ct	xyz
1020	2	assetfinder	xyz
1020	2	subfinder	xyz
1020	2	brand_ct	xyz
1021	2	assetfinder	xyz
1021	2	subfinder	xyz
1021	2	brand_ct	xyz
1022	2	assetfinder	xyz
1022	2	subfinder	xyz
1022	2	brand_ct	xyz
1023	2	assetfinder	xyz
1023	2	subfinder	xyz
1023	2	brand_ct	xyz
1024	2	assetfinder	xyz
1024	2	subfinder	xyz
1024	2	brand_ct	xyz
1025	2	assetfinder	xyz
1025	2	subfinder	xyz
1025	2	brand_ct	xyz
1026	2	assetfinder	xyz
1026	2	subfinder	xyz
1026	2	brand_ct	xyz
1027	2	assetfinder	xyz
1027	2	subfinder	xyz
1027	2	brand_ct	xyz
1028	2	assetfinder	xyz
1028	2	subfinder	xyz
1028	2	brand_ct	xyz
1029	2	assetfinder	xyz
1029	2	subfinder	xyz
1029	2	brand_ct	xyz
1030	2	assetfinder	xyz
1030	2	subfinder	xyz
1030	2	brand_ct	xyz
1031	2	assetfinder	xyz
1031	2	subfinder	xyz
1031	2	brand_ct	xyz
1032	2	assetfinder	xyz
1032	2	subfinder	xyz
1032	2	brand_ct	xyz
1033	2	assetfinder	xyz
1033	2	subfinder	xyz
1033	2	brand_ct	xyz
1034	2	assetfinder	xyz
1034	2	subfinder	xyz
1034	2	brand_ct	xyz
1035	2	assetfinder	xyz
1035	2	subfinder	xyz
1035	2	brand_ct	xyz
1036	2	assetfinder	xyz
1036	2	subfinder	xyz
1036	2	brand_ct	xyz
1037	2	assetfinder	xyz
1037	2	subfinder	xyz
1037	2	brand_ct	xyz
1038	2	assetfinder	xyz
1039	2	assetfinder	xyz
1039	2	subfinder	xyz
1039	2	brand_ct	xyz
1040	2	assetfinder	xyz
1040	2	subfinder	xyz
1040	2	brand_ct	xyz
1041	2	assetfinder	xyz
1041	2	subfinder	xyz
1041	2	brand_ct	xyz
1042	2	assetfinder	xyz
1042	2	subfinder	xyz
1042	2	brand_ct	xyz
1043	2	assetfinder	xyz
1043	2	subfinder	xyz
1043	2	brand_ct	xyz
1044	2	assetfinder	xyz
1044	2	subfinder	xyz
1044	2	brand_ct	xyz
1045	2	assetfinder	xyz
1045	2	subfinder	xyz
1045	2	brand_ct	xyz
1046	2	assetfinder	xyz
1046	2	subfinder	xyz
1046	2	brand_ct	xyz
1047	2	assetfinder	xyz
1047	2	subfinder	xyz
1047	2	brand_ct	xyz
1048	2	assetfinder	xyz
1049	2	assetfinder	xyz
1049	2	subfinder	xyz
1049	2	brand_ct	xyz
1050	2	assetfinder	xyz
1050	2	subfinder	xyz
1050	2	brand_ct	xyz
1051	2	assetfinder	xyz
1051	2	subfinder	xyz
1051	2	brand_ct	xyz
1052	2	assetfinder	xyz
1052	2	subfinder	xyz
1052	2	brand_ct	xyz
1053	2	assetfinder	xyz
1053	2	subfinder	xyz
1053	2	brand_ct	xyz
1054	2	assetfinder	xyz
1054	2	subfinder	xyz
1054	2	brand_ct	xyz
1055	2	assetfinder	xyz
1055	2	subfinder	xyz
1055	2	brand_ct	xyz
1056	2	assetfinder	xyz
1056	2	subfinder	xyz
1056	2	brand_ct	xyz
1057	2	assetfinder	xyz
1057	2	subfinder	xyz
1057	2	brand_ct	xyz
1058	2	assetfinder	xyz
1058	2	subfinder	xyz
1058	2	brand_ct	xyz
1059	2	assetfinder	xyz
1059	2	subfinder	xyz
1059	2	brand_ct	xyz
1060	2	assetfinder	xyz
1060	2	subfinder	xyz
1060	2	brand_ct	xyz
1061	2	assetfinder	xyz
1061	2	subfinder	xyz
1061	2	brand_ct	xyz
1062	2	assetfinder	xyz
1062	2	subfinder	xyz
1062	2	brand_ct	xyz
1063	2	assetfinder	xyz
1063	2	subfinder	xyz
1063	2	brand_ct	xyz
1064	2	assetfinder	xyz
1064	2	subfinder	xyz
1064	2	brand_ct	xyz
1065	2	assetfinder	xyz
1065	2	subfinder	xyz
1065	2	brand_ct	xyz
1066	2	assetfinder	xyz
1066	2	subfinder	xyz
1066	2	brand_ct	xyz
1067	2	assetfinder	xyz
1067	2	subfinder	xyz
1067	2	brand_ct	xyz
1068	2	assetfinder	xyz
1068	2	subfinder	xyz
1068	2	brand_ct	xyz
1069	2	assetfinder	xyz
1069	2	subfinder	xyz
1069	2	brand_ct	xyz
1070	2	assetfinder	xyz
1070	2	subfinder	xyz
1070	2	brand_ct	xyz
1071	2	assetfinder	xyz
1071	2	subfinder	xyz
1071	2	brand_ct	xyz
1072	2	assetfinder	xyz
1072	2	subfinder	xyz
1072	2	brand_ct	xyz
1073	2	assetfinder	xyz
1073	2	subfinder	xyz
1073	2	brand_ct	xyz
1074	2	assetfinder	xyz
1074	2	subfinder	xyz
1074	2	brand_ct	xyz
1075	2	assetfinder	xyz
1075	2	subfinder	xyz
1075	2	brand_ct	xyz
1076	2	assetfinder	xyz
1076	2	subfinder	xyz
1076	2	brand_ct	xyz
1077	2	assetfinder	xyz
1078	2	assetfinder	xyz
1078	2	subfinder	xyz
1078	2	brand_ct	xyz
1079	2	assetfinder	xyz
1079	2	subfinder	xyz
1079	2	brand_ct	xyz
1080	2	assetfinder	xyz
1080	2	subfinder	xyz
1080	2	brand_ct	xyz
1081	2	assetfinder	xyz
1081	2	subfinder	xyz
1081	2	brand_ct	xyz
1082	2	assetfinder	xyz
1082	2	subfinder	xyz
1082	2	brand_ct	xyz
1083	2	assetfinder	xyz
1083	2	subfinder	xyz
1083	2	brand_ct	xyz
1084	2	assetfinder	xyz
1084	2	subfinder	xyz
1084	2	brand_ct	xyz
1085	2	assetfinder	xyz
1085	2	subfinder	xyz
1085	2	brand_ct	xyz
1086	2	assetfinder	xyz
1086	2	subfinder	xyz
1086	2	brand_ct	xyz
1087	2	assetfinder	xyz
1087	2	subfinder	xyz
1087	2	brand_ct	xyz
1088	2	assetfinder	xyz
1088	2	subfinder	xyz
1088	2	brand_ct	xyz
1089	2	assetfinder	xyz
1089	2	subfinder	xyz
1089	2	brand_ct	xyz
1090	2	assetfinder	xyz
1090	2	subfinder	xyz
1090	2	brand_ct	xyz
1091	2	assetfinder	xyz
1091	2	subfinder	xyz
1091	2	brand_ct	xyz
1092	2	assetfinder	xyz
1092	2	subfinder	xyz
1092	2	brand_ct	xyz
1093	2	assetfinder	xyz
1093	2	subfinder	xyz
1093	2	brand_ct	xyz
1094	2	assetfinder	xyz
1094	2	subfinder	xyz
1094	2	brand_ct	xyz
1095	2	assetfinder	xyz
1096	2	assetfinder	xyz
1097	2	assetfinder	xyz
1097	2	subfinder	xyz
1097	2	brand_ct	xyz
1098	2	assetfinder	xyz
1098	2	subfinder	xyz
1098	2	brand_ct	xyz
1099	2	assetfinder	xyz
1100	2	assetfinder	xyz
1100	2	subfinder	xyz
1100	2	brand_ct	xyz
1101	2	assetfinder	xyz
1101	2	subfinder	xyz
1101	2	brand_ct	xyz
1102	2	assetfinder	xyz
1102	2	subfinder	xyz
1102	2	brand_ct	xyz
1103	2	assetfinder	xyz
1103	2	subfinder	xyz
1103	2	brand_ct	xyz
1104	2	assetfinder	xyz
1104	2	subfinder	xyz
1104	2	brand_ct	xyz
1105	2	assetfinder	xyz
1105	2	subfinder	xyz
1105	2	brand_ct	xyz
1106	2	assetfinder	xyz
1106	2	subfinder	xyz
1106	2	brand_ct	xyz
1107	2	assetfinder	xyz
1107	2	subfinder	xyz
1107	2	brand_ct	xyz
1108	2	assetfinder	xyz
1108	2	subfinder	xyz
1108	2	brand_ct	xyz
1109	2	assetfinder	xyz
1109	2	subfinder	xyz
1109	2	brand_ct	xyz
1110	2	assetfinder	xyz
1110	2	subfinder	xyz
1110	2	brand_ct	xyz
1111	2	assetfinder	xyz
1111	2	subfinder	xyz
1111	2	brand_ct	xyz
1112	2	assetfinder	xyz
1112	2	subfinder	xyz
1112	2	brand_ct	xyz
1113	2	assetfinder	xyz
1113	2	subfinder	xyz
1113	2	brand_ct	xyz
1114	2	assetfinder	xyz
1114	2	subfinder	xyz
1114	2	brand_ct	xyz
1115	2	assetfinder	xyz
1115	2	subfinder	xyz
1115	2	brand_ct	xyz
1116	2	assetfinder	xyz
1116	2	subfinder	xyz
1116	2	brand_ct	xyz
1117	2	assetfinder	xyz
1117	2	subfinder	xyz
1117	2	brand_ct	xyz
1118	2	assetfinder	xyz
1118	2	subfinder	xyz
1118	2	brand_ct	xyz
1119	2	assetfinder	xyz
1119	2	subfinder	xyz
1119	2	brand_ct	xyz
1120	2	assetfinder	xyz
1120	2	subfinder	xyz
1120	2	brand_ct	xyz
1121	2	assetfinder	xyz
1121	2	subfinder	xyz
1121	2	brand_ct	xyz
1122	2	assetfinder	xyz
1122	2	subfinder	xyz
1122	2	brand_ct	xyz
1123	2	assetfinder	xyz
1123	2	subfinder	xyz
1123	2	brand_ct	xyz
1124	2	assetfinder	xyz
1124	2	subfinder	xyz
1124	2	brand_ct	xyz
1125	2	assetfinder	xyz
1125	2	subfinder	xyz
1125	2	brand_ct	xyz
1126	2	assetfinder	xyz
1126	2	subfinder	xyz
1126	2	brand_ct	xyz
1127	2	assetfinder	xyz
1127	2	subfinder	xyz
1127	2	brand_ct	xyz
1128	2	assetfinder	xyz
1128	2	subfinder	xyz
1128	2	brand_ct	xyz
1129	2	assetfinder	xyz
1129	2	subfinder	xyz
1129	2	brand_ct	xyz
1130	2	assetfinder	xyz
1131	2	assetfinder	xyz
1131	2	subfinder	xyz
1131	2	brand_ct	xyz
1132	2	assetfinder	xyz
1132	2	subfinder	xyz
1132	2	brand_ct	xyz
1133	2	assetfinder	xyz
1133	2	subfinder	xyz
1133	2	brand_ct	xyz
1134	2	assetfinder	xyz
1134	2	subfinder	xyz
1134	2	brand_ct	xyz
1135	2	assetfinder	xyz
1135	2	subfinder	xyz
1135	2	brand_ct	xyz
1136	2	assetfinder	xyz
1136	2	subfinder	xyz
1136	2	brand_ct	xyz
1137	2	assetfinder	xyz
1137	2	subfinder	xyz
1137	2	brand_ct	xyz
1138	2	assetfinder	xyz
1138	2	subfinder	xyz
1138	2	brand_ct	xyz
1139	2	assetfinder	xyz
1139	2	subfinder	xyz
1139	2	brand_ct	xyz
1140	2	assetfinder	xyz
1141	2	assetfinder	xyz
1141	2	subfinder	xyz
1141	2	brand_ct	xyz
1142	2	assetfinder	xyz
1142	2	subfinder	xyz
1142	2	brand_ct	xyz
1143	2	assetfinder	xyz
1143	2	subfinder	xyz
1143	2	brand_ct	xyz
1144	2	assetfinder	xyz
1144	2	subfinder	xyz
1144	2	brand_ct	xyz
1145	2	assetfinder	xyz
1145	2	subfinder	xyz
1145	2	brand_ct	xyz
1146	2	assetfinder	xyz
1146	2	subfinder	xyz
1146	2	brand_ct	xyz
1147	2	assetfinder	xyz
1147	2	subfinder	xyz
1147	2	brand_ct	xyz
1148	2	assetfinder	xyz
1148	2	subfinder	xyz
1148	2	brand_ct	xyz
1149	2	assetfinder	xyz
1149	2	subfinder	xyz
1149	2	brand_ct	xyz
1150	2	assetfinder	xyz
1150	2	subfinder	xyz
1150	2	brand_ct	xyz
1151	2	assetfinder	xyz
1151	2	subfinder	xyz
1151	2	brand_ct	xyz
1152	2	assetfinder	xyz
1152	2	subfinder	xyz
1152	2	brand_ct	xyz
1153	2	assetfinder	xyz
1153	2	subfinder	xyz
1153	2	brand_ct	xyz
1154	2	assetfinder	xyz
1154	2	subfinder	xyz
1154	2	brand_ct	xyz
1155	2	assetfinder	xyz
1155	2	subfinder	xyz
1155	2	brand_ct	xyz
1156	2	assetfinder	xyz
1156	2	subfinder	xyz
1156	2	brand_ct	xyz
1157	2	assetfinder	xyz
1157	2	subfinder	xyz
1157	2	brand_ct	xyz
1158	2	assetfinder	xyz
1158	2	subfinder	xyz
1158	2	brand_ct	xyz
1159	2	assetfinder	xyz
1159	2	subfinder	xyz
1159	2	brand_ct	xyz
1160	2	assetfinder	xyz
1160	2	subfinder	xyz
1160	2	brand_ct	xyz
1161	2	assetfinder	xyz
1161	2	subfinder	xyz
1161	2	brand_ct	xyz
1162	2	assetfinder	xyz
1162	2	subfinder	xyz
1162	2	brand_ct	xyz
1163	2	assetfinder	xyz
1163	2	subfinder	xyz
1163	2	brand_ct	xyz
1164	2	assetfinder	xyz
1164	2	subfinder	xyz
1164	2	brand_ct	xyz
1165	2	assetfinder	xyz
1165	2	subfinder	xyz
1165	2	brand_ct	xyz
1166	2	assetfinder	xyz
1166	2	subfinder	xyz
1166	2	brand_ct	xyz
1167	2	assetfinder	xyz
1168	2	assetfinder	xyz
1168	2	subfinder	xyz
1168	2	brand_ct	xyz
1169	2	assetfinder	xyz
1169	2	subfinder	xyz
1169	2	brand_ct	xyz
1170	2	assetfinder	xyz
1170	2	subfinder	xyz
1170	2	brand_ct	xyz
1171	2	assetfinder	xyz
1171	2	subfinder	xyz
1171	2	brand_ct	xyz
1172	2	assetfinder	xyz
1172	2	subfinder	xyz
1172	2	brand_ct	xyz
1173	2	assetfinder	xyz
1173	2	subfinder	xyz
1173	2	brand_ct	xyz
1174	2	assetfinder	xyz
1174	2	subfinder	xyz
1174	2	brand_ct	xyz
1175	2	assetfinder	xyz
1175	2	subfinder	xyz
1175	2	brand_ct	xyz
1176	2	assetfinder	xyz
1176	2	subfinder	xyz
1176	2	brand_ct	xyz
1177	2	assetfinder	xyz
1177	2	subfinder	xyz
1177	2	brand_ct	xyz
1178	2	assetfinder	xyz
1178	2	subfinder	xyz
1178	2	brand_ct	xyz
1179	2	assetfinder	xyz
1179	2	subfinder	xyz
1179	2	brand_ct	xyz
1180	2	assetfinder	xyz
1180	2	subfinder	xyz
1180	2	brand_ct	xyz
1181	2	assetfinder	xyz
1181	2	subfinder	xyz
1181	2	brand_ct	xyz
1182	2	assetfinder	xyz
1182	2	subfinder	xyz
1182	2	brand_ct	xyz
1183	2	assetfinder	xyz
1183	2	subfinder	xyz
1183	2	brand_ct	xyz
1184	2	assetfinder	xyz
1184	2	subfinder	xyz
1184	2	brand_ct	xyz
1185	2	assetfinder	xyz
1185	2	subfinder	xyz
1185	2	brand_ct	xyz
1186	2	assetfinder	xyz
1186	2	subfinder	xyz
1186	2	brand_ct	xyz
1187	2	assetfinder	xyz
1187	2	subfinder	xyz
1187	2	brand_ct	xyz
1188	2	assetfinder	xyz
1188	2	subfinder	xyz
1188	2	brand_ct	xyz
1189	2	assetfinder	xyz
1189	2	subfinder	xyz
1189	2	brand_ct	xyz
1190	2	assetfinder	xyz
1190	2	subfinder	xyz
1190	2	brand_ct	xyz
1191	2	assetfinder	xyz
1191	2	subfinder	xyz
1191	2	brand_ct	xyz
1192	2	assetfinder	xyz
1192	2	subfinder	xyz
1192	2	brand_ct	xyz
1193	2	assetfinder	xyz
1193	2	subfinder	xyz
1193	2	brand_ct	xyz
1194	2	assetfinder	xyz
1194	2	subfinder	xyz
1194	2	brand_ct	xyz
1195	2	assetfinder	xyz
1196	2	assetfinder	xyz
1196	2	subfinder	xyz
1196	2	brand_ct	xyz
1197	2	assetfinder	xyz
1197	2	subfinder	xyz
1197	2	brand_ct	xyz
1198	2	assetfinder	xyz
1198	2	subfinder	xyz
1198	2	brand_ct	xyz
1199	2	brand_ct	xyz
1200	2	subfinder	xyz
1201	2	brand_ct	xyz
1202	2	assetfinder	xyz
1202	2	subfinder	xyz
1202	2	brand_ct	xyz
1203	2	assetfinder	xyz
1203	2	subfinder	xyz
1203	2	brand_ct	xyz
1204	2	assetfinder	xyz
1204	2	subfinder	xyz
1204	2	brand_ct	xyz
1205	2	assetfinder	xyz
1205	2	subfinder	xyz
1205	2	brand_ct	xyz
1206	2	assetfinder	xyz
1206	2	subfinder	xyz
1206	2	brand_ct	xyz
1207	2	assetfinder	xyz
1207	2	subfinder	xyz
1207	2	brand_ct	xyz
1208	2	assetfinder	xyz
1208	2	subfinder	xyz
1208	2	brand_ct	xyz
1209	2	assetfinder	xyz
1209	2	subfinder	xyz
1209	2	brand_ct	xyz
1210	2	assetfinder	xyz
1210	2	subfinder	xyz
1210	2	brand_ct	xyz
1211	2	assetfinder	xyz
1211	2	subfinder	xyz
1211	2	brand_ct	xyz
1212	2	assetfinder	xyz
1212	2	subfinder	xyz
1212	2	brand_ct	xyz
1213	2	assetfinder	xyz
1213	2	subfinder	xyz
1213	2	brand_ct	xyz
1214	2	assetfinder	xyz
1214	2	subfinder	xyz
1214	2	brand_ct	xyz
1215	2	assetfinder	xyz
1215	2	subfinder	xyz
1215	2	brand_ct	xyz
1216	2	assetfinder	xyz
1216	2	subfinder	xyz
1216	2	brand_ct	xyz
1217	2	assetfinder	xyz
1217	2	subfinder	xyz
1217	2	brand_ct	xyz
1218	2	assetfinder	xyz
1218	2	subfinder	xyz
1218	2	brand_ct	xyz
1219	2	assetfinder	xyz
1219	2	subfinder	xyz
1219	2	brand_ct	xyz
1220	2	assetfinder	xyz
1220	2	subfinder	xyz
1220	2	brand_ct	xyz
1221	2	assetfinder	xyz
1221	2	subfinder	xyz
1221	2	brand_ct	xyz
1222	2	assetfinder	xyz
1222	2	subfinder	xyz
1222	2	brand_ct	xyz
1223	2	assetfinder	xyz
1223	2	subfinder	xyz
1223	2	brand_ct	xyz
1224	2	assetfinder	xyz
1224	2	subfinder	xyz
1224	2	brand_ct	xyz
1225	2	assetfinder	xyz
1225	2	subfinder	xyz
1225	2	brand_ct	xyz
1226	2	assetfinder	xyz
1226	2	subfinder	xyz
1226	2	brand_ct	xyz
1227	2	assetfinder	xyz
1227	2	subfinder	xyz
1227	2	brand_ct	xyz
1228	2	assetfinder	xyz
1229	2	assetfinder	xyz
1229	2	subfinder	xyz
1229	2	brand_ct	xyz
1230	2	assetfinder	xyz
1230	2	subfinder	xyz
1230	2	brand_ct	xyz
1231	2	assetfinder	xyz
1231	2	subfinder	xyz
1231	2	brand_ct	xyz
1232	2	assetfinder	xyz
1232	2	subfinder	xyz
1232	2	brand_ct	xyz
1233	2	assetfinder	xyz
1233	2	subfinder	xyz
1233	2	brand_ct	xyz
1234	2	assetfinder	xyz
1234	2	subfinder	xyz
1234	2	brand_ct	xyz
1235	2	assetfinder	xyz
1235	2	subfinder	xyz
1235	2	brand_ct	xyz
1236	2	assetfinder	xyz
1236	2	subfinder	xyz
1236	2	brand_ct	xyz
1237	2	assetfinder	xyz
1237	2	subfinder	xyz
1237	2	brand_ct	xyz
1238	2	assetfinder	xyz
1238	2	subfinder	xyz
1238	2	brand_ct	xyz
1239	2	assetfinder	xyz
1239	2	subfinder	xyz
1239	2	brand_ct	xyz
1240	2	assetfinder	xyz
1240	2	subfinder	xyz
1240	2	brand_ct	xyz
1241	2	assetfinder	xyz
1241	2	subfinder	xyz
1241	2	brand_ct	xyz
1242	2	assetfinder	xyz
1242	2	subfinder	xyz
1242	2	brand_ct	xyz
1243	2	assetfinder	xyz
1243	2	subfinder	xyz
1243	2	brand_ct	xyz
1244	2	assetfinder	xyz
1244	2	subfinder	xyz
1244	2	brand_ct	xyz
1245	2	assetfinder	xyz
1245	2	subfinder	xyz
1245	2	brand_ct	xyz
1246	2	assetfinder	xyz
1246	2	subfinder	xyz
1246	2	brand_ct	xyz
1247	2	assetfinder	xyz
1247	2	subfinder	xyz
1247	2	brand_ct	xyz
1248	2	assetfinder	xyz
1248	2	subfinder	xyz
1248	2	brand_ct	xyz
1249	2	assetfinder	xyz
1249	2	subfinder	xyz
1249	2	brand_ct	xyz
1250	2	assetfinder	xyz
1250	2	subfinder	xyz
1250	2	brand_ct	xyz
1251	2	assetfinder	xyz
1251	2	subfinder	xyz
1251	2	brand_ct	xyz
1252	2	assetfinder	xyz
1252	2	subfinder	xyz
1252	2	brand_ct	xyz
1253	2	assetfinder	xyz
1253	2	subfinder	xyz
1253	2	brand_ct	xyz
1254	2	assetfinder	xyz
1254	2	subfinder	xyz
1254	2	brand_ct	xyz
1255	2	assetfinder	xyz
1255	2	subfinder	xyz
1255	2	brand_ct	xyz
1256	2	assetfinder	xyz
1256	2	subfinder	xyz
1256	2	brand_ct	xyz
1257	2	assetfinder	xyz
1257	2	subfinder	xyz
1257	2	brand_ct	xyz
1258	2	assetfinder	xyz
1258	2	subfinder	xyz
1258	2	brand_ct	xyz
1259	2	assetfinder	xyz
1259	2	subfinder	xyz
1259	2	brand_ct	xyz
1260	2	assetfinder	xyz
1261	2	assetfinder	xyz
1261	2	subfinder	xyz
1261	2	brand_ct	xyz
1262	2	assetfinder	xyz
1262	2	subfinder	xyz
1262	2	brand_ct	xyz
1263	2	assetfinder	xyz
1264	2	assetfinder	xyz
1264	2	subfinder	xyz
1264	2	brand_ct	xyz
1265	2	assetfinder	xyz
1265	2	subfinder	xyz
1265	2	brand_ct	xyz
1266	2	assetfinder	xyz
1266	2	subfinder	xyz
1266	2	brand_ct	xyz
1267	2	assetfinder	xyz
1267	2	subfinder	xyz
1267	2	brand_ct	xyz
1268	2	assetfinder	xyz
1268	2	subfinder	xyz
1268	2	brand_ct	xyz
1269	2	assetfinder	xyz
1269	2	subfinder	xyz
1269	2	brand_ct	xyz
1270	2	assetfinder	xyz
1270	2	subfinder	xyz
1270	2	brand_ct	xyz
1271	2	assetfinder	xyz
1271	2	subfinder	xyz
1271	2	brand_ct	xyz
1272	2	assetfinder	xyz
1272	2	subfinder	xyz
1272	2	brand_ct	xyz
1273	2	assetfinder	xyz
1273	2	subfinder	xyz
1273	2	brand_ct	xyz
1274	2	assetfinder	xyz
1274	2	subfinder	xyz
1274	2	brand_ct	xyz
1275	2	assetfinder	xyz
1275	2	subfinder	xyz
1275	2	brand_ct	xyz
1276	2	assetfinder	xyz
1276	2	subfinder	xyz
1276	2	brand_ct	xyz
1277	2	assetfinder	xyz
1278	2	assetfinder	xyz
1278	2	subfinder	xyz
1278	2	brand_ct	xyz
1279	2	assetfinder	xyz
1279	2	subfinder	xyz
1279	2	brand_ct	xyz
1280	2	assetfinder	xyz
1280	2	subfinder	xyz
1280	2	brand_ct	xyz
1281	2	brand_pattern	xyz
1282	2	assetfinder	xyz
1282	2	subfinder	xyz
1282	2	brand_ct	xyz
1283	2	assetfinder	xyz
1283	2	subfinder	xyz
1283	2	brand_ct	xyz
1284	2	brand_pattern	xyz
1285	2	assetfinder	xyz
1285	2	subfinder	xyz
1285	2	brand_ct	xyz
1286	2	assetfinder	xyz
1286	2	subfinder	xyz
1286	2	brand_ct	xyz
1287	2	assetfinder	xyz
1287	2	subfinder	xyz
1287	2	brand_ct	xyz
1288	2	assetfinder	xyz
1288	2	subfinder	xyz
1288	2	brand_ct	xyz
1289	2	assetfinder	xyz
1289	2	subfinder	xyz
1289	2	brand_ct	xyz
1290	2	assetfinder	xyz
1290	2	subfinder	xyz
1290	2	brand_ct	xyz
1291	2	assetfinder	xyz
1291	2	subfinder	xyz
1291	2	brand_ct	xyz
1292	2	assetfinder	xyz
1292	2	subfinder	xyz
1292	2	brand_ct	xyz
1293	2	assetfinder	xyz
1293	2	subfinder	xyz
1293	2	brand_ct	xyz
1294	2	assetfinder	xyz
1294	2	subfinder	xyz
1294	2	brand_ct	xyz
1295	2	assetfinder	xyz
1295	2	subfinder	xyz
1295	2	brand_ct	xyz
1296	2	assetfinder	xyz
1296	2	subfinder	xyz
1296	2	brand_ct	xyz
1297	2	assetfinder	xyz
1297	2	subfinder	xyz
1297	2	brand_ct	xyz
1298	2	assetfinder	xyz
1298	2	subfinder	xyz
1298	2	brand_ct	xyz
1299	2	assetfinder	xyz
1299	2	subfinder	xyz
1299	2	brand_ct	xyz
1300	2	assetfinder	xyz
1300	2	subfinder	xyz
1300	2	brand_ct	xyz
1301	2	assetfinder	xyz
1301	2	subfinder	xyz
1301	2	brand_ct	xyz
1302	2	assetfinder	xyz
1302	2	subfinder	xyz
1302	2	brand_ct	xyz
1303	2	assetfinder	xyz
1303	2	subfinder	xyz
1303	2	brand_ct	xyz
1304	2	assetfinder	xyz
1304	2	subfinder	xyz
1304	2	brand_ct	xyz
1305	2	assetfinder	xyz
1305	2	subfinder	xyz
1305	2	brand_ct	xyz
1306	2	assetfinder	xyz
1306	2	subfinder	xyz
1306	2	brand_ct	xyz
1307	2	assetfinder	xyz
1307	2	subfinder	xyz
1307	2	brand_ct	xyz
1308	2	assetfinder	xyz
1308	2	subfinder	xyz
1308	2	brand_ct	xyz
1309	2	assetfinder	xyz
1309	2	subfinder	xyz
1309	2	brand_ct	xyz
1310	2	assetfinder	xyz
1311	2	assetfinder	xyz
1311	2	subfinder	xyz
1311	2	brand_ct	xyz
1312	2	assetfinder	xyz
1312	2	subfinder	xyz
1312	2	brand_ct	xyz
1313	2	assetfinder	xyz
1313	2	subfinder	xyz
1313	2	brand_ct	xyz
1314	2	assetfinder	xyz
1314	2	subfinder	xyz
1314	2	brand_ct	xyz
1315	2	assetfinder	xyz
1315	2	subfinder	xyz
1315	2	brand_ct	xyz
1316	2	assetfinder	xyz
1316	2	subfinder	xyz
1316	2	brand_ct	xyz
1317	2	assetfinder	xyz
1317	2	subfinder	xyz
1317	2	brand_ct	xyz
1318	2	assetfinder	xyz
1318	2	subfinder	xyz
1318	2	brand_ct	xyz
1319	2	assetfinder	xyz
1319	2	subfinder	xyz
1319	2	brand_ct	xyz
1320	2	assetfinder	xyz
1320	2	subfinder	xyz
1320	2	brand_ct	xyz
1321	2	assetfinder	xyz
1321	2	subfinder	xyz
1321	2	brand_ct	xyz
1322	2	assetfinder	xyz
1322	2	subfinder	xyz
1322	2	brand_ct	xyz
1323	2	assetfinder	xyz
1323	2	subfinder	xyz
1323	2	brand_ct	xyz
1324	2	assetfinder	xyz
1324	2	subfinder	xyz
1324	2	brand_ct	xyz
1325	2	assetfinder	xyz
1325	2	subfinder	xyz
1325	2	brand_ct	xyz
1326	2	assetfinder	xyz
1326	2	subfinder	xyz
1326	2	brand_ct	xyz
1327	2	assetfinder	xyz
1327	2	subfinder	xyz
1327	2	brand_ct	xyz
1328	2	assetfinder	xyz
1328	2	subfinder	xyz
1328	2	brand_ct	xyz
1329	2	assetfinder	xyz
1329	2	subfinder	xyz
1329	2	brand_ct	xyz
1330	2	assetfinder	xyz
1330	2	subfinder	xyz
1330	2	brand_ct	xyz
1331	2	assetfinder	xyz
1331	2	subfinder	xyz
1331	2	brand_ct	xyz
1332	2	assetfinder	xyz
1332	2	subfinder	xyz
1332	2	brand_ct	xyz
1333	2	assetfinder	xyz
1333	2	subfinder	xyz
1333	2	brand_ct	xyz
1334	2	assetfinder	xyz
1334	2	subfinder	xyz
1334	2	brand_ct	xyz
1335	2	assetfinder	xyz
1335	2	subfinder	xyz
1335	2	brand_ct	xyz
1336	2	subfinder	xyz
1336	2	brand_ct	xyz
1337	2	assetfinder	xyz
1337	2	subfinder	xyz
1337	2	brand_ct	xyz
1338	2	assetfinder	xyz
1338	2	subfinder	xyz
1338	2	brand_ct	xyz
1339	2	assetfinder	xyz
1339	2	subfinder	xyz
1339	2	brand_ct	xyz
1340	2	assetfinder	xyz
1340	2	subfinder	xyz
1340	2	brand_ct	xyz
1341	2	assetfinder	xyz
1341	2	subfinder	xyz
1341	2	brand_ct	xyz
1342	2	assetfinder	xyz
1342	2	subfinder	xyz
1342	2	brand_ct	xyz
1343	2	assetfinder	xyz
1343	2	subfinder	xyz
1343	2	brand_ct	xyz
1344	2	assetfinder	xyz
1344	2	subfinder	xyz
1344	2	brand_ct	xyz
1345	2	assetfinder	xyz
1345	2	subfinder	xyz
1345	2	brand_ct	xyz
1346	2	assetfinder	xyz
1346	2	subfinder	xyz
1346	2	brand_ct	xyz
1347	2	assetfinder	xyz
1347	2	subfinder	xyz
1347	2	brand_ct	xyz
1348	2	assetfinder	xyz
1349	2	assetfinder	xyz
1349	2	subfinder	xyz
1349	2	brand_ct	xyz
1350	2	assetfinder	xyz
1350	2	subfinder	xyz
1350	2	brand_ct	xyz
1351	2	assetfinder	xyz
1351	2	subfinder	xyz
1351	2	brand_ct	xyz
1352	2	assetfinder	xyz
1352	2	subfinder	xyz
1352	2	brand_ct	xyz
1353	2	assetfinder	xyz
1354	2	assetfinder	xyz
1354	2	subfinder	xyz
1354	2	brand_ct	xyz
1355	2	assetfinder	xyz
1355	2	subfinder	xyz
1355	2	brand_ct	xyz
1356	2	assetfinder	xyz
1356	2	subfinder	xyz
1356	2	brand_ct	xyz
1357	2	assetfinder	xyz
1357	2	subfinder	xyz
1357	2	brand_ct	xyz
1358	2	assetfinder	xyz
1358	2	subfinder	xyz
1358	2	brand_ct	xyz
1359	2	assetfinder	xyz
1359	2	subfinder	xyz
1359	2	brand_ct	xyz
1360	2	assetfinder	xyz
1360	2	subfinder	xyz
1360	2	brand_ct	xyz
1361	2	assetfinder	xyz
1361	2	subfinder	xyz
1361	2	brand_ct	xyz
1362	2	assetfinder	xyz
1362	2	subfinder	xyz
1362	2	brand_ct	xyz
1363	2	assetfinder	xyz
1364	2	assetfinder	xyz
1364	2	brand_ct	xyz
1365	2	assetfinder	xyz
1365	2	brand_ct	xyz
1366	2	assetfinder	xyz
1366	2	brand_ct	xyz
1367	2	assetfinder	xyz
1367	2	subfinder	xyz
1367	2	brand_ct	xyz
1368	2	assetfinder	xyz
1368	2	subfinder	xyz
1368	2	brand_ct	xyz
1369	2	assetfinder	xyz
1369	2	subfinder	xyz
1369	2	brand_ct	xyz
1370	2	assetfinder	xyz
1370	2	subfinder	xyz
1370	2	brand_ct	xyz
1371	2	assetfinder	xyz
1371	2	subfinder	xyz
1371	2	brand_ct	xyz
1372	2	assetfinder	xyz
1372	2	subfinder	xyz
1372	2	brand_ct	xyz
1373	2	assetfinder	xyz
1373	2	subfinder	xyz
1373	2	brand_ct	xyz
1374	2	assetfinder	xyz
1374	2	subfinder	xyz
1374	2	brand_ct	xyz
1375	2	assetfinder	xyz
1375	2	subfinder	xyz
1375	2	brand_ct	xyz
1376	2	assetfinder	xyz
1376	2	subfinder	xyz
1376	2	brand_ct	xyz
1377	2	assetfinder	xyz
1377	2	subfinder	xyz
1377	2	brand_ct	xyz
1378	2	assetfinder	xyz
1378	2	subfinder	xyz
1378	2	brand_ct	xyz
1379	2	assetfinder	xyz
1379	2	subfinder	xyz
1379	2	brand_ct	xyz
1380	2	assetfinder	xyz
1380	2	subfinder	xyz
1380	2	brand_ct	xyz
1381	2	assetfinder	xyz
1381	2	subfinder	xyz
1381	2	brand_ct	xyz
1382	2	assetfinder	xyz
1382	2	subfinder	xyz
1382	2	brand_ct	xyz
1383	2	assetfinder	xyz
1383	2	subfinder	xyz
1383	2	brand_ct	xyz
1384	2	assetfinder	xyz
1384	2	subfinder	xyz
1384	2	brand_ct	xyz
1385	2	assetfinder	xyz
1385	2	subfinder	xyz
1385	2	brand_ct	xyz
1386	2	assetfinder	xyz
1386	2	subfinder	xyz
1386	2	brand_ct	xyz
1387	2	assetfinder	xyz
1387	2	subfinder	xyz
1387	2	brand_ct	xyz
1388	2	assetfinder	xyz
1388	2	subfinder	xyz
1388	2	brand_ct	xyz
1389	2	assetfinder	xyz
1389	2	subfinder	xyz
1389	2	brand_ct	xyz
1390	2	assetfinder	xyz
1390	2	subfinder	xyz
1390	2	brand_ct	xyz
1391	2	assetfinder	xyz
1391	2	subfinder	xyz
1391	2	brand_ct	xyz
1392	2	assetfinder	xyz
1392	2	subfinder	xyz
1392	2	brand_ct	xyz
1393	2	assetfinder	xyz
1393	2	subfinder	xyz
1393	2	brand_ct	xyz
1394	2	assetfinder	xyz
1394	2	subfinder	xyz
1394	2	brand_ct	xyz
1395	2	assetfinder	xyz
1395	2	subfinder	xyz
1395	2	brand_ct	xyz
1396	2	assetfinder	xyz
1396	2	subfinder	xyz
1396	2	brand_ct	xyz
1397	2	assetfinder	xyz
1397	2	subfinder	xyz
1397	2	brand_ct	xyz
1398	2	assetfinder	xyz
1398	2	subfinder	xyz
1398	2	brand_ct	xyz
1399	2	assetfinder	xyz
1399	2	subfinder	xyz
1399	2	brand_ct	xyz
1400	2	assetfinder	xyz
1400	2	subfinder	xyz
1400	2	brand_ct	xyz
1401	2	assetfinder	xyz
1401	2	subfinder	xyz
1401	2	brand_ct	xyz
1402	2	assetfinder	xyz
1402	2	subfinder	xyz
1402	2	brand_ct	xyz
1403	2	assetfinder	xyz
1403	2	subfinder	xyz
1403	2	brand_ct	xyz
1404	2	assetfinder	xyz
1404	2	subfinder	xyz
1404	2	brand_ct	xyz
1405	2	assetfinder	xyz
1405	2	subfinder	xyz
1405	2	brand_ct	xyz
1406	2	assetfinder	xyz
1406	2	subfinder	xyz
1406	2	brand_ct	xyz
1407	2	assetfinder	xyz
1407	2	subfinder	xyz
1407	2	brand_ct	xyz
1408	2	assetfinder	xyz
1408	2	subfinder	xyz
1408	2	brand_ct	xyz
1409	2	assetfinder	xyz
1409	2	subfinder	xyz
1409	2	brand_ct	xyz
1410	2	assetfinder	xyz
1410	2	subfinder	xyz
1410	2	brand_ct	xyz
1411	2	assetfinder	xyz
1411	2	subfinder	xyz
1411	2	brand_ct	xyz
1412	2	assetfinder	xyz
1412	2	subfinder	xyz
1412	2	brand_ct	xyz
1413	2	assetfinder	xyz
1413	2	subfinder	xyz
1413	2	brand_ct	xyz
1414	2	assetfinder	xyz
1414	2	subfinder	xyz
1414	2	brand_ct	xyz
1415	2	assetfinder	xyz
1415	2	subfinder	xyz
1415	2	brand_ct	xyz
1416	2	assetfinder	xyz
1416	2	subfinder	xyz
1416	2	brand_ct	xyz
1417	2	assetfinder	xyz
1417	2	subfinder	xyz
1417	2	brand_ct	xyz
1418	2	assetfinder	xyz
1418	2	subfinder	xyz
1418	2	brand_ct	xyz
1419	2	assetfinder	xyz
1419	2	subfinder	xyz
1419	2	brand_ct	xyz
1420	2	assetfinder	xyz
1420	2	subfinder	xyz
1420	2	brand_ct	xyz
1421	2	assetfinder	xyz
1421	2	subfinder	xyz
1421	2	brand_ct	xyz
1422	2	assetfinder	xyz
1422	2	subfinder	xyz
1422	2	brand_ct	xyz
1423	2	assetfinder	xyz
1423	2	subfinder	xyz
1423	2	brand_ct	xyz
1424	2	assetfinder	xyz
1424	2	subfinder	xyz
1424	2	brand_ct	xyz
1425	2	assetfinder	xyz
1425	2	subfinder	xyz
1425	2	brand_ct	xyz
1426	2	assetfinder	xyz
1426	2	subfinder	xyz
1426	2	brand_ct	xyz
1427	2	assetfinder	xyz
1427	2	subfinder	xyz
1427	2	brand_ct	xyz
1428	2	assetfinder	xyz
1428	2	subfinder	xyz
1428	2	brand_ct	xyz
1429	2	assetfinder	xyz
1429	2	subfinder	xyz
1429	2	brand_ct	xyz
1430	2	assetfinder	xyz
1430	2	subfinder	xyz
1430	2	brand_ct	xyz
1431	2	assetfinder	xyz
1431	2	subfinder	xyz
1431	2	brand_ct	xyz
1432	2	assetfinder	xyz
1432	2	subfinder	xyz
1432	2	brand_ct	xyz
1433	2	assetfinder	xyz
1433	2	subfinder	xyz
1433	2	brand_ct	xyz
1434	2	assetfinder	xyz
1434	2	subfinder	xyz
1434	2	brand_ct	xyz
1435	2	assetfinder	xyz
1435	2	subfinder	xyz
1435	2	brand_ct	xyz
1436	2	assetfinder	xyz
1436	2	subfinder	xyz
1436	2	brand_ct	xyz
1437	2	assetfinder	xyz
1437	2	subfinder	xyz
1437	2	brand_ct	xyz
1438	2	assetfinder	xyz
1438	2	subfinder	xyz
1438	2	brand_ct	xyz
1439	2	assetfinder	xyz
1439	2	subfinder	xyz
1439	2	brand_ct	xyz
1440	2	assetfinder	xyz
1440	2	subfinder	xyz
1440	2	brand_ct	xyz
1441	2	assetfinder	xyz
1441	2	subfinder	xyz
1441	2	brand_ct	xyz
1442	2	assetfinder	xyz
1442	2	subfinder	xyz
1442	2	brand_ct	xyz
1443	2	assetfinder	xyz
1443	2	subfinder	xyz
1443	2	brand_ct	xyz
1444	2	assetfinder	xyz
1444	2	subfinder	xyz
1444	2	brand_ct	xyz
1445	2	assetfinder	xyz
1445	2	subfinder	xyz
1445	2	brand_ct	xyz
1446	2	assetfinder	xyz
1446	2	subfinder	xyz
1446	2	brand_ct	xyz
1447	2	assetfinder	xyz
1447	2	subfinder	xyz
1447	2	brand_ct	xyz
1448	2	assetfinder	xyz
1448	2	subfinder	xyz
1448	2	brand_ct	xyz
1449	2	assetfinder	xyz
1449	2	subfinder	xyz
1449	2	brand_ct	xyz
1450	2	assetfinder	xyz
1450	2	subfinder	xyz
1450	2	brand_ct	xyz
1451	2	assetfinder	xyz
1451	2	subfinder	xyz
1451	2	brand_ct	xyz
1452	2	assetfinder	xyz
1452	2	subfinder	xyz
1452	2	brand_ct	xyz
1453	2	assetfinder	xyz
1453	2	subfinder	xyz
1453	2	brand_ct	xyz
1454	2	assetfinder	xyz
1454	2	subfinder	xyz
1454	2	brand_ct	xyz
1455	2	assetfinder	xyz
1455	2	subfinder	xyz
1455	2	brand_ct	xyz
1456	2	brand_pattern	xyz
1457	2	brand_pattern	xyz
1458	2	assetfinder	xyz
1458	2	subfinder	xyz
1458	2	brand_ct	xyz
1459	2	assetfinder	xyz
1459	2	subfinder	xyz
1459	2	brand_ct	xyz
1460	2	assetfinder	xyz
1460	2	subfinder	xyz
1460	2	brand_ct	xyz
1461	2	assetfinder	xyz
1461	2	subfinder	xyz
1461	2	brand_ct	xyz
1462	2	assetfinder	xyz
1462	2	subfinder	xyz
1462	2	brand_ct	xyz
1463	2	assetfinder	xyz
1463	2	subfinder	xyz
1463	2	brand_ct	xyz
1464	2	assetfinder	xyz
1464	2	subfinder	xyz
1464	2	brand_ct	xyz
1465	2	assetfinder	xyz
1465	2	subfinder	xyz
1465	2	brand_ct	xyz
1466	2	assetfinder	xyz
1466	2	subfinder	xyz
1466	2	brand_ct	xyz
1467	2	assetfinder	xyz
1467	2	subfinder	xyz
1467	2	brand_ct	xyz
1468	2	assetfinder	xyz
1468	2	subfinder	xyz
1468	2	brand_ct	xyz
1469	2	assetfinder	xyz
1469	2	subfinder	xyz
1469	2	brand_ct	xyz
1470	2	assetfinder	xyz
1470	2	subfinder	xyz
1470	2	brand_ct	xyz
1471	2	assetfinder	xyz
1471	2	subfinder	xyz
1471	2	brand_ct	xyz
1472	2	assetfinder	xyz
1472	2	subfinder	xyz
1472	2	brand_ct	xyz
1473	2	assetfinder	xyz
1473	2	subfinder	xyz
1473	2	brand_ct	xyz
1474	2	assetfinder	xyz
1474	2	subfinder	xyz
1474	2	brand_ct	xyz
1475	2	assetfinder	xyz
1475	2	subfinder	xyz
1475	2	brand_ct	xyz
1476	2	assetfinder	xyz
1476	2	subfinder	xyz
1476	2	brand_ct	xyz
1477	2	assetfinder	xyz
1477	2	subfinder	xyz
1477	2	brand_ct	xyz
1478	2	assetfinder	xyz
1478	2	subfinder	xyz
1478	2	brand_ct	xyz
1479	2	assetfinder	xyz
1479	2	subfinder	xyz
1479	2	brand_ct	xyz
1480	2	assetfinder	xyz
1480	2	subfinder	xyz
1480	2	brand_ct	xyz
1481	2	assetfinder	xyz
1481	2	subfinder	xyz
1481	2	brand_ct	xyz
1482	2	assetfinder	xyz
1482	2	subfinder	xyz
1482	2	brand_ct	xyz
1483	2	assetfinder	xyz
1483	2	subfinder	xyz
1483	2	brand_ct	xyz
1484	2	assetfinder	xyz
1484	2	subfinder	xyz
1484	2	brand_ct	xyz
1485	2	assetfinder	xyz
1485	2	subfinder	xyz
1485	2	brand_ct	xyz
1486	2	assetfinder	xyz
1486	2	subfinder	xyz
1486	2	brand_ct	xyz
1487	2	assetfinder	xyz
1487	2	subfinder	xyz
1487	2	brand_ct	xyz
1488	2	assetfinder	xyz
1488	2	subfinder	xyz
1488	2	brand_ct	xyz
1489	2	assetfinder	xyz
1489	2	subfinder	xyz
1489	2	brand_ct	xyz
1490	2	assetfinder	xyz
1490	2	subfinder	xyz
1490	2	brand_ct	xyz
1491	2	assetfinder	xyz
1491	2	subfinder	xyz
1491	2	brand_ct	xyz
1492	2	assetfinder	xyz
1492	2	subfinder	xyz
1492	2	brand_ct	xyz
1493	2	assetfinder	xyz
1493	2	subfinder	xyz
1493	2	brand_ct	xyz
1494	2	assetfinder	xyz
1494	2	subfinder	xyz
1494	2	brand_ct	xyz
1495	2	assetfinder	xyz
1495	2	subfinder	xyz
1495	2	brand_ct	xyz
1496	2	assetfinder	xyz
1496	2	subfinder	xyz
1496	2	brand_ct	xyz
1497	2	assetfinder	xyz
1498	2	assetfinder	xyz
1498	2	subfinder	xyz
1498	2	brand_ct	xyz
1499	2	assetfinder	xyz
1499	2	subfinder	xyz
1499	2	brand_ct	xyz
1500	2	assetfinder	xyz
1500	2	subfinder	xyz
1500	2	brand_ct	xyz
1501	2	assetfinder	xyz
1501	2	subfinder	xyz
1501	2	brand_ct	xyz
1502	2	assetfinder	xyz
1502	2	subfinder	xyz
1502	2	brand_ct	xyz
1503	2	assetfinder	xyz
1503	2	subfinder	xyz
1503	2	brand_ct	xyz
1504	2	assetfinder	xyz
1504	2	subfinder	xyz
1504	2	brand_ct	xyz
1505	2	assetfinder	xyz
1505	2	subfinder	xyz
1505	2	brand_ct	xyz
1506	2	assetfinder	xyz
1506	2	subfinder	xyz
1506	2	brand_ct	xyz
1507	2	assetfinder	xyz
1507	2	subfinder	xyz
1507	2	brand_ct	xyz
1508	2	assetfinder	xyz
1508	2	subfinder	xyz
1508	2	brand_ct	xyz
1509	2	assetfinder	xyz
1509	2	subfinder	xyz
1509	2	brand_ct	xyz
1510	2	assetfinder	xyz
1510	2	subfinder	xyz
1510	2	brand_ct	xyz
1511	2	assetfinder	xyz
1511	2	subfinder	xyz
1512	2	assetfinder	xyz
1512	2	subfinder	xyz
1512	2	brand_ct	xyz
1513	2	assetfinder	xyz
1513	2	subfinder	xyz
1513	2	brand_ct	xyz
1514	2	assetfinder	xyz
1514	2	subfinder	xyz
1515	2	assetfinder	xyz
1515	2	subfinder	xyz
1515	2	brand_ct	xyz
1516	2	assetfinder	xyz
1516	2	subfinder	xyz
1516	2	brand_ct	xyz
1517	2	assetfinder	xyz
1517	2	subfinder	xyz
1517	2	brand_ct	xyz
1518	2	assetfinder	xyz
1518	2	subfinder	xyz
1518	2	brand_ct	xyz
1519	2	assetfinder	xyz
1519	2	subfinder	xyz
1519	2	brand_ct	xyz
1520	2	assetfinder	xyz
1520	2	subfinder	xyz
1520	2	brand_ct	xyz
1521	2	assetfinder	xyz
1521	2	subfinder	xyz
1521	2	brand_ct	xyz
1522	2	assetfinder	xyz
1522	2	subfinder	xyz
1522	2	brand_ct	xyz
1523	2	assetfinder	xyz
1523	2	subfinder	xyz
1523	2	brand_ct	xyz
1524	2	assetfinder	xyz
1524	2	subfinder	xyz
1524	2	brand_ct	xyz
1525	2	assetfinder	xyz
1525	2	subfinder	xyz
1525	2	brand_ct	xyz
1526	2	subfinder	xyz
1527	2	brand_ct	xyz
1528	2	assetfinder	xyz
1528	2	subfinder	xyz
1528	2	brand_ct	xyz
1529	2	assetfinder	xyz
1529	2	subfinder	xyz
1529	2	brand_ct	xyz
1530	2	assetfinder	xyz
1530	2	subfinder	xyz
1530	2	brand_ct	xyz
1531	2	assetfinder	xyz
1531	2	subfinder	xyz
1531	2	brand_ct	xyz
1532	2	assetfinder	xyz
1532	2	subfinder	xyz
1532	2	brand_ct	xyz
1533	2	assetfinder	xyz
1533	2	subfinder	xyz
1533	2	brand_ct	xyz
1534	2	assetfinder	xyz
1534	2	subfinder	xyz
1534	2	brand_ct	xyz
1535	2	assetfinder	xyz
1535	2	subfinder	xyz
1535	2	brand_ct	xyz
1536	2	assetfinder	xyz
1536	2	subfinder	xyz
1536	2	brand_ct	xyz
1537	2	assetfinder	xyz
1537	2	subfinder	xyz
1537	2	brand_ct	xyz
1538	2	assetfinder	xyz
1538	2	subfinder	xyz
1538	2	brand_ct	xyz
1539	2	assetfinder	xyz
1539	2	subfinder	xyz
1539	2	brand_ct	xyz
1540	2	assetfinder	xyz
1540	2	subfinder	xyz
1540	2	brand_ct	xyz
1541	2	assetfinder	xyz
1541	2	subfinder	xyz
1541	2	brand_ct	xyz
1542	2	assetfinder	xyz
1542	2	subfinder	xyz
1542	2	brand_ct	xyz
1543	2	assetfinder	xyz
1543	2	subfinder	xyz
1543	2	brand_ct	xyz
1544	2	assetfinder	xyz
1544	2	subfinder	xyz
1544	2	brand_ct	xyz
1545	2	assetfinder	xyz
1545	2	subfinder	xyz
1545	2	brand_ct	xyz
1546	2	assetfinder	xyz
1546	2	subfinder	xyz
1546	2	brand_ct	xyz
1547	2	assetfinder	xyz
1547	2	subfinder	xyz
1547	2	brand_ct	xyz
1548	2	assetfinder	xyz
1548	2	subfinder	xyz
1548	2	brand_ct	xyz
1549	2	assetfinder	xyz
1549	2	subfinder	xyz
1549	2	brand_ct	xyz
1550	2	assetfinder	xyz
1550	2	subfinder	xyz
1550	2	brand_ct	xyz
1551	2	assetfinder	xyz
1551	2	subfinder	xyz
1551	2	brand_ct	xyz
1552	2	assetfinder	xyz
1552	2	subfinder	xyz
1552	2	brand_ct	xyz
1553	2	assetfinder	xyz
1553	2	subfinder	xyz
1553	2	brand_ct	xyz
1554	2	assetfinder	xyz
1554	2	subfinder	xyz
1554	2	brand_ct	xyz
1555	2	assetfinder	xyz
1555	2	subfinder	xyz
1555	2	brand_ct	xyz
1556	2	assetfinder	xyz
1556	2	subfinder	xyz
1556	2	brand_ct	xyz
1557	2	assetfinder	xyz
1557	2	subfinder	xyz
1558	2	assetfinder	xyz
1558	2	subfinder	xyz
1558	2	brand_ct	xyz
1559	2	assetfinder	xyz
1559	2	subfinder	xyz
1559	2	brand_ct	xyz
1560	2	assetfinder	xyz
1560	2	subfinder	xyz
1560	2	brand_ct	xyz
1561	2	assetfinder	xyz
1561	2	subfinder	xyz
1561	2	brand_ct	xyz
1562	2	assetfinder	xyz
1562	2	subfinder	xyz
1562	2	brand_ct	xyz
1563	2	assetfinder	xyz
1563	2	subfinder	xyz
1563	2	brand_ct	xyz
1564	2	assetfinder	xyz
1564	2	subfinder	xyz
1564	2	brand_ct	xyz
1565	2	assetfinder	xyz
1565	2	subfinder	xyz
1565	2	brand_ct	xyz
1566	2	assetfinder	xyz
1566	2	subfinder	xyz
1566	2	brand_ct	xyz
1567	2	assetfinder	xyz
1567	2	subfinder	xyz
1567	2	brand_ct	xyz
1568	2	assetfinder	xyz
1568	2	subfinder	xyz
1569	2	assetfinder	xyz
1569	2	subfinder	xyz
1570	2	assetfinder	xyz
1571	2	assetfinder	xyz
1572	2	assetfinder	xyz
1573	2	assetfinder	xyz
1573	2	subfinder	xyz
1573	2	brand_ct	xyz
1574	2	assetfinder	xyz
1575	2	assetfinder	xyz
1575	2	subfinder	xyz
1575	2	brand_ct	xyz
1576	2	assetfinder	xyz
1577	2	subfinder	xyz
1578	2	brand_ct	xyz
1579	2	assetfinder	xyz
1580	2	subfinder	xyz
1581	2	assetfinder	xyz
1581	2	brand_ct	xyz
1582	2	assetfinder	xyz
1582	2	subfinder	xyz
1582	2	brand_ct	xyz
1583	2	assetfinder	xyz
1583	2	subfinder	xyz
1583	2	brand_ct	xyz
1584	2	assetfinder	xyz
1584	2	subfinder	xyz
1584	2	brand_ct	xyz
1585	2	assetfinder	xyz
1585	2	subfinder	xyz
1585	2	brand_ct	xyz
1586	2	assetfinder	xyz
1586	2	subfinder	xyz
1586	2	brand_ct	xyz
1587	2	assetfinder	xyz
1587	2	subfinder	xyz
1587	2	brand_ct	xyz
1588	2	assetfinder	xyz
1588	2	subfinder	xyz
1588	2	brand_ct	xyz
1589	2	assetfinder	xyz
1589	2	subfinder	xyz
1589	2	brand_ct	xyz
1590	2	assetfinder	xyz
1590	2	subfinder	xyz
1590	2	brand_ct	xyz
1591	2	assetfinder	xyz
1591	2	subfinder	xyz
1591	2	brand_ct	xyz
1592	2	assetfinder	xyz
1592	2	subfinder	xyz
1592	2	brand_ct	xyz
1593	2	assetfinder	xyz
1593	2	subfinder	xyz
1593	2	brand_ct	xyz
1594	2	assetfinder	xyz
1594	2	subfinder	xyz
1594	2	brand_ct	xyz
1595	2	assetfinder	xyz
1595	2	subfinder	xyz
1595	2	brand_ct	xyz
1596	2	assetfinder	xyz
1596	2	subfinder	xyz
1596	2	brand_ct	xyz
1597	2	assetfinder	xyz
1597	2	subfinder	xyz
1597	2	brand_ct	xyz
1598	2	assetfinder	xyz
1598	2	subfinder	xyz
1598	2	brand_ct	xyz
1599	2	assetfinder	xyz
1599	2	subfinder	xyz
1599	2	brand_ct	xyz
1600	2	assetfinder	xyz
1600	2	subfinder	xyz
1600	2	brand_ct	xyz
1601	2	assetfinder	xyz
1601	2	subfinder	xyz
1601	2	brand_ct	xyz
1602	2	assetfinder	xyz
1602	2	subfinder	xyz
1602	2	brand_ct	xyz
1603	2	assetfinder	xyz
1603	2	subfinder	xyz
1603	2	brand_ct	xyz
1604	2	assetfinder	xyz
1604	2	subfinder	xyz
1604	2	brand_ct	xyz
1605	2	assetfinder	xyz
1605	2	subfinder	xyz
1605	2	brand_ct	xyz
1606	2	assetfinder	xyz
1606	2	subfinder	xyz
1606	2	brand_ct	xyz
1607	2	assetfinder	xyz
1607	2	subfinder	xyz
1607	2	brand_ct	xyz
1608	2	assetfinder	xyz
1608	2	subfinder	xyz
1608	2	brand_ct	xyz
1609	2	assetfinder	xyz
1609	2	subfinder	xyz
1609	2	brand_ct	xyz
1610	2	assetfinder	xyz
1611	2	assetfinder	xyz
1611	2	subfinder	xyz
1612	2	assetfinder	xyz
1612	2	subfinder	xyz
1612	2	brand_ct	xyz
1613	2	assetfinder	xyz
1613	2	subfinder	xyz
1613	2	brand_ct	xyz
1614	2	assetfinder	xyz
1614	2	subfinder	xyz
1614	2	brand_ct	xyz
1615	2	assetfinder	xyz
1615	2	subfinder	xyz
1615	2	brand_ct	xyz
1616	2	assetfinder	xyz
1616	2	subfinder	xyz
1616	2	brand_ct	xyz
1617	2	assetfinder	xyz
1617	2	subfinder	xyz
1617	2	brand_ct	xyz
1618	2	assetfinder	xyz
1618	2	subfinder	xyz
1618	2	brand_ct	xyz
1619	2	assetfinder	xyz
1619	2	subfinder	xyz
1619	2	brand_ct	xyz
1620	2	assetfinder	xyz
1620	2	subfinder	xyz
1620	2	brand_ct	xyz
1621	2	assetfinder	xyz
1621	2	subfinder	xyz
1621	2	brand_ct	xyz
1622	2	assetfinder	xyz
1622	2	subfinder	xyz
1622	2	brand_ct	xyz
1623	2	assetfinder	xyz
1623	2	subfinder	xyz
1623	2	brand_ct	xyz
1624	2	assetfinder	xyz
1624	2	subfinder	xyz
1624	2	brand_ct	xyz
1625	2	assetfinder	xyz
1625	2	subfinder	xyz
1625	2	brand_ct	xyz
1626	2	assetfinder	xyz
1626	2	subfinder	xyz
1626	2	brand_ct	xyz
1627	2	assetfinder	xyz
1627	2	subfinder	xyz
1627	2	brand_ct	xyz
1628	2	assetfinder	xyz
1628	2	subfinder	xyz
1628	2	brand_ct	xyz
1629	2	assetfinder	xyz
1629	2	subfinder	xyz
1629	2	brand_ct	xyz
1630	2	assetfinder	xyz
1630	2	subfinder	xyz
1630	2	brand_ct	xyz
1631	2	assetfinder	xyz
1632	2	assetfinder	xyz
1633	2	assetfinder	xyz
1633	2	subfinder	xyz
1633	2	brand_ct	xyz
1634	2	assetfinder	xyz
1634	2	subfinder	xyz
1634	2	brand_ct	xyz
1635	2	assetfinder	xyz
1635	2	subfinder	xyz
1635	2	brand_ct	xyz
1636	2	assetfinder	xyz
1636	2	subfinder	xyz
1636	2	brand_ct	xyz
1637	2	assetfinder	xyz
1637	2	subfinder	xyz
1637	2	brand_ct	xyz
1638	2	assetfinder	xyz
1638	2	subfinder	xyz
1638	2	brand_ct	xyz
1639	2	assetfinder	xyz
1640	2	assetfinder	xyz
1640	2	subfinder	xyz
1640	2	brand_ct	xyz
1641	2	assetfinder	xyz
1641	2	subfinder	xyz
1641	2	brand_ct	xyz
1642	2	assetfinder	xyz
1642	2	subfinder	xyz
1642	2	brand_ct	xyz
1643	2	assetfinder	xyz
1643	2	subfinder	xyz
1643	2	brand_ct	xyz
1644	2	assetfinder	xyz
1644	2	subfinder	xyz
1644	2	brand_ct	xyz
1645	2	assetfinder	xyz
1645	2	subfinder	xyz
1645	2	brand_ct	xyz
1646	2	assetfinder	xyz
1646	2	subfinder	xyz
1646	2	brand_ct	xyz
1647	2	assetfinder	xyz
1647	2	subfinder	xyz
1647	2	brand_ct	xyz
1648	2	assetfinder	xyz
1648	2	subfinder	xyz
1648	2	brand_ct	xyz
1649	2	assetfinder	xyz
1649	2	subfinder	xyz
1649	2	brand_ct	xyz
1650	2	assetfinder	xyz
1650	2	subfinder	xyz
1650	2	brand_ct	xyz
1651	2	assetfinder	xyz
1651	2	subfinder	xyz
1651	2	brand_ct	xyz
1652	2	assetfinder	xyz
1652	2	subfinder	xyz
1652	2	brand_ct	xyz
1653	2	assetfinder	xyz
1653	2	subfinder	xyz
1653	2	brand_ct	xyz
1654	2	assetfinder	xyz
1654	2	subfinder	xyz
1654	2	brand_ct	xyz
1655	2	assetfinder	xyz
1655	2	subfinder	xyz
1655	2	brand_ct	xyz
1656	2	assetfinder	xyz
1656	2	subfinder	xyz
1656	2	brand_ct	xyz
1657	2	assetfinder	xyz
1657	2	subfinder	xyz
1657	2	brand_ct	xyz
1658	2	assetfinder	xyz
1658	2	subfinder	xyz
1658	2	brand_ct	xyz
1659	2	brand_ct	xyz
1660	2	assetfinder	xyz
1660	2	subfinder	xyz
1660	2	brand_ct	xyz
1661	2	subfinder	xyz
1662	2	brand_ct	xyz
1663	2	assetfinder	xyz
1663	2	subfinder	xyz
1663	2	brand_ct	xyz
1664	2	brand_pattern	xyz
1665	2	assetfinder	xyz
1665	2	subfinder	xyz
1665	2	brand_ct	xyz
1666	2	assetfinder	xyz
1666	2	subfinder	xyz
1666	2	brand_ct	xyz
1667	2	assetfinder	xyz
1667	2	subfinder	xyz
1667	2	brand_ct	xyz
1668	2	assetfinder	xyz
1668	2	subfinder	xyz
1668	2	brand_ct	xyz
1669	2	assetfinder	xyz
1669	2	subfinder	xyz
1669	2	brand_ct	xyz
1670	2	assetfinder	xyz
1670	2	subfinder	xyz
1670	2	brand_ct	xyz
1671	2	assetfinder	xyz
1671	2	subfinder	xyz
1671	2	brand_ct	xyz
1672	2	assetfinder	xyz
1672	2	subfinder	xyz
1672	2	brand_ct	xyz
1673	2	assetfinder	xyz
1673	2	subfinder	xyz
1673	2	brand_ct	xyz
1674	2	brand_pattern	xyz
1675	2	assetfinder	xyz
1675	2	subfinder	xyz
1675	2	brand_ct	xyz
1676	2	assetfinder	xyz
1676	2	subfinder	xyz
1676	2	brand_ct	xyz
1677	2	assetfinder	xyz
1677	2	subfinder	xyz
1677	2	brand_ct	xyz
1678	2	assetfinder	xyz
1678	2	subfinder	xyz
1678	2	brand_ct	xyz
1679	2	assetfinder	xyz
1679	2	subfinder	xyz
1679	2	brand_ct	xyz
1680	2	assetfinder	xyz
1680	2	subfinder	xyz
1680	2	brand_ct	xyz
1681	2	assetfinder	xyz
1681	2	subfinder	xyz
1681	2	brand_ct	xyz
1682	2	assetfinder	xyz
1682	2	subfinder	xyz
1682	2	brand_ct	xyz
1683	2	assetfinder	xyz
1683	2	subfinder	xyz
1683	2	brand_ct	xyz
1684	2	assetfinder	xyz
1684	2	subfinder	xyz
1684	2	brand_ct	xyz
1685	2	assetfinder	xyz
1685	2	subfinder	xyz
1685	2	brand_ct	xyz
1686	2	assetfinder	xyz
1686	2	subfinder	xyz
1686	2	brand_ct	xyz
1687	2	assetfinder	xyz
1687	2	subfinder	xyz
1687	2	brand_ct	xyz
1688	2	assetfinder	xyz
1688	2	subfinder	xyz
1689	2	assetfinder	xyz
1689	2	subfinder	xyz
1690	2	assetfinder	xyz
1690	2	subfinder	xyz
1691	2	assetfinder	xyz
1691	2	subfinder	xyz
1691	2	brand_ct	xyz
1692	2	assetfinder	xyz
1692	2	subfinder	xyz
1692	2	brand_ct	xyz
1693	2	assetfinder	xyz
1693	2	subfinder	xyz
1693	2	brand_ct	xyz
1694	2	assetfinder	xyz
1695	2	assetfinder	xyz
1695	2	subfinder	xyz
1695	2	brand_ct	xyz
1696	2	assetfinder	xyz
1696	2	subfinder	xyz
1696	2	brand_ct	xyz
1697	2	assetfinder	xyz
1697	2	subfinder	xyz
1697	2	brand_ct	xyz
1698	2	assetfinder	xyz
1698	2	subfinder	xyz
1698	2	brand_ct	xyz
1699	2	assetfinder	xyz
1699	2	subfinder	xyz
1699	2	brand_ct	xyz
1700	2	assetfinder	xyz
1700	2	subfinder	xyz
1700	2	brand_ct	xyz
1701	2	assetfinder	xyz
1701	2	subfinder	xyz
1701	2	brand_ct	xyz
1702	2	assetfinder	xyz
1702	2	subfinder	xyz
1702	2	brand_ct	xyz
1703	2	assetfinder	xyz
1703	2	subfinder	xyz
1703	2	brand_ct	xyz
1704	2	assetfinder	xyz
1704	2	subfinder	xyz
1704	2	brand_ct	xyz
1705	2	assetfinder	xyz
1705	2	subfinder	xyz
1705	2	brand_ct	xyz
1706	2	assetfinder	xyz
1706	2	subfinder	xyz
1706	2	brand_ct	xyz
1707	2	assetfinder	xyz
1707	2	subfinder	xyz
1707	2	brand_ct	xyz
1708	2	assetfinder	xyz
1708	2	subfinder	xyz
1708	2	brand_ct	xyz
1709	2	assetfinder	xyz
1709	2	subfinder	xyz
1709	2	brand_ct	xyz
1710	2	assetfinder	xyz
1710	2	subfinder	xyz
1710	2	brand_ct	xyz
1711	2	assetfinder	xyz
1711	2	subfinder	xyz
1711	2	brand_ct	xyz
1712	2	assetfinder	xyz
1712	2	subfinder	xyz
1712	2	brand_ct	xyz
1713	2	assetfinder	xyz
1713	2	subfinder	xyz
1713	2	brand_ct	xyz
1714	2	assetfinder	xyz
1714	2	subfinder	xyz
1714	2	brand_ct	xyz
1715	2	assetfinder	xyz
1715	2	subfinder	xyz
1715	2	brand_ct	xyz
1716	2	assetfinder	xyz
1716	2	subfinder	xyz
1716	2	brand_ct	xyz
1717	2	assetfinder	xyz
1717	2	subfinder	xyz
1717	2	brand_ct	xyz
1718	2	assetfinder	xyz
1718	2	subfinder	xyz
1718	2	brand_ct	xyz
1719	2	assetfinder	xyz
1719	2	subfinder	xyz
1719	2	brand_ct	xyz
1720	2	assetfinder	xyz
1720	2	subfinder	xyz
1720	2	brand_ct	xyz
1721	2	assetfinder	xyz
1721	2	subfinder	xyz
1721	2	brand_ct	xyz
1722	2	assetfinder	xyz
1722	2	subfinder	xyz
1722	2	brand_ct	xyz
1723	2	assetfinder	xyz
1723	2	subfinder	xyz
1723	2	brand_ct	xyz
1724	2	assetfinder	xyz
1724	2	subfinder	xyz
1724	2	brand_ct	xyz
1725	2	assetfinder	xyz
1725	2	subfinder	xyz
1725	2	brand_ct	xyz
1726	2	assetfinder	xyz
1726	2	subfinder	xyz
1726	2	brand_ct	xyz
1727	2	assetfinder	xyz
1727	2	subfinder	xyz
1727	2	brand_ct	xyz
1728	2	assetfinder	xyz
1728	2	subfinder	xyz
1728	2	brand_ct	xyz
1729	2	assetfinder	xyz
1729	2	subfinder	xyz
1729	2	brand_ct	xyz
1730	2	assetfinder	xyz
1730	2	subfinder	xyz
1730	2	brand_ct	xyz
1731	2	assetfinder	xyz
1731	2	subfinder	xyz
1731	2	brand_ct	xyz
1732	2	assetfinder	xyz
1733	2	assetfinder	xyz
1733	2	subfinder	xyz
1733	2	brand_ct	xyz
1734	2	assetfinder	xyz
1734	2	subfinder	xyz
1734	2	brand_ct	xyz
1735	2	assetfinder	xyz
1735	2	subfinder	xyz
1735	2	brand_ct	xyz
1736	2	assetfinder	xyz
1736	2	subfinder	xyz
1736	2	brand_ct	xyz
1737	2	assetfinder	xyz
1737	2	subfinder	xyz
1737	2	brand_ct	xyz
1738	2	assetfinder	xyz
1738	2	subfinder	xyz
1738	2	brand_ct	xyz
1739	2	assetfinder	xyz
1739	2	subfinder	xyz
1739	2	brand_ct	xyz
1740	2	assetfinder	xyz
1740	2	subfinder	xyz
1740	2	brand_ct	xyz
1741	2	assetfinder	xyz
1741	2	subfinder	xyz
1741	2	brand_ct	xyz
1742	2	assetfinder	xyz
1742	2	subfinder	xyz
1742	2	brand_ct	xyz
1743	2	assetfinder	xyz
1743	2	subfinder	xyz
1743	2	brand_ct	xyz
1744	2	assetfinder	xyz
1744	2	subfinder	xyz
1744	2	brand_ct	xyz
1745	2	assetfinder	xyz
1745	2	subfinder	xyz
1745	2	brand_ct	xyz
1746	2	assetfinder	xyz
1747	2	assetfinder	xyz
1747	2	subfinder	xyz
1747	2	brand_ct	xyz
1748	2	assetfinder	xyz
1748	2	subfinder	xyz
1748	2	brand_ct	xyz
1749	2	assetfinder	xyz
1749	2	subfinder	xyz
1749	2	brand_ct	xyz
1750	2	assetfinder	xyz
1750	2	subfinder	xyz
1750	2	brand_ct	xyz
1751	2	assetfinder	xyz
1751	2	subfinder	xyz
1751	2	brand_ct	xyz
1752	2	assetfinder	xyz
1752	2	subfinder	xyz
1752	2	brand_ct	xyz
1753	2	assetfinder	xyz
1753	2	subfinder	xyz
1753	2	brand_ct	xyz
1754	2	assetfinder	xyz
1754	2	subfinder	xyz
1754	2	brand_ct	xyz
1755	2	assetfinder	xyz
1755	2	subfinder	xyz
1755	2	brand_ct	xyz
1756	2	assetfinder	xyz
1756	2	subfinder	xyz
1756	2	brand_ct	xyz
1757	2	assetfinder	xyz
1757	2	subfinder	xyz
1757	2	brand_ct	xyz
1758	2	assetfinder	xyz
1758	2	subfinder	xyz
1758	2	brand_ct	xyz
1759	2	assetfinder	xyz
1759	2	subfinder	xyz
1759	2	brand_ct	xyz
1760	2	assetfinder	xyz
1760	2	subfinder	xyz
1760	2	brand_ct	xyz
1761	2	assetfinder	xyz
1761	2	subfinder	xyz
1761	2	brand_ct	xyz
1762	2	assetfinder	xyz
1762	2	subfinder	xyz
1762	2	brand_ct	xyz
1763	2	assetfinder	xyz
1764	2	assetfinder	xyz
1764	2	subfinder	xyz
1764	2	brand_ct	xyz
1765	2	assetfinder	xyz
1765	2	subfinder	xyz
1765	2	brand_ct	xyz
1766	2	assetfinder	xyz
1766	2	subfinder	xyz
1766	2	brand_ct	xyz
1767	2	assetfinder	xyz
1767	2	subfinder	xyz
1767	2	brand_ct	xyz
1768	2	assetfinder	xyz
1768	2	subfinder	xyz
1768	2	brand_ct	xyz
1769	2	assetfinder	xyz
1769	2	subfinder	xyz
1769	2	brand_ct	xyz
1770	2	assetfinder	xyz
1770	2	subfinder	xyz
1770	2	brand_ct	xyz
1771	2	assetfinder	xyz
1771	2	subfinder	xyz
1771	2	brand_ct	xyz
1772	2	assetfinder	xyz
1772	2	subfinder	xyz
1772	2	brand_ct	xyz
1773	2	assetfinder	xyz
1774	2	assetfinder	xyz
1775	2	assetfinder	xyz
1775	2	subfinder	xyz
1775	2	brand_ct	xyz
1776	2	assetfinder	xyz
1776	2	subfinder	xyz
1776	2	brand_ct	xyz
1777	2	assetfinder	xyz
1778	2	assetfinder	xyz
1778	2	subfinder	xyz
1778	2	brand_ct	xyz
1779	2	assetfinder	xyz
1779	2	subfinder	xyz
1779	2	brand_ct	xyz
1780	2	assetfinder	xyz
1780	2	subfinder	xyz
1780	2	brand_ct	xyz
1781	2	assetfinder	xyz
1781	2	subfinder	xyz
1781	2	brand_ct	xyz
1782	2	assetfinder	xyz
1782	2	subfinder	xyz
1782	2	brand_ct	xyz
1783	2	assetfinder	xyz
1783	2	subfinder	xyz
1783	2	brand_ct	xyz
1784	2	assetfinder	xyz
1785	2	assetfinder	xyz
1785	2	subfinder	xyz
1785	2	brand_ct	xyz
1786	2	assetfinder	xyz
1786	2	subfinder	xyz
1786	2	brand_ct	xyz
1787	2	assetfinder	xyz
1787	2	subfinder	xyz
1787	2	brand_ct	xyz
1788	2	assetfinder	xyz
1788	2	subfinder	xyz
1788	2	brand_ct	xyz
1789	2	assetfinder	xyz
1789	2	subfinder	xyz
1789	2	brand_ct	xyz
1790	2	assetfinder	xyz
1790	2	subfinder	xyz
1790	2	brand_ct	xyz
1791	2	assetfinder	xyz
1791	2	subfinder	xyz
1791	2	brand_ct	xyz
1792	2	assetfinder	xyz
1792	2	subfinder	xyz
1792	2	brand_ct	xyz
1793	2	assetfinder	xyz
1793	2	subfinder	xyz
1793	2	brand_ct	xyz
1794	2	assetfinder	xyz
1794	2	subfinder	xyz
1794	2	brand_ct	xyz
1795	2	assetfinder	xyz
1795	2	subfinder	xyz
1795	2	brand_ct	xyz
1796	2	assetfinder	xyz
1796	2	subfinder	xyz
1796	2	brand_ct	xyz
1797	2	assetfinder	xyz
1797	2	subfinder	xyz
1797	2	brand_ct	xyz
1798	2	assetfinder	xyz
1798	2	subfinder	xyz
1798	2	brand_ct	xyz
1799	2	assetfinder	xyz
1799	2	subfinder	xyz
1799	2	brand_ct	xyz
1800	2	assetfinder	xyz
1800	2	subfinder	xyz
1800	2	brand_ct	xyz
1801	2	assetfinder	xyz
1801	2	subfinder	xyz
1801	2	brand_ct	xyz
1802	2	assetfinder	xyz
1802	2	subfinder	xyz
1802	2	brand_ct	xyz
1803	2	assetfinder	xyz
1803	2	subfinder	xyz
1803	2	brand_ct	xyz
1804	2	assetfinder	xyz
1804	2	subfinder	xyz
1804	2	brand_ct	xyz
1805	2	assetfinder	xyz
1805	2	subfinder	xyz
1805	2	brand_ct	xyz
1806	2	assetfinder	xyz
1806	2	subfinder	xyz
1806	2	brand_ct	xyz
1807	2	assetfinder	xyz
1807	2	subfinder	xyz
1807	2	brand_ct	xyz
1808	2	assetfinder	xyz
1808	2	subfinder	xyz
1808	2	brand_ct	xyz
1809	2	assetfinder	xyz
1809	2	subfinder	xyz
1809	2	brand_ct	xyz
1810	2	assetfinder	xyz
1810	2	subfinder	xyz
1810	2	brand_ct	xyz
1811	2	assetfinder	xyz
1811	2	subfinder	xyz
1811	2	brand_ct	xyz
1812	2	assetfinder	xyz
1813	2	assetfinder	xyz
1814	2	assetfinder	xyz
1814	2	subfinder	xyz
1814	2	brand_ct	xyz
1815	2	assetfinder	xyz
1815	2	subfinder	xyz
1816	2	assetfinder	xyz
1816	2	subfinder	xyz
1816	2	brand_ct	xyz
1817	2	assetfinder	xyz
1817	2	subfinder	xyz
1817	2	brand_ct	xyz
1818	2	assetfinder	xyz
1818	2	subfinder	xyz
1818	2	brand_ct	xyz
1819	2	assetfinder	xyz
1819	2	subfinder	xyz
1819	2	brand_ct	xyz
1820	2	assetfinder	xyz
1820	2	subfinder	xyz
1820	2	brand_ct	xyz
1821	2	assetfinder	xyz
1821	2	subfinder	xyz
1821	2	brand_ct	xyz
1822	2	assetfinder	xyz
1822	2	subfinder	xyz
1822	2	brand_ct	xyz
1823	2	assetfinder	xyz
1823	2	subfinder	xyz
1823	2	brand_ct	xyz
1824	2	assetfinder	xyz
1824	2	subfinder	xyz
1824	2	brand_ct	xyz
1825	2	assetfinder	xyz
1825	2	subfinder	xyz
1825	2	brand_ct	xyz
1826	2	assetfinder	xyz
1826	2	subfinder	xyz
1826	2	brand_ct	xyz
1827	2	assetfinder	xyz
1827	2	subfinder	xyz
1827	2	brand_ct	xyz
1828	2	assetfinder	xyz
1828	2	subfinder	xyz
1828	2	brand_ct	xyz
1829	2	assetfinder	xyz
1829	2	subfinder	xyz
1829	2	brand_ct	xyz
1830	2	assetfinder	xyz
1830	2	subfinder	xyz
1830	2	brand_ct	xyz
1831	2	assetfinder	xyz
1831	2	brand_ct	xyz
1832	2	assetfinder	xyz
1832	2	brand_ct	xyz
1833	2	assetfinder	xyz
1833	2	brand_ct	xyz
1834	2	assetfinder	xyz
1834	2	brand_ct	xyz
1835	2	assetfinder	xyz
1835	2	brand_ct	xyz
1836	2	assetfinder	xyz
1836	2	subfinder	xyz
1836	2	brand_ct	xyz
1837	2	assetfinder	xyz
1837	2	subfinder	xyz
1837	2	brand_ct	xyz
1838	2	assetfinder	xyz
1838	2	subfinder	xyz
1838	2	brand_ct	xyz
1839	2	assetfinder	xyz
1839	2	subfinder	xyz
1839	2	brand_ct	xyz
1840	2	assetfinder	xyz
1840	2	subfinder	xyz
1840	2	brand_ct	xyz
1841	2	assetfinder	xyz
1841	2	subfinder	xyz
1841	2	brand_ct	xyz
1842	2	assetfinder	xyz
1842	2	subfinder	xyz
1842	2	brand_ct	xyz
1843	2	assetfinder	xyz
1843	2	subfinder	xyz
1843	2	brand_ct	xyz
1844	2	assetfinder	xyz
1844	2	subfinder	xyz
1844	2	brand_ct	xyz
1845	2	assetfinder	xyz
1845	2	subfinder	xyz
1845	2	brand_ct	xyz
1846	2	assetfinder	xyz
1846	2	subfinder	xyz
1846	2	brand_ct	xyz
1847	2	assetfinder	xyz
1847	2	subfinder	xyz
1847	2	brand_ct	xyz
1848	2	assetfinder	xyz
1848	2	subfinder	xyz
1848	2	brand_ct	xyz
1849	2	assetfinder	xyz
1849	2	subfinder	xyz
1849	2	brand_ct	xyz
1850	2	assetfinder	xyz
1850	2	subfinder	xyz
1850	2	brand_ct	xyz
1851	2	assetfinder	xyz
1851	2	subfinder	xyz
1851	2	brand_ct	xyz
1852	2	assetfinder	xyz
1852	2	subfinder	xyz
1852	2	brand_ct	xyz
1853	2	assetfinder	xyz
1853	2	subfinder	xyz
1853	2	brand_ct	xyz
1854	2	assetfinder	xyz
1854	2	subfinder	xyz
1854	2	brand_ct	xyz
1855	2	assetfinder	xyz
1855	2	subfinder	xyz
1855	2	brand_ct	xyz
1856	2	assetfinder	xyz
1856	2	subfinder	xyz
1856	2	brand_ct	xyz
1857	2	assetfinder	xyz
1857	2	subfinder	xyz
1857	2	brand_ct	xyz
1858	2	assetfinder	xyz
1858	2	subfinder	xyz
1858	2	brand_ct	xyz
1859	2	assetfinder	xyz
1859	2	subfinder	xyz
1859	2	brand_ct	xyz
1860	2	assetfinder	xyz
1860	2	subfinder	xyz
1860	2	brand_ct	xyz
1861	2	assetfinder	xyz
1861	2	subfinder	xyz
1861	2	brand_ct	xyz
1862	2	assetfinder	xyz
1862	2	subfinder	xyz
1862	2	brand_ct	xyz
1863	2	assetfinder	xyz
1863	2	subfinder	xyz
1863	2	brand_ct	xyz
1864	2	assetfinder	xyz
1864	2	subfinder	xyz
1864	2	brand_ct	xyz
1865	2	assetfinder	xyz
1865	2	subfinder	xyz
1865	2	brand_ct	xyz
1866	2	assetfinder	xyz
1866	2	subfinder	xyz
1866	2	brand_ct	xyz
1867	2	assetfinder	xyz
1867	2	subfinder	xyz
1867	2	brand_ct	xyz
1868	2	assetfinder	xyz
1868	2	subfinder	xyz
1868	2	brand_ct	xyz
1869	2	assetfinder	xyz
1869	2	subfinder	xyz
1869	2	brand_ct	xyz
1870	2	assetfinder	xyz
1870	2	subfinder	xyz
1870	2	brand_ct	xyz
1871	2	assetfinder	xyz
1871	2	subfinder	xyz
1871	2	brand_ct	xyz
1872	2	assetfinder	xyz
1873	2	assetfinder	xyz
1874	2	assetfinder	xyz
1875	2	assetfinder	xyz
1876	2	assetfinder	xyz
1876	2	subfinder	xyz
1876	2	brand_ct	xyz
1877	2	assetfinder	xyz
1877	2	subfinder	xyz
1877	2	brand_ct	xyz
1878	2	assetfinder	xyz
1878	2	subfinder	xyz
1878	2	brand_ct	xyz
1879	2	assetfinder	xyz
1879	2	subfinder	xyz
1879	2	brand_ct	xyz
1880	2	assetfinder	xyz
1880	2	subfinder	xyz
1880	2	brand_ct	xyz
1881	2	assetfinder	xyz
1881	2	subfinder	xyz
1881	2	brand_ct	xyz
1882	2	assetfinder	xyz
1882	2	subfinder	xyz
1882	2	brand_ct	xyz
1883	2	assetfinder	xyz
1883	2	subfinder	xyz
1883	2	brand_ct	xyz
1884	2	assetfinder	xyz
1884	2	subfinder	xyz
1884	2	brand_ct	xyz
1885	2	assetfinder	xyz
1885	2	subfinder	xyz
1885	2	brand_ct	xyz
1886	2	assetfinder	xyz
1886	2	subfinder	xyz
1886	2	brand_ct	xyz
1887	2	assetfinder	xyz
1887	2	subfinder	xyz
1887	2	brand_ct	xyz
1888	2	assetfinder	xyz
1888	2	subfinder	xyz
1888	2	brand_ct	xyz
1889	2	assetfinder	xyz
1889	2	subfinder	xyz
1889	2	brand_ct	xyz
1890	2	assetfinder	xyz
1890	2	subfinder	xyz
1890	2	brand_ct	xyz
1891	2	assetfinder	xyz
1891	2	subfinder	xyz
1891	2	brand_ct	xyz
1892	2	assetfinder	xyz
1892	2	subfinder	xyz
1892	2	brand_ct	xyz
1893	2	assetfinder	xyz
1893	2	subfinder	xyz
1893	2	brand_ct	xyz
1894	2	assetfinder	xyz
1894	2	subfinder	xyz
1894	2	brand_ct	xyz
1895	2	assetfinder	xyz
1895	2	subfinder	xyz
1895	2	brand_ct	xyz
1896	2	assetfinder	xyz
1896	2	subfinder	xyz
1896	2	brand_ct	xyz
1897	2	assetfinder	xyz
1897	2	subfinder	xyz
1897	2	brand_ct	xyz
1898	2	assetfinder	xyz
1898	2	subfinder	xyz
1898	2	brand_ct	xyz
1899	2	assetfinder	xyz
1899	2	subfinder	xyz
1899	2	brand_ct	xyz
1900	2	assetfinder	xyz
1900	2	subfinder	xyz
1900	2	brand_ct	xyz
1901	2	assetfinder	xyz
1901	2	subfinder	xyz
1901	2	brand_ct	xyz
1902	2	assetfinder	xyz
1902	2	subfinder	xyz
1902	2	brand_ct	xyz
1903	2	assetfinder	xyz
1903	2	subfinder	xyz
1903	2	brand_ct	xyz
1904	2	assetfinder	xyz
1904	2	subfinder	xyz
1904	2	brand_ct	xyz
1905	2	assetfinder	xyz
1905	2	subfinder	xyz
1905	2	brand_ct	xyz
1906	2	assetfinder	xyz
1906	2	subfinder	xyz
1906	2	brand_ct	xyz
1907	2	assetfinder	xyz
1907	2	subfinder	xyz
1907	2	brand_ct	xyz
1908	2	assetfinder	xyz
1908	2	subfinder	xyz
1908	2	brand_ct	xyz
1909	2	assetfinder	xyz
1909	2	subfinder	xyz
1909	2	brand_ct	xyz
1910	2	assetfinder	xyz
1910	2	subfinder	xyz
1910	2	brand_ct	xyz
1911	2	assetfinder	xyz
1911	2	subfinder	xyz
1911	2	brand_ct	xyz
1912	2	assetfinder	xyz
1912	2	subfinder	xyz
1912	2	brand_ct	xyz
1913	2	subfinder	xyz
1914	2	brand_ct	xyz
1915	2	assetfinder	xyz
1915	2	subfinder	xyz
1915	2	brand_ct	xyz
1916	2	assetfinder	xyz
1916	2	subfinder	xyz
1916	2	brand_ct	xyz
1917	2	assetfinder	xyz
1917	2	subfinder	xyz
1917	2	brand_ct	xyz
1918	2	assetfinder	xyz
1918	2	subfinder	xyz
1918	2	brand_ct	xyz
1919	2	assetfinder	xyz
1919	2	subfinder	xyz
1919	2	brand_ct	xyz
1920	2	assetfinder	xyz
1920	2	subfinder	xyz
1920	2	brand_ct	xyz
1921	2	assetfinder	xyz
1921	2	subfinder	xyz
1921	2	brand_ct	xyz
1922	2	assetfinder	xyz
1922	2	subfinder	xyz
1922	2	brand_ct	xyz
1923	2	assetfinder	xyz
1923	2	subfinder	xyz
1923	2	brand_ct	xyz
1924	2	assetfinder	xyz
1924	2	subfinder	xyz
1924	2	brand_ct	xyz
1925	2	assetfinder	xyz
1925	2	subfinder	xyz
1925	2	brand_ct	xyz
1926	2	assetfinder	xyz
1926	2	subfinder	xyz
1926	2	brand_ct	xyz
1927	2	assetfinder	xyz
1927	2	subfinder	xyz
1927	2	brand_ct	xyz
1928	2	assetfinder	xyz
1928	2	subfinder	xyz
1928	2	brand_ct	xyz
1929	2	assetfinder	xyz
1929	2	subfinder	xyz
1929	2	brand_ct	xyz
1930	2	assetfinder	xyz
1930	2	subfinder	xyz
1930	2	brand_ct	xyz
1931	2	assetfinder	xyz
1931	2	subfinder	xyz
1931	2	brand_ct	xyz
1932	2	assetfinder	xyz
1932	2	subfinder	xyz
1932	2	brand_ct	xyz
1933	2	assetfinder	xyz
1933	2	subfinder	xyz
1933	2	brand_ct	xyz
1934	2	assetfinder	xyz
1934	2	subfinder	xyz
1934	2	brand_ct	xyz
1935	2	assetfinder	xyz
1935	2	subfinder	xyz
1935	2	brand_ct	xyz
1936	2	assetfinder	xyz
1936	2	subfinder	xyz
1936	2	brand_ct	xyz
1937	2	assetfinder	xyz
1937	2	subfinder	xyz
1937	2	brand_ct	xyz
1938	2	assetfinder	xyz
1938	2	subfinder	xyz
1938	2	brand_ct	xyz
1939	2	assetfinder	xyz
1939	2	subfinder	xyz
1939	2	brand_ct	xyz
1940	2	assetfinder	xyz
1940	2	subfinder	xyz
1940	2	brand_ct	xyz
1941	2	assetfinder	xyz
1941	2	subfinder	xyz
1941	2	brand_ct	xyz
1942	2	assetfinder	xyz
1942	2	subfinder	xyz
1942	2	brand_ct	xyz
1943	2	assetfinder	xyz
1943	2	subfinder	xyz
1943	2	brand_ct	xyz
1944	2	assetfinder	xyz
1944	2	subfinder	xyz
1944	2	brand_ct	xyz
1945	2	assetfinder	xyz
1945	2	subfinder	xyz
1945	2	brand_ct	xyz
1946	2	assetfinder	xyz
1946	2	subfinder	xyz
1946	2	brand_ct	xyz
1947	2	assetfinder	xyz
1947	2	subfinder	xyz
1947	2	brand_ct	xyz
1948	2	assetfinder	xyz
1948	2	subfinder	xyz
1948	2	brand_ct	xyz
1949	2	assetfinder	xyz
1949	2	subfinder	xyz
1949	2	brand_ct	xyz
1950	2	assetfinder	xyz
1951	2	assetfinder	xyz
1951	2	subfinder	xyz
1951	2	brand_ct	xyz
1952	2	assetfinder	xyz
1952	2	subfinder	xyz
1952	2	brand_ct	xyz
1953	2	assetfinder	xyz
1953	2	subfinder	xyz
1953	2	brand_ct	xyz
1954	2	assetfinder	xyz
1954	2	subfinder	xyz
1954	2	brand_ct	xyz
1955	2	assetfinder	xyz
1955	2	subfinder	xyz
1955	2	brand_ct	xyz
1956	2	assetfinder	xyz
1956	2	subfinder	xyz
1956	2	brand_ct	xyz
1957	2	assetfinder	xyz
1957	2	subfinder	xyz
1957	2	brand_ct	xyz
1958	2	assetfinder	xyz
1958	2	subfinder	xyz
1958	2	brand_ct	xyz
1959	2	assetfinder	xyz
1959	2	subfinder	xyz
1959	2	brand_ct	xyz
1960	2	assetfinder	xyz
1960	2	subfinder	xyz
1960	2	brand_ct	xyz
1961	2	assetfinder	xyz
1962	2	assetfinder	xyz
1962	2	subfinder	xyz
1962	2	brand_ct	xyz
1963	2	assetfinder	xyz
1963	2	subfinder	xyz
1963	2	brand_ct	xyz
1964	2	assetfinder	xyz
1964	2	subfinder	xyz
1964	2	brand_ct	xyz
1965	2	assetfinder	xyz
1965	2	subfinder	xyz
1965	2	brand_ct	xyz
1966	2	assetfinder	xyz
1966	2	subfinder	xyz
1966	2	brand_ct	xyz
1967	2	assetfinder	xyz
1967	2	subfinder	xyz
1967	2	brand_ct	xyz
1968	2	assetfinder	xyz
1968	2	subfinder	xyz
1968	2	brand_ct	xyz
1969	2	assetfinder	xyz
1969	2	subfinder	xyz
1969	2	brand_ct	xyz
1970	2	assetfinder	xyz
1970	2	subfinder	xyz
1970	2	brand_ct	xyz
1971	2	assetfinder	xyz
1971	2	subfinder	xyz
1971	2	brand_ct	xyz
1972	2	assetfinder	xyz
1972	2	subfinder	xyz
1972	2	brand_ct	xyz
1973	2	assetfinder	xyz
1973	2	subfinder	xyz
1973	2	brand_ct	xyz
1974	2	assetfinder	xyz
1974	2	subfinder	xyz
1974	2	brand_ct	xyz
1975	2	assetfinder	xyz
1975	2	subfinder	xyz
1975	2	brand_ct	xyz
1976	2	assetfinder	xyz
1976	2	subfinder	xyz
1976	2	brand_ct	xyz
1977	2	assetfinder	xyz
1977	2	subfinder	xyz
1977	2	brand_ct	xyz
1978	2	brand_pattern	xyz
1979	2	assetfinder	xyz
1979	2	subfinder	xyz
1979	2	brand_ct	xyz
1980	2	assetfinder	xyz
1980	2	subfinder	xyz
1980	2	brand_ct	xyz
1981	2	assetfinder	xyz
1981	2	brand_ct	xyz
1982	2	assetfinder	xyz
1982	2	subfinder	xyz
1982	2	brand_ct	xyz
1983	2	brand_pattern	xyz
1984	2	assetfinder	xyz
1984	2	subfinder	xyz
1984	2	brand_ct	xyz
1985	2	assetfinder	xyz
1985	2	subfinder	xyz
1985	2	brand_ct	xyz
1986	2	assetfinder	xyz
1986	2	subfinder	xyz
1986	2	brand_ct	xyz
1987	2	assetfinder	xyz
1987	2	subfinder	xyz
1987	2	brand_ct	xyz
1988	2	assetfinder	xyz
1988	2	subfinder	xyz
1988	2	brand_ct	xyz
1989	2	assetfinder	xyz
1989	2	subfinder	xyz
1989	2	brand_ct	xyz
1990	2	assetfinder	xyz
1990	2	subfinder	xyz
1990	2	brand_ct	xyz
1991	2	assetfinder	xyz
1991	2	subfinder	xyz
1991	2	brand_ct	xyz
1992	2	assetfinder	xyz
1992	2	subfinder	xyz
1992	2	brand_ct	xyz
1993	2	assetfinder	xyz
1994	2	assetfinder	xyz
1994	2	subfinder	xyz
1994	2	brand_ct	xyz
1995	2	assetfinder	xyz
1995	2	subfinder	xyz
1995	2	brand_ct	xyz
1996	2	assetfinder	xyz
1996	2	subfinder	xyz
1996	2	brand_ct	xyz
1997	2	assetfinder	xyz
1997	2	subfinder	xyz
1997	2	brand_ct	xyz
1998	2	assetfinder	xyz
1998	2	subfinder	xyz
1998	2	brand_ct	xyz
1999	2	assetfinder	xyz
1999	2	subfinder	xyz
1999	2	brand_ct	xyz
2000	2	assetfinder	xyz
2000	2	subfinder	xyz
2000	2	brand_ct	xyz
2001	2	assetfinder	xyz
2001	2	subfinder	xyz
2001	2	brand_ct	xyz
2002	2	assetfinder	xyz
2002	2	subfinder	xyz
2002	2	brand_ct	xyz
2003	2	assetfinder	xyz
2003	2	subfinder	xyz
2003	2	brand_ct	xyz
2004	2	assetfinder	xyz
2004	2	subfinder	xyz
2004	2	brand_ct	xyz
2005	2	assetfinder	xyz
2005	2	subfinder	xyz
2005	2	brand_ct	xyz
2006	2	assetfinder	xyz
2006	2	subfinder	xyz
2006	2	brand_ct	xyz
2007	2	assetfinder	xyz
2007	2	subfinder	xyz
2007	2	brand_ct	xyz
2008	2	assetfinder	xyz
2008	2	subfinder	xyz
2008	2	brand_ct	xyz
2009	2	assetfinder	xyz
2009	2	subfinder	xyz
2009	2	brand_ct	xyz
2010	2	assetfinder	xyz
2010	2	subfinder	xyz
2010	2	brand_ct	xyz
2011	2	assetfinder	xyz
2011	2	subfinder	xyz
2011	2	brand_ct	xyz
2012	2	assetfinder	xyz
2012	2	subfinder	xyz
2012	2	brand_ct	xyz
2013	2	assetfinder	xyz
2013	2	subfinder	xyz
2013	2	brand_ct	xyz
2014	2	assetfinder	xyz
2014	2	subfinder	xyz
2014	2	brand_ct	xyz
2015	2	assetfinder	xyz
2015	2	subfinder	xyz
2015	2	brand_ct	xyz
2016	2	assetfinder	xyz
2016	2	subfinder	xyz
2016	2	brand_ct	xyz
2017	2	assetfinder	xyz
2017	2	subfinder	xyz
2017	2	brand_ct	xyz
2018	2	assetfinder	xyz
2019	2	assetfinder	xyz
2019	2	subfinder	xyz
2019	2	brand_ct	xyz
2020	2	assetfinder	xyz
2020	2	subfinder	xyz
2020	2	brand_ct	xyz
2021	2	assetfinder	xyz
2021	2	subfinder	xyz
2021	2	brand_ct	xyz
2022	2	assetfinder	xyz
2022	2	subfinder	xyz
2022	2	brand_ct	xyz
2023	2	assetfinder	xyz
2023	2	subfinder	xyz
2023	2	brand_ct	xyz
2024	2	assetfinder	xyz
2024	2	subfinder	xyz
2024	2	brand_ct	xyz
2025	2	assetfinder	xyz
2025	2	subfinder	xyz
2025	2	brand_ct	xyz
2026	2	assetfinder	xyz
2026	2	subfinder	xyz
2026	2	brand_ct	xyz
2027	2	assetfinder	xyz
2027	2	subfinder	xyz
2027	2	brand_ct	xyz
2028	2	assetfinder	xyz
2028	2	subfinder	xyz
2028	2	brand_ct	xyz
2029	2	assetfinder	xyz
2029	2	subfinder	xyz
2029	2	brand_ct	xyz
2030	2	assetfinder	xyz
2030	2	subfinder	xyz
2030	2	brand_ct	xyz
2031	2	assetfinder	xyz
2031	2	subfinder	xyz
2031	2	brand_ct	xyz
2032	2	assetfinder	xyz
2032	2	subfinder	xyz
2032	2	brand_ct	xyz
2033	2	assetfinder	xyz
2033	2	subfinder	xyz
2033	2	brand_ct	xyz
2034	2	assetfinder	xyz
2034	2	subfinder	xyz
2034	2	brand_ct	xyz
2035	2	assetfinder	xyz
2035	2	subfinder	xyz
2035	2	brand_ct	xyz
2036	2	assetfinder	xyz
2036	2	subfinder	xyz
2036	2	brand_ct	xyz
2037	2	assetfinder	xyz
2037	2	subfinder	xyz
2037	2	brand_ct	xyz
2038	2	assetfinder	xyz
2038	2	subfinder	xyz
2038	2	brand_ct	xyz
2039	2	assetfinder	xyz
2039	2	subfinder	xyz
2039	2	brand_ct	xyz
2040	2	assetfinder	xyz
2040	2	subfinder	xyz
2040	2	brand_ct	xyz
2041	2	assetfinder	xyz
2041	2	subfinder	xyz
2041	2	brand_ct	xyz
2042	2	assetfinder	xyz
2042	2	subfinder	xyz
2042	2	brand_ct	xyz
2043	2	assetfinder	xyz
2043	2	subfinder	xyz
2043	2	brand_ct	xyz
2044	2	assetfinder	xyz
2044	2	subfinder	xyz
2044	2	brand_ct	xyz
2045	2	assetfinder	xyz
2045	2	subfinder	xyz
2045	2	brand_ct	xyz
2046	2	assetfinder	xyz
2046	2	subfinder	xyz
2046	2	brand_ct	xyz
2047	2	assetfinder	xyz
2047	2	subfinder	xyz
2047	2	brand_ct	xyz
2048	2	assetfinder	xyz
2048	2	subfinder	xyz
2048	2	brand_ct	xyz
2049	2	assetfinder	xyz
2049	2	subfinder	xyz
2049	2	brand_ct	xyz
2050	2	assetfinder	xyz
2050	2	subfinder	xyz
2050	2	brand_ct	xyz
2051	2	assetfinder	xyz
2051	2	subfinder	xyz
2051	2	brand_ct	xyz
2052	2	assetfinder	xyz
2052	2	subfinder	xyz
2052	2	brand_ct	xyz
2053	2	assetfinder	xyz
2053	2	subfinder	xyz
2053	2	brand_ct	xyz
2054	2	assetfinder	xyz
2054	2	subfinder	xyz
2054	2	brand_ct	xyz
2055	2	assetfinder	xyz
2055	2	subfinder	xyz
2055	2	brand_ct	xyz
2056	2	assetfinder	xyz
2056	2	subfinder	xyz
2056	2	brand_ct	xyz
2057	2	assetfinder	xyz
2057	2	subfinder	xyz
2057	2	brand_ct	xyz
2058	2	assetfinder	xyz
2058	2	subfinder	xyz
2058	2	brand_ct	xyz
2059	2	assetfinder	xyz
2059	2	subfinder	xyz
2059	2	brand_ct	xyz
2060	2	assetfinder	xyz
2060	2	subfinder	xyz
2060	2	brand_ct	xyz
2061	2	assetfinder	xyz
2061	2	subfinder	xyz
2061	2	brand_ct	xyz
2062	2	assetfinder	xyz
2062	2	subfinder	xyz
2062	2	brand_ct	xyz
2063	2	assetfinder	xyz
2063	2	subfinder	xyz
2063	2	brand_ct	xyz
2064	2	assetfinder	xyz
2064	2	subfinder	xyz
2064	2	brand_ct	xyz
2065	2	assetfinder	xyz
2065	2	subfinder	xyz
2065	2	brand_ct	xyz
2066	2	assetfinder	xyz
2066	2	subfinder	xyz
2066	2	brand_ct	xyz
2067	2	assetfinder	xyz
2067	2	subfinder	xyz
2067	2	brand_ct	xyz
2068	2	assetfinder	xyz
2068	2	subfinder	xyz
2068	2	brand_ct	xyz
2069	2	assetfinder	xyz
2069	2	subfinder	xyz
2069	2	brand_ct	xyz
2070	2	assetfinder	xyz
2070	2	subfinder	xyz
2070	2	brand_ct	xyz
2071	2	assetfinder	xyz
2071	2	subfinder	xyz
2071	2	brand_ct	xyz
2072	2	assetfinder	xyz
2073	2	assetfinder	xyz
2073	2	subfinder	xyz
2073	2	brand_ct	xyz
2074	2	assetfinder	xyz
2074	2	subfinder	xyz
2074	2	brand_ct	xyz
2075	2	assetfinder	xyz
2075	2	subfinder	xyz
2075	2	brand_ct	xyz
2076	2	assetfinder	xyz
2076	2	subfinder	xyz
2076	2	brand_ct	xyz
2077	2	assetfinder	xyz
2077	2	subfinder	xyz
2077	2	brand_ct	xyz
2078	2	assetfinder	xyz
2078	2	subfinder	xyz
2078	2	brand_ct	xyz
2079	2	assetfinder	xyz
2079	2	subfinder	xyz
2079	2	brand_ct	xyz
2080	2	assetfinder	xyz
2080	2	subfinder	xyz
2080	2	brand_ct	xyz
2081	2	assetfinder	xyz
2081	2	subfinder	xyz
2081	2	brand_ct	xyz
2082	2	assetfinder	xyz
2082	2	subfinder	xyz
2082	2	brand_ct	xyz
2083	2	assetfinder	xyz
2083	2	subfinder	xyz
2083	2	brand_ct	xyz
2084	2	assetfinder	xyz
2084	2	subfinder	xyz
2084	2	brand_ct	xyz
2085	2	assetfinder	xyz
2085	2	subfinder	xyz
2085	2	brand_ct	xyz
2086	2	assetfinder	xyz
2086	2	subfinder	xyz
2086	2	brand_ct	xyz
2087	2	assetfinder	xyz
2087	2	subfinder	xyz
2087	2	brand_ct	xyz
2088	2	assetfinder	xyz
2088	2	subfinder	xyz
2088	2	brand_ct	xyz
2089	2	assetfinder	xyz
2089	2	subfinder	xyz
2089	2	brand_ct	xyz
2090	2	assetfinder	xyz
2090	2	subfinder	xyz
2090	2	brand_ct	xyz
2091	2	assetfinder	xyz
2091	2	subfinder	xyz
2091	2	brand_ct	xyz
2092	2	assetfinder	xyz
2092	2	subfinder	xyz
2092	2	brand_ct	xyz
2093	2	assetfinder	xyz
2093	2	subfinder	xyz
2093	2	brand_ct	xyz
2094	2	assetfinder	xyz
2094	2	subfinder	xyz
2094	2	brand_ct	xyz
2095	2	assetfinder	xyz
2095	2	subfinder	xyz
2095	2	brand_ct	xyz
2096	2	assetfinder	xyz
2096	2	subfinder	xyz
2096	2	brand_ct	xyz
2097	2	assetfinder	xyz
2097	2	subfinder	xyz
2097	2	brand_ct	xyz
2098	2	assetfinder	xyz
2098	2	subfinder	xyz
2098	2	brand_ct	xyz
2099	2	assetfinder	xyz
2099	2	subfinder	xyz
2099	2	brand_ct	xyz
2100	2	assetfinder	xyz
2100	2	subfinder	xyz
2100	2	brand_ct	xyz
2101	2	assetfinder	xyz
2101	2	subfinder	xyz
2101	2	brand_ct	xyz
2102	2	assetfinder	xyz
2102	2	subfinder	xyz
2102	2	brand_ct	xyz
2103	2	assetfinder	xyz
2103	2	subfinder	xyz
2103	2	brand_ct	xyz
2104	2	assetfinder	xyz
2104	2	subfinder	xyz
2104	2	brand_ct	xyz
2105	2	assetfinder	xyz
2105	2	subfinder	xyz
2105	2	brand_ct	xyz
2106	2	assetfinder	xyz
2106	2	subfinder	xyz
2106	2	brand_ct	xyz
2107	2	assetfinder	xyz
2107	2	subfinder	xyz
2107	2	brand_ct	xyz
2108	2	assetfinder	xyz
2108	2	subfinder	xyz
2108	2	brand_ct	xyz
2109	2	assetfinder	xyz
2109	2	subfinder	xyz
2109	2	brand_ct	xyz
2110	2	assetfinder	xyz
2110	2	subfinder	xyz
2110	2	brand_ct	xyz
2111	2	assetfinder	xyz
2111	2	subfinder	xyz
2111	2	brand_ct	xyz
2112	2	assetfinder	xyz
2112	2	subfinder	xyz
2112	2	brand_ct	xyz
2113	2	assetfinder	xyz
2113	2	subfinder	xyz
2113	2	brand_ct	xyz
2114	2	assetfinder	xyz
2114	2	subfinder	xyz
2114	2	brand_ct	xyz
2115	2	assetfinder	xyz
2115	2	subfinder	xyz
2115	2	brand_ct	xyz
2116	2	assetfinder	xyz
2116	2	subfinder	xyz
2116	2	brand_ct	xyz
2117	2	assetfinder	xyz
2117	2	subfinder	xyz
2117	2	brand_ct	xyz
2118	2	assetfinder	xyz
2118	2	subfinder	xyz
2118	2	brand_ct	xyz
2119	2	assetfinder	xyz
2119	2	subfinder	xyz
2119	2	brand_ct	xyz
2120	2	assetfinder	xyz
2120	2	subfinder	xyz
2120	2	brand_ct	xyz
2121	2	assetfinder	xyz
2121	2	subfinder	xyz
2121	2	brand_ct	xyz
2122	2	assetfinder	xyz
2122	2	subfinder	xyz
2122	2	brand_ct	xyz
2123	2	assetfinder	xyz
2123	2	subfinder	xyz
2123	2	brand_ct	xyz
2124	2	assetfinder	xyz
2124	2	subfinder	xyz
2124	2	brand_ct	xyz
2125	2	assetfinder	xyz
2125	2	subfinder	xyz
2125	2	brand_ct	xyz
2126	2	assetfinder	xyz
2126	2	subfinder	xyz
2126	2	brand_ct	xyz
2127	2	assetfinder	xyz
2127	2	subfinder	xyz
2127	2	brand_ct	xyz
2128	2	assetfinder	xyz
2128	2	subfinder	xyz
2128	2	brand_ct	xyz
2129	2	assetfinder	xyz
2129	2	subfinder	xyz
2129	2	brand_ct	xyz
2130	2	assetfinder	xyz
2130	2	subfinder	xyz
2130	2	brand_ct	xyz
2131	2	assetfinder	xyz
2131	2	subfinder	xyz
2131	2	brand_ct	xyz
2132	2	assetfinder	xyz
2132	2	subfinder	xyz
2132	2	brand_ct	xyz
2133	2	assetfinder	xyz
2133	2	subfinder	xyz
2133	2	brand_ct	xyz
2134	2	assetfinder	xyz
2134	2	subfinder	xyz
2134	2	brand_ct	xyz
2135	2	assetfinder	xyz
2135	2	subfinder	xyz
2135	2	brand_ct	xyz
2136	2	brand_pattern	xyz
2137	2	brand_pattern	xyz
2138	2	assetfinder	xyz
2138	2	subfinder	xyz
2138	2	brand_ct	xyz
2139	2	assetfinder	xyz
2139	2	subfinder	xyz
2139	2	brand_ct	xyz
2140	2	assetfinder	xyz
2140	2	subfinder	xyz
2140	2	brand_ct	xyz
2141	2	assetfinder	xyz
2141	2	subfinder	xyz
2141	2	brand_ct	xyz
2142	2	assetfinder	xyz
2142	2	subfinder	xyz
2142	2	brand_ct	xyz
2143	2	assetfinder	xyz
2143	2	subfinder	xyz
2143	2	brand_ct	xyz
2144	2	assetfinder	xyz
2144	2	subfinder	xyz
2144	2	brand_ct	xyz
2145	2	assetfinder	xyz
2145	2	subfinder	xyz
2145	2	brand_ct	xyz
2146	2	assetfinder	xyz
2146	2	subfinder	xyz
2146	2	brand_ct	xyz
2147	2	assetfinder	xyz
2147	2	subfinder	xyz
2147	2	brand_ct	xyz
2148	2	assetfinder	xyz
2148	2	subfinder	xyz
2148	2	brand_ct	xyz
2149	2	assetfinder	xyz
2149	2	subfinder	xyz
2149	2	brand_ct	xyz
2150	2	assetfinder	xyz
2150	2	subfinder	xyz
2150	2	brand_ct	xyz
2151	2	assetfinder	xyz
2151	2	subfinder	xyz
2151	2	brand_ct	xyz
2152	2	assetfinder	xyz
2152	2	subfinder	xyz
2152	2	brand_ct	xyz
2153	2	assetfinder	xyz
2153	2	subfinder	xyz
2153	2	brand_ct	xyz
2154	2	assetfinder	xyz
2154	2	subfinder	xyz
2154	2	brand_ct	xyz
2155	2	assetfinder	xyz
2155	2	subfinder	xyz
2155	2	brand_ct	xyz
2156	2	assetfinder	xyz
2156	2	subfinder	xyz
2156	2	brand_ct	xyz
2157	2	assetfinder	xyz
2157	2	subfinder	xyz
2157	2	brand_ct	xyz
2158	2	assetfinder	xyz
2158	2	subfinder	xyz
2158	2	brand_ct	xyz
2159	2	assetfinder	xyz
2159	2	subfinder	xyz
2159	2	brand_ct	xyz
2160	2	assetfinder	xyz
2160	2	subfinder	xyz
2160	2	brand_ct	xyz
2161	2	assetfinder	xyz
2161	2	subfinder	xyz
2161	2	brand_ct	xyz
2162	2	assetfinder	xyz
2162	2	subfinder	xyz
2162	2	brand_ct	xyz
2163	2	assetfinder	xyz
2163	2	subfinder	xyz
2163	2	brand_ct	xyz
2164	2	assetfinder	xyz
2164	2	subfinder	xyz
2164	2	brand_ct	xyz
2165	2	assetfinder	xyz
2165	2	subfinder	xyz
2165	2	brand_ct	xyz
2166	2	assetfinder	xyz
2166	2	subfinder	xyz
2166	2	brand_ct	xyz
2167	2	assetfinder	xyz
2167	2	subfinder	xyz
2167	2	brand_ct	xyz
2168	2	assetfinder	xyz
2168	2	subfinder	xyz
2168	2	brand_ct	xyz
2169	2	assetfinder	xyz
2169	2	subfinder	xyz
2169	2	brand_ct	xyz
2170	2	assetfinder	xyz
2170	2	subfinder	xyz
2170	2	brand_ct	xyz
2171	2	assetfinder	xyz
2171	2	subfinder	xyz
2171	2	brand_ct	xyz
2172	2	assetfinder	xyz
2172	2	subfinder	xyz
2172	2	brand_ct	xyz
2173	2	assetfinder	xyz
2173	2	subfinder	xyz
2173	2	brand_ct	xyz
2174	2	assetfinder	xyz
2174	2	subfinder	xyz
2174	2	brand_ct	xyz
2175	2	assetfinder	xyz
2175	2	subfinder	xyz
2175	2	brand_ct	xyz
2176	2	assetfinder	xyz
2176	2	subfinder	xyz
2176	2	brand_ct	xyz
2177	2	assetfinder	xyz
2177	2	subfinder	xyz
2177	2	brand_ct	xyz
2178	2	assetfinder	xyz
2178	2	subfinder	xyz
2178	2	brand_ct	xyz
2179	2	assetfinder	xyz
2180	2	assetfinder	xyz
2180	2	subfinder	xyz
2180	2	brand_ct	xyz
2181	2	assetfinder	xyz
2181	2	subfinder	xyz
2181	2	brand_ct	xyz
2182	2	assetfinder	xyz
2182	2	subfinder	xyz
2182	2	brand_ct	xyz
2183	2	assetfinder	xyz
2183	2	subfinder	xyz
2183	2	brand_ct	xyz
2184	2	assetfinder	xyz
2184	2	subfinder	xyz
2184	2	brand_ct	xyz
2185	2	assetfinder	xyz
2186	2	assetfinder	xyz
2186	2	subfinder	xyz
2186	2	brand_ct	xyz
2187	2	assetfinder	xyz
2187	2	subfinder	xyz
2187	2	brand_ct	xyz
2188	2	assetfinder	xyz
2188	2	subfinder	xyz
2188	2	brand_ct	xyz
2189	2	assetfinder	xyz
2189	2	subfinder	xyz
2189	2	brand_ct	xyz
2190	2	assetfinder	xyz
2190	2	subfinder	xyz
2190	2	brand_ct	xyz
2191	2	assetfinder	xyz
2191	2	subfinder	xyz
2191	2	brand_ct	xyz
2192	2	assetfinder	xyz
2192	2	subfinder	xyz
2192	2	brand_ct	xyz
2193	2	assetfinder	xyz
2193	2	subfinder	xyz
2193	2	brand_ct	xyz
2194	2	assetfinder	xyz
2194	2	subfinder	xyz
2194	2	brand_ct	xyz
2195	2	assetfinder	xyz
2195	2	subfinder	xyz
2195	2	brand_ct	xyz
2196	2	assetfinder	xyz
2196	2	subfinder	xyz
2196	2	brand_ct	xyz
2197	2	assetfinder	xyz
2197	2	subfinder	xyz
2197	2	brand_ct	xyz
2198	2	assetfinder	xyz
2198	2	subfinder	xyz
2198	2	brand_ct	xyz
2199	2	assetfinder	xyz
2200	2	assetfinder	xyz
2200	2	subfinder	xyz
2200	2	brand_ct	xyz
2201	2	assetfinder	xyz
2201	2	subfinder	xyz
2201	2	brand_ct	xyz
2202	2	assetfinder	xyz
2202	2	subfinder	xyz
2202	2	brand_ct	xyz
2203	2	assetfinder	xyz
2203	2	subfinder	xyz
2203	2	brand_ct	xyz
2204	2	assetfinder	xyz
2204	2	subfinder	xyz
2204	2	brand_ct	xyz
2205	2	assetfinder	xyz
2205	2	subfinder	xyz
2205	2	brand_ct	xyz
2206	2	assetfinder	xyz
2207	2	assetfinder	xyz
2207	2	subfinder	xyz
2207	2	brand_ct	xyz
2208	2	assetfinder	xyz
2208	2	subfinder	xyz
2208	2	brand_ct	xyz
2209	2	assetfinder	xyz
2209	2	subfinder	xyz
2209	2	brand_ct	xyz
2210	2	assetfinder	xyz
2210	2	subfinder	xyz
2210	2	brand_ct	xyz
2211	2	assetfinder	xyz
2211	2	subfinder	xyz
2211	2	brand_ct	xyz
2212	2	assetfinder	xyz
2213	2	assetfinder	xyz
2213	2	subfinder	xyz
2213	2	brand_ct	xyz
2214	2	assetfinder	xyz
2214	2	subfinder	xyz
2214	2	brand_ct	xyz
2215	2	assetfinder	xyz
2215	2	subfinder	xyz
2215	2	brand_ct	xyz
2216	2	assetfinder	xyz
2216	2	subfinder	xyz
2216	2	brand_ct	xyz
2217	2	assetfinder	xyz
2217	2	subfinder	xyz
2217	2	brand_ct	xyz
2218	2	assetfinder	xyz
2218	2	brand_ct	xyz
2219	2	assetfinder	xyz
2219	2	brand_ct	xyz
2220	2	assetfinder	xyz
2220	2	brand_ct	xyz
2221	2	assetfinder	xyz
2221	2	brand_ct	xyz
2222	2	assetfinder	xyz
2222	2	brand_ct	xyz
2223	2	assetfinder	xyz
2223	2	brand_ct	xyz
2224	2	assetfinder	xyz
2224	2	subfinder	xyz
2224	2	brand_ct	xyz
2225	2	assetfinder	xyz
2225	2	subfinder	xyz
2225	2	brand_ct	xyz
2226	2	assetfinder	xyz
2226	2	subfinder	xyz
2226	2	brand_ct	xyz
2227	2	assetfinder	xyz
2227	2	subfinder	xyz
2227	2	brand_ct	xyz
2228	2	assetfinder	xyz
2228	2	subfinder	xyz
2228	2	brand_ct	xyz
2229	2	assetfinder	xyz
2229	2	subfinder	xyz
2229	2	brand_ct	xyz
2230	2	assetfinder	xyz
2230	2	subfinder	xyz
2230	2	brand_ct	xyz
2231	2	assetfinder	xyz
2231	2	subfinder	xyz
2231	2	brand_ct	xyz
2232	2	assetfinder	xyz
2232	2	subfinder	xyz
2232	2	brand_ct	xyz
2233	2	assetfinder	xyz
2233	2	subfinder	xyz
2233	2	brand_ct	xyz
2234	2	assetfinder	xyz
2234	2	subfinder	xyz
2234	2	brand_ct	xyz
2235	2	assetfinder	xyz
2235	2	subfinder	xyz
2235	2	brand_ct	xyz
2236	2	assetfinder	xyz
2236	2	subfinder	xyz
2236	2	brand_ct	xyz
2237	2	assetfinder	xyz
2237	2	subfinder	xyz
2237	2	brand_ct	xyz
2238	2	assetfinder	xyz
2238	2	subfinder	xyz
2238	2	brand_ct	xyz
2239	2	assetfinder	xyz
2239	2	subfinder	xyz
2239	2	brand_ct	xyz
2240	2	assetfinder	xyz
2240	2	subfinder	xyz
2240	2	brand_ct	xyz
2241	2	assetfinder	xyz
2241	2	subfinder	xyz
2241	2	brand_ct	xyz
2242	2	assetfinder	xyz
2242	2	subfinder	xyz
2242	2	brand_ct	xyz
2243	2	assetfinder	xyz
2243	2	subfinder	xyz
2243	2	brand_ct	xyz
2244	2	assetfinder	xyz
2244	2	subfinder	xyz
2244	2	brand_ct	xyz
2245	2	assetfinder	xyz
2245	2	subfinder	xyz
2245	2	brand_ct	xyz
2246	2	assetfinder	xyz
2246	2	subfinder	xyz
2246	2	brand_ct	xyz
2247	2	assetfinder	xyz
2247	2	subfinder	xyz
2247	2	brand_ct	xyz
2248	2	assetfinder	xyz
2248	2	subfinder	xyz
2248	2	brand_ct	xyz
2249	2	assetfinder	xyz
2249	2	subfinder	xyz
2249	2	brand_ct	xyz
2250	2	assetfinder	xyz
2250	2	subfinder	xyz
2250	2	brand_ct	xyz
2251	2	assetfinder	xyz
2251	2	subfinder	xyz
2251	2	brand_ct	xyz
2252	2	assetfinder	xyz
2252	2	subfinder	xyz
2253	2	assetfinder	xyz
2253	2	subfinder	xyz
2254	2	assetfinder	xyz
2254	2	subfinder	xyz
2255	2	assetfinder	xyz
2255	2	subfinder	xyz
2256	2	assetfinder	xyz
2256	2	subfinder	xyz
2257	2	assetfinder	xyz
2257	2	subfinder	xyz
2258	2	assetfinder	xyz
2258	2	subfinder	xyz
2259	2	assetfinder	xyz
2259	2	subfinder	xyz
2260	2	assetfinder	xyz
2261	2	assetfinder	xyz
2261	2	subfinder	xyz
2261	2	brand_ct	xyz
2262	2	assetfinder	xyz
2262	2	subfinder	xyz
2262	2	brand_ct	xyz
2263	2	assetfinder	xyz
2263	2	subfinder	xyz
2263	2	brand_ct	xyz
2264	2	assetfinder	xyz
2264	2	subfinder	xyz
2264	2	brand_ct	xyz
2265	2	assetfinder	xyz
2265	2	subfinder	xyz
2265	2	brand_ct	xyz
2266	2	assetfinder	xyz
2266	2	subfinder	xyz
2266	2	brand_ct	xyz
2267	2	assetfinder	xyz
2267	2	subfinder	xyz
2267	2	brand_ct	xyz
2268	2	assetfinder	xyz
2268	2	subfinder	xyz
2269	2	assetfinder	xyz
2269	2	subfinder	xyz
2269	2	brand_ct	xyz
2270	2	assetfinder	xyz
2271	2	assetfinder	xyz
2271	2	subfinder	xyz
2271	2	brand_ct	xyz
2272	2	assetfinder	xyz
2272	2	subfinder	xyz
2272	2	brand_ct	xyz
2273	2	assetfinder	xyz
2273	2	subfinder	xyz
2273	2	brand_ct	xyz
2274	2	assetfinder	xyz
2274	2	subfinder	xyz
2274	2	brand_ct	xyz
2275	2	assetfinder	xyz
2276	2	assetfinder	xyz
2276	2	subfinder	xyz
2276	2	brand_ct	xyz
2277	2	assetfinder	xyz
2277	2	subfinder	xyz
2278	2	assetfinder	xyz
2278	2	subfinder	xyz
2278	2	brand_ct	xyz
2279	2	assetfinder	xyz
2279	2	subfinder	xyz
2279	2	brand_ct	xyz
2280	2	assetfinder	xyz
2280	2	subfinder	xyz
2280	2	brand_ct	xyz
2281	2	assetfinder	xyz
2281	2	subfinder	xyz
2281	2	brand_ct	xyz
2282	2	assetfinder	xyz
2282	2	subfinder	xyz
2282	2	brand_ct	xyz
2283	2	assetfinder	xyz
2283	2	subfinder	xyz
2283	2	brand_ct	xyz
2284	2	assetfinder	xyz
2284	2	subfinder	xyz
2284	2	brand_ct	xyz
2285	2	assetfinder	xyz
2285	2	subfinder	xyz
2285	2	brand_ct	xyz
2286	2	assetfinder	xyz
2286	2	subfinder	xyz
2286	2	brand_ct	xyz
2287	2	assetfinder	xyz
2287	2	subfinder	xyz
2287	2	brand_ct	xyz
2288	2	assetfinder	xyz
2288	2	subfinder	xyz
2288	2	brand_ct	xyz
2289	2	assetfinder	xyz
2289	2	subfinder	xyz
2289	2	brand_ct	xyz
2290	2	assetfinder	xyz
2290	2	subfinder	xyz
2290	2	brand_ct	xyz
2291	2	assetfinder	xyz
2291	2	subfinder	xyz
2291	2	brand_ct	xyz
2292	2	assetfinder	xyz
2292	2	subfinder	xyz
2292	2	brand_ct	xyz
2293	2	assetfinder	xyz
2293	2	subfinder	xyz
2293	2	brand_ct	xyz
2294	2	assetfinder	xyz
2295	2	assetfinder	xyz
2295	2	subfinder	xyz
2295	2	brand_ct	xyz
2296	2	assetfinder	xyz
2296	2	subfinder	xyz
2296	2	brand_ct	xyz
2297	2	assetfinder	xyz
2297	2	subfinder	xyz
2297	2	brand_ct	xyz
2298	2	assetfinder	xyz
2298	2	subfinder	xyz
2298	2	brand_ct	xyz
2299	2	assetfinder	xyz
2299	2	subfinder	xyz
2299	2	brand_ct	xyz
2300	2	assetfinder	xyz
2300	2	subfinder	xyz
2300	2	brand_ct	xyz
2301	2	assetfinder	xyz
2301	2	subfinder	xyz
2301	2	brand_ct	xyz
2302	2	assetfinder	xyz
2302	2	subfinder	xyz
2302	2	brand_ct	xyz
2303	2	assetfinder	xyz
2303	2	subfinder	xyz
2303	2	brand_ct	xyz
2304	2	assetfinder	xyz
2304	2	subfinder	xyz
2305	2	assetfinder	xyz
2305	2	subfinder	xyz
2305	2	brand_ct	xyz
2306	2	assetfinder	xyz
2306	2	subfinder	xyz
2306	2	brand_ct	xyz
2307	2	assetfinder	xyz
2307	2	subfinder	xyz
2308	2	assetfinder	xyz
2308	2	subfinder	xyz
2308	2	brand_ct	xyz
2309	2	assetfinder	xyz
2309	2	subfinder	xyz
2309	2	brand_ct	xyz
2310	2	assetfinder	xyz
2310	2	subfinder	xyz
2310	2	brand_ct	xyz
2311	2	assetfinder	xyz
2311	2	subfinder	xyz
2311	2	brand_ct	xyz
2312	2	subfinder	xyz
2313	2	assetfinder	xyz
2313	2	brand_ct	xyz
2314	2	assetfinder	xyz
2314	2	subfinder	xyz
2314	2	brand_ct	xyz
2315	2	assetfinder	xyz
2315	2	subfinder	xyz
2315	2	brand_ct	xyz
2316	2	assetfinder	xyz
2316	2	subfinder	xyz
2316	2	brand_ct	xyz
2317	2	assetfinder	xyz
2317	2	subfinder	xyz
2317	2	brand_ct	xyz
2318	2	assetfinder	xyz
2318	2	subfinder	xyz
2318	2	brand_ct	xyz
2319	2	assetfinder	xyz
2319	2	subfinder	xyz
2319	2	brand_ct	xyz
2320	2	assetfinder	xyz
2320	2	subfinder	xyz
2320	2	brand_ct	xyz
2321	2	assetfinder	xyz
2321	2	subfinder	xyz
2321	2	brand_ct	xyz
2322	2	assetfinder	xyz
2322	2	subfinder	xyz
2322	2	brand_ct	xyz
2323	2	assetfinder	xyz
2323	2	subfinder	xyz
2323	2	brand_ct	xyz
2324	2	assetfinder	xyz
2324	2	subfinder	xyz
2324	2	brand_ct	xyz
2325	2	assetfinder	xyz
2325	2	subfinder	xyz
2325	2	brand_ct	xyz
2326	2	assetfinder	xyz
2326	2	subfinder	xyz
2326	2	brand_ct	xyz
2327	2	assetfinder	xyz
2327	2	subfinder	xyz
2327	2	brand_ct	xyz
2328	2	assetfinder	xyz
2328	2	subfinder	xyz
2328	2	brand_ct	xyz
2329	2	assetfinder	xyz
2329	2	subfinder	xyz
2329	2	brand_ct	xyz
2330	2	assetfinder	xyz
2330	2	subfinder	xyz
2330	2	brand_ct	xyz
2331	2	assetfinder	xyz
2331	2	subfinder	xyz
2331	2	brand_ct	xyz
2332	2	assetfinder	xyz
2332	2	subfinder	xyz
2332	2	brand_ct	xyz
2333	2	assetfinder	xyz
2333	2	subfinder	xyz
2333	2	brand_ct	xyz
2334	2	subfinder	xyz
2335	2	brand_ct	xyz
2336	2	assetfinder	xyz
2336	2	subfinder	xyz
2336	2	brand_ct	xyz
2337	2	assetfinder	xyz
2337	2	subfinder	xyz
2337	2	brand_ct	xyz
2338	2	assetfinder	xyz
2338	2	subfinder	xyz
2338	2	brand_ct	xyz
2339	2	assetfinder	xyz
2339	2	subfinder	xyz
2339	2	brand_ct	xyz
2340	2	assetfinder	xyz
2341	2	assetfinder	xyz
2341	2	subfinder	xyz
2341	2	brand_ct	xyz
2342	2	assetfinder	xyz
2342	2	subfinder	xyz
2342	2	brand_ct	xyz
2343	2	assetfinder	xyz
2343	2	subfinder	xyz
2343	2	brand_ct	xyz
2344	2	assetfinder	xyz
2344	2	subfinder	xyz
2344	2	brand_ct	xyz
2345	2	assetfinder	xyz
2345	2	subfinder	xyz
2345	2	brand_ct	xyz
2346	2	assetfinder	xyz
2347	2	assetfinder	xyz
2347	2	subfinder	xyz
2347	2	brand_ct	xyz
2348	2	assetfinder	xyz
2348	2	subfinder	xyz
2348	2	brand_ct	xyz
2349	2	assetfinder	xyz
2349	2	subfinder	xyz
2349	2	brand_ct	xyz
2350	2	assetfinder	xyz
2350	2	subfinder	xyz
2350	2	brand_ct	xyz
2351	2	assetfinder	xyz
2351	2	subfinder	xyz
2351	2	brand_ct	xyz
2352	2	assetfinder	xyz
2353	2	assetfinder	xyz
2353	2	subfinder	xyz
2353	2	brand_ct	xyz
2354	2	assetfinder	xyz
2354	2	subfinder	xyz
2354	2	brand_ct	xyz
2355	2	assetfinder	xyz
2356	2	assetfinder	xyz
2356	2	subfinder	xyz
2356	2	brand_ct	xyz
2357	2	assetfinder	xyz
2357	2	subfinder	xyz
2357	2	brand_ct	xyz
2358	2	assetfinder	xyz
2358	2	subfinder	xyz
2358	2	brand_ct	xyz
2359	2	assetfinder	xyz
2359	2	subfinder	xyz
2359	2	brand_ct	xyz
2360	2	assetfinder	xyz
2360	2	subfinder	xyz
2360	2	brand_ct	xyz
2361	2	assetfinder	xyz
2361	2	subfinder	xyz
2361	2	brand_ct	xyz
2362	2	assetfinder	xyz
2362	2	subfinder	xyz
2362	2	brand_ct	xyz
2363	2	assetfinder	xyz
2363	2	subfinder	xyz
2363	2	brand_ct	xyz
2364	2	assetfinder	xyz
2364	2	subfinder	xyz
2364	2	brand_ct	xyz
2365	2	assetfinder	xyz
2365	2	subfinder	xyz
2365	2	brand_ct	xyz
2366	2	assetfinder	xyz
2367	2	assetfinder	xyz
2368	2	assetfinder	xyz
2368	2	subfinder	xyz
2368	2	brand_ct	xyz
2369	2	assetfinder	xyz
2369	2	brand_ct	xyz
2370	2	assetfinder	xyz
2370	2	subfinder	xyz
2370	2	brand_ct	xyz
2371	2	assetfinder	xyz
2371	2	subfinder	xyz
2371	2	brand_ct	xyz
2372	2	subfinder	xyz
2373	2	brand_ct	xyz
2374	2	brand_ct	xyz
2375	2	brand_ct	xyz
2376	2	assetfinder	xyz
2376	2	subfinder	xyz
2377	2	assetfinder	xyz
2377	2	subfinder	xyz
2377	2	brand_ct	xyz
2378	2	assetfinder	xyz
2378	2	subfinder	xyz
2378	2	brand_ct	xyz
2379	2	assetfinder	xyz
2379	2	subfinder	xyz
2379	2	brand_ct	xyz
2380	2	assetfinder	xyz
2380	2	subfinder	xyz
2380	2	brand_ct	xyz
2381	2	assetfinder	xyz
2381	2	subfinder	xyz
2381	2	brand_ct	xyz
2382	2	assetfinder	xyz
2382	2	subfinder	xyz
2382	2	brand_ct	xyz
2383	2	assetfinder	xyz
2383	2	subfinder	xyz
2383	2	brand_ct	xyz
2384	2	assetfinder	xyz
2384	2	subfinder	xyz
2384	2	brand_ct	xyz
2385	2	assetfinder	xyz
2385	2	subfinder	xyz
2385	2	brand_ct	xyz
2386	2	assetfinder	xyz
2386	2	subfinder	xyz
2386	2	brand_ct	xyz
2387	2	assetfinder	xyz
2387	2	subfinder	xyz
2387	2	brand_ct	xyz
2388	2	assetfinder	xyz
2388	2	subfinder	xyz
2388	2	brand_ct	xyz
2389	2	assetfinder	xyz
2389	2	subfinder	xyz
2389	2	brand_ct	xyz
2390	2	assetfinder	xyz
2390	2	subfinder	xyz
2390	2	brand_ct	xyz
2391	2	assetfinder	xyz
2391	2	subfinder	xyz
2391	2	brand_ct	xyz
2392	2	assetfinder	xyz
2392	2	subfinder	xyz
2392	2	brand_ct	xyz
2393	2	assetfinder	xyz
2393	2	subfinder	xyz
2393	2	brand_ct	xyz
2394	2	assetfinder	xyz
2394	2	subfinder	xyz
2394	2	brand_ct	xyz
2395	2	assetfinder	xyz
2395	2	subfinder	xyz
2395	2	brand_ct	xyz
2396	2	assetfinder	xyz
2396	2	subfinder	xyz
2396	2	brand_ct	xyz
2397	2	assetfinder	xyz
2397	2	subfinder	xyz
2397	2	brand_ct	xyz
2398	2	assetfinder	xyz
2398	2	subfinder	xyz
2398	2	brand_ct	xyz
2399	2	assetfinder	xyz
2399	2	subfinder	xyz
2399	2	brand_ct	xyz
2400	2	assetfinder	xyz
2400	2	subfinder	xyz
2400	2	brand_ct	xyz
2401	2	brand_ct	xyz
2402	2	brand_ct	xyz
2403	2	brand_ct	xyz
2404	2	brand_ct	xyz
2405	2	brand_pattern	xyz
2406	2	brand_pattern	xyz
2407	2	brand_pattern	xyz
2408	2	brand_pattern	xyz
2409	2	brand_pattern	xyz
2410	2	brand_pattern	xyz
2411	2	brand_tld	xyz
2412	2	brand_tld	xyz
2413	2	brand_tld	xyz
2414	2	brand_ct	xyz
2415	2	brand_tld	xyz
2416	2	brand_tld	xyz
2417	2	brand_tld	xyz
2418	2	brand_ct	xyz
2419	2	brand_tld	xyz
2420	2	brand_tld	xyz
2421	2	brand_tld	xyz
2422	2	brand_tld	xyz
2423	2	brand_ct	xyz
2424	2	brand_pattern	xyz
2425	2	brand_pattern	xyz
2426	2	brand_pattern	xyz
2427	2	brand_ct	xyz
2428	2	brand_pattern	xyz
2429	2	assetfinder	xyz
2429	2	subfinder	xyz
2429	2	brand_ct	xyz
2430	2	brand_ct	xyz
2431	2	subfinder	xyz
2432	2	brand_ct	xyz
2433	2	brand_pattern	xyz
2434	2	brand_pattern	xyz
2435	2	assetfinder	xyz
2435	2	subfinder	xyz
2435	2	brand_ct	xyz
2436	2	assetfinder	xyz
2436	2	subfinder	xyz
2436	2	brand_ct	xyz
2437	2	assetfinder	xyz
2437	2	subfinder	xyz
2437	2	brand_ct	xyz
2438	2	assetfinder	xyz
2438	2	subfinder	xyz
2438	2	brand_ct	xyz
2439	2	assetfinder	xyz
2439	2	subfinder	xyz
2439	2	brand_ct	xyz
2440	2	assetfinder	xyz
2440	2	subfinder	xyz
2440	2	brand_ct	xyz
2441	2	assetfinder	xyz
2441	2	subfinder	xyz
2441	2	brand_ct	xyz
2442	2	assetfinder	xyz
2442	2	subfinder	xyz
2442	2	brand_ct	xyz
2443	2	assetfinder	xyz
2443	2	subfinder	xyz
2443	2	brand_ct	xyz
2444	2	assetfinder	xyz
2444	2	subfinder	xyz
2444	2	brand_ct	xyz
2445	2	assetfinder	xyz
2445	2	subfinder	xyz
2445	2	brand_ct	xyz
2446	2	assetfinder	xyz
2446	2	subfinder	xyz
2446	2	brand_ct	xyz
2447	2	assetfinder	xyz
2447	2	subfinder	xyz
2447	2	brand_ct	xyz
2448	2	assetfinder	xyz
2448	2	subfinder	xyz
2448	2	brand_ct	xyz
2449	2	assetfinder	xyz
2449	2	subfinder	xyz
2449	2	brand_ct	xyz
2450	2	assetfinder	xyz
2450	2	subfinder	xyz
2450	2	brand_ct	xyz
2451	2	assetfinder	xyz
2451	2	subfinder	xyz
2451	2	brand_ct	xyz
2452	2	assetfinder	xyz
2452	2	subfinder	xyz
2452	2	brand_ct	xyz
2453	2	assetfinder	xyz
2453	2	subfinder	xyz
2453	2	brand_ct	xyz
2454	2	assetfinder	xyz
2454	2	subfinder	xyz
2454	2	brand_ct	xyz
2455	2	assetfinder	xyz
2455	2	subfinder	xyz
2455	2	brand_ct	xyz
2456	2	assetfinder	xyz
2456	2	subfinder	xyz
2456	2	brand_ct	xyz
2457	2	assetfinder	xyz
2457	2	subfinder	xyz
2457	2	brand_ct	xyz
2458	2	assetfinder	xyz
2458	2	subfinder	xyz
2458	2	brand_ct	xyz
2459	2	assetfinder	xyz
2459	2	subfinder	xyz
2459	2	brand_ct	xyz
2460	2	assetfinder	xyz
2460	2	subfinder	xyz
2460	2	brand_ct	xyz
2461	2	assetfinder	xyz
2461	2	subfinder	xyz
2461	2	brand_ct	xyz
2462	2	assetfinder	xyz
2462	2	subfinder	xyz
2462	2	brand_ct	xyz
2463	2	assetfinder	xyz
2463	2	subfinder	xyz
2463	2	brand_ct	xyz
2464	2	assetfinder	xyz
2464	2	subfinder	xyz
2464	2	brand_ct	xyz
2465	2	assetfinder	xyz
2465	2	subfinder	xyz
2465	2	brand_ct	xyz
2466	2	assetfinder	xyz
2466	2	subfinder	xyz
2466	2	brand_ct	xyz
2467	2	assetfinder	xyz
2467	2	subfinder	xyz
2467	2	brand_ct	xyz
2468	2	assetfinder	xyz
2468	2	subfinder	xyz
2468	2	brand_ct	xyz
2469	2	assetfinder	xyz
2469	2	subfinder	xyz
2469	2	brand_ct	xyz
2470	2	assetfinder	xyz
2470	2	subfinder	xyz
2470	2	brand_ct	xyz
2471	2	assetfinder	xyz
2471	2	subfinder	xyz
2471	2	brand_ct	xyz
2472	2	assetfinder	xyz
2472	2	subfinder	xyz
2472	2	brand_ct	xyz
2473	2	assetfinder	xyz
2473	2	subfinder	xyz
2473	2	brand_ct	xyz
2474	2	assetfinder	xyz
2474	2	subfinder	xyz
2474	2	brand_ct	xyz
2475	2	assetfinder	xyz
2475	2	subfinder	xyz
2475	2	brand_ct	xyz
2476	2	assetfinder	xyz
2476	2	subfinder	xyz
2476	2	brand_ct	xyz
2477	2	assetfinder	xyz
2477	2	subfinder	xyz
2477	2	brand_ct	xyz
2478	2	assetfinder	xyz
2478	2	subfinder	xyz
2478	2	brand_ct	xyz
2479	2	assetfinder	xyz
2479	2	subfinder	xyz
2479	2	brand_ct	xyz
2480	2	assetfinder	xyz
2480	2	subfinder	xyz
2480	2	brand_ct	xyz
1	1	subfinder	abc.com
2	1	subfinder	abc.com
3	1	subfinder	abc.com
4	1	subfinder	abc.com
5	1	subfinder	abc.com
6	1	subfinder	abc.com
7	1	subfinder	abc.com
8	1	subfinder	abc.com
8	1	findomain	abc.com
8	1	assetfinder	abc.com
9	1	subfinder	abc.com
10	1	brand_pattern	abc.com
11	1	brand_pattern	abc.com
12	1	brand_pattern	abc.com
13	1	brand_pattern	abc.com
14	1	brand_pattern	abc.com
15	1	brand_pattern	abc.com
16	1	subfinder	abc.com
17	1	brand_tld	abc.com
18	1	brand_tld	abc.com
19	1	brand_tld	abc.com
20	1	brand_tld	abc.com
21	1	brand_tld	abc.com
21	1	findomain	abc.com
21	1	assetfinder	abc.com
22	1	brand_tld	abc.com
23	1	brand_tld	abc.com
24	1	brand_tld	abc.com
25	1	brand_tld	abc.com
26	1	brand_tld	abc.com
27	1	brand_pattern	abc.com
28	1	brand_pattern	abc.com
29	1	brand_pattern	abc.com
30	1	brand_pattern	abc.com
31	1	subfinder	abc.com
31	1	findomain	abc.com
32	1	subfinder	abc.com
32	1	findomain	abc.com
33	1	brand_pattern	abc.com
34	1	brand_pattern	abc.com
35	1	subfinder	abc.com
35	1	assetfinder	abc.com
36	1	subfinder	abc.com
36	1	findomain	abc.com
37	1	subfinder	abc.com
37	1	findomain	abc.com
38	1	subfinder	abc.com
38	1	assetfinder	abc.com
39	1	subfinder	abc.com
39	1	findomain	abc.com
39	1	assetfinder	abc.com
40	1	subfinder	abc.com
40	1	findomain	abc.com
41	1	subfinder	abc.com
42	1	subfinder	abc.com
43	1	subfinder	abc.com
44	1	subfinder	abc.com
45	1	subfinder	abc.com
46	1	subfinder	abc.com
46	1	findomain	abc.com
47	1	subfinder	abc.com
48	1	subfinder	abc.com
49	1	subfinder	abc.com
50	1	subfinder	abc.com
51	1	subfinder	abc.com
52	1	subfinder	abc.com
52	1	assetfinder	abc.com
53	1	subfinder	abc.com
53	1	findomain	abc.com
53	1	assetfinder	abc.com
54	1	subfinder	abc.com
54	1	findomain	abc.com
55	1	subfinder	abc.com
55	1	assetfinder	abc.com
56	1	subfinder	abc.com
56	1	findomain	abc.com
57	1	subfinder	abc.com
58	1	subfinder	abc.com
58	1	assetfinder	abc.com
59	1	subfinder	abc.com
60	1	subfinder	abc.com
60	1	assetfinder	abc.com
61	1	subfinder	abc.com
61	1	findomain	abc.com
61	1	assetfinder	abc.com
62	1	subfinder	abc.com
62	1	findomain	abc.com
62	1	assetfinder	abc.com
63	1	subfinder	abc.com
63	1	findomain	abc.com
64	1	subfinder	abc.com
64	1	findomain	abc.com
65	1	subfinder	abc.com
65	1	assetfinder	abc.com
66	1	subfinder	abc.com
67	1	subfinder	abc.com
68	1	subfinder	abc.com
68	1	assetfinder	abc.com
69	1	subfinder	abc.com
70	1	subfinder	abc.com
70	1	findomain	abc.com
70	1	assetfinder	abc.com
71	1	subfinder	abc.com
71	1	findomain	abc.com
72	1	subfinder	abc.com
73	1	subfinder	abc.com
74	1	subfinder	abc.com
75	1	subfinder	abc.com
76	1	subfinder	abc.com
77	1	subfinder	abc.com
78	1	subfinder	abc.com
79	1	subfinder	abc.com
79	1	assetfinder	abc.com
80	1	subfinder	abc.com
81	1	subfinder	abc.com
82	1	subfinder	abc.com
83	1	subfinder	abc.com
83	1	assetfinder	abc.com
84	1	subfinder	abc.com
85	1	subfinder	abc.com
86	1	subfinder	abc.com
86	1	assetfinder	abc.com
87	1	subfinder	abc.com
87	1	assetfinder	abc.com
88	1	subfinder	abc.com
88	1	findomain	abc.com
89	1	subfinder	abc.com
90	1	subfinder	abc.com
90	1	findomain	abc.com
90	1	assetfinder	abc.com
91	1	subfinder	abc.com
92	1	subfinder	abc.com
92	1	findomain	abc.com
93	1	subfinder	abc.com
93	1	findomain	abc.com
94	1	subfinder	abc.com
94	1	findomain	abc.com
95	1	subfinder	abc.com
95	1	findomain	abc.com
96	1	subfinder	abc.com
96	1	findomain	abc.com
97	1	subfinder	abc.com
97	1	findomain	abc.com
98	1	subfinder	abc.com
98	1	assetfinder	abc.com
99	1	subfinder	abc.com
99	1	findomain	abc.com
99	1	assetfinder	abc.com
100	1	subfinder	abc.com
100	1	assetfinder	abc.com
101	1	subfinder	abc.com
102	1	subfinder	abc.com
102	1	assetfinder	abc.com
103	1	subfinder	abc.com
103	1	findomain	abc.com
104	1	subfinder	abc.com
104	1	findomain	abc.com
104	1	assetfinder	abc.com
105	1	subfinder	abc.com
105	1	findomain	abc.com
106	1	subfinder	abc.com
106	1	findomain	abc.com
106	1	assetfinder	abc.com
107	1	subfinder	abc.com
108	1	subfinder	abc.com
108	1	findomain	abc.com
109	1	subfinder	abc.com
109	1	findomain	abc.com
110	1	subfinder	abc.com
110	1	findomain	abc.com
111	1	subfinder	abc.com
111	1	findomain	abc.com
112	1	subfinder	abc.com
112	1	findomain	abc.com
112	1	assetfinder	abc.com
113	1	subfinder	abc.com
113	1	assetfinder	abc.com
114	1	subfinder	abc.com
114	1	findomain	abc.com
115	1	subfinder	abc.com
115	1	findomain	abc.com
116	1	subfinder	abc.com
116	1	findomain	abc.com
117	1	subfinder	abc.com
117	1	findomain	abc.com
118	1	subfinder	abc.com
118	1	findomain	abc.com
119	1	subfinder	abc.com
119	1	findomain	abc.com
120	1	subfinder	abc.com
120	1	findomain	abc.com
121	1	subfinder	abc.com
122	1	subfinder	abc.com
122	1	findomain	abc.com
122	1	assetfinder	abc.com
123	1	subfinder	abc.com
123	1	findomain	abc.com
124	1	subfinder	abc.com
124	1	assetfinder	abc.com
125	1	subfinder	abc.com
126	1	subfinder	abc.com
127	1	subfinder	abc.com
128	1	subfinder	abc.com
129	1	subfinder	abc.com
129	1	findomain	abc.com
129	1	assetfinder	abc.com
130	1	subfinder	abc.com
130	1	findomain	abc.com
130	1	assetfinder	abc.com
131	1	subfinder	abc.com
131	1	findomain	abc.com
132	1	subfinder	abc.com
132	1	findomain	abc.com
133	1	subfinder	abc.com
134	1	subfinder	abc.com
135	1	subfinder	abc.com
136	1	subfinder	abc.com
137	1	subfinder	abc.com
137	1	assetfinder	abc.com
138	1	subfinder	abc.com
138	1	findomain	abc.com
138	1	assetfinder	abc.com
139	1	subfinder	abc.com
139	1	findomain	abc.com
139	1	assetfinder	abc.com
140	1	subfinder	abc.com
140	1	assetfinder	abc.com
141	1	brand_pattern	abc.com
142	1	brand_pattern	abc.com
143	1	subfinder	abc.com
143	1	findomain	abc.com
144	1	subfinder	abc.com
144	1	findomain	abc.com
145	1	subfinder	abc.com
145	1	findomain	abc.com
146	1	subfinder	abc.com
146	1	findomain	abc.com
146	1	assetfinder	abc.com
147	1	subfinder	abc.com
148	1	subfinder	abc.com
148	1	assetfinder	abc.com
149	1	subfinder	abc.com
150	1	subfinder	abc.com
151	1	subfinder	abc.com
151	1	findomain	abc.com
152	1	subfinder	abc.com
152	1	findomain	abc.com
152	1	assetfinder	abc.com
153	1	subfinder	abc.com
153	1	findomain	abc.com
153	1	assetfinder	abc.com
154	1	subfinder	abc.com
154	1	assetfinder	abc.com
155	1	subfinder	abc.com
156	1	subfinder	abc.com
156	1	assetfinder	abc.com
157	1	brand_pattern	abc.com
158	1	brand_pattern	abc.com
159	1	subfinder	abc.com
160	1	subfinder	abc.com
160	1	assetfinder	abc.com
161	1	subfinder	abc.com
162	1	subfinder	abc.com
163	1	subfinder	abc.com
164	1	subfinder	abc.com
165	1	subfinder	abc.com
166	1	subfinder	abc.com
167	1	subfinder	abc.com
168	1	subfinder	abc.com
169	1	subfinder	abc.com
170	1	subfinder	abc.com
171	1	subfinder	abc.com
171	1	findomain	abc.com
171	1	assetfinder	abc.com
172	1	subfinder	abc.com
172	1	assetfinder	abc.com
173	1	subfinder	abc.com
173	1	assetfinder	abc.com
174	1	subfinder	abc.com
175	1	subfinder	abc.com
176	1	subfinder	abc.com
177	1	subfinder	abc.com
177	1	findomain	abc.com
178	1	subfinder	abc.com
178	1	findomain	abc.com
179	1	subfinder	abc.com
179	1	findomain	abc.com
179	1	assetfinder	abc.com
180	1	subfinder	abc.com
180	1	assetfinder	abc.com
181	1	subfinder	abc.com
181	1	findomain	abc.com
182	1	subfinder	abc.com
183	1	subfinder	abc.com
184	1	subfinder	abc.com
185	1	subfinder	abc.com
186	1	subfinder	abc.com
187	1	subfinder	abc.com
188	1	subfinder	abc.com
189	1	subfinder	abc.com
190	1	subfinder	abc.com
191	1	subfinder	abc.com
192	1	subfinder	abc.com
193	1	subfinder	abc.com
194	1	subfinder	abc.com
195	1	subfinder	abc.com
195	1	assetfinder	abc.com
196	1	subfinder	abc.com
197	1	subfinder	abc.com
197	1	findomain	abc.com
198	1	brand_pattern	abc.com
199	1	brand_pattern	abc.com
200	1	subfinder	abc.com
201	1	subfinder	abc.com
201	1	findomain	abc.com
202	1	subfinder	abc.com
202	1	assetfinder	abc.com
203	1	subfinder	abc.com
203	1	findomain	abc.com
204	1	subfinder	abc.com
204	1	findomain	abc.com
205	1	subfinder	abc.com
205	1	findomain	abc.com
206	1	subfinder	abc.com
207	1	subfinder	abc.com
207	1	findomain	abc.com
208	1	subfinder	abc.com
209	1	subfinder	abc.com
209	1	findomain	abc.com
210	1	subfinder	abc.com
211	1	subfinder	abc.com
212	1	subfinder	abc.com
213	1	subfinder	abc.com
213	1	findomain	abc.com
214	1	subfinder	abc.com
214	1	findomain	abc.com
215	1	subfinder	abc.com
215	1	findomain	abc.com
216	1	subfinder	abc.com
216	1	findomain	abc.com
217	1	subfinder	abc.com
218	1	subfinder	abc.com
219	1	subfinder	abc.com
220	1	subfinder	abc.com
221	1	subfinder	abc.com
221	1	findomain	abc.com
222	1	subfinder	abc.com
222	1	findomain	abc.com
223	1	subfinder	abc.com
223	1	findomain	abc.com
224	1	subfinder	abc.com
225	1	subfinder	abc.com
225	1	findomain	abc.com
226	1	subfinder	abc.com
226	1	findomain	abc.com
227	1	subfinder	abc.com
228	1	subfinder	abc.com
229	1	subfinder	abc.com
230	1	subfinder	abc.com
231	1	subfinder	abc.com
232	1	subfinder	abc.com
233	1	subfinder	abc.com
234	1	subfinder	abc.com
234	1	findomain	abc.com
235	1	subfinder	abc.com
236	1	brand_pattern	abc.com
237	1	subfinder	abc.com
237	1	findomain	abc.com
238	1	brand_pattern	abc.com
239	1	subfinder	abc.com
239	1	findomain	abc.com
240	1	subfinder	abc.com
241	1	subfinder	abc.com
242	1	subfinder	abc.com
243	1	subfinder	abc.com
243	1	findomain	abc.com
244	1	subfinder	abc.com
245	1	subfinder	abc.com
245	1	findomain	abc.com
246	1	subfinder	abc.com
246	1	findomain	abc.com
247	1	subfinder	abc.com
247	1	findomain	abc.com
248	1	subfinder	abc.com
248	1	findomain	abc.com
249	1	subfinder	abc.com
250	1	subfinder	abc.com
250	1	findomain	abc.com
251	1	subfinder	abc.com
251	1	findomain	abc.com
252	1	subfinder	abc.com
252	1	findomain	abc.com
253	1	subfinder	abc.com
253	1	findomain	abc.com
254	1	subfinder	abc.com
254	1	findomain	abc.com
255	1	subfinder	abc.com
255	1	findomain	abc.com
256	1	subfinder	abc.com
256	1	findomain	abc.com
257	1	subfinder	abc.com
257	1	findomain	abc.com
258	1	subfinder	abc.com
258	1	findomain	abc.com
259	1	subfinder	abc.com
260	1	subfinder	abc.com
260	1	findomain	abc.com
261	1	subfinder	abc.com
261	1	findomain	abc.com
262	1	subfinder	abc.com
262	1	findomain	abc.com
263	1	subfinder	abc.com
264	1	subfinder	abc.com
265	1	subfinder	abc.com
265	1	findomain	abc.com
266	1	subfinder	abc.com
267	1	brand_pattern	abc.com
268	1	brand_pattern	abc.com
269	1	subfinder	abc.com
269	1	findomain	abc.com
270	1	subfinder	abc.com
270	1	findomain	abc.com
271	1	subfinder	abc.com
272	1	subfinder	abc.com
273	1	subfinder	abc.com
274	1	subfinder	abc.com
275	1	subfinder	abc.com
276	1	subfinder	abc.com
277	1	subfinder	abc.com
278	1	subfinder	abc.com
279	1	subfinder	abc.com
279	1	findomain	abc.com
280	1	subfinder	abc.com
280	1	findomain	abc.com
281	1	subfinder	abc.com
282	1	subfinder	abc.com
283	1	subfinder	abc.com
284	1	subfinder	abc.com
285	1	subfinder	abc.com
286	1	subfinder	abc.com
287	1	subfinder	abc.com
288	1	subfinder	abc.com
289	1	subfinder	abc.com
290	1	subfinder	abc.com
291	1	subfinder	abc.com
292	1	subfinder	abc.com
292	1	findomain	abc.com
293	1	subfinder	abc.com
294	1	subfinder	abc.com
294	1	findomain	abc.com
295	1	subfinder	abc.com
296	1	subfinder	abc.com
297	1	subfinder	abc.com
298	1	subfinder	abc.com
298	1	findomain	abc.com
299	1	subfinder	abc.com
299	1	findomain	abc.com
299	1	assetfinder	abc.com
300	1	subfinder	abc.com
301	1	subfinder	abc.com
302	1	subfinder	abc.com
303	1	subfinder	abc.com
304	1	subfinder	abc.com
305	1	subfinder	abc.com
305	1	assetfinder	abc.com
306	1	subfinder	abc.com
307	1	subfinder	abc.com
308	1	subfinder	abc.com
309	1	subfinder	abc.com
310	1	subfinder	abc.com
311	1	subfinder	abc.com
312	1	subfinder	abc.com
313	1	subfinder	abc.com
313	1	findomain	abc.com
314	1	subfinder	abc.com
315	1	subfinder	abc.com
316	1	subfinder	abc.com
317	1	subfinder	abc.com
318	1	subfinder	abc.com
319	1	subfinder	abc.com
320	1	subfinder	abc.com
321	1	subfinder	abc.com
322	1	subfinder	abc.com
323	1	subfinder	abc.com
323	1	findomain	abc.com
324	1	subfinder	abc.com
324	1	findomain	abc.com
325	1	subfinder	abc.com
325	1	findomain	abc.com
1	2	subfinder	abc.com
2	2	subfinder	abc.com
1673	2	subfinder	abc.com
3	2	subfinder	abc.com
4	2	subfinder	abc.com
5	2	subfinder	abc.com
6	2	subfinder	abc.com
7	2	subfinder	abc.com
1679	2	subfinder	abc.com
1680	2	subfinder	abc.com
1681	2	subfinder	abc.com
1682	2	subfinder	abc.com
1683	2	subfinder	abc.com
8	2	subfinder	abc.com
8	2	findomain	abc.com
8	2	assetfinder	abc.com
9	2	subfinder	abc.com
1686	2	subfinder	abc.com
1687	2	subfinder	abc.com
10	2	brand_pattern	abc.com
11	2	brand_pattern	abc.com
12	2	brand_pattern	abc.com
13	2	brand_pattern	abc.com
14	2	brand_pattern	abc.com
15	2	brand_pattern	abc.com
1694	2	subfinder	abc.com
16	2	subfinder	abc.com
17	2	brand_tld	abc.com
18	2	brand_tld	abc.com
19	2	brand_tld	abc.com
20	2	brand_tld	abc.com
21	2	assetfinder	abc.com
21	2	findomain	abc.com
21	2	brand_tld	abc.com
22	2	brand_tld	abc.com
23	2	brand_tld	abc.com
24	2	brand_tld	abc.com
25	2	brand_tld	abc.com
26	2	brand_tld	abc.com
1706	2	subfinder	abc.com
27	2	brand_pattern	abc.com
28	2	brand_pattern	abc.com
29	2	brand_pattern	abc.com
30	2	brand_pattern	abc.com
31	2	subfinder	abc.com
31	2	findomain	abc.com
32	2	subfinder	abc.com
32	2	findomain	abc.com
33	2	brand_pattern	abc.com
34	2	brand_pattern	abc.com
1715	2	subfinder	abc.com
1716	2	subfinder	abc.com
1717	2	subfinder	abc.com
35	2	subfinder	abc.com
35	2	assetfinder	abc.com
36	2	subfinder	abc.com
36	2	findomain	abc.com
37	2	subfinder	abc.com
37	2	findomain	abc.com
38	2	subfinder	abc.com
38	2	assetfinder	abc.com
39	2	subfinder	abc.com
39	2	findomain	abc.com
39	2	assetfinder	abc.com
40	2	subfinder	abc.com
40	2	findomain	abc.com
41	2	subfinder	abc.com
1725	2	subfinder	abc.com
42	2	subfinder	abc.com
43	2	subfinder	abc.com
44	2	subfinder	abc.com
45	2	subfinder	abc.com
46	2	subfinder	abc.com
46	2	findomain	abc.com
1731	2	subfinder	abc.com
47	2	subfinder	abc.com
48	2	subfinder	abc.com
49	2	subfinder	abc.com
50	2	subfinder	abc.com
51	2	subfinder	abc.com
52	2	subfinder	abc.com
52	2	assetfinder	abc.com
1738	2	subfinder	abc.com
53	2	subfinder	abc.com
53	2	findomain	abc.com
53	2	assetfinder	abc.com
54	2	subfinder	abc.com
54	2	findomain	abc.com
55	2	subfinder	abc.com
55	2	assetfinder	abc.com
56	2	subfinder	abc.com
56	2	findomain	abc.com
57	2	subfinder	abc.com
58	2	subfinder	abc.com
58	2	assetfinder	abc.com
1745	2	subfinder	abc.com
59	2	subfinder	abc.com
60	2	subfinder	abc.com
60	2	assetfinder	abc.com
61	2	subfinder	abc.com
61	2	findomain	abc.com
61	2	assetfinder	abc.com
62	2	subfinder	abc.com
62	2	findomain	abc.com
63	2	subfinder	abc.com
63	2	findomain	abc.com
64	2	subfinder	abc.com
64	2	findomain	abc.com
65	2	subfinder	abc.com
65	2	assetfinder	abc.com
1753	2	subfinder	abc.com
66	2	subfinder	abc.com
67	2	subfinder	abc.com
68	2	subfinder	abc.com
68	2	assetfinder	abc.com
69	2	subfinder	abc.com
70	2	subfinder	abc.com
70	2	findomain	abc.com
70	2	assetfinder	abc.com
71	2	subfinder	abc.com
71	2	findomain	abc.com
72	2	subfinder	abc.com
73	2	subfinder	abc.com
74	2	subfinder	abc.com
75	2	subfinder	abc.com
76	2	subfinder	abc.com
77	2	subfinder	abc.com
78	2	subfinder	abc.com
1767	2	subfinder	abc.com
79	2	subfinder	abc.com
79	2	assetfinder	abc.com
80	2	subfinder	abc.com
1770	2	subfinder	abc.com
1771	2	subfinder	abc.com
81	2	subfinder	abc.com
1773	2	subfinder	abc.com
82	2	subfinder	abc.com
1775	2	subfinder	abc.com
83	2	subfinder	abc.com
83	2	assetfinder	abc.com
1777	2	subfinder	abc.com
84	2	subfinder	abc.com
85	2	subfinder	abc.com
86	2	subfinder	abc.com
86	2	assetfinder	abc.com
87	2	subfinder	abc.com
87	2	assetfinder	abc.com
88	2	subfinder	abc.com
88	2	findomain	abc.com
89	2	subfinder	abc.com
90	2	subfinder	abc.com
90	2	findomain	abc.com
90	2	assetfinder	abc.com
91	2	subfinder	abc.com
92	2	subfinder	abc.com
92	2	findomain	abc.com
93	2	subfinder	abc.com
93	2	findomain	abc.com
94	2	subfinder	abc.com
94	2	findomain	abc.com
95	2	subfinder	abc.com
95	2	findomain	abc.com
96	2	subfinder	abc.com
96	2	findomain	abc.com
97	2	subfinder	abc.com
97	2	findomain	abc.com
1792	2	subfinder	abc.com
98	2	subfinder	abc.com
98	2	assetfinder	abc.com
99	2	subfinder	abc.com
99	2	findomain	abc.com
99	2	assetfinder	abc.com
100	2	subfinder	abc.com
100	2	assetfinder	abc.com
1796	2	subfinder	abc.com
101	2	subfinder	abc.com
102	2	subfinder	abc.com
102	2	assetfinder	abc.com
103	2	subfinder	abc.com
103	2	findomain	abc.com
104	2	subfinder	abc.com
104	2	findomain	abc.com
104	2	assetfinder	abc.com
105	2	subfinder	abc.com
105	2	findomain	abc.com
105	2	assetfinder	abc.com
106	2	subfinder	abc.com
106	2	findomain	abc.com
106	2	assetfinder	abc.com
107	2	subfinder	abc.com
108	2	subfinder	abc.com
108	2	findomain	abc.com
109	2	subfinder	abc.com
109	2	findomain	abc.com
110	2	subfinder	abc.com
110	2	findomain	abc.com
111	2	subfinder	abc.com
111	2	findomain	abc.com
112	2	subfinder	abc.com
112	2	findomain	abc.com
113	2	subfinder	abc.com
113	2	assetfinder	abc.com
114	2	subfinder	abc.com
114	2	findomain	abc.com
115	2	subfinder	abc.com
115	2	findomain	abc.com
116	2	subfinder	abc.com
116	2	findomain	abc.com
117	2	subfinder	abc.com
117	2	findomain	abc.com
118	2	subfinder	abc.com
118	2	findomain	abc.com
119	2	subfinder	abc.com
119	2	findomain	abc.com
120	2	subfinder	abc.com
120	2	findomain	abc.com
121	2	subfinder	abc.com
122	2	subfinder	abc.com
122	2	findomain	abc.com
122	2	assetfinder	abc.com
123	2	subfinder	abc.com
123	2	findomain	abc.com
1820	2	subfinder	abc.com
124	2	subfinder	abc.com
124	2	assetfinder	abc.com
1822	2	subfinder	abc.com
125	2	subfinder	abc.com
126	2	subfinder	abc.com
127	2	subfinder	abc.com
128	2	subfinder	abc.com
129	2	subfinder	abc.com
129	2	findomain	abc.com
129	2	assetfinder	abc.com
130	2	subfinder	abc.com
130	2	findomain	abc.com
130	2	assetfinder	abc.com
131	2	subfinder	abc.com
131	2	findomain	abc.com
132	2	subfinder	abc.com
132	2	findomain	abc.com
1831	2	subfinder	abc.com
133	2	subfinder	abc.com
134	2	subfinder	abc.com
135	2	subfinder	abc.com
136	2	subfinder	abc.com
137	2	subfinder	abc.com
137	2	assetfinder	abc.com
138	2	subfinder	abc.com
138	2	findomain	abc.com
138	2	assetfinder	abc.com
139	2	subfinder	abc.com
139	2	findomain	abc.com
139	2	assetfinder	abc.com
140	2	subfinder	abc.com
140	2	assetfinder	abc.com
141	2	brand_pattern	abc.com
142	2	brand_pattern	abc.com
1842	2	subfinder	abc.com
1843	2	subfinder	abc.com
143	2	subfinder	abc.com
143	2	findomain	abc.com
144	2	subfinder	abc.com
144	2	findomain	abc.com
145	2	subfinder	abc.com
145	2	findomain	abc.com
1847	2	subfinder	abc.com
146	2	subfinder	abc.com
146	2	findomain	abc.com
146	2	assetfinder	abc.com
1849	2	subfinder	abc.com
147	2	subfinder	abc.com
148	2	subfinder	abc.com
148	2	assetfinder	abc.com
149	2	subfinder	abc.com
150	2	subfinder	abc.com
1854	2	subfinder	abc.com
151	2	subfinder	abc.com
151	2	findomain	abc.com
152	2	subfinder	abc.com
152	2	findomain	abc.com
152	2	assetfinder	abc.com
153	2	subfinder	abc.com
153	2	findomain	abc.com
153	2	assetfinder	abc.com
1858	2	subfinder	abc.com
1859	2	subfinder	abc.com
154	2	subfinder	abc.com
154	2	assetfinder	abc.com
155	2	subfinder	abc.com
1862	2	subfinder	abc.com
1863	2	subfinder	abc.com
1864	2	subfinder	abc.com
156	2	subfinder	abc.com
156	2	assetfinder	abc.com
157	2	brand_pattern	abc.com
158	2	brand_pattern	abc.com
159	2	subfinder	abc.com
160	2	subfinder	abc.com
160	2	assetfinder	abc.com
1870	2	subfinder	abc.com
1871	2	subfinder	abc.com
161	2	subfinder	abc.com
162	2	subfinder	abc.com
163	2	subfinder	abc.com
1875	2	subfinder	abc.com
164	2	subfinder	abc.com
165	2	subfinder	abc.com
166	2	subfinder	abc.com
167	2	subfinder	abc.com
168	2	subfinder	abc.com
169	2	subfinder	abc.com
170	2	subfinder	abc.com
1883	2	subfinder	abc.com
1884	2	subfinder	abc.com
1884	2	assetfinder	abc.com
171	2	subfinder	abc.com
171	2	findomain	abc.com
171	2	assetfinder	abc.com
1886	2	subfinder	abc.com
172	2	subfinder	abc.com
172	2	assetfinder	abc.com
173	2	subfinder	abc.com
173	2	assetfinder	abc.com
1889	2	subfinder	abc.com
1890	2	subfinder	abc.com
174	2	subfinder	abc.com
1892	2	subfinder	abc.com
1893	2	subfinder	abc.com
175	2	subfinder	abc.com
176	2	subfinder	abc.com
177	2	subfinder	abc.com
177	2	findomain	abc.com
178	2	subfinder	abc.com
178	2	findomain	abc.com
179	2	subfinder	abc.com
179	2	findomain	abc.com
179	2	assetfinder	abc.com
180	2	subfinder	abc.com
180	2	assetfinder	abc.com
181	2	subfinder	abc.com
181	2	findomain	abc.com
182	2	subfinder	abc.com
183	2	subfinder	abc.com
184	2	subfinder	abc.com
185	2	subfinder	abc.com
186	2	subfinder	abc.com
187	2	subfinder	abc.com
188	2	subfinder	abc.com
189	2	subfinder	abc.com
190	2	subfinder	abc.com
191	2	subfinder	abc.com
192	2	subfinder	abc.com
193	2	subfinder	abc.com
194	2	subfinder	abc.com
195	2	subfinder	abc.com
195	2	assetfinder	abc.com
196	2	subfinder	abc.com
1916	2	subfinder	abc.com
197	2	subfinder	abc.com
197	2	findomain	abc.com
1918	2	subfinder	abc.com
198	2	brand_pattern	abc.com
199	2	brand_pattern	abc.com
200	2	subfinder	abc.com
201	2	subfinder	abc.com
201	2	findomain	abc.com
1923	2	subfinder	abc.com
202	2	subfinder	abc.com
1925	2	subfinder	abc.com
203	2	subfinder	abc.com
203	2	findomain	abc.com
204	2	subfinder	abc.com
204	2	findomain	abc.com
205	2	subfinder	abc.com
205	2	findomain	abc.com
1929	2	subfinder	abc.com
1930	2	subfinder	abc.com
1931	2	subfinder	abc.com
206	2	subfinder	abc.com
207	2	subfinder	abc.com
207	2	findomain	abc.com
1934	2	subfinder	abc.com
1935	2	subfinder	abc.com
1936	2	subfinder	abc.com
208	2	subfinder	abc.com
1938	2	subfinder	abc.com
209	2	subfinder	abc.com
209	2	findomain	abc.com
1940	2	subfinder	abc.com
210	2	subfinder	abc.com
1942	2	subfinder	abc.com
1943	2	subfinder	abc.com
211	2	subfinder	abc.com
212	2	subfinder	abc.com
213	2	subfinder	abc.com
213	2	findomain	abc.com
214	2	subfinder	abc.com
214	2	findomain	abc.com
1948	2	subfinder	abc.com
215	2	subfinder	abc.com
215	2	findomain	abc.com
216	2	subfinder	abc.com
216	2	findomain	abc.com
217	2	subfinder	abc.com
1952	2	subfinder	abc.com
218	2	subfinder	abc.com
219	2	subfinder	abc.com
220	2	subfinder	abc.com
1956	2	subfinder	abc.com
221	2	subfinder	abc.com
221	2	findomain	abc.com
222	2	subfinder	abc.com
222	2	findomain	abc.com
223	2	subfinder	abc.com
223	2	findomain	abc.com
1960	2	subfinder	abc.com
224	2	subfinder	abc.com
225	2	subfinder	abc.com
225	2	findomain	abc.com
226	2	subfinder	abc.com
226	2	findomain	abc.com
227	2	subfinder	abc.com
1965	2	subfinder	abc.com
228	2	subfinder	abc.com
229	2	subfinder	abc.com
230	2	subfinder	abc.com
231	2	subfinder	abc.com
232	2	subfinder	abc.com
233	2	subfinder	abc.com
234	2	subfinder	abc.com
234	2	findomain	abc.com
235	2	subfinder	abc.com
1974	2	subfinder	abc.com
236	2	brand_pattern	abc.com
237	2	subfinder	abc.com
237	2	findomain	abc.com
238	2	brand_pattern	abc.com
239	2	subfinder	abc.com
239	2	findomain	abc.com
240	2	subfinder	abc.com
241	2	subfinder	abc.com
1981	2	subfinder	abc.com
1982	2	subfinder	abc.com
242	2	subfinder	abc.com
243	2	subfinder	abc.com
243	2	findomain	abc.com
244	2	subfinder	abc.com
245	2	subfinder	abc.com
245	2	findomain	abc.com
246	2	subfinder	abc.com
246	2	findomain	abc.com
1988	2	subfinder	abc.com
1989	2	subfinder	abc.com
247	2	subfinder	abc.com
247	2	findomain	abc.com
248	2	subfinder	abc.com
248	2	findomain	abc.com
249	2	subfinder	abc.com
250	2	subfinder	abc.com
250	2	findomain	abc.com
251	2	subfinder	abc.com
251	2	findomain	abc.com
252	2	subfinder	abc.com
252	2	findomain	abc.com
1996	2	subfinder	abc.com
1997	2	subfinder	abc.com
1998	2	subfinder	abc.com
253	2	subfinder	abc.com
253	2	findomain	abc.com
254	2	subfinder	abc.com
254	2	findomain	abc.com
255	2	subfinder	abc.com
255	2	findomain	abc.com
256	2	subfinder	abc.com
256	2	findomain	abc.com
257	2	subfinder	abc.com
257	2	findomain	abc.com
2004	2	subfinder	abc.com
258	2	subfinder	abc.com
258	2	findomain	abc.com
258	2	assetfinder	abc.com
2006	2	subfinder	abc.com
259	2	subfinder	abc.com
260	2	subfinder	abc.com
260	2	findomain	abc.com
261	2	subfinder	abc.com
261	2	findomain	abc.com
2010	2	subfinder	abc.com
262	2	subfinder	abc.com
262	2	findomain	abc.com
263	2	subfinder	abc.com
2013	2	subfinder	abc.com
264	2	subfinder	abc.com
2015	2	subfinder	abc.com
2016	2	subfinder	abc.com
265	2	subfinder	abc.com
265	2	findomain	abc.com
266	2	subfinder	abc.com
267	2	brand_pattern	abc.com
268	2	brand_pattern	abc.com
2021	2	subfinder	abc.com
2022	2	subfinder	abc.com
269	2	subfinder	abc.com
269	2	findomain	abc.com
270	2	subfinder	abc.com
270	2	findomain	abc.com
271	2	subfinder	abc.com
272	2	subfinder	abc.com
273	2	subfinder	abc.com
274	2	subfinder	abc.com
275	2	subfinder	abc.com
276	2	subfinder	abc.com
277	2	subfinder	abc.com
278	2	subfinder	abc.com
2033	2	subfinder	abc.com
279	2	subfinder	abc.com
279	2	findomain	abc.com
280	2	subfinder	abc.com
280	2	findomain	abc.com
281	2	subfinder	abc.com
282	2	subfinder	abc.com
283	2	subfinder	abc.com
284	2	subfinder	abc.com
285	2	subfinder	abc.com
286	2	subfinder	abc.com
287	2	subfinder	abc.com
288	2	subfinder	abc.com
289	2	subfinder	abc.com
290	2	subfinder	abc.com
291	2	subfinder	abc.com
292	2	subfinder	abc.com
292	2	findomain	abc.com
2048	2	subfinder	abc.com
2049	2	subfinder	abc.com
293	2	subfinder	abc.com
2051	2	subfinder	abc.com
294	2	subfinder	abc.com
294	2	findomain	abc.com
2053	2	subfinder	abc.com
295	2	subfinder	abc.com
296	2	subfinder	abc.com
2056	2	subfinder	abc.com
2057	2	subfinder	abc.com
297	2	subfinder	abc.com
2059	2	subfinder	abc.com
2060	2	subfinder	abc.com
2061	2	subfinder	abc.com
298	2	subfinder	abc.com
298	2	findomain	abc.com
2063	2	subfinder	abc.com
299	2	subfinder	abc.com
299	2	findomain	abc.com
299	2	assetfinder	abc.com
300	2	subfinder	abc.com
301	2	subfinder	abc.com
302	2	subfinder	abc.com
303	2	subfinder	abc.com
304	2	subfinder	abc.com
305	2	subfinder	abc.com
305	2	assetfinder	abc.com
306	2	subfinder	abc.com
2072	2	subfinder	abc.com
2072	2	assetfinder	abc.com
307	2	subfinder	abc.com
308	2	subfinder	abc.com
309	2	subfinder	abc.com
310	2	subfinder	abc.com
311	2	subfinder	abc.com
312	2	subfinder	abc.com
313	2	subfinder	abc.com
313	2	findomain	abc.com
314	2	subfinder	abc.com
315	2	subfinder	abc.com
316	2	subfinder	abc.com
317	2	subfinder	abc.com
318	2	subfinder	abc.com
319	2	subfinder	abc.com
2086	2	subfinder	abc.com
320	2	subfinder	abc.com
321	2	subfinder	abc.com
322	2	subfinder	abc.com
323	2	subfinder	abc.com
323	2	findomain	abc.com
324	2	subfinder	abc.com
324	2	findomain	abc.com
325	2	subfinder	abc.com
325	2	findomain	abc.com
1	3	subfinder	abc.com
2	3	subfinder	abc.com
1673	3	subfinder	abc.com
3	3	subfinder	abc.com
4	3	subfinder	abc.com
5	3	subfinder	abc.com
6	3	subfinder	abc.com
7	3	subfinder	abc.com
1679	3	subfinder	abc.com
1680	3	subfinder	abc.com
1681	3	subfinder	abc.com
1682	3	subfinder	abc.com
1683	3	subfinder	abc.com
8	3	findomain	abc.com
8	3	subfinder	abc.com
8	3	assetfinder	abc.com
9	3	subfinder	abc.com
1686	3	subfinder	abc.com
1687	3	subfinder	abc.com
10	3	brand_pattern	abc.com
11	3	brand_pattern	abc.com
12	3	brand_pattern	abc.com
13	3	brand_pattern	abc.com
14	3	brand_pattern	abc.com
15	3	brand_pattern	abc.com
1694	3	subfinder	abc.com
16	3	subfinder	abc.com
17	3	brand_tld	abc.com
18	3	brand_tld	abc.com
19	3	brand_tld	abc.com
20	3	brand_tld	abc.com
21	3	findomain	abc.com
21	3	brand_tld	abc.com
21	3	assetfinder	abc.com
22	3	brand_tld	abc.com
23	3	brand_tld	abc.com
24	3	brand_tld	abc.com
25	3	brand_tld	abc.com
26	3	brand_tld	abc.com
1706	3	subfinder	abc.com
27	3	brand_pattern	abc.com
28	3	brand_pattern	abc.com
29	3	brand_pattern	abc.com
30	3	brand_pattern	abc.com
31	3	findomain	abc.com
31	3	subfinder	abc.com
32	3	findomain	abc.com
32	3	subfinder	abc.com
33	3	brand_pattern	abc.com
34	3	brand_pattern	abc.com
1715	3	subfinder	abc.com
1716	3	subfinder	abc.com
1717	3	subfinder	abc.com
35	3	subfinder	abc.com
35	3	assetfinder	abc.com
36	3	findomain	abc.com
36	3	subfinder	abc.com
37	3	findomain	abc.com
38	3	subfinder	abc.com
38	3	assetfinder	abc.com
39	3	findomain	abc.com
39	3	subfinder	abc.com
39	3	assetfinder	abc.com
40	3	findomain	abc.com
40	3	subfinder	abc.com
41	3	subfinder	abc.com
1725	3	subfinder	abc.com
42	3	subfinder	abc.com
43	3	subfinder	abc.com
44	3	subfinder	abc.com
45	3	subfinder	abc.com
46	3	findomain	abc.com
46	3	subfinder	abc.com
1731	3	subfinder	abc.com
47	3	subfinder	abc.com
48	3	subfinder	abc.com
49	3	subfinder	abc.com
50	3	subfinder	abc.com
51	3	subfinder	abc.com
52	3	subfinder	abc.com
52	3	assetfinder	abc.com
1738	3	subfinder	abc.com
53	3	findomain	abc.com
53	3	subfinder	abc.com
53	3	assetfinder	abc.com
54	3	findomain	abc.com
54	3	subfinder	abc.com
55	3	subfinder	abc.com
55	3	assetfinder	abc.com
56	3	findomain	abc.com
56	3	subfinder	abc.com
57	3	subfinder	abc.com
58	3	subfinder	abc.com
58	3	assetfinder	abc.com
1745	3	subfinder	abc.com
59	3	subfinder	abc.com
60	3	subfinder	abc.com
60	3	assetfinder	abc.com
61	3	findomain	abc.com
61	3	subfinder	abc.com
61	3	assetfinder	abc.com
62	3	findomain	abc.com
62	3	subfinder	abc.com
63	3	findomain	abc.com
64	3	findomain	abc.com
65	3	subfinder	abc.com
65	3	assetfinder	abc.com
1753	3	subfinder	abc.com
66	3	subfinder	abc.com
67	3	subfinder	abc.com
68	3	subfinder	abc.com
68	3	assetfinder	abc.com
69	3	subfinder	abc.com
70	3	findomain	abc.com
70	3	subfinder	abc.com
70	3	assetfinder	abc.com
71	3	findomain	abc.com
71	3	subfinder	abc.com
72	3	subfinder	abc.com
73	3	subfinder	abc.com
74	3	subfinder	abc.com
75	3	subfinder	abc.com
76	3	subfinder	abc.com
77	3	subfinder	abc.com
78	3	subfinder	abc.com
1767	3	subfinder	abc.com
79	3	subfinder	abc.com
79	3	assetfinder	abc.com
80	3	subfinder	abc.com
1770	3	subfinder	abc.com
1771	3	subfinder	abc.com
81	3	subfinder	abc.com
1773	3	subfinder	abc.com
82	3	subfinder	abc.com
1775	3	subfinder	abc.com
83	3	subfinder	abc.com
83	3	assetfinder	abc.com
1777	3	subfinder	abc.com
84	3	subfinder	abc.com
86	3	subfinder	abc.com
86	3	assetfinder	abc.com
87	3	subfinder	abc.com
87	3	assetfinder	abc.com
88	3	findomain	abc.com
88	3	subfinder	abc.com
89	3	subfinder	abc.com
90	3	findomain	abc.com
90	3	subfinder	abc.com
90	3	assetfinder	abc.com
91	3	subfinder	abc.com
92	3	findomain	abc.com
93	3	findomain	abc.com
94	3	findomain	abc.com
95	3	findomain	abc.com
95	3	subfinder	abc.com
96	3	findomain	abc.com
97	3	findomain	abc.com
1792	3	subfinder	abc.com
98	3	subfinder	abc.com
98	3	assetfinder	abc.com
99	3	findomain	abc.com
99	3	subfinder	abc.com
99	3	assetfinder	abc.com
100	3	subfinder	abc.com
100	3	assetfinder	abc.com
1796	3	subfinder	abc.com
102	3	subfinder	abc.com
102	3	assetfinder	abc.com
103	3	findomain	abc.com
103	3	subfinder	abc.com
104	3	findomain	abc.com
104	3	subfinder	abc.com
104	3	assetfinder	abc.com
105	3	findomain	abc.com
105	3	subfinder	abc.com
105	3	assetfinder	abc.com
106	3	findomain	abc.com
106	3	subfinder	abc.com
106	3	assetfinder	abc.com
107	3	subfinder	abc.com
108	3	findomain	abc.com
108	3	subfinder	abc.com
109	3	findomain	abc.com
109	3	subfinder	abc.com
110	3	findomain	abc.com
110	3	subfinder	abc.com
111	3	findomain	abc.com
111	3	subfinder	abc.com
112	3	findomain	abc.com
112	3	subfinder	abc.com
113	3	subfinder	abc.com
113	3	assetfinder	abc.com
114	3	findomain	abc.com
115	3	findomain	abc.com
116	3	findomain	abc.com
116	3	subfinder	abc.com
117	3	findomain	abc.com
117	3	subfinder	abc.com
118	3	findomain	abc.com
119	3	findomain	abc.com
119	3	subfinder	abc.com
120	3	findomain	abc.com
120	3	subfinder	abc.com
121	3	subfinder	abc.com
122	3	findomain	abc.com
122	3	subfinder	abc.com
122	3	assetfinder	abc.com
123	3	findomain	abc.com
123	3	subfinder	abc.com
1820	3	subfinder	abc.com
124	3	subfinder	abc.com
124	3	assetfinder	abc.com
1822	3	subfinder	abc.com
126	3	subfinder	abc.com
127	3	subfinder	abc.com
128	3	subfinder	abc.com
129	3	findomain	abc.com
129	3	subfinder	abc.com
129	3	assetfinder	abc.com
130	3	findomain	abc.com
130	3	subfinder	abc.com
130	3	assetfinder	abc.com
131	3	findomain	abc.com
131	3	subfinder	abc.com
132	3	findomain	abc.com
132	3	subfinder	abc.com
1831	3	subfinder	abc.com
133	3	subfinder	abc.com
134	3	subfinder	abc.com
135	3	subfinder	abc.com
136	3	subfinder	abc.com
137	3	subfinder	abc.com
137	3	assetfinder	abc.com
138	3	findomain	abc.com
138	3	subfinder	abc.com
138	3	assetfinder	abc.com
139	3	findomain	abc.com
139	3	subfinder	abc.com
139	3	assetfinder	abc.com
140	3	subfinder	abc.com
140	3	assetfinder	abc.com
141	3	brand_pattern	abc.com
142	3	brand_pattern	abc.com
1842	3	subfinder	abc.com
1843	3	subfinder	abc.com
143	3	findomain	abc.com
144	3	findomain	abc.com
145	3	findomain	abc.com
145	3	subfinder	abc.com
1847	3	subfinder	abc.com
146	3	findomain	abc.com
146	3	subfinder	abc.com
146	3	assetfinder	abc.com
1849	3	subfinder	abc.com
147	3	subfinder	abc.com
148	3	subfinder	abc.com
148	3	assetfinder	abc.com
149	3	subfinder	abc.com
150	3	subfinder	abc.com
1854	3	subfinder	abc.com
151	3	findomain	abc.com
151	3	subfinder	abc.com
152	3	findomain	abc.com
152	3	subfinder	abc.com
152	3	assetfinder	abc.com
153	3	findomain	abc.com
153	3	subfinder	abc.com
153	3	assetfinder	abc.com
1858	3	subfinder	abc.com
1859	3	subfinder	abc.com
154	3	subfinder	abc.com
154	3	assetfinder	abc.com
155	3	subfinder	abc.com
1862	3	subfinder	abc.com
1863	3	subfinder	abc.com
1864	3	subfinder	abc.com
156	3	subfinder	abc.com
156	3	assetfinder	abc.com
157	3	brand_pattern	abc.com
158	3	brand_pattern	abc.com
160	3	subfinder	abc.com
160	3	assetfinder	abc.com
1870	3	subfinder	abc.com
1871	3	subfinder	abc.com
161	3	subfinder	abc.com
162	3	subfinder	abc.com
163	3	subfinder	abc.com
1875	3	subfinder	abc.com
164	3	subfinder	abc.com
165	3	subfinder	abc.com
166	3	subfinder	abc.com
167	3	subfinder	abc.com
168	3	subfinder	abc.com
169	3	subfinder	abc.com
170	3	subfinder	abc.com
1883	3	subfinder	abc.com
1884	3	subfinder	abc.com
1884	3	assetfinder	abc.com
171	3	findomain	abc.com
171	3	subfinder	abc.com
171	3	assetfinder	abc.com
1886	3	subfinder	abc.com
172	3	subfinder	abc.com
172	3	assetfinder	abc.com
173	3	subfinder	abc.com
173	3	assetfinder	abc.com
1889	3	subfinder	abc.com
1890	3	subfinder	abc.com
174	3	subfinder	abc.com
1892	3	subfinder	abc.com
1893	3	subfinder	abc.com
175	3	subfinder	abc.com
177	3	findomain	abc.com
177	3	subfinder	abc.com
178	3	findomain	abc.com
178	3	subfinder	abc.com
179	3	findomain	abc.com
179	3	subfinder	abc.com
179	3	assetfinder	abc.com
180	3	subfinder	abc.com
180	3	assetfinder	abc.com
181	3	findomain	abc.com
181	3	subfinder	abc.com
183	3	subfinder	abc.com
184	3	subfinder	abc.com
185	3	subfinder	abc.com
186	3	subfinder	abc.com
187	3	subfinder	abc.com
188	3	subfinder	abc.com
189	3	subfinder	abc.com
190	3	subfinder	abc.com
191	3	subfinder	abc.com
192	3	subfinder	abc.com
193	3	subfinder	abc.com
194	3	subfinder	abc.com
195	3	subfinder	abc.com
195	3	assetfinder	abc.com
1916	3	subfinder	abc.com
197	3	findomain	abc.com
197	3	subfinder	abc.com
1918	3	subfinder	abc.com
198	3	brand_pattern	abc.com
199	3	brand_pattern	abc.com
200	3	subfinder	abc.com
201	3	findomain	abc.com
201	3	subfinder	abc.com
1923	3	subfinder	abc.com
202	3	subfinder	abc.com
1925	3	subfinder	abc.com
203	3	findomain	abc.com
203	3	subfinder	abc.com
204	3	findomain	abc.com
204	3	subfinder	abc.com
205	3	findomain	abc.com
205	3	subfinder	abc.com
1929	3	subfinder	abc.com
1930	3	subfinder	abc.com
1931	3	subfinder	abc.com
206	3	subfinder	abc.com
207	3	findomain	abc.com
207	3	subfinder	abc.com
1934	3	subfinder	abc.com
1935	3	subfinder	abc.com
1936	3	subfinder	abc.com
208	3	subfinder	abc.com
1938	3	subfinder	abc.com
209	3	findomain	abc.com
209	3	subfinder	abc.com
1940	3	subfinder	abc.com
210	3	subfinder	abc.com
1942	3	subfinder	abc.com
1943	3	subfinder	abc.com
211	3	subfinder	abc.com
212	3	subfinder	abc.com
213	3	findomain	abc.com
213	3	subfinder	abc.com
214	3	findomain	abc.com
1948	3	subfinder	abc.com
215	3	findomain	abc.com
215	3	subfinder	abc.com
216	3	findomain	abc.com
216	3	subfinder	abc.com
217	3	subfinder	abc.com
1952	3	subfinder	abc.com
218	3	subfinder	abc.com
219	3	subfinder	abc.com
220	3	subfinder	abc.com
1956	3	subfinder	abc.com
221	3	findomain	abc.com
221	3	subfinder	abc.com
222	3	findomain	abc.com
222	3	subfinder	abc.com
223	3	findomain	abc.com
223	3	subfinder	abc.com
1960	3	subfinder	abc.com
224	3	subfinder	abc.com
225	3	findomain	abc.com
226	3	findomain	abc.com
227	3	subfinder	abc.com
1965	3	subfinder	abc.com
228	3	subfinder	abc.com
229	3	subfinder	abc.com
230	3	subfinder	abc.com
231	3	subfinder	abc.com
232	3	subfinder	abc.com
233	3	subfinder	abc.com
234	3	findomain	abc.com
235	3	subfinder	abc.com
1974	3	subfinder	abc.com
236	3	brand_pattern	abc.com
237	3	findomain	abc.com
237	3	subfinder	abc.com
238	3	brand_pattern	abc.com
239	3	findomain	abc.com
239	3	subfinder	abc.com
240	3	subfinder	abc.com
241	3	subfinder	abc.com
1981	3	subfinder	abc.com
1982	3	subfinder	abc.com
242	3	subfinder	abc.com
243	3	findomain	abc.com
244	3	subfinder	abc.com
245	3	findomain	abc.com
245	3	subfinder	abc.com
246	3	findomain	abc.com
1988	3	subfinder	abc.com
1989	3	subfinder	abc.com
247	3	findomain	abc.com
248	3	findomain	abc.com
248	3	subfinder	abc.com
249	3	subfinder	abc.com
250	3	findomain	abc.com
251	3	findomain	abc.com
251	3	subfinder	abc.com
252	3	findomain	abc.com
252	3	subfinder	abc.com
1996	3	subfinder	abc.com
1997	3	subfinder	abc.com
1998	3	subfinder	abc.com
253	3	findomain	abc.com
253	3	subfinder	abc.com
254	3	findomain	abc.com
254	3	subfinder	abc.com
255	3	findomain	abc.com
255	3	subfinder	abc.com
256	3	findomain	abc.com
256	3	subfinder	abc.com
257	3	findomain	abc.com
257	3	subfinder	abc.com
2004	3	subfinder	abc.com
258	3	findomain	abc.com
258	3	subfinder	abc.com
258	3	assetfinder	abc.com
2006	3	subfinder	abc.com
259	3	subfinder	abc.com
260	3	findomain	abc.com
260	3	subfinder	abc.com
261	3	findomain	abc.com
2010	3	subfinder	abc.com
262	3	findomain	abc.com
262	3	subfinder	abc.com
2013	3	subfinder	abc.com
264	3	subfinder	abc.com
2015	3	subfinder	abc.com
2016	3	subfinder	abc.com
265	3	findomain	abc.com
266	3	subfinder	abc.com
267	3	brand_pattern	abc.com
268	3	brand_pattern	abc.com
2021	3	subfinder	abc.com
2022	3	subfinder	abc.com
269	3	findomain	abc.com
270	3	findomain	abc.com
271	3	subfinder	abc.com
272	3	subfinder	abc.com
273	3	subfinder	abc.com
274	3	subfinder	abc.com
275	3	subfinder	abc.com
276	3	subfinder	abc.com
277	3	subfinder	abc.com
278	3	subfinder	abc.com
2033	3	subfinder	abc.com
279	3	findomain	abc.com
279	3	subfinder	abc.com
280	3	findomain	abc.com
280	3	subfinder	abc.com
281	3	subfinder	abc.com
282	3	subfinder	abc.com
283	3	subfinder	abc.com
284	3	subfinder	abc.com
285	3	subfinder	abc.com
286	3	subfinder	abc.com
287	3	subfinder	abc.com
288	3	subfinder	abc.com
289	3	subfinder	abc.com
290	3	subfinder	abc.com
291	3	subfinder	abc.com
292	3	findomain	abc.com
292	3	subfinder	abc.com
2048	3	subfinder	abc.com
2049	3	subfinder	abc.com
293	3	subfinder	abc.com
2051	3	subfinder	abc.com
294	3	findomain	abc.com
294	3	subfinder	abc.com
2053	3	subfinder	abc.com
295	3	subfinder	abc.com
296	3	subfinder	abc.com
2056	3	subfinder	abc.com
2057	3	subfinder	abc.com
297	3	subfinder	abc.com
2059	3	subfinder	abc.com
2060	3	subfinder	abc.com
2061	3	subfinder	abc.com
298	3	findomain	abc.com
2063	3	subfinder	abc.com
299	3	findomain	abc.com
299	3	subfinder	abc.com
299	3	assetfinder	abc.com
303	3	subfinder	abc.com
305	3	subfinder	abc.com
305	3	assetfinder	abc.com
306	3	subfinder	abc.com
2072	3	subfinder	abc.com
2072	3	assetfinder	abc.com
313	3	findomain	abc.com
314	3	subfinder	abc.com
315	3	subfinder	abc.com
317	3	subfinder	abc.com
2086	3	subfinder	abc.com
320	3	subfinder	abc.com
323	3	findomain	abc.com
323	3	subfinder	abc.com
324	3	findomain	abc.com
325	3	findomain	abc.com
\.


--
-- Data for Name: domain_states; Type: TABLE DATA; Schema: public; Owner: asm
--

COPY public.domain_states (scan_id, domain_id, ip, has_ip, http_status, http_live, reverse_dns, http_reason, final_url, final_status, title) FROM stdin;
1	1		f	0	f	nan	nan	nan	0	nan
1	2		f	0	f	nan	nan	nan	0	nan
1	3		f	0	f	nan	nan	nan	0	nan
1	4		f	0	f	nan	nan	nan	0	nan
1	5		f	0	f	nan	nan	nan	0	nan
1	6		f	0	f	nan	nan	nan	0	nan
1	7		f	0	f	nan	nan	nan	0	nan
1	8	49.44.175.16	t	0	f	nan	nan	nan	0	nan
1	9	49.44.175.10	t	200	t	nan	OK	https://abc.com/show/0a6328a2-6451-46e7-a55a-fa84ddbb9541	200	The Oscars 2026 | 98th Academy Awards
1	10	98.82.42.139	t	0	f	ec2-98-82-42-139.compute-1.amazonaws.com	nan	nan	0	nan
1	11		f	0	f	nan	nan	nan	0	nan
1	12	146.59.149.209	t	200	t	ont101.onnet.tech	OK	https://www.abc-global.com/	200	ABC GROUP OF COMPANIES
1	13	88.198.55.147	t	200	t	server6.greavesdesign.co.uk	OK	https://www.abc-group.com/	200	ABC Group - Maintenance, Construction and Civil Engineering
1	14	44.232.173.249	t	200	t	ec2-44-232-173-249.us-west-2.compute.amazonaws.com	OK	https://abc-services.com/	200	abc-services.com for sale | Spaceship.com
1	15	18.224.83.222	t	200	t	ec2-18-224-83-222.us-east-2.compute.amazonaws.com	OK	https://abc-tech.com/	200	Home - ABC Technologies
1	16		f	0	f	nan	nan	nan	0	nan
1	17	13.248.169.48	t	200	t	a904c694c05102f30.awsglobalaccelerator.com	OK	https://abc.ai/	200	nan
1	18		f	0	f	nan	nan	nan	0	nan
1	19		f	0	f	nan	nan	nan	0	nan
1	20	88.208.252.9	t	200	t	server88-208-252-9.fasthosts.net.uk	OK	https://www.abc.org.uk/	200	ABC - Delivering a valued stamp of trust - ABC UK
1	21	108.158.245.116	t	200	t	server-108-158-245-116.del51.r.cloudfront.net	OK	https://abc.com/	200	ABC Network - ABC.com
1	22	47.242.94.198	t	200	t	nan	OK	http://abc.in/	200	3d photo DIY--3d lenticular photo print Customized
1	23	54.215.31.113	t	200	t	ec2-54-215-31-113.us-west-1.compute.amazonaws.com	OK	https://forsale.ddot.in/abc.io?drefid=2071	200	For Sale Domain: abc.io
1	24	162.243.117.188	t	200	t	vip.nomoz.com	OK	http://abc.net/	200	ABC.NET
1	25	172.67.72.194	t	403	t	nan	Forbidden	https://abc.org/	403	Attention Required! | Cloudflare
1	26		f	0	f	nan	nan	nan	0	nan
1	27	66.147.242.96	t	406	t	box496.bluehost.com	Not Acceptable	https://abccloud.com/	406	Not Acceptable!
1	28	76.223.67.189	t	200	t	a67c48129651a0940.awsglobalaccelerator.com	OK	https://abccorp.com/	200	nan
1	29	216.92.209.88	t	200	t	bradley-consulting.com	OK	http://abcglobal.com/	200	index.gif
1	30	18.224.83.222	t	200	t	ec2-18-224-83-222.us-east-2.compute.amazonaws.com	OK	https://abcgroup.com/	200	Home - ABC Technologies
1	31	139.104.232.65	t	0	f	nan	nan	nan	0	nan
1	32	139.104.232.66	t	0	f	nan	nan	nan	0	nan
1	33	173.236.214.24	t	500	t	vps27316.dreamhostps.com	Internal Server Error	https://abcservices.com/	500	WordPress &rsaquo; Error
1	34	18.224.83.222	t	200	t	ec2-18-224-83-222.us-east-2.compute.amazonaws.com	OK	https://abctech.com/	200	Home - ABC Technologies
1	35	52.40.138.92	t	200	t	ec2-52-40-138-92.us-west-2.compute.amazonaws.com	OK	https://abc.com/browse	200	ABC TV Shows, Specials &amp; Movies
1	36		f	0	f	nan	nan	nan	0	nan
1	37		f	0	f	nan	nan	nan	0	nan
1	38	44.245.73.38	t	200	t	ec2-44-245-73-38.us-west-2.compute.amazonaws.com	OK	https://abc.com/show/21b50293-3493-44f9-ae80-bdb0564b39cf	200	Watch American Music Awards TV Show - ABC.com
1	39	18.66.102.99	t	403	t	server-18-66-102-99.fra56.r.cloudfront.net	Forbidden	https://api.abc.com/	403	ERROR: The request could not be satisfied
1	40	3.175.86.5	t	403	t	server-3-175-86-5.mrs53.r.cloudfront.net	Forbidden	https://api.partners.abc.com/	403	ERROR: The request could not be satisfied
1	41	18.66.102.9	t	403	t	server-18-66-102-9.fra56.r.cloudfront.net	Forbidden	http://api2.abc.com/	403	ERROR: The request could not be satisfied
1	42		f	0	f	nan	nan	nan	0	nan
1	43		f	0	f	nan	nan	nan	0	nan
1	44		f	0	f	nan	nan	nan	0	nan
1	45		f	0	f	nan	nan	nan	0	nan
1	46		f	0	f	nan	nan	nan	0	nan
1	47		f	0	f	nan	nan	nan	0	nan
1	48		f	0	f	nan	nan	nan	0	nan
1	49		f	0	f	nan	nan	nan	0	nan
1	50		f	0	f	nan	nan	nan	0	nan
1	51		f	0	f	nan	nan	nan	0	nan
1	52	139.104.36.49	t	0	f	autodiscover.fxnetworkspressroom.com	nan	nan	0	nan
1	53	192.195.67.80	t	0	f	nan	nan	nan	0	nan
1	54		f	0	f	nan	nan	nan	0	nan
1	55	44.253.167.177	t	200	t	ec2-44-253-167-177.us-west-2.compute.amazonaws.com	OK	https://abc.com/browse	200	ABC TV Shows, Specials &amp; Movies
1	56		f	0	f	nan	nan	nan	0	nan
1	57		f	0	f	nan	nan	nan	0	nan
1	58	52.40.138.92	t	200	t	ec2-52-40-138-92.us-west-2.compute.amazonaws.com	OK	https://abc.com/	200	ABC Network - ABC.com
1	59		f	0	f	nan	nan	nan	0	nan
1	60	192.195.67.80	t	0	f	nan	nan	nan	0	nan
1	61	104.18.116.121	t	403	t	nan	Forbidden	https://blogs.abc.com/	403	403 Forbidden
1	62	192.195.67.10	t	0	f	nan	nan	nan	0	nan
1	63		f	0	f	nan	nan	nan	0	nan
1	64		f	0	f	nan	nan	nan	0	nan
1	65	44.245.73.38	t	404	t	ec2-44-245-73-38.us-west-2.compute.amazonaws.com	Not Found	https://abc.com/shows/castle	404	Page not found - ABC.com
1	66		f	0	f	nan	nan	nan	0	nan
1	67		f	0	f	nan	nan	nan	0	nan
1	68	49.44.175.16	t	200	t	nan	OK	https://cdn.media.abc.com/	200	nan
1	69		f	0	f	nan	nan	nan	0	nan
1	70	184.85.220.95	t	404	t	a184-85-220-95.deploy.static.akamaitechnologies.com	Not Found	https://cdn.mktg.abc.com/	404	nan
1	71	49.44.175.9	t	200	t	nan	OK	https://cdn.video.abc.com/	200	nan
1	72		f	0	f	nan	nan	nan	0	nan
1	73		f	0	f	nan	nan	nan	0	nan
1	74		f	0	f	nan	nan	nan	0	nan
1	75		f	0	f	nan	nan	nan	0	nan
1	76		f	0	f	nan	nan	nan	0	nan
1	77		f	0	f	nan	nan	nan	0	nan
1	78		f	0	f	nan	nan	nan	0	nan
1	79	18.205.77.36	t	404	t	lb-d.us1.gigya.com	Not Found	https://connect.abc.com/	404	nan
1	80		f	0	f	nan	nan	nan	0	nan
1	81		f	0	f	nan	nan	nan	0	nan
1	82		f	0	f	nan	nan	nan	0	nan
1	83	172.24.74.81	t	0	f	nan	nan	nan	0	nan
1	84		f	0	f	nan	nan	nan	0	nan
1	85		f	0	f	nan	nan	nan	0	nan
1	86	10.102.125.155	t	0	f	nan	nan	nan	0	nan
1	87	192.195.67.81	t	0	f	nan	nan	nan	0	nan
1	88	18.164.237.51	t	403	t	server-18-164-237-51.del54.r.cloudfront.net	Forbidden	https://dev.cd.abc.com/	403	nan
1	89		f	0	f	nan	nan	nan	0	nan
1	90	3.218.80.165	t	200	t	ec2-3-218-80-165.compute-1.amazonaws.com	OK	https://dev.galaxy.abc.com/WebSpace/login.html	200	Webspace Login page
1	91		f	0	f	nan	nan	nan	0	nan
1	92	3.212.204.30	t	200	t	ec2-3-212-204-30.compute-1.amazonaws.com	OK	https://dev.netbox.abc.com/login/?next=/	200	Home | NetBox
1	93		f	0	f	nan	nan	nan	0	nan
1	94		f	0	f	nan	nan	nan	0	nan
1	95		f	0	f	nan	nan	nan	0	nan
1	96		f	0	f	nan	nan	nan	0	nan
1	97		f	0	f	nan	nan	nan	0	nan
1	98	75.101.163.207	t	0	f	ec2-75-101-163-207.compute-1.amazonaws.com	nan	nan	0	nan
1	99	24.144.66.46	t	503	t	nan	Service Unavailable	https://doctorodysseysweepstakes.abc.com/	503	503 Service Unavailable
1	100	192.195.67.81	t	0	f	nan	nan	nan	0	nan
1	101		f	0	f	nan	nan	nan	0	nan
1	102	44.253.167.177	t	200	t	ec2-44-253-167-177.us-west-2.compute.amazonaws.com	OK	http://www.disneyinternational.com/	200	Disney - Disney Online International
1	103	151.101.106.137	t	200	t	nan	OK	https://abc.com/show/f66d60e7-29f2-49cf-85dd-44a11bce42e4	200	Watch Dancing with the Stars Streaming on ABC platforms and Disney+ - ABC.com
1	104	151.101.106.217	t	200	t	nan	OK	https://abc.com/show/f66d60e7-29f2-49cf-85dd-44a11bce42e4	200	Watch Dancing with the Stars Streaming on ABC platforms and Disney+ - ABC.com
1	105	151.101.106.137	t	200	t	nan	OK	https://dwtsvote-test.abc.com/	200	Dancing with the Stars Voting | ABC & Disney+
1	106	151.101.106.217	t	200	t	nan	OK	https://dwtsvote.abc.com/	200	Dancing with the Stars Voting | ABC & Disney+
1	107		f	0	f	nan	nan	nan	0	nan
1	108		f	0	f	nan	nan	nan	0	nan
1	109		f	0	f	nan	nan	nan	0	nan
1	110		f	0	f	nan	nan	nan	0	nan
1	111		f	0	f	nan	nan	nan	0	nan
1	112	192.195.63.65	t	0	f	nan	nan	nan	0	nan
1	113	44.253.167.177	t	200	t	ec2-44-253-167-177.us-west-2.compute.amazonaws.com	OK	https://abc.com/browse	200	ABC TV Shows, Specials &amp; Movies
1	114		f	0	f	nan	nan	nan	0	nan
1	115		f	0	f	nan	nan	nan	0	nan
1	116		f	0	f	nan	nan	nan	0	nan
1	117		f	0	f	nan	nan	nan	0	nan
1	118		f	0	f	nan	nan	nan	0	nan
1	119		f	0	f	nan	nan	nan	0	nan
1	120	192.195.67.22	t	0	f	nan	nan	nan	0	nan
1	121		f	0	f	nan	nan	nan	0	nan
1	122	40.71.70.250	t	200	t	nan	OK	http://ets.abc.com:80/Login	200	Welcome to MediaPulse Sky
1	123	40.71.70.250	t	200	t	nan	OK	http://etsdev.abc.com:80/Login	200	Welcome to MediaPulse Sky
1	124	72.44.37.156	t	401	t	ec2-72-44-37-156.compute-1.amazonaws.com	Unauthorized	https://facebook.abc.com/	401	nan
1	125		f	0	f	nan	nan	nan	0	nan
1	126		f	0	f	nan	nan	nan	0	nan
1	127		f	0	f	nan	nan	nan	0	nan
1	128		f	0	f	nan	nan	nan	0	nan
1	129	184.85.220.71	t	404	t	a184-85-220-71.deploy.static.akamaitechnologies.com	Not Found	https://fcast.cdn.abc.com/	404	nan
1	130	184.85.220.97	t	404	t	a184-85-220-97.deploy.static.akamaitechnologies.com	Not Found	https://fcast.qa.cdn.abc.com/	404	nan
1	131		f	0	f	nan	nan	nan	0	nan
1	132		f	0	f	nan	nan	nan	0	nan
1	133		f	0	f	nan	nan	nan	0	nan
1	134		f	0	f	nan	nan	nan	0	nan
1	135		f	0	f	nan	nan	nan	0	nan
1	136	204.87.172.6	t	0	f	nan	nan	nan	0	nan
1	137	204.87.172.6	t	0	f	nan	nan	nan	0	nan
1	138		f	0	f	nan	nan	nan	0	nan
1	139	52.84.150.42	t	403	t	nan	Forbidden	https://gambit.abc.com/	403	403 Forbidden
1	140	72.2.116.92	t	0	f	nan	nan	nan	0	nan
1	141		f	0	f	nan	nan	nan	0	nan
1	142	76.223.54.146	t	200	t	a904c694c05102f30.awsglobalaccelerator.com	OK	https://getabc.com/	200	nan
1	143		f	0	f	nan	nan	nan	0	nan
1	144		f	0	f	nan	nan	nan	0	nan
1	145	54.165.131.183	t	200	t	ec2-54-165-131-183.compute-1.amazonaws.com	OK	http://gksrv.abc.com/	200	NameBright - Coming Soon
1	146	139.104.232.35	t	0	f	nan	nan	nan	0	nan
1	147		f	0	f	nan	nan	nan	0	nan
1	148	139.104.232.30	t	0	f	nan	nan	nan	0	nan
1	149	139.104.232.31	t	0	f	nan	nan	nan	0	nan
1	150	139.104.232.32	t	0	f	nan	nan	nan	0	nan
1	151	139.104.232.13	t	0	f	nan	nan	nan	0	nan
1	152	151.101.106.217	t	200	t	nan	OK	https://idolvote-test.abc.com/	200	Client Challenge
1	153	151.101.106.217	t	200	t	nan	OK	https://idolvote.abc.com/	200	Client Challenge
1	154	52.40.138.92	t	200	t	ec2-52-40-138-92.us-west-2.compute.amazonaws.com	OK	https://abc.com/browse	200	ABC TV Shows, Specials &amp; Movies
1	155		f	0	f	nan	nan	nan	0	nan
1	156	44.253.167.177	t	200	t	ec2-44-253-167-177.us-west-2.compute.amazonaws.com	OK	https://abc.com/show/9bfe2f4f-41ad-4492-a6dd-0b67db180543	200	Watch Jimmy Kimmel Live! TV Show - ABC.com
1	157	15.197.148.33	t	200	t	a2aa9ff50de748dbe.awsglobalaccelerator.com	OK	https://join-abc.com/	200	nan
1	158	34.174.221.135	t	200	t	135.221.174.34.bc.googleusercontent.com	OK	https://www.actionbehavior.com/careers	200	Careers | ABA Therapy, BCBA &amp; RBT Jobs
1	159		f	0	f	nan	nan	nan	0	nan
1	160	192.195.67.81	t	0	f	nan	nan	nan	0	nan
1	161		f	0	f	nan	nan	nan	0	nan
1	162		f	0	f	nan	nan	nan	0	nan
1	163		f	0	f	nan	nan	nan	0	nan
1	164		f	0	f	nan	nan	nan	0	nan
1	165		f	0	f	nan	nan	nan	0	nan
1	166		f	0	f	nan	nan	nan	0	nan
1	167		f	0	f	nan	nan	nan	0	nan
1	168		f	0	f	nan	nan	nan	0	nan
1	169		f	0	f	nan	nan	nan	0	nan
1	170		f	0	f	nan	nan	nan	0	nan
1	171	49.44.119.26	t	200	t	nan	OK	https://ll.media.abc.com/	200	nan
1	172	52.40.138.92	t	200	t	ec2-52-40-138-92.us-west-2.compute.amazonaws.com	OK	https://abc.com/browse	200	ABC TV Shows, Specials &amp; Movies
1	173	44.253.167.177	t	200	t	ec2-44-253-167-177.us-west-2.compute.amazonaws.com	OK	https://abc.com/	200	ABC Network - ABC.com
1	174		f	0	f	nan	nan	nan	0	nan
1	175		f	0	f	nan	nan	nan	0	nan
1	176		f	0	f	nan	nan	nan	0	nan
1	177		f	0	f	nan	nan	nan	0	nan
1	178		f	0	f	nan	nan	nan	0	nan
1	179	192.195.67.33	t	200	t	nan	OK	https://mc.abc.com/	200	mc.abc.com
1	180	68.71.212.241	t	0	f	media.abc.go.com	nan	nan	0	nan
1	181	40.71.70.250	t	502	t	nan	Bad Gateway	https://mediapulsepoc2.abc.com/	502	502 Bad Gateway
1	182		f	0	f	nan	nan	nan	0	nan
1	183		f	0	f	nan	nan	nan	0	nan
1	184		f	0	f	nan	nan	nan	0	nan
1	185		f	0	f	nan	nan	nan	0	nan
1	186		f	0	f	nan	nan	nan	0	nan
1	187		f	0	f	nan	nan	nan	0	nan
1	188		f	0	f	nan	nan	nan	0	nan
1	189		f	0	f	nan	nan	nan	0	nan
1	190		f	0	f	nan	nan	nan	0	nan
1	191		f	0	f	nan	nan	nan	0	nan
1	192		f	0	f	nan	nan	nan	0	nan
1	193		f	0	f	nan	nan	nan	0	nan
1	194		f	0	f	nan	nan	nan	0	nan
1	195	44.253.167.177	t	200	t	ec2-44-253-167-177.us-west-2.compute.amazonaws.com	OK	https://abc.com/show/d72316e9-c889-494b-bb3c-a48266fb326d	200	Watch Modern Family TV Show - ABC.com
1	196		f	0	f	nan	nan	nan	0	nan
1	197	192.195.63.64	t	0	f	nan	nan	nan	0	nan
1	198	15.156.104.222	t	502	t	ec2-15-156-104-222.ca-central-1.compute.amazonaws.com	Bad Gateway	https://my-abc.com/	502	502 Bad Gateway
1	199	165.160.15.20	t	200	t	nan	OK	http://myabc.com/	200	nan
1	200		f	0	f	nan	nan	nan	0	nan
1	201		f	0	f	nan	nan	nan	0	nan
1	202	209.34.85.149	t	0	f	nan	nan	nan	0	nan
1	203	54.205.246.153	t	200	t	ec2-54-205-246-153.compute-1.amazonaws.com	OK	https://netbox.abc.com/login/?next=/	200	Home | NetBox
1	204		f	0	f	nan	nan	nan	0	nan
1	205		f	0	f	nan	nan	nan	0	nan
1	206		f	0	f	nan	nan	nan	0	nan
1	207	139.104.232.44	t	0	f	nan	nan	nan	0	nan
1	208	44.245.73.38	t	404	t	ec2-44-245-73-38.us-west-2.compute.amazonaws.com	Not Found	https://abc.com/shows/once-upon-a-time	404	Page not found - ABC.com
1	209		f	0	f	nan	nan	nan	0	nan
1	210		f	0	f	nan	nan	nan	0	nan
1	211		f	0	f	nan	nan	nan	0	nan
1	212		f	0	f	nan	nan	nan	0	nan
1	213	108.158.245.4	t	403	t	server-108-158-245-4.del51.r.cloudfront.net	Forbidden	https://prod.cd.abc.com/	403	nan
1	214		f	0	f	nan	nan	nan	0	nan
1	215	34.195.213.174	t	596	t	ec2-34-195-213-174.compute-1.amazonaws.com	596	https://qa.api.abc.com/	596	nan
1	216	99.86.30.39	t	403	t	server-99-86-30-39.del51.r.cloudfront.net	Forbidden	https://qa.cd.abc.com/	403	nan
1	217		f	0	f	nan	nan	nan	0	nan
1	218	204.202.134.76	t	0	f	nan	nan	nan	0	nan
1	219	204.202.134.77	t	0	f	nan	nan	nan	0	nan
1	220	204.202.134.78	t	0	f	nan	nan	nan	0	nan
1	221	192.195.67.129	t	200	t	nan	OK	https://redirect.abc.com/	200	Redirect
1	222	52.150.35.231	t	0	f	nan	nan	nan	0	nan
1	223	44.206.52.255	t	0	f	ec2-44-206-52-255.compute-1.amazonaws.com	nan	nan	0	nan
1	224		f	0	f	nan	nan	nan	0	nan
1	225		f	0	f	nan	nan	nan	0	nan
1	226		f	0	f	nan	nan	nan	0	nan
1	227		f	0	f	nan	nan	nan	0	nan
1	228		f	0	f	nan	nan	nan	0	nan
1	229		f	0	f	nan	nan	nan	0	nan
1	230		f	0	f	nan	nan	nan	0	nan
1	231		f	0	f	nan	nan	nan	0	nan
1	232		f	0	f	nan	nan	nan	0	nan
1	233		f	0	f	nan	nan	nan	0	nan
1	234		f	0	f	nan	nan	nan	0	nan
1	235	44.245.73.38	t	404	t	ec2-44-245-73-38.us-west-2.compute.amazonaws.com	Not Found	https://abc.com/shows/scandal	404	Page not found - ABC.com
1	236		f	0	f	nan	nan	nan	0	nan
1	237		f	0	f	nan	nan	nan	0	nan
1	238	35.197.121.119	t	403	t	119.121.197.35.bc.googleusercontent.com	Forbidden	https://secureabc.com/	403	403 Forbidden
1	239	139.104.232.57	t	0	f	nan	nan	nan	0	nan
1	240		f	0	f	nan	nan	nan	0	nan
1	241		f	0	f	nan	nan	nan	0	nan
1	242		f	0	f	nan	nan	nan	0	nan
1	243		f	0	f	nan	nan	nan	0	nan
1	244	192.195.66.83	t	0	f	nan	nan	nan	0	nan
1	245		f	0	f	nan	nan	nan	0	nan
1	246		f	0	f	nan	nan	nan	0	nan
1	247		f	0	f	nan	nan	nan	0	nan
1	248		f	0	f	nan	nan	nan	0	nan
1	249		f	0	f	nan	nan	nan	0	nan
1	250		f	0	f	nan	nan	nan	0	nan
1	251		f	0	f	nan	nan	nan	0	nan
1	252		f	0	f	nan	nan	nan	0	nan
1	253	18.164.217.118	t	403	t	server-18-164-217-118.del54.r.cloudfront.net	Forbidden	https://stage.cd.abc.com/	403	nan
1	254	3.160.188.51	t	403	t	server-3-160-188-51.mrs52.r.cloudfront.net	Forbidden	http://storefront.abc.com/	403	ERROR: The request could not be satisfied
2	6		f	0	f	nan	nan	nan	0	nan
1	255	99.84.152.57	t	403	t	server-99-84-152-57.fra56.r.cloudfront.net	Forbidden	http://storefrontdev.abc.com/	403	ERROR: The request could not be satisfied
1	256		f	0	f	nan	nan	nan	0	nan
1	257		f	0	f	nan	nan	nan	0	nan
1	258	216.198.53.11	t	403	t	nan	Forbidden	https://support.abc.com/hc/en-us	403	Just a moment...
1	259		f	0	f	nan	nan	nan	0	nan
1	260	66.117.22.190	t	200	t	ip-66-117-22-190.data.adobedc.net	OK	https://sw88.abc.com/	200	nan
1	261		f	0	f	nan	nan	nan	0	nan
1	262		f	0	f	nan	nan	nan	0	nan
1	263		f	0	f	nan	nan	nan	0	nan
1	264		f	0	f	nan	nan	nan	0	nan
1	265		f	0	f	nan	nan	nan	0	nan
1	266		f	0	f	nan	nan	nan	0	nan
1	267	13.248.169.48	t	200	t	a904c694c05102f30.awsglobalaccelerator.com	OK	https://try-abc.com/	200	nan
1	268	208.115.240.122	t	200	t	122-240-115-208.static.reverse.lstn.net	OK	http://www.chinesemenu.com	200	Chinese Menu | Chinese Restaurant | Chinese Cuisine | Chinese Food in LA | Delivery Food
1	269		f	0	f	nan	nan	nan	0	nan
1	270		f	0	f	nan	nan	nan	0	nan
1	271		f	0	f	nan	nan	nan	0	nan
1	272		f	0	f	nan	nan	nan	0	nan
1	273		f	0	f	nan	nan	nan	0	nan
1	274		f	0	f	nan	nan	nan	0	nan
1	275		f	0	f	nan	nan	nan	0	nan
1	276		f	0	f	nan	nan	nan	0	nan
1	277		f	0	f	nan	nan	nan	0	nan
1	278		f	0	f	nan	nan	nan	0	nan
1	279	52.147.216.119	t	0	f	nan	nan	nan	0	nan
1	280	52.147.216.119	t	0	f	nan	nan	nan	0	nan
1	281		f	0	f	nan	nan	nan	0	nan
1	282		f	0	f	nan	nan	nan	0	nan
1	283		f	0	f	nan	nan	nan	0	nan
1	284	139.104.232.100	t	0	f	nan	nan	nan	0	nan
1	285	139.104.232.107	t	0	f	nan	nan	nan	0	nan
1	286		f	0	f	nan	nan	nan	0	nan
1	287		f	0	f	nan	nan	nan	0	nan
1	288	67.212.182.149	t	200	t	xperience.plus	OK	https://vdigate5.abc.com/	200	Vdigate5
1	289		f	0	f	nan	nan	nan	0	nan
1	290		f	0	f	nan	nan	nan	0	nan
1	291		f	0	f	nan	nan	nan	0	nan
1	292	20.127.42.140	t	502	t	nan	Bad Gateway	https://vdigateqa.abc.com/	502	502 Bad Gateway
1	293	49.44.50.75	t	503	t	nan	Service Unavailable	https://vp2.abc.com/	503	Service Unavailable
1	294	66.117.22.113	t	200	t	ip-66-117-22-113.data.adobedc.net	OK	https://w88.abc.com/	200	nan
1	295	44.245.73.38	t	200	t	ec2-44-245-73-38.us-west-2.compute.amazonaws.com	OK	http://www.disneyinternational.com/	200	Disney - Disney Online International
1	296		f	0	f	nan	nan	nan	0	nan
1	297		f	0	f	nan	nan	nan	0	nan
1	298		f	0	f	nan	nan	nan	0	nan
1	299	108.158.245.59	t	200	t	server-108-158-245-59.del51.r.cloudfront.net	OK	https://abc.com/	200	ABC Network - ABC.com
1	300		f	0	f	nan	nan	nan	0	nan
1	301		f	0	f	nan	nan	nan	0	nan
1	302		f	0	f	nan	nan	nan	0	nan
1	303		f	0	f	nan	nan	nan	0	nan
1	304		f	0	f	nan	nan	nan	0	nan
1	305	52.40.138.92	t	200	t	ec2-52-40-138-92.us-west-2.compute.amazonaws.com	OK	https://abc.com/browse	200	ABC TV Shows, Specials &amp; Movies
1	306		f	0	f	nan	nan	nan	0	nan
1	307		f	0	f	nan	nan	nan	0	nan
1	308		f	0	f	nan	nan	nan	0	nan
1	309		f	0	f	nan	nan	nan	0	nan
1	310		f	0	f	nan	nan	nan	0	nan
1	311		f	0	f	nan	nan	nan	0	nan
1	312		f	0	f	nan	nan	nan	0	nan
1	313		f	0	f	nan	nan	nan	0	nan
1	314		f	0	f	nan	nan	nan	0	nan
1	315		f	0	f	nan	nan	nan	0	nan
1	316		f	0	f	nan	nan	nan	0	nan
1	317		f	0	f	nan	nan	nan	0	nan
1	318		f	0	f	nan	nan	nan	0	nan
1	319		f	0	f	nan	nan	nan	0	nan
1	320		f	0	f	nan	nan	nan	0	nan
1	321		f	0	f	nan	nan	nan	0	nan
1	322		f	0	f	nan	nan	nan	0	nan
1	323		f	0	f	nan	nan	nan	0	nan
1	324		f	0	f	nan	nan	nan	0	nan
1	325		f	0	f	nan	nan	nan	0	nan
1	326		f	0	f	\N	\N	\N	\N	\N
1	327		f	0	f	\N	\N	\N	\N	\N
1	457		f	0	f	\N	\N	\N	\N	\N
1	530		f	0	f	\N	\N	\N	\N	\N
1	328		f	0	f	\N	\N	\N	\N	\N
1	329		f	0	f	\N	\N	\N	\N	\N
1	330		f	0	f	\N	\N	\N	\N	\N
1	331		f	0	f	\N	\N	\N	\N	\N
1	332		f	0	f	\N	\N	\N	\N	\N
1	333		f	0	f	\N	\N	\N	\N	\N
1	334		f	0	f	\N	\N	\N	\N	\N
1	335		f	0	f	\N	\N	\N	\N	\N
1	336		f	0	f	\N	\N	\N	\N	\N
1	337		f	0	f	\N	\N	\N	\N	\N
1	338		f	0	f	\N	\N	\N	\N	\N
1	339		f	0	f	\N	\N	\N	\N	\N
1	340		f	0	f	\N	\N	\N	\N	\N
1	343		f	0	f	\N	\N	\N	\N	\N
1	342		f	0	f	\N	\N	\N	\N	\N
1	344		f	0	f	\N	\N	\N	\N	\N
1	345		f	0	f	\N	\N	\N	\N	\N
1	573		f	0	f	\N	\N	\N	\N	\N
1	595		f	0	f	\N	\N	\N	\N	\N
1	596		f	0	f	\N	\N	\N	\N	\N
1	597		f	0	f	\N	\N	\N	\N	\N
1	598		f	0	f	\N	\N	\N	\N	\N
1	599		f	0	f	\N	\N	\N	\N	\N
1	600		f	0	f	\N	\N	\N	\N	\N
1	601		f	0	f	\N	\N	\N	\N	\N
1	602		f	0	f	\N	\N	\N	\N	\N
2	1		f	0	f	nan	nan	nan	0	nan
2	2		f	0	f	nan	nan	nan	0	nan
2	1673		f	0	f	nan	nan	nan	0	nan
2	3		f	0	f	nan	nan	nan	0	nan
2	4		f	0	f	nan	nan	nan	0	nan
2	5		f	0	f	nan	nan	nan	0	nan
2	7		f	0	f	nan	nan	nan	0	nan
2	1679		f	0	f	nan	nan	nan	0	nan
2	1680		f	0	f	nan	nan	nan	0	nan
2	1681		f	0	f	nan	nan	nan	0	nan
2	1682		f	0	f	nan	nan	nan	0	nan
2	1683		f	0	f	nan	nan	nan	0	nan
2	8	49.44.95.152	t	0	f	nan	nan	nan	0	nan
2	9	49.44.175.10	t	200	t	nan	OK	https://abc.com/show/0a6328a2-6451-46e7-a55a-fa84ddbb9541	200	The Oscars 2026 | 98th Academy Awards
2	1686	49.44.50.82	t	0	f	nan	nan	nan	0	nan
2	1687		f	0	f	nan	nan	nan	0	nan
2	10	52.201.53.166	t	0	f	ec2-52-201-53-166.compute-1.amazonaws.com	nan	nan	0	nan
2	11		f	0	f	nan	nan	nan	0	nan
2	12	146.59.149.209	t	200	t	ont101.onnet.tech	OK	https://www.abc-global.com/	200	ABC GROUP OF COMPANIES
2	13	88.198.55.147	t	200	t	server6.greavesdesign.co.uk	OK	https://www.abc-group.com/	200	ABC Group - Maintenance, Construction and Civil Engineering
2	14	44.232.173.249	t	200	t	ec2-44-232-173-249.us-west-2.compute.amazonaws.com	OK	https://abc-services.com/	200	abc-services.com for sale | Spaceship.com
2	15	18.224.83.222	t	200	t	ec2-18-224-83-222.us-east-2.compute.amazonaws.com	OK	https://abc-tech.com/	200	Home - ABC Technologies
2	1694		f	0	f	nan	nan	nan	0	nan
2	16		f	0	f	nan	nan	nan	0	nan
2	17	76.223.54.146	t	200	t	a904c694c05102f30.awsglobalaccelerator.com	OK	https://abc.ai/	200	nan
2	18		f	0	f	nan	nan	nan	0	nan
2	19		f	0	f	nan	nan	nan	0	nan
2	20	88.208.252.9	t	200	t	server88-208-252-9.fasthosts.net.uk	OK	https://www.abc.org.uk/	200	ABC - Delivering a valued stamp of trust - ABC UK
2	21	13.225.103.113	t	200	t	server-13-225-103-113.del51.r.cloudfront.net	OK	https://abc.com/	200	ABC Network - ABC.com
2	22	47.242.94.198	t	0	f	nan	nan	nan	0	nan
2	23	54.215.31.113	t	200	t	ec2-54-215-31-113.us-west-1.compute.amazonaws.com	OK	https://forsale.ddot.in/abc.io?drefid=2071	200	For Sale Domain: abc.io
2	24	162.243.117.188	t	200	t	vip.nomoz.com	OK	http://abc.net/	200	ABC.NET
2	25	104.26.7.66	t	403	t	nan	Forbidden	https://abc.org/	403	Attention Required! | Cloudflare
2	26		f	0	f	nan	nan	nan	0	nan
2	1706		f	0	f	nan	nan	nan	0	nan
2	27	66.147.242.96	t	406	t	box496.bluehost.com	Not Acceptable	https://abccloud.com/	406	Not Acceptable!
2	28	15.197.148.33	t	200	t	a2aa9ff50de748dbe.awsglobalaccelerator.com	OK	https://abccorp.com/	200	nan
2	29	216.92.209.88	t	200	t	bradley-consulting.com	OK	http://abcglobal.com/	200	index.gif
2	30	18.224.83.222	t	200	t	ec2-18-224-83-222.us-east-2.compute.amazonaws.com	OK	https://abcgroup.com/	200	Home - ABC Technologies
2	31	139.104.232.65	t	0	f	nan	nan	nan	0	nan
2	32	139.104.232.66	t	0	f	nan	nan	nan	0	nan
2	33	173.236.214.24	t	500	t	vps27316.dreamhostps.com	Internal Server Error	https://abcservices.com/	500	WordPress &rsaquo; Error
2	34	18.224.83.222	t	200	t	ec2-18-224-83-222.us-east-2.compute.amazonaws.com	OK	https://abctech.com/	200	Home - ABC Technologies
2	1715		f	0	f	nan	nan	nan	0	nan
2	1716		f	0	f	nan	nan	nan	0	nan
2	1717		f	0	f	nan	nan	nan	0	nan
2	35	54.190.118.130	t	200	t	ec2-54-190-118-130.us-west-2.compute.amazonaws.com	OK	https://abc.com/browse	200	ABC TV Shows, Specials &amp; Movies
2	36		f	0	f	nan	nan	nan	0	nan
2	37		f	0	f	nan	nan	nan	0	nan
2	38	100.49.209.37	t	200	t	ec2-100-49-209-37.compute-1.amazonaws.com	OK	https://abc.com/show/21b50293-3493-44f9-ae80-bdb0564b39cf	200	Watch American Music Awards TV Show - ABC.com
2	39	18.66.102.117	t	403	t	server-18-66-102-117.fra56.r.cloudfront.net	Forbidden	https://api.abc.com/	403	ERROR: The request could not be satisfied
2	40	18.66.102.117	t	403	t	server-18-66-102-117.fra56.r.cloudfront.net	Forbidden	https://api.partners.abc.com/	403	ERROR: The request could not be satisfied
2	41	3.175.86.116	t	403	t	server-3-175-86-116.mrs53.r.cloudfront.net	Forbidden	http://api2.abc.com/	403	ERROR: The request could not be satisfied
2	1725		f	0	f	nan	nan	nan	0	nan
2	42		f	0	f	nan	nan	nan	0	nan
2	43		f	0	f	nan	nan	nan	0	nan
2	44		f	0	f	nan	nan	nan	0	nan
2	45		f	0	f	nan	nan	nan	0	nan
2	46		f	0	f	nan	nan	nan	0	nan
2	1731		f	0	f	nan	nan	nan	0	nan
2	47		f	0	f	nan	nan	nan	0	nan
2	48		f	0	f	nan	nan	nan	0	nan
2	49		f	0	f	nan	nan	nan	0	nan
2	50		f	0	f	nan	nan	nan	0	nan
2	51		f	0	f	nan	nan	nan	0	nan
2	52	139.104.36.49	t	0	f	autodiscover.fxnetworkspressroom.com	nan	nan	0	nan
2	1738		f	0	f	nan	nan	nan	0	nan
2	53	192.195.67.80	t	0	f	nan	nan	nan	0	nan
2	54		f	0	f	nan	nan	nan	0	nan
2	55	54.70.112.205	t	200	t	ec2-54-70-112-205.us-west-2.compute.amazonaws.com	OK	https://abc.com/browse	200	ABC TV Shows, Specials &amp; Movies
2	56		f	0	f	nan	nan	nan	0	nan
2	57		f	0	f	nan	nan	nan	0	nan
2	58	54.197.191.132	t	200	t	ec2-54-197-191-132.compute-1.amazonaws.com	OK	https://abc.com/	200	ABC Network - ABC.com
2	1745		f	0	f	nan	nan	nan	0	nan
2	59		f	0	f	nan	nan	nan	0	nan
2	60	192.195.67.80	t	0	f	nan	nan	nan	0	nan
2	61	104.18.115.121	t	403	t	nan	Forbidden	https://blogs.abc.com/	403	403 Forbidden
2	62	192.195.67.10	t	0	f	nan	nan	nan	0	nan
2	63		f	0	f	nan	nan	nan	0	nan
2	64		f	0	f	nan	nan	nan	0	nan
2	65	54.70.112.205	t	404	t	ec2-54-70-112-205.us-west-2.compute.amazonaws.com	Not Found	https://abc.com/shows/castle	404	Page not found - ABC.com
2	1753		f	0	f	nan	nan	nan	0	nan
2	66		f	0	f	nan	nan	nan	0	nan
2	67		f	0	f	nan	nan	nan	0	nan
2	68	49.44.50.80	t	200	t	nan	OK	https://cdn.media.abc.com/	200	nan
2	69		f	0	f	nan	nan	nan	0	nan
2	70	184.85.220.73	t	404	t	a184-85-220-73.deploy.static.akamaitechnologies.com	Not Found	https://cdn.mktg.abc.com/	404	nan
2	71	49.44.175.9	t	200	t	nan	OK	https://cdn.video.abc.com/	200	nan
2	72		f	0	f	nan	nan	nan	0	nan
2	73		f	0	f	nan	nan	nan	0	nan
2	74		f	0	f	nan	nan	nan	0	nan
2	75		f	0	f	nan	nan	nan	0	nan
2	76		f	0	f	nan	nan	nan	0	nan
2	77		f	0	f	nan	nan	nan	0	nan
2	78		f	0	f	nan	nan	nan	0	nan
2	1767		f	0	f	nan	nan	nan	0	nan
2	79	18.210.153.8	t	404	t	lb-d.us1.gigya.com	Not Found	https://connect.abc.com/	404	nan
2	80		f	0	f	nan	nan	nan	0	nan
2	1770		f	0	f	nan	nan	nan	0	nan
2	1771		f	0	f	nan	nan	nan	0	nan
2	81		f	0	f	nan	nan	nan	0	nan
2	1773		f	0	f	nan	nan	nan	0	nan
2	82		f	0	f	nan	nan	nan	0	nan
2	1775		f	0	f	nan	nan	nan	0	nan
2	83	172.24.74.81	t	0	f	nan	nan	nan	0	nan
2	1777		f	0	f	nan	nan	nan	0	nan
2	84		f	0	f	nan	nan	nan	0	nan
2	85		f	0	f	nan	nan	nan	0	nan
2	86	10.102.125.155	t	0	f	nan	nan	nan	0	nan
2	87	192.195.67.81	t	0	f	nan	nan	nan	0	nan
2	88	18.164.237.97	t	403	t	server-18-164-237-97.del54.r.cloudfront.net	Forbidden	https://dev.cd.abc.com/	403	nan
2	89		f	0	f	nan	nan	nan	0	nan
2	90	54.152.97.113	t	503	t	ec2-54-152-97-113.compute-1.amazonaws.com	Service Temporarily Unavailable	https://dev.galaxy.abc.com/	503	503 Service Temporarily Unavailable
2	91		f	0	f	nan	nan	nan	0	nan
2	92	50.17.227.109	t	200	t	ec2-50-17-227-109.compute-1.amazonaws.com	OK	https://dev.netbox.abc.com/login/?next=/	200	Home | NetBox
2	93		f	0	f	nan	nan	nan	0	nan
2	94		f	0	f	nan	nan	nan	0	nan
2	95		f	0	f	nan	nan	nan	0	nan
2	96		f	0	f	nan	nan	nan	0	nan
2	97		f	0	f	nan	nan	nan	0	nan
2	1792		f	0	f	nan	nan	nan	0	nan
2	98	75.101.163.207	t	0	f	ec2-75-101-163-207.compute-1.amazonaws.com	nan	nan	0	nan
2	99	24.144.66.46	t	503	t	nan	Service Unavailable	https://doctorodysseysweepstakes.abc.com/	503	503 Service Unavailable
2	100	192.195.67.81	t	0	f	nan	nan	nan	0	nan
2	1796		f	0	f	nan	nan	nan	0	nan
2	101		f	0	f	nan	nan	nan	0	nan
2	102	100.49.209.37	t	200	t	ec2-100-49-209-37.compute-1.amazonaws.com	OK	http://www.disneyinternational.com/	200	Disney - Disney Online International
2	103	151.101.106.137	t	200	t	nan	OK	https://abc.com/show/f66d60e7-29f2-49cf-85dd-44a11bce42e4	200	Watch Dancing with the Stars Streaming on ABC platforms and Disney+ - ABC.com
2	104	151.101.106.217	t	200	t	nan	OK	https://abc.com/show/f66d60e7-29f2-49cf-85dd-44a11bce42e4	200	Watch Dancing with the Stars Streaming on ABC platforms and Disney+ - ABC.com
2	105	151.101.106.137	t	200	t	nan	OK	https://dwtsvote-test.abc.com/	200	Dancing with the Stars Voting | ABC & Disney+
2	106	151.101.106.217	t	200	t	nan	OK	https://dwtsvote.abc.com/	200	Dancing with the Stars Voting | ABC & Disney+
2	107		f	0	f	nan	nan	nan	0	nan
2	108		f	0	f	nan	nan	nan	0	nan
2	109		f	0	f	nan	nan	nan	0	nan
2	110		f	0	f	nan	nan	nan	0	nan
2	111		f	0	f	nan	nan	nan	0	nan
2	112	192.195.63.65	t	0	f	nan	nan	nan	0	nan
2	113	54.197.191.132	t	200	t	ec2-54-197-191-132.compute-1.amazonaws.com	OK	https://abc.com/browse	200	ABC TV Shows, Specials &amp; Movies
2	114		f	0	f	nan	nan	nan	0	nan
2	115		f	0	f	nan	nan	nan	0	nan
2	116		f	0	f	nan	nan	nan	0	nan
2	117		f	0	f	nan	nan	nan	0	nan
2	118		f	0	f	nan	nan	nan	0	nan
2	119		f	0	f	nan	nan	nan	0	nan
2	120	192.195.67.22	t	0	f	nan	nan	nan	0	nan
2	121		f	0	f	nan	nan	nan	0	nan
2	122	40.71.70.250	t	200	t	nan	OK	http://ets.abc.com:80/Login	200	Welcome to MediaPulse Sky
2	123	40.71.70.250	t	200	t	nan	OK	http://etsdev.abc.com:80/Login	200	Welcome to MediaPulse Sky
2	1820		f	0	f	nan	nan	nan	0	nan
2	124	72.44.37.156	t	401	t	ec2-72-44-37-156.compute-1.amazonaws.com	Unauthorized	https://facebook.abc.com/	401	nan
2	1822		f	0	f	nan	nan	nan	0	nan
2	125		f	0	f	nan	nan	nan	0	nan
2	126		f	0	f	nan	nan	nan	0	nan
2	127		f	0	f	nan	nan	nan	0	nan
2	128		f	0	f	nan	nan	nan	0	nan
2	129	184.85.220.70	t	404	t	a184-85-220-70.deploy.static.akamaitechnologies.com	Not Found	https://fcast.cdn.abc.com/	404	nan
2	130	184.85.220.97	t	404	t	a184-85-220-97.deploy.static.akamaitechnologies.com	Not Found	https://fcast.qa.cdn.abc.com/	404	nan
2	131		f	0	f	nan	nan	nan	0	nan
2	132		f	0	f	nan	nan	nan	0	nan
2	1831		f	0	f	nan	nan	nan	0	nan
2	133		f	0	f	nan	nan	nan	0	nan
2	134		f	0	f	nan	nan	nan	0	nan
2	135		f	0	f	nan	nan	nan	0	nan
2	136	204.87.172.6	t	0	f	nan	nan	nan	0	nan
2	137	204.87.172.6	t	0	f	nan	nan	nan	0	nan
2	138		f	0	f	nan	nan	nan	0	nan
2	139	52.84.150.57	t	403	t	nan	Forbidden	https://gambit.abc.com/	403	403 Forbidden
2	140	72.2.116.92	t	0	f	nan	nan	nan	0	nan
2	141		f	0	f	nan	nan	nan	0	nan
2	142	13.248.169.48	t	200	t	a904c694c05102f30.awsglobalaccelerator.com	OK	https://getabc.com/	200	nan
2	1842		f	0	f	nan	nan	nan	0	nan
2	1843		f	0	f	nan	nan	nan	0	nan
2	143		f	0	f	nan	nan	nan	0	nan
2	144		f	0	f	nan	nan	nan	0	nan
2	145	52.44.244.98	t	200	t	ec2-52-44-244-98.compute-1.amazonaws.com	OK	http://gksrv.abc.com/	200	NameBright - Coming Soon
2	1847		f	0	f	nan	nan	nan	0	nan
2	146	139.104.232.35	t	0	f	nan	nan	nan	0	nan
2	1849		f	0	f	nan	nan	nan	0	nan
2	147		f	0	f	nan	nan	nan	0	nan
2	148	139.104.232.30	t	0	f	nan	nan	nan	0	nan
2	149	139.104.232.31	t	0	f	nan	nan	nan	0	nan
2	150	139.104.232.32	t	0	f	nan	nan	nan	0	nan
2	1854		f	0	f	nan	nan	nan	0	nan
2	151	139.104.232.13	t	0	f	nan	nan	nan	0	nan
2	152	151.101.106.217	t	200	t	nan	OK	https://idolvote-test.abc.com/	200	Client Challenge
2	153	151.101.106.217	t	200	t	nan	OK	https://idolvote.abc.com/	200	Client Challenge
2	1858		f	0	f	nan	nan	nan	0	nan
2	1859		f	0	f	nan	nan	nan	0	nan
2	154	52.43.57.102	t	200	t	ec2-52-43-57-102.us-west-2.compute.amazonaws.com	OK	https://abc.com/browse	200	ABC TV Shows, Specials &amp; Movies
2	155		f	0	f	nan	nan	nan	0	nan
2	1862		f	0	f	nan	nan	nan	0	nan
2	1863		f	0	f	nan	nan	nan	0	nan
2	1864		f	0	f	nan	nan	nan	0	nan
2	156	52.43.57.102	t	200	t	ec2-52-43-57-102.us-west-2.compute.amazonaws.com	OK	https://abc.com/show/9bfe2f4f-41ad-4492-a6dd-0b67db180543	200	Watch Jimmy Kimmel Live! TV Show - ABC.com
2	157	15.197.148.33	t	200	t	a2aa9ff50de748dbe.awsglobalaccelerator.com	OK	https://join-abc.com/	200	nan
2	158	34.174.221.135	t	200	t	135.221.174.34.bc.googleusercontent.com	OK	https://www.actionbehavior.com/careers	200	Careers | ABA Therapy, BCBA &amp; RBT Jobs
2	159		f	0	f	nan	nan	nan	0	nan
2	160	192.195.67.81	t	0	f	nan	nan	nan	0	nan
2	1870		f	0	f	nan	nan	nan	0	nan
2	1871		f	0	f	nan	nan	nan	0	nan
2	161		f	0	f	nan	nan	nan	0	nan
2	162		f	0	f	nan	nan	nan	0	nan
2	163		f	0	f	nan	nan	nan	0	nan
2	1875		f	0	f	nan	nan	nan	0	nan
2	164		f	0	f	nan	nan	nan	0	nan
2	165		f	0	f	nan	nan	nan	0	nan
2	166		f	0	f	nan	nan	nan	0	nan
2	167		f	0	f	nan	nan	nan	0	nan
2	168		f	0	f	nan	nan	nan	0	nan
2	169		f	0	f	nan	nan	nan	0	nan
2	170		f	0	f	nan	nan	nan	0	nan
2	1883		f	0	f	nan	nan	nan	0	nan
2	1884	54.70.112.205	t	200	t	ec2-54-70-112-205.us-west-2.compute.amazonaws.com	OK	http://www.disneyinternational.com/	200	Disney - Disney Online International
2	171	49.44.175.33	t	200	t	nan	OK	https://ll.media.abc.com/	200	nan
2	1886		f	0	f	nan	nan	nan	0	nan
2	172	100.49.209.37	t	200	t	ec2-100-49-209-37.compute-1.amazonaws.com	OK	https://abc.com/browse	200	ABC TV Shows, Specials &amp; Movies
2	173	13.217.182.13	t	200	t	ec2-13-217-182-13.compute-1.amazonaws.com	OK	https://abc.com/	200	ABC Network - ABC.com
2	1889		f	0	f	nan	nan	nan	0	nan
2	1890		f	0	f	nan	nan	nan	0	nan
2	174		f	0	f	nan	nan	nan	0	nan
2	1892		f	0	f	nan	nan	nan	0	nan
2	1893		f	0	f	nan	nan	nan	0	nan
2	175		f	0	f	nan	nan	nan	0	nan
2	176		f	0	f	nan	nan	nan	0	nan
2	177		f	0	f	nan	nan	nan	0	nan
2	178		f	0	f	nan	nan	nan	0	nan
2	179	192.195.67.33	t	200	t	nan	OK	https://mc.abc.com/	200	mc.abc.com
2	180	68.71.212.241	t	0	f	media.abc.go.com	nan	nan	0	nan
2	181	40.71.70.250	t	502	t	nan	Bad Gateway	https://mediapulsepoc2.abc.com/	502	502 Bad Gateway
2	182		f	0	f	nan	nan	nan	0	nan
2	183		f	0	f	nan	nan	nan	0	nan
2	184		f	0	f	nan	nan	nan	0	nan
2	185		f	0	f	nan	nan	nan	0	nan
2	186		f	0	f	nan	nan	nan	0	nan
2	187		f	0	f	nan	nan	nan	0	nan
2	188		f	0	f	nan	nan	nan	0	nan
2	189		f	0	f	nan	nan	nan	0	nan
2	190		f	0	f	nan	nan	nan	0	nan
2	191		f	0	f	nan	nan	nan	0	nan
2	192		f	0	f	nan	nan	nan	0	nan
2	193		f	0	f	nan	nan	nan	0	nan
2	194		f	0	f	nan	nan	nan	0	nan
2	195	54.197.191.132	t	200	t	ec2-54-197-191-132.compute-1.amazonaws.com	OK	https://abc.com/show/d72316e9-c889-494b-bb3c-a48266fb326d	200	Watch Modern Family TV Show - ABC.com
2	196		f	0	f	nan	nan	nan	0	nan
2	1916		f	0	f	nan	nan	nan	0	nan
2	197	192.195.63.64	t	0	f	nan	nan	nan	0	nan
2	1918		f	0	f	nan	nan	nan	0	nan
2	198	3.96.22.179	t	502	t	ec2-3-96-22-179.ca-central-1.compute.amazonaws.com	Bad Gateway	https://my-abc.com/	502	502 Bad Gateway
2	199	165.160.13.20	t	200	t	nan	OK	http://myabc.com/	200	nan
2	200		f	0	f	nan	nan	nan	0	nan
2	201		f	0	f	nan	nan	nan	0	nan
2	1923		f	0	f	nan	nan	nan	0	nan
2	202	209.34.85.149	t	0	f	nan	nan	nan	0	nan
2	1925		f	0	f	nan	nan	nan	0	nan
2	203	3.213.171.250	t	200	t	ec2-3-213-171-250.compute-1.amazonaws.com	OK	https://netbox.abc.com/login/?next=/	200	Home | NetBox
2	204		f	0	f	nan	nan	nan	0	nan
2	205		f	0	f	nan	nan	nan	0	nan
2	1929		f	0	f	nan	nan	nan	0	nan
2	1930		f	0	f	nan	nan	nan	0	nan
2	1931		f	0	f	nan	nan	nan	0	nan
2	206		f	0	f	nan	nan	nan	0	nan
2	207	139.104.232.44	t	0	f	nan	nan	nan	0	nan
2	1934		f	0	f	nan	nan	nan	0	nan
2	1935		f	0	f	nan	nan	nan	0	nan
2	1936		f	0	f	nan	nan	nan	0	nan
2	208	13.217.182.13	t	404	t	ec2-13-217-182-13.compute-1.amazonaws.com	Not Found	https://abc.com/shows/once-upon-a-time	404	Page not found - ABC.com
2	1938	192.147.170.20	t	404	t	nan	Not Found	https://origin.beta.vp2.abc.com/	404	Error
2	209		f	0	f	nan	nan	nan	0	nan
2	1940		f	0	f	nan	nan	nan	0	nan
2	210		f	0	f	nan	nan	nan	0	nan
2	282		f	0	f	nan	nan	nan	0	nan
2	1942	184.85.220.78	t	200	t	a184-85-220-78.deploy.static.akamaitechnologies.com	OK	https://abc.com/	200	ABC Network - ABC.com
2	1943		f	0	f	nan	nan	nan	0	nan
2	211		f	0	f	nan	nan	nan	0	nan
2	212		f	0	f	nan	nan	nan	0	nan
2	213	108.158.245.18	t	403	t	server-108-158-245-18.del51.r.cloudfront.net	Forbidden	https://prod.cd.abc.com/	403	nan
2	214		f	0	f	nan	nan	nan	0	nan
2	1948	54.190.118.130	t	200	t	ec2-54-190-118-130.us-west-2.compute.amazonaws.com	OK	https://abc.com/browse	200	ABC TV Shows, Specials &amp; Movies
2	215	52.44.31.214	t	596	t	ec2-52-44-31-214.compute-1.amazonaws.com	596	https://qa.api.abc.com/	596	nan
2	216	99.86.30.107	t	403	t	server-99-86-30-107.del51.r.cloudfront.net	Forbidden	https://qa.cd.abc.com/	403	nan
2	217		f	0	f	nan	nan	nan	0	nan
2	1952		f	0	f	nan	nan	nan	0	nan
2	218	204.202.134.76	t	0	f	nan	nan	nan	0	nan
2	219	204.202.134.77	t	0	f	nan	nan	nan	0	nan
2	220	204.202.134.78	t	0	f	nan	nan	nan	0	nan
2	1956		f	0	f	nan	nan	nan	0	nan
2	221	192.195.67.129	t	200	t	nan	OK	https://redirect.abc.com/	200	Redirect
2	222	52.150.35.231	t	0	f	nan	nan	nan	0	nan
2	223	100.30.242.112	t	0	f	ec2-100-30-242-112.compute-1.amazonaws.com	nan	nan	0	nan
2	1960	100.49.209.37	t	404	t	ec2-100-49-209-37.compute-1.amazonaws.com	Not Found	https://abc.com/shows/revenge	404	Page not found - ABC.com
2	224		f	0	f	nan	nan	nan	0	nan
2	225		f	0	f	nan	nan	nan	0	nan
2	226		f	0	f	nan	nan	nan	0	nan
2	227		f	0	f	nan	nan	nan	0	nan
2	1965		f	0	f	nan	nan	nan	0	nan
2	228		f	0	f	nan	nan	nan	0	nan
2	229		f	0	f	nan	nan	nan	0	nan
2	230		f	0	f	nan	nan	nan	0	nan
2	231		f	0	f	nan	nan	nan	0	nan
2	232		f	0	f	nan	nan	nan	0	nan
2	233		f	0	f	nan	nan	nan	0	nan
2	234		f	0	f	nan	nan	nan	0	nan
2	235	54.190.118.130	t	404	t	ec2-54-190-118-130.us-west-2.compute.amazonaws.com	Not Found	https://abc.com/shows/scandal	404	Page not found - ABC.com
2	1974		f	0	f	nan	nan	nan	0	nan
2	236		f	0	f	nan	nan	nan	0	nan
2	237		f	0	f	nan	nan	nan	0	nan
2	238	35.197.121.119	t	403	t	119.121.197.35.bc.googleusercontent.com	Forbidden	https://secureabc.com/	403	403 Forbidden
2	239	139.104.232.57	t	0	f	nan	nan	nan	0	nan
2	240		f	0	f	nan	nan	nan	0	nan
2	241		f	0	f	nan	nan	nan	0	nan
2	1981		f	0	f	nan	nan	nan	0	nan
2	1982		f	0	f	nan	nan	nan	0	nan
2	242		f	0	f	nan	nan	nan	0	nan
2	243		f	0	f	nan	nan	nan	0	nan
2	244	192.195.66.83	t	0	f	nan	nan	nan	0	nan
2	245		f	0	f	nan	nan	nan	0	nan
2	246		f	0	f	nan	nan	nan	0	nan
2	1988		f	0	f	nan	nan	nan	0	nan
2	1989		f	0	f	nan	nan	nan	0	nan
2	247		f	0	f	nan	nan	nan	0	nan
2	248		f	0	f	nan	nan	nan	0	nan
2	249		f	0	f	nan	nan	nan	0	nan
2	250		f	0	f	nan	nan	nan	0	nan
2	251		f	0	f	nan	nan	nan	0	nan
2	252		f	0	f	nan	nan	nan	0	nan
2	1996		f	0	f	nan	nan	nan	0	nan
2	1997		f	0	f	nan	nan	nan	0	nan
2	1998		f	0	f	nan	nan	nan	0	nan
2	253	18.164.217.42	t	403	t	server-18-164-217-42.del54.r.cloudfront.net	Forbidden	https://stage.cd.abc.com/	403	nan
2	254	99.84.152.104	t	403	t	server-99-84-152-104.fra56.r.cloudfront.net	Forbidden	http://storefront.abc.com/	403	ERROR: The request could not be satisfied
2	255	3.160.188.82	t	403	t	server-3-160-188-82.mrs52.r.cloudfront.net	Forbidden	http://storefrontdev.abc.com/	403	ERROR: The request could not be satisfied
2	256		f	0	f	nan	nan	nan	0	nan
2	257		f	0	f	nan	nan	nan	0	nan
2	2004		f	0	f	nan	nan	nan	0	nan
2	258	216.198.53.11	t	403	t	nan	Forbidden	https://support.abc.com/hc/en-us	403	Just a moment...
2	2006		f	0	f	nan	nan	nan	0	nan
2	259		f	0	f	nan	nan	nan	0	nan
2	260	66.117.22.190	t	200	t	ip-66-117-22-190.data.adobedc.net	OK	https://sw88.abc.com/	200	nan
2	261		f	0	f	nan	nan	nan	0	nan
2	2010		f	0	f	nan	nan	nan	0	nan
2	262		f	0	f	nan	nan	nan	0	nan
2	263		f	0	f	nan	nan	nan	0	nan
2	2013		f	0	f	nan	nan	nan	0	nan
2	264		f	0	f	nan	nan	nan	0	nan
2	2015		f	0	f	nan	nan	nan	0	nan
2	2016	204.202.134.45	t	0	f	nan	nan	nan	0	nan
2	265		f	0	f	nan	nan	nan	0	nan
2	266		f	0	f	nan	nan	nan	0	nan
2	267	76.223.54.146	t	200	t	a904c694c05102f30.awsglobalaccelerator.com	OK	https://try-abc.com/	200	nan
2	268	208.115.240.122	t	200	t	122-240-115-208.static.reverse.lstn.net	OK	http://www.chinesemenu.com	200	Chinese Menu | Chinese Restaurant | Chinese Cuisine | Chinese Food in LA | Delivery Food
2	2021		f	0	f	nan	nan	nan	0	nan
2	2022		f	0	f	nan	nan	nan	0	nan
2	269		f	0	f	nan	nan	nan	0	nan
2	270		f	0	f	nan	nan	nan	0	nan
2	271		f	0	f	nan	nan	nan	0	nan
2	272		f	0	f	nan	nan	nan	0	nan
2	273		f	0	f	nan	nan	nan	0	nan
2	274		f	0	f	nan	nan	nan	0	nan
2	275		f	0	f	nan	nan	nan	0	nan
2	276		f	0	f	nan	nan	nan	0	nan
2	277		f	0	f	nan	nan	nan	0	nan
2	278		f	0	f	nan	nan	nan	0	nan
2	2033	199.181.134.92	t	0	f	nan	nan	nan	0	nan
2	279	52.147.216.119	t	0	f	nan	nan	nan	0	nan
2	280	52.147.216.119	t	0	f	nan	nan	nan	0	nan
2	281		f	0	f	nan	nan	nan	0	nan
2	283		f	0	f	nan	nan	nan	0	nan
2	284	139.104.232.100	t	0	f	nan	nan	nan	0	nan
2	285	139.104.232.107	t	0	f	nan	nan	nan	0	nan
2	286		f	0	f	nan	nan	nan	0	nan
2	287		f	0	f	nan	nan	nan	0	nan
2	288	67.212.182.149	t	200	t	xperience.plus	OK	https://vdigate5.abc.com/	200	Vdigate5
2	289		f	0	f	nan	nan	nan	0	nan
2	290		f	0	f	nan	nan	nan	0	nan
2	291		f	0	f	nan	nan	nan	0	nan
2	292	20.127.42.140	t	502	t	nan	Bad Gateway	https://vdigateqa.abc.com/	502	502 Bad Gateway
2	2048		f	0	f	nan	nan	nan	0	nan
2	2049		f	0	f	nan	nan	nan	0	nan
2	293	49.44.50.80	t	503	t	nan	Service Unavailable	https://vp2.abc.com/	503	Service Unavailable
2	2051		f	0	f	nan	nan	nan	0	nan
2	294	66.117.22.191	t	200	t	ip-66-117-22-191.data.adobedc.net	OK	https://w88.abc.com/	200	nan
2	2053		f	0	f	nan	nan	nan	0	nan
2	295	54.70.112.205	t	200	t	ec2-54-70-112-205.us-west-2.compute.amazonaws.com	OK	http://www.disneyinternational.com/	200	Disney - Disney Online International
2	296		f	0	f	nan	nan	nan	0	nan
2	2056		f	0	f	nan	nan	nan	0	nan
2	2057		f	0	f	nan	nan	nan	0	nan
2	297		f	0	f	nan	nan	nan	0	nan
2	2059		f	0	f	nan	nan	nan	0	nan
2	2060		f	0	f	nan	nan	nan	0	nan
2	2061		f	0	f	nan	nan	nan	0	nan
2	298		f	0	f	nan	nan	nan	0	nan
2	2063		f	0	f	nan	nan	nan	0	nan
2	299	13.225.103.38	t	200	t	server-13-225-103-38.del51.r.cloudfront.net	OK	https://abc.com/	200	ABC Network - ABC.com
2	300		f	0	f	nan	nan	nan	0	nan
2	301		f	0	f	nan	nan	nan	0	nan
2	302		f	0	f	nan	nan	nan	0	nan
2	303		f	0	f	nan	nan	nan	0	nan
2	304		f	0	f	nan	nan	nan	0	nan
2	305	54.70.112.205	t	200	t	ec2-54-70-112-205.us-west-2.compute.amazonaws.com	OK	https://abc.com/browse	200	ABC TV Shows, Specials &amp; Movies
2	306		f	0	f	nan	nan	nan	0	nan
2	2072	49.44.50.67	t	404	t	nan	Not Found	https://www.datgpodcast.abc.com/	404	nan
2	307		f	0	f	nan	nan	nan	0	nan
2	308		f	0	f	nan	nan	nan	0	nan
2	309		f	0	f	nan	nan	nan	0	nan
2	310		f	0	f	nan	nan	nan	0	nan
2	311		f	0	f	nan	nan	nan	0	nan
2	312		f	0	f	nan	nan	nan	0	nan
2	313		f	0	f	nan	nan	nan	0	nan
2	314		f	0	f	nan	nan	nan	0	nan
2	315		f	0	f	nan	nan	nan	0	nan
2	316		f	0	f	nan	nan	nan	0	nan
2	317		f	0	f	nan	nan	nan	0	nan
2	318		f	0	f	nan	nan	nan	0	nan
2	319		f	0	f	nan	nan	nan	0	nan
2	2086		f	0	f	nan	nan	nan	0	nan
2	320		f	0	f	nan	nan	nan	0	nan
2	321		f	0	f	nan	nan	nan	0	nan
2	322		f	0	f	nan	nan	nan	0	nan
2	323		f	0	f	nan	nan	nan	0	nan
2	324		f	0	f	nan	nan	nan	0	nan
2	325		f	0	f	nan	nan	nan	0	nan
3	1		f	0	f	nan	nan	nan	0	nan
3	2		f	0	f	nan	nan	nan	0	nan
3	1673		f	0	f	nan	nan	nan	0	nan
3	3		f	0	f	nan	nan	nan	0	nan
3	4		f	0	f	nan	nan	nan	0	nan
3	5		f	0	f	nan	nan	nan	0	nan
3	6		f	0	f	nan	nan	nan	0	nan
3	7		f	0	f	nan	nan	nan	0	nan
3	1679		f	0	f	nan	nan	nan	0	nan
3	1680		f	0	f	nan	nan	nan	0	nan
3	1681		f	0	f	nan	nan	nan	0	nan
3	1682		f	0	f	nan	nan	nan	0	nan
3	1683		f	0	f	nan	nan	nan	0	nan
3	8	49.44.95.153	t	0	f	nan	nan	nan	0	nan
3	9	49.44.175.32	t	200	t	nan	OK	https://abc.com/show/0a6328a2-6451-46e7-a55a-fa84ddbb9541	200	The Oscars 2026 | 98th Academy Awards
3	1686	49.44.50.82	t	0	f	nan	nan	nan	0	nan
3	1687		f	0	f	nan	nan	nan	0	nan
3	10	98.82.42.139	t	200	t	ec2-98-82-42-139.compute-1.amazonaws.com	OK	https://www.hugedomains.com/domain_profile.cfm?d=abc-cloud.com	200	abc-cloud.com is for sale | HugeDomains
3	11		f	0	f	nan	nan	nan	0	nan
3	12	146.59.149.209	t	200	t	ont101.onnet.tech	OK	https://www.abc-global.com/	200	ABC GROUP OF COMPANIES
3	13	88.198.55.147	t	200	t	server6.greavesdesign.co.uk	OK	https://www.abc-group.com/	200	ABC Group - Maintenance, Construction and Civil Engineering
3	14	52.40.42.113	t	200	t	ec2-52-40-42-113.us-west-2.compute.amazonaws.com	OK	https://abc-services.com/	200	abc-services.com for sale | Spaceship.com
3	15	18.224.83.222	t	200	t	ec2-18-224-83-222.us-east-2.compute.amazonaws.com	OK	https://abc-tech.com/	200	Home - ABC Technologies
3	1694		f	0	f	nan	nan	nan	0	nan
3	16		f	0	f	nan	nan	nan	0	nan
3	17	76.223.54.146	t	200	t	a904c694c05102f30.awsglobalaccelerator.com	OK	https://abc.ai/	200	nan
3	18		f	0	f	nan	nan	nan	0	nan
3	19		f	0	f	nan	nan	nan	0	nan
3	20	88.208.252.9	t	200	t	server88-208-252-9.fasthosts.net.uk	OK	https://www.abc.org.uk/	200	ABC - Delivering a valued stamp of trust - ABC UK
3	21	13.225.103.113	t	200	t	server-13-225-103-113.del51.r.cloudfront.net	OK	https://abc.com/	200	ABC Network - ABC.com
3	22	47.242.94.198	t	0	f	nan	nan	nan	0	nan
3	23	54.215.31.113	t	200	t	ec2-54-215-31-113.us-west-1.compute.amazonaws.com	OK	https://forsale.ddot.in/abc.io?drefid=2071	200	For Sale Domain: abc.io
3	24	162.243.117.188	t	200	t	vip.nomoz.com	OK	http://abc.net/	200	ABC.NET
3	25	172.67.72.194	t	403	t	nan	Forbidden	https://abc.org/	403	Attention Required! | Cloudflare
3	26		f	0	f	nan	nan	nan	0	nan
3	1706		f	0	f	nan	nan	nan	0	nan
3	27	66.147.242.96	t	406	t	box496.bluehost.com	Not Acceptable	https://abccloud.com/	406	Not Acceptable!
3	28	3.33.130.190	t	200	t	a2aa9ff50de748dbe.awsglobalaccelerator.com	OK	https://abccorp.com/	200	nan
3	29	216.92.209.88	t	200	t	bradley-consulting.com	OK	http://abcglobal.com/	200	index.gif
3	30	18.224.83.222	t	200	t	ec2-18-224-83-222.us-east-2.compute.amazonaws.com	OK	https://abcgroup.com/	200	Home - ABC Technologies
3	31	139.104.232.65	t	0	f	nan	nan	nan	0	nan
3	32	139.104.232.66	t	0	f	nan	nan	nan	0	nan
3	33	173.236.214.24	t	500	t	vps27316.dreamhostps.com	Internal Server Error	https://abcservices.com/	500	WordPress &rsaquo; Error
3	34	18.224.83.222	t	200	t	ec2-18-224-83-222.us-east-2.compute.amazonaws.com	OK	https://abctech.com/	200	Home - ABC Technologies
3	1715		f	0	f	nan	nan	nan	0	nan
3	1716		f	0	f	nan	nan	nan	0	nan
3	1717		f	0	f	nan	nan	nan	0	nan
3	35	13.217.182.13	t	200	t	ec2-13-217-182-13.compute-1.amazonaws.com	OK	https://abc.com/browse	200	ABC TV Shows, Specials &amp; Movies
3	36		f	0	f	nan	nan	nan	0	nan
3	37		f	0	f	nan	nan	nan	0	nan
3	38	100.49.209.37	t	200	t	ec2-100-49-209-37.compute-1.amazonaws.com	OK	https://abc.com/show/21b50293-3493-44f9-ae80-bdb0564b39cf	200	Watch American Music Awards TV Show - ABC.com
3	39	18.66.102.117	t	403	t	server-18-66-102-117.fra56.r.cloudfront.net	Forbidden	https://api.abc.com/	403	ERROR: The request could not be satisfied
3	40	18.66.102.117	t	403	t	server-18-66-102-117.fra56.r.cloudfront.net	Forbidden	https://api.partners.abc.com/	403	ERROR: The request could not be satisfied
3	41	18.66.102.117	t	403	t	server-18-66-102-117.fra56.r.cloudfront.net	Forbidden	http://api2.abc.com/	403	ERROR: The request could not be satisfied
3	1725		f	0	f	nan	nan	nan	0	nan
3	42		f	0	f	nan	nan	nan	0	nan
3	43		f	0	f	nan	nan	nan	0	nan
3	44		f	0	f	nan	nan	nan	0	nan
3	45		f	0	f	nan	nan	nan	0	nan
3	46		f	0	f	nan	nan	nan	0	nan
3	1731		f	0	f	nan	nan	nan	0	nan
3	47		f	0	f	nan	nan	nan	0	nan
3	48		f	0	f	nan	nan	nan	0	nan
3	49		f	0	f	nan	nan	nan	0	nan
3	50		f	0	f	nan	nan	nan	0	nan
3	51		f	0	f	nan	nan	nan	0	nan
3	52	139.104.64.14	t	0	f	autodiscover.fxnetworkspressroom.com	nan	nan	0	nan
3	1738		f	0	f	nan	nan	nan	0	nan
3	53	192.195.67.80	t	0	f	nan	nan	nan	0	nan
3	54		f	0	f	nan	nan	nan	0	nan
3	55	54.70.112.205	t	200	t	ec2-54-70-112-205.us-west-2.compute.amazonaws.com	OK	https://abc.com/browse	200	ABC TV Shows, Specials &amp; Movies
3	56		f	0	f	nan	nan	nan	0	nan
3	57		f	0	f	nan	nan	nan	0	nan
3	58	54.70.112.205	t	200	t	ec2-54-70-112-205.us-west-2.compute.amazonaws.com	OK	https://abc.com/	200	ABC Network - ABC.com
3	1745		f	0	f	nan	nan	nan	0	nan
3	59		f	0	f	nan	nan	nan	0	nan
3	60	192.195.67.80	t	0	f	nan	nan	nan	0	nan
3	61	104.18.117.121	t	403	t	nan	Forbidden	https://blogs.abc.com/	403	403 Forbidden
3	62	192.195.67.10	t	0	f	nan	nan	nan	0	nan
3	63		f	0	f	nan	nan	nan	0	nan
3	64		f	0	f	nan	nan	nan	0	nan
3	65	52.43.57.102	t	404	t	ec2-52-43-57-102.us-west-2.compute.amazonaws.com	Not Found	https://abc.com/shows/castle	404	Page not found - ABC.com
3	1753		f	0	f	nan	nan	nan	0	nan
3	66		f	0	f	nan	nan	nan	0	nan
3	67		f	0	f	nan	nan	nan	0	nan
3	68	49.44.175.8	t	200	t	nan	OK	https://cdn.media.abc.com/	200	nan
3	69		f	0	f	nan	nan	nan	0	nan
3	70	184.85.220.73	t	404	t	a184-85-220-73.deploy.static.akamaitechnologies.com	Not Found	https://cdn.mktg.abc.com/	404	nan
3	71	49.44.175.9	t	200	t	nan	OK	https://cdn.video.abc.com/	200	nan
3	72		f	0	f	nan	nan	nan	0	nan
3	73		f	0	f	nan	nan	nan	0	nan
3	74		f	0	f	nan	nan	nan	0	nan
3	75		f	0	f	nan	nan	nan	0	nan
3	76		f	0	f	nan	nan	nan	0	nan
3	77		f	0	f	nan	nan	nan	0	nan
3	78		f	0	f	nan	nan	nan	0	nan
3	1767		f	0	f	nan	nan	nan	0	nan
3	79	18.210.153.8	t	404	t	lb-d.us1.gigya.com	Not Found	https://connect.abc.com/	404	nan
3	80		f	0	f	nan	nan	nan	0	nan
3	1770		f	0	f	nan	nan	nan	0	nan
3	1771		f	0	f	nan	nan	nan	0	nan
3	81		f	0	f	nan	nan	nan	0	nan
3	1773		f	0	f	nan	nan	nan	0	nan
3	82		f	0	f	nan	nan	nan	0	nan
3	1775		f	0	f	nan	nan	nan	0	nan
3	83	172.24.74.81	t	0	f	nan	nan	nan	0	nan
3	1777		f	0	f	nan	nan	nan	0	nan
3	84		f	0	f	nan	nan	nan	0	nan
3	86	10.102.125.155	t	0	f	nan	nan	nan	0	nan
3	87	192.195.67.81	t	0	f	nan	nan	nan	0	nan
3	88	18.164.237.97	t	403	t	server-18-164-237-97.del54.r.cloudfront.net	Forbidden	https://dev.cd.abc.com/	403	nan
3	89		f	0	f	nan	nan	nan	0	nan
3	90	54.243.116.183	t	503	t	ec2-54-243-116-183.compute-1.amazonaws.com	Service Temporarily Unavailable	https://dev.galaxy.abc.com/	503	503 Service Temporarily Unavailable
3	91		f	0	f	nan	nan	nan	0	nan
3	92	44.196.164.156	t	200	t	ec2-44-196-164-156.compute-1.amazonaws.com	OK	https://dev.netbox.abc.com/login/?next=/	200	Home | NetBox
3	93		f	0	f	nan	nan	nan	0	nan
3	94		f	0	f	nan	nan	nan	0	nan
3	95		f	0	f	nan	nan	nan	0	nan
3	96		f	0	f	nan	nan	nan	0	nan
3	97		f	0	f	nan	nan	nan	0	nan
3	1792		f	0	f	nan	nan	nan	0	nan
3	98	75.101.163.207	t	0	f	ec2-75-101-163-207.compute-1.amazonaws.com	nan	nan	0	nan
3	99	24.144.66.46	t	503	t	nan	Service Unavailable	https://doctorodysseysweepstakes.abc.com/	503	503 Service Unavailable
3	100	192.195.67.81	t	0	f	nan	nan	nan	0	nan
3	1796		f	0	f	nan	nan	nan	0	nan
3	102	100.49.209.37	t	200	t	ec2-100-49-209-37.compute-1.amazonaws.com	OK	http://www.disneyinternational.com/	200	Disney - Disney Online International
3	103	151.101.106.137	t	200	t	nan	OK	https://abc.com/show/f66d60e7-29f2-49cf-85dd-44a11bce42e4	200	Watch Dancing with the Stars Streaming on ABC platforms and Disney+ - ABC.com
3	104	151.101.106.217	t	200	t	nan	OK	https://abc.com/show/f66d60e7-29f2-49cf-85dd-44a11bce42e4	200	Watch Dancing with the Stars Streaming on ABC platforms and Disney+ - ABC.com
3	105	151.101.106.137	t	200	t	nan	OK	https://dwtsvote-test.abc.com/	200	Dancing with the Stars Voting | ABC & Disney+
3	106	151.101.106.217	t	200	t	nan	OK	https://dwtsvote.abc.com/	200	Dancing with the Stars Voting | ABC & Disney+
3	107		f	0	f	nan	nan	nan	0	nan
3	108		f	0	f	nan	nan	nan	0	nan
3	109		f	0	f	nan	nan	nan	0	nan
3	110		f	0	f	nan	nan	nan	0	nan
3	111		f	0	f	nan	nan	nan	0	nan
3	112	192.195.63.65	t	0	f	nan	nan	nan	0	nan
3	113	54.190.118.130	t	200	t	ec2-54-190-118-130.us-west-2.compute.amazonaws.com	OK	https://abc.com/browse	200	ABC TV Shows, Specials &amp; Movies
3	114		f	0	f	nan	nan	nan	0	nan
3	115		f	0	f	nan	nan	nan	0	nan
3	116		f	0	f	nan	nan	nan	0	nan
3	117		f	0	f	nan	nan	nan	0	nan
3	118		f	0	f	nan	nan	nan	0	nan
3	119		f	0	f	nan	nan	nan	0	nan
3	120	192.195.67.22	t	0	f	nan	nan	nan	0	nan
3	121		f	0	f	nan	nan	nan	0	nan
3	122	40.71.70.250	t	200	t	nan	OK	http://ets.abc.com:80/Login	200	Welcome to MediaPulse Sky
3	123	40.71.70.250	t	200	t	nan	OK	http://etsdev.abc.com:80/Login	200	Welcome to MediaPulse Sky
3	1820		f	0	f	nan	nan	nan	0	nan
3	124	72.44.37.156	t	401	t	ec2-72-44-37-156.compute-1.amazonaws.com	Unauthorized	https://facebook.abc.com/	401	nan
3	1822		f	0	f	nan	nan	nan	0	nan
3	126		f	0	f	nan	nan	nan	0	nan
3	127		f	0	f	nan	nan	nan	0	nan
3	128		f	0	f	nan	nan	nan	0	nan
3	129	184.85.220.71	t	404	t	a184-85-220-71.deploy.static.akamaitechnologies.com	Not Found	https://fcast.cdn.abc.com/	404	nan
3	130	184.85.220.86	t	404	t	a184-85-220-86.deploy.static.akamaitechnologies.com	Not Found	https://fcast.qa.cdn.abc.com/	404	nan
3	131		f	0	f	nan	nan	nan	0	nan
3	132		f	0	f	nan	nan	nan	0	nan
3	1831		f	0	f	nan	nan	nan	0	nan
3	133		f	0	f	nan	nan	nan	0	nan
3	134		f	0	f	nan	nan	nan	0	nan
3	135		f	0	f	nan	nan	nan	0	nan
3	136	204.87.172.6	t	0	f	nan	nan	nan	0	nan
3	137	204.87.172.6	t	0	f	nan	nan	nan	0	nan
3	138		f	0	f	nan	nan	nan	0	nan
3	139	52.84.150.57	t	403	t	nan	Forbidden	https://gambit.abc.com/	403	403 Forbidden
3	140	72.2.116.92	t	0	f	nan	nan	nan	0	nan
3	141		f	0	f	nan	nan	nan	0	nan
3	142	76.223.54.146	t	200	t	a904c694c05102f30.awsglobalaccelerator.com	OK	https://getabc.com/	200	nan
3	1842		f	0	f	nan	nan	nan	0	nan
3	1843		f	0	f	nan	nan	nan	0	nan
3	143		f	0	f	nan	nan	nan	0	nan
3	144		f	0	f	nan	nan	nan	0	nan
3	145	52.44.244.98	t	200	t	ec2-52-44-244-98.compute-1.amazonaws.com	OK	http://gksrv.abc.com/	200	NameBright - Coming Soon
3	1847		f	0	f	nan	nan	nan	0	nan
3	146	139.104.232.35	t	0	f	nan	nan	nan	0	nan
3	1849		f	0	f	nan	nan	nan	0	nan
3	147		f	0	f	nan	nan	nan	0	nan
3	148	139.104.232.30	t	0	f	nan	nan	nan	0	nan
3	149	139.104.232.31	t	0	f	nan	nan	nan	0	nan
3	150	139.104.232.32	t	0	f	nan	nan	nan	0	nan
3	1854		f	0	f	nan	nan	nan	0	nan
3	151	139.104.232.13	t	0	f	nan	nan	nan	0	nan
3	152	151.101.106.217	t	200	t	nan	OK	https://idolvote-test.abc.com/	200	Client Challenge
3	153	151.101.106.217	t	200	t	nan	OK	https://idolvote.abc.com/	200	Client Challenge
3	1858		f	0	f	nan	nan	nan	0	nan
3	1859		f	0	f	nan	nan	nan	0	nan
3	154	54.70.112.205	t	200	t	ec2-54-70-112-205.us-west-2.compute.amazonaws.com	OK	https://abc.com/browse	200	ABC TV Shows, Specials &amp; Movies
3	155		f	0	f	nan	nan	nan	0	nan
3	1862		f	0	f	nan	nan	nan	0	nan
3	1863		f	0	f	nan	nan	nan	0	nan
3	1864		f	0	f	nan	nan	nan	0	nan
3	156	52.43.57.102	t	200	t	ec2-52-43-57-102.us-west-2.compute.amazonaws.com	OK	https://abc.com/show/9bfe2f4f-41ad-4492-a6dd-0b67db180543	200	Watch Jimmy Kimmel Live! TV Show - ABC.com
3	157	3.33.130.190	t	200	t	a2aa9ff50de748dbe.awsglobalaccelerator.com	OK	https://join-abc.com/	200	nan
3	158	34.174.221.135	t	200	t	135.221.174.34.bc.googleusercontent.com	OK	https://www.actionbehavior.com/careers	200	Careers | ABA Therapy, BCBA &amp; RBT Jobs
3	160	192.195.67.81	t	0	f	nan	nan	nan	0	nan
3	1870		f	0	f	nan	nan	nan	0	nan
3	1871		f	0	f	nan	nan	nan	0	nan
3	161		f	0	f	nan	nan	nan	0	nan
3	162		f	0	f	nan	nan	nan	0	nan
3	163		f	0	f	nan	nan	nan	0	nan
3	1875		f	0	f	nan	nan	nan	0	nan
3	164		f	0	f	nan	nan	nan	0	nan
3	165		f	0	f	nan	nan	nan	0	nan
3	166		f	0	f	nan	nan	nan	0	nan
3	167		f	0	f	nan	nan	nan	0	nan
3	168		f	0	f	nan	nan	nan	0	nan
3	169		f	0	f	nan	nan	nan	0	nan
3	170		f	0	f	nan	nan	nan	0	nan
3	1883		f	0	f	nan	nan	nan	0	nan
3	1884	54.190.118.130	t	200	t	ec2-54-190-118-130.us-west-2.compute.amazonaws.com	OK	http://www.disneyinternational.com/	200	Disney - Disney Online International
3	171	49.44.95.143	t	200	t	nan	OK	https://ll.media.abc.com/	200	nan
3	1886		f	0	f	nan	nan	nan	0	nan
3	172	54.190.118.130	t	200	t	ec2-54-190-118-130.us-west-2.compute.amazonaws.com	OK	https://abc.com/browse	200	ABC TV Shows, Specials &amp; Movies
3	173	54.190.118.130	t	200	t	ec2-54-190-118-130.us-west-2.compute.amazonaws.com	OK	https://abc.com/	200	ABC Network - ABC.com
3	1889		f	0	f	nan	nan	nan	0	nan
3	1890		f	0	f	nan	nan	nan	0	nan
3	174		f	0	f	nan	nan	nan	0	nan
3	1892		f	0	f	nan	nan	nan	0	nan
3	1893		f	0	f	nan	nan	nan	0	nan
3	175		f	0	f	nan	nan	nan	0	nan
3	177		f	0	f	nan	nan	nan	0	nan
3	178		f	0	f	nan	nan	nan	0	nan
3	179	192.195.67.33	t	200	t	nan	OK	https://mc.abc.com/	200	mc.abc.com
3	180	68.71.212.241	t	0	f	media.abc.go.com	nan	nan	0	nan
3	181	40.71.70.250	t	502	t	nan	Bad Gateway	https://mediapulsepoc2.abc.com/	502	502 Bad Gateway
3	183		f	0	f	nan	nan	nan	0	nan
3	184		f	0	f	nan	nan	nan	0	nan
3	185		f	0	f	nan	nan	nan	0	nan
3	186		f	0	f	nan	nan	nan	0	nan
3	187		f	0	f	nan	nan	nan	0	nan
3	188		f	0	f	nan	nan	nan	0	nan
3	189		f	0	f	nan	nan	nan	0	nan
3	190		f	0	f	nan	nan	nan	0	nan
3	191		f	0	f	nan	nan	nan	0	nan
3	192		f	0	f	nan	nan	nan	0	nan
3	193		f	0	f	nan	nan	nan	0	nan
3	194		f	0	f	nan	nan	nan	0	nan
3	195	100.49.209.37	t	200	t	ec2-100-49-209-37.compute-1.amazonaws.com	OK	https://abc.com/show/d72316e9-c889-494b-bb3c-a48266fb326d	200	Watch Modern Family TV Show - ABC.com
3	1916		f	0	f	nan	nan	nan	0	nan
3	197	192.195.63.64	t	0	f	nan	nan	nan	0	nan
3	1918		f	0	f	nan	nan	nan	0	nan
3	198	3.96.22.179	t	502	t	ec2-3-96-22-179.ca-central-1.compute.amazonaws.com	Bad Gateway	https://my-abc.com/	502	502 Bad Gateway
3	199	165.160.15.20	t	200	t	nan	OK	http://myabc.com/	200	nan
3	200		f	0	f	nan	nan	nan	0	nan
3	201		f	0	f	nan	nan	nan	0	nan
3	1923		f	0	f	nan	nan	nan	0	nan
3	202	209.34.85.149	t	0	f	nan	nan	nan	0	nan
3	1925		f	0	f	nan	nan	nan	0	nan
3	203	52.0.158.81	t	200	t	ec2-52-0-158-81.compute-1.amazonaws.com	OK	https://netbox.abc.com/login/?next=/	200	Home | NetBox
3	204		f	0	f	nan	nan	nan	0	nan
3	205		f	0	f	nan	nan	nan	0	nan
3	1929		f	0	f	nan	nan	nan	0	nan
3	1930		f	0	f	nan	nan	nan	0	nan
3	1931		f	0	f	nan	nan	nan	0	nan
3	206		f	0	f	nan	nan	nan	0	nan
3	207	139.104.232.44	t	0	f	nan	nan	nan	0	nan
3	1934		f	0	f	nan	nan	nan	0	nan
3	1935		f	0	f	nan	nan	nan	0	nan
3	1936		f	0	f	nan	nan	nan	0	nan
3	208	54.70.112.205	t	404	t	ec2-54-70-112-205.us-west-2.compute.amazonaws.com	Not Found	https://abc.com/shows/once-upon-a-time	404	Page not found - ABC.com
3	1938	192.147.170.20	t	0	f	nan	nan	nan	0	nan
3	209		f	0	f	nan	nan	nan	0	nan
3	1940		f	0	f	nan	nan	nan	0	nan
3	210		f	0	f	nan	nan	nan	0	nan
3	1942	184.85.220.78	t	200	t	a184-85-220-78.deploy.static.akamaitechnologies.com	OK	https://abc.com/	200	ABC Network - ABC.com
3	1943		f	0	f	nan	nan	nan	0	nan
3	211		f	0	f	nan	nan	nan	0	nan
3	212		f	0	f	nan	nan	nan	0	nan
3	213	108.158.245.6	t	403	t	server-108-158-245-6.del51.r.cloudfront.net	Forbidden	https://prod.cd.abc.com/	403	nan
3	214		f	0	f	nan	nan	nan	0	nan
3	1948	54.190.118.130	t	200	t	ec2-54-190-118-130.us-west-2.compute.amazonaws.com	OK	https://abc.com/browse	200	ABC TV Shows, Specials &amp; Movies
3	215	3.218.217.30	t	596	t	ec2-3-218-217-30.compute-1.amazonaws.com	596	https://qa.api.abc.com/	596	nan
3	216	99.86.30.39	t	403	t	server-99-86-30-39.del51.r.cloudfront.net	Forbidden	https://qa.cd.abc.com/	403	nan
3	217		f	0	f	nan	nan	nan	0	nan
3	1952		f	0	f	nan	nan	nan	0	nan
3	218	204.202.134.76	t	0	f	nan	nan	nan	0	nan
3	219	204.202.134.77	t	0	f	nan	nan	nan	0	nan
3	220	204.202.134.78	t	0	f	nan	nan	nan	0	nan
3	1956		f	0	f	nan	nan	nan	0	nan
3	221	192.195.67.129	t	200	t	nan	OK	https://redirect.abc.com/	200	Redirect
3	222	52.150.35.231	t	0	f	nan	nan	nan	0	nan
3	223	100.30.242.112	t	0	f	ec2-100-30-242-112.compute-1.amazonaws.com	nan	nan	0	nan
3	1960	13.217.182.13	t	404	t	ec2-13-217-182-13.compute-1.amazonaws.com	Not Found	https://abc.com/shows/revenge	404	Page not found - ABC.com
3	224		f	0	f	nan	nan	nan	0	nan
3	225		f	0	f	nan	nan	nan	0	nan
3	226		f	0	f	nan	nan	nan	0	nan
3	227		f	0	f	nan	nan	nan	0	nan
3	1965		f	0	f	nan	nan	nan	0	nan
3	228		f	0	f	nan	nan	nan	0	nan
3	229		f	0	f	nan	nan	nan	0	nan
3	230		f	0	f	nan	nan	nan	0	nan
3	231		f	0	f	nan	nan	nan	0	nan
3	232		f	0	f	nan	nan	nan	0	nan
3	233		f	0	f	nan	nan	nan	0	nan
3	234		f	0	f	nan	nan	nan	0	nan
3	235	54.70.112.205	t	404	t	ec2-54-70-112-205.us-west-2.compute.amazonaws.com	Not Found	https://abc.com/shows/scandal	404	Page not found - ABC.com
3	1974		f	0	f	nan	nan	nan	0	nan
3	236		f	0	f	nan	nan	nan	0	nan
3	237		f	0	f	nan	nan	nan	0	nan
3	238	35.197.121.119	t	403	t	119.121.197.35.bc.googleusercontent.com	Forbidden	https://secureabc.com/	403	403 Forbidden
3	239	139.104.232.57	t	0	f	nan	nan	nan	0	nan
3	240		f	0	f	nan	nan	nan	0	nan
3	241		f	0	f	nan	nan	nan	0	nan
3	1981		f	0	f	nan	nan	nan	0	nan
3	1982		f	0	f	nan	nan	nan	0	nan
3	242		f	0	f	nan	nan	nan	0	nan
3	243		f	0	f	nan	nan	nan	0	nan
3	244	192.195.66.83	t	0	f	nan	nan	nan	0	nan
3	245		f	0	f	nan	nan	nan	0	nan
3	246		f	0	f	nan	nan	nan	0	nan
3	1988		f	0	f	nan	nan	nan	0	nan
3	1989		f	0	f	nan	nan	nan	0	nan
3	247		f	0	f	nan	nan	nan	0	nan
3	248		f	0	f	nan	nan	nan	0	nan
3	249		f	0	f	nan	nan	nan	0	nan
3	250		f	0	f	nan	nan	nan	0	nan
3	251		f	0	f	nan	nan	nan	0	nan
3	252		f	0	f	nan	nan	nan	0	nan
3	1996		f	0	f	nan	nan	nan	0	nan
3	1997		f	0	f	nan	nan	nan	0	nan
3	1998		f	0	f	nan	nan	nan	0	nan
3	253	18.164.217.118	t	403	t	server-18-164-217-118.del54.r.cloudfront.net	Forbidden	https://stage.cd.abc.com/	403	nan
3	254	99.84.152.104	t	403	t	server-99-84-152-104.fra56.r.cloudfront.net	Forbidden	http://storefront.abc.com/	403	ERROR: The request could not be satisfied
3	255	99.84.152.6	t	403	t	server-99-84-152-6.fra56.r.cloudfront.net	Forbidden	http://storefrontdev.abc.com/	403	ERROR: The request could not be satisfied
3	256		f	0	f	nan	nan	nan	0	nan
3	257		f	0	f	nan	nan	nan	0	nan
3	2004		f	0	f	nan	nan	nan	0	nan
3	258	216.198.53.11	t	403	t	nan	Forbidden	https://support.abc.com/hc/en-us	403	Just a moment...
3	2006		f	0	f	nan	nan	nan	0	nan
3	259		f	0	f	nan	nan	nan	0	nan
3	260	66.117.22.113	t	200	t	ip-66-117-22-113.data.adobedc.net	OK	https://sw88.abc.com/	200	nan
3	261		f	0	f	nan	nan	nan	0	nan
3	2010		f	0	f	nan	nan	nan	0	nan
3	262		f	0	f	nan	nan	nan	0	nan
3	2013		f	0	f	nan	nan	nan	0	nan
3	264		f	0	f	nan	nan	nan	0	nan
3	2015		f	0	f	nan	nan	nan	0	nan
3	2016	204.202.137.92	t	0	f	nan	nan	nan	0	nan
3	265		f	0	f	nan	nan	nan	0	nan
3	266		f	0	f	nan	nan	nan	0	nan
3	267	13.248.169.48	t	200	t	a904c694c05102f30.awsglobalaccelerator.com	OK	https://try-abc.com/	200	nan
3	268	208.115.240.122	t	200	t	122-240-115-208.static.reverse.lstn.net	OK	http://www.chinesemenu.com	200	Chinese Menu | Chinese Restaurant | Chinese Cuisine | Chinese Food in LA | Delivery Food
3	2021		f	0	f	nan	nan	nan	0	nan
3	2022		f	0	f	nan	nan	nan	0	nan
3	269		f	0	f	nan	nan	nan	0	nan
3	270		f	0	f	nan	nan	nan	0	nan
3	271		f	0	f	nan	nan	nan	0	nan
3	272		f	0	f	nan	nan	nan	0	nan
3	273		f	0	f	nan	nan	nan	0	nan
3	274		f	0	f	nan	nan	nan	0	nan
3	275		f	0	f	nan	nan	nan	0	nan
3	276		f	0	f	nan	nan	nan	0	nan
3	277		f	0	f	nan	nan	nan	0	nan
3	278		f	0	f	nan	nan	nan	0	nan
3	2033	199.181.134.92	t	0	f	nan	nan	nan	0	nan
3	279	52.147.216.119	t	0	f	nan	nan	nan	0	nan
3	280	52.147.216.119	t	0	f	nan	nan	nan	0	nan
3	281		f	0	f	nan	nan	nan	0	nan
3	282		f	0	f	nan	nan	nan	0	nan
3	283		f	0	f	nan	nan	nan	0	nan
3	284	139.104.232.100	t	0	f	nan	nan	nan	0	nan
3	285	139.104.232.107	t	0	f	nan	nan	nan	0	nan
3	286		f	0	f	nan	nan	nan	0	nan
3	287		f	0	f	nan	nan	nan	0	nan
3	288	67.212.182.149	t	200	t	xperience.plus	OK	https://vdigate5.abc.com/	200	Vdigate5
3	289		f	0	f	nan	nan	nan	0	nan
3	290		f	0	f	nan	nan	nan	0	nan
3	291		f	0	f	nan	nan	nan	0	nan
3	292	20.127.42.140	t	502	t	nan	Bad Gateway	https://vdigateqa.abc.com/	502	502 Bad Gateway
3	2048		f	0	f	nan	nan	nan	0	nan
3	2049		f	0	f	nan	nan	nan	0	nan
3	293	49.44.175.11	t	503	t	nan	Service Unavailable	https://vp2.abc.com/	503	Service Unavailable
3	2051		f	0	f	nan	nan	nan	0	nan
3	294	66.117.22.113	t	200	t	ip-66-117-22-113.data.adobedc.net	OK	https://w88.abc.com/	200	nan
3	2053		f	0	f	nan	nan	nan	0	nan
3	295	54.190.118.130	t	200	t	ec2-54-190-118-130.us-west-2.compute.amazonaws.com	OK	http://www.disneyinternational.com/	200	Disney - Disney Online International
3	296		f	0	f	nan	nan	nan	0	nan
3	2056		f	0	f	nan	nan	nan	0	nan
3	2057		f	0	f	nan	nan	nan	0	nan
3	297		f	0	f	nan	nan	nan	0	nan
3	2059		f	0	f	nan	nan	nan	0	nan
3	2060		f	0	f	nan	nan	nan	0	nan
3	2061		f	0	f	nan	nan	nan	0	nan
3	298		f	0	f	nan	nan	nan	0	nan
3	2063		f	0	f	nan	nan	nan	0	nan
3	299	13.225.103.63	t	200	t	server-13-225-103-63.del51.r.cloudfront.net	OK	https://abc.com/	200	ABC Network - ABC.com
3	303		f	0	f	nan	nan	nan	0	nan
3	305	54.190.118.130	t	200	t	ec2-54-190-118-130.us-west-2.compute.amazonaws.com	OK	https://abc.com/browse	200	ABC TV Shows, Specials &amp; Movies
3	306		f	0	f	nan	nan	nan	0	nan
3	2072	49.44.50.67	t	404	t	nan	Not Found	https://www.datgpodcast.abc.com/	404	nan
3	313		f	0	f	nan	nan	nan	0	nan
3	314		f	0	f	nan	nan	nan	0	nan
3	315		f	0	f	nan	nan	nan	0	nan
3	317		f	0	f	nan	nan	nan	0	nan
3	2086		f	0	f	nan	nan	nan	0	nan
3	320		f	0	f	nan	nan	nan	0	nan
3	323		f	0	f	nan	nan	nan	0	nan
3	324		f	0	f	nan	nan	nan	0	nan
3	325		f	0	f	nan	nan	nan	0	nan
3	326		f	0	f	\N	\N	\N	\N	\N
3	601		f	0	f	\N	\N	\N	\N	\N
3	599		f	0	f	\N	\N	\N	\N	\N
3	1156		f	0	f	\N	\N	\N	\N	\N
3	338		f	0	f	\N	\N	\N	\N	\N
3	330		f	0	f	\N	\N	\N	\N	\N
3	996		f	0	f	\N	\N	\N	\N	\N
3	345		f	0	f	\N	\N	\N	\N	\N
3	339		f	0	f	\N	\N	\N	\N	\N
3	344		f	0	f	\N	\N	\N	\N	\N
3	335		f	0	f	\N	\N	\N	\N	\N
3	343		f	0	f	\N	\N	\N	\N	\N
3	998		f	0	f	\N	\N	\N	\N	\N
3	1009		f	0	f	\N	\N	\N	\N	\N
3	984		f	0	f	\N	\N	\N	\N	\N
3	333		f	0	f	\N	\N	\N	\N	\N
3	337		f	0	f	\N	\N	\N	\N	\N
3	334		f	0	f	\N	\N	\N	\N	\N
3	328		f	0	f	\N	\N	\N	\N	\N
3	340		f	0	f	\N	\N	\N	\N	\N
3	336		f	0	f	\N	\N	\N	\N	\N
3	342		f	0	f	\N	\N	\N	\N	\N
3	329		f	0	f	\N	\N	\N	\N	\N
3	332		f	0	f	\N	\N	\N	\N	\N
3	331		f	0	f	\N	\N	\N	\N	\N
3	327		f	0	f	\N	\N	\N	\N	\N
3	1295		f	0	f	\N	\N	\N	\N	\N
3	1297		f	0	f	\N	\N	\N	\N	\N
3	1292		f	0	f	\N	\N	\N	\N	\N
3	1291		f	0	f	\N	\N	\N	\N	\N
3	1296		f	0	f	\N	\N	\N	\N	\N
3	602		f	0	f	\N	\N	\N	\N	\N
3	595		f	0	f	\N	\N	\N	\N	\N
3	597		f	0	f	\N	\N	\N	\N	\N
3	598		f	0	f	\N	\N	\N	\N	\N
3	596		f	0	f	\N	\N	\N	\N	\N
3	457		f	0	f	\N	\N	\N	\N	\N
3	600		f	0	f	\N	\N	\N	\N	\N
3	530		f	0	f	\N	\N	\N	\N	\N
3	573		f	0	f	\N	\N	\N	\N	\N
3	971		f	0	f	\N	\N	\N	\N	\N
3	4518		f	0	f	\N	\N	\N	\N	\N
3	4519		f	0	f	\N	\N	\N	\N	\N
3	4520		f	0	f	\N	\N	\N	\N	\N
3	4524		f	0	f	\N	\N	\N	\N	\N
3	4525		f	0	f	\N	\N	\N	\N	\N
3	4529		f	0	f	\N	\N	\N	\N	\N
3	4531		f	0	f	\N	\N	\N	\N	\N
3	4532		f	0	f	\N	\N	\N	\N	\N
3	4533		f	0	f	\N	\N	\N	\N	\N
3	4534		f	0	f	\N	\N	\N	\N	\N
3	4538		f	0	f	\N	\N	\N	\N	\N
3	4539		f	0	f	\N	\N	\N	\N	\N
3	4543		f	0	f	\N	\N	\N	\N	\N
3	4545		f	0	f	\N	\N	\N	\N	\N
3	4546		f	0	f	\N	\N	\N	\N	\N
3	4547		f	0	f	\N	\N	\N	\N	\N
3	4548		f	0	f	\N	\N	\N	\N	\N
3	4549		f	0	f	\N	\N	\N	\N	\N
3	4550		f	0	f	\N	\N	\N	\N	\N
3	4523		f	0	f	\N	\N	\N	\N	\N
3	4552		f	0	f	\N	\N	\N	\N	\N
3	4554		f	0	f	\N	\N	\N	\N	\N
3	4555		f	0	f	\N	\N	\N	\N	\N
3	4556		f	0	f	\N	\N	\N	\N	\N
3	4557		f	0	f	\N	\N	\N	\N	\N
3	4559		f	0	f	\N	\N	\N	\N	\N
3	4560		f	0	f	\N	\N	\N	\N	\N
3	4537		f	0	f	\N	\N	\N	\N	\N
3	4535		f	0	f	\N	\N	\N	\N	\N
3	4521		f	0	f	\N	\N	\N	\N	\N
3	4566		f	0	f	\N	\N	\N	\N	\N
3	4568		f	0	f	\N	\N	\N	\N	\N
3	4569		f	0	f	\N	\N	\N	\N	\N
3	4571		f	0	f	\N	\N	\N	\N	\N
3	4572		f	0	f	\N	\N	\N	\N	\N
3	4573		f	0	f	\N	\N	\N	\N	\N
3	4574		f	0	f	\N	\N	\N	\N	\N
3	4540		f	0	f	\N	\N	\N	\N	\N
3	4577		f	0	f	\N	\N	\N	\N	\N
3	4579		f	0	f	\N	\N	\N	\N	\N
3	4565		f	0	f	\N	\N	\N	\N	\N
3	4582		f	0	f	\N	\N	\N	\N	\N
3	4530		f	0	f	\N	\N	\N	\N	\N
3	4584		f	0	f	\N	\N	\N	\N	\N
3	4585		f	0	f	\N	\N	\N	\N	\N
3	4526		f	0	f	\N	\N	\N	\N	\N
3	4587		f	0	f	\N	\N	\N	\N	\N
3	4536		f	0	f	\N	\N	\N	\N	\N
3	4570		f	0	f	\N	\N	\N	\N	\N
3	4561		f	0	f	\N	\N	\N	\N	\N
3	4591		f	0	f	\N	\N	\N	\N	\N
3	4592		f	0	f	\N	\N	\N	\N	\N
3	4558		f	0	f	\N	\N	\N	\N	\N
3	4594		f	0	f	\N	\N	\N	\N	\N
3	4595		f	0	f	\N	\N	\N	\N	\N
3	4596		f	0	f	\N	\N	\N	\N	\N
3	4567		f	0	f	\N	\N	\N	\N	\N
3	4598		f	0	f	\N	\N	\N	\N	\N
3	4522		f	0	f	\N	\N	\N	\N	\N
3	4541		f	0	f	\N	\N	\N	\N	\N
3	4601		f	0	f	\N	\N	\N	\N	\N
3	4542		f	0	f	\N	\N	\N	\N	\N
3	4603		f	0	f	\N	\N	\N	\N	\N
3	4604		f	0	f	\N	\N	\N	\N	\N
3	4528		f	0	f	\N	\N	\N	\N	\N
3	4563		f	0	f	\N	\N	\N	\N	\N
3	4606		f	0	f	\N	\N	\N	\N	\N
3	4544		f	0	f	\N	\N	\N	\N	\N
3	4553		f	0	f	\N	\N	\N	\N	\N
3	4611		f	0	f	\N	\N	\N	\N	\N
3	4612		f	0	f	\N	\N	\N	\N	\N
3	4613		f	0	f	\N	\N	\N	\N	\N
3	4614		f	0	f	\N	\N	\N	\N	\N
3	4527		f	0	f	\N	\N	\N	\N	\N
\.


--
-- Data for Name: domain_tech; Type: TABLE DATA; Schema: public; Owner: asm
--

COPY public.domain_tech (scan_id, domain_id, tech) FROM stdin;
3	9	nginx
3	9	bootstrap
3	9	aws
3	9	react/nextjs
3	21	nginx
3	21	bootstrap
3	21	aws
3	21	react/nextjs
3	35	nginx
3	35	bootstrap
3	35	aws
3	35	react/nextjs
3	38	nginx
3	38	bootstrap
3	38	aws
3	38	react/nextjs
3	39	aws
3	40	aws
3	41	aws
3	55	nginx
3	55	bootstrap
3	55	aws
3	55	react/nextjs
3	58	nginx
3	58	bootstrap
3	58	aws
3	58	react/nextjs
3	61	cloudflare
3	65	bootstrap
3	65	aws
3	65	react/nextjs
3	68	aws
3	70	akamai
3	71	akamai
3	71	jquery
3	71	aws
3	79	unknown
3	88	aws
3	90	unknown
3	92	nginx
3	99	apache
3	102	jquery
3	102	aws
3	103	nginx
3	103	bootstrap
3	103	aws
3	103	react/nextjs
3	104	nginx
3	104	bootstrap
3	104	aws
3	104	react/nextjs
3	105	nginx
3	106	nginx
3	113	nginx
3	113	bootstrap
3	113	aws
3	113	react/nextjs
3	122	microsoft-iis
3	123	microsoft-iis
3	124	unknown
3	129	unknown
3	130	unknown
3	139	aws
3	145	unknown
3	152	unknown
3	153	unknown
3	154	nginx
3	154	bootstrap
3	154	aws
3	154	react/nextjs
3	156	nginx
3	156	bootstrap
3	156	aws
3	156	react/nextjs
3	171	akamai
3	171	jquery
3	171	aws
3	172	nginx
3	172	bootstrap
3	172	aws
3	172	react/nextjs
3	173	nginx
3	173	bootstrap
3	173	aws
3	173	react/nextjs
3	179	bootstrap
3	179	apache
3	181	azure
3	195	nginx
3	195	bootstrap
3	195	aws
3	195	react/nextjs
3	203	nginx
3	208	bootstrap
3	208	aws
3	208	react/nextjs
3	213	aws
3	215	unknown
3	216	aws
3	221	bootstrap
3	221	microsoft-iis
3	235	bootstrap
3	235	aws
3	235	react/nextjs
3	253	aws
3	254	aws
3	255	aws
3	258	cloudflare
3	260	unknown
3	288	nginx
3	288	jquery
3	288	bootstrap
3	292	unknown
3	293	akamai
3	294	unknown
3	295	jquery
3	295	aws
3	299	nginx
3	299	bootstrap
3	299	aws
3	299	react/nextjs
3	305	nginx
3	305	bootstrap
3	305	aws
3	305	react/nextjs
3	1884	jquery
3	1884	aws
3	1942	nginx
3	1942	bootstrap
3	1942	aws
3	1942	react/nextjs
3	1948	nginx
3	1948	bootstrap
3	1948	aws
3	1948	react/nextjs
3	1960	bootstrap
3	1960	aws
3	1960	react/nextjs
3	2072	akamai
\.


--
-- Data for Name: domain_validation_log; Type: TABLE DATA; Schema: public; Owner: asm
--

COPY public.domain_validation_log (domain, status, source, created_at) FROM stdin;
\.


--
-- Data for Name: domains; Type: TABLE DATA; Schema: public; Owner: asm
--

COPY public.domains (id, domain, first_seen_scan, last_seen_scan, is_known, source, enrichment_status, san_processed, port_done, tech_done, asn_done, provider_done, scannable, confidence_score, confidence_label, confidence_reasons, validation_source, first_seen_at, last_seen_at) FROM stdin;
175	mailxi.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
177	marketingops.net.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
10	abc-cloud.com	1	3	f	seed	pending	f	f	f	f	f	f	5	medium	{"contains keyword 'abc'","same ASN/provider"}	\N	\N	\N
4582	fan.core.api.espn.nl	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4521	espn.cl	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4595	fan.api.espn.com.gt	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4568	fan.core.api.espn.com.co	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4529	fan.core.api.espn.cl	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4525	api.espn.com.sg	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4570	espn.com.ec	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
178	mc-aprimo.net.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
183	mi0325.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
184	mi0328.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
4592	fan.api.espn.com.pa	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4587	fan.api.espn.com.pe	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4530	espn.go.com	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
1296	espn.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4563	espn.com.ve	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4569	api.espn.com.ve	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
1	0327.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
4555	editions.espn.com	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4	1121.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
4565	espn.com.gt	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4554	fan.core.api.espn.co.uk	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4534	api.espn.in	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4596	fan.core.api.espn.com.pa	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
5	1127.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
4533	fan.api.espn.es	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4552	api.espn.cl	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4524	api.espn.com.au	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4549	api.espn.com.pe	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4542	espn.co.uk	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4544	espn.com.sg	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
6	1at0325.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
4584	fan.core.api.espn.in	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4558	espn.com.mx	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4550	fan.api.espn.com.do	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4537	espn.com.au	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4560	api.espn.com.gt	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4548	fan.core.api.espn.com.pe	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4567	espn.co.cr	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4522	espn.com.ar	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4572	api.espn.nl	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
8	a.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
4547	fan.api.espn.com.uy	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4527	espn.com.pe	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4601	fan.core.api.espn.com.uy	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4603	api.espn.com.mx	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4528	espn.es	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4579	api.espn.co.cr	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4566	fan.core.api.espn.co.cr	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4591	fan.core.api.espn.com.gt	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4541	espn.com.pa	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
326	www.abc-services.com	1	3	f	seed	pending	f	f	f	f	f	f	6	medium	{"contains keyword 'abc'","shares IP with known asset"}	\N	\N	2026-04-27 21:28:07.696169
14	abc-services.com	1	3	f	seed	pending	f	f	f	f	f	f	5	medium	{"contains keyword 'abc'","same ASN/provider"}	\N	\N	2026-04-27 21:30:59.815242
13	abc-group.com	1	3	f	seed	pending	f	f	f	f	f	f	5	medium	{"contains keyword 'abc'","same ASN/provider"}	\N	\N	\N
15	abc-tech.com	1	3	f	seed	pending	f	f	f	f	f	f	8	high	{"contains keyword 'abc'","shares IP with known asset","same ASN/provider"}	\N	\N	\N
17	abc.ai	1	3	f	seed	pending	f	f	f	f	f	f	5	medium	{"contains keyword 'abc'","same ASN/provider"}	\N	\N	\N
4535	espn.com.co	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4532	api.espn.com.ec	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4577	fan.api.espn.ph	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4561	espndeportes.com	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4553	espn.com.br	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4585	fan.core.api.espn.com.do	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4614	fan.core.api.espn.es	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
7	1mi0325.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
9	a.oscar.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
16	abc.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
20	abc.co	1	3	f	seed	pending	f	f	f	f	f	f	5	medium	{"contains keyword 'abc'","same ASN/provider"}	\N	\N	\N
22	abc.in	1	3	f	seed	pending	f	f	f	f	f	f	5	medium	{"contains keyword 'abc'","same ASN/provider"}	\N	\N	\N
108	emdesign-stage.net.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
2	0706.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
243	sgadmin.mit.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
256	stories.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
257	stratodesk.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
259	svrctx01.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
261	sweepstakes.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
262	test.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
264	test2.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
265	tower.mit.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
266	transfer.mit.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
269	uag.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
270	ugw.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
287	vdigate4qa.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
31	abcnyprod01.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
32	abcnyprod02.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
35	afv.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
288	vdigate5.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
291	vdigate6qa.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
292	vdigateqa.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
293	vp2.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
294	w88.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
109	emdesign.net.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
110	emindex.net.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
111	emindexdb.net.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
114	emreach-staging.net.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
115	emreach.net.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
295	watch.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
116	emsetup.net.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
23	abc.io	1	3	f	seed	pending	f	f	f	f	f	f	5	medium	{"contains keyword 'abc'","same ASN/provider"}	\N	\N	\N
164	la0325.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
165	la0328.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
166	la03281.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
167	la0330.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
168	la0331.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
170	la1117.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
182	mediascreening.net.abc.com	1	2	t	seed	pending	f	f	f	f	f	\N	0	\N	\N	\N	\N	\N
106	dwtsvote.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
3	10gserver.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
112	emmedia.net.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
113	emmys.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
163	khanjari.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
36	akarmi.abc.com.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
37	altavault01.mit.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
38	ama.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
296	webdisk.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
297	webmail.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
298	workspaces.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
169	la1115.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
176	manage.splunk.mit.abc.com	1	2	t	seed	pending	f	f	f	f	f	\N	0	\N	\N	\N	\N	\N
196	monitor.splunk.mit.abc.com	1	2	f	seed	pending	f	f	f	f	f	\N	0	\N	\N	\N	\N	\N
174	mail.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
187	mi0330.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
188	mi0331.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
303	www.autolink.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
305	www.bachelor.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
39	api.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	2026-04-27 21:28:07.696169
41	api2.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
42	appstore17.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
43	appstore3.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
44	appstore7.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
45	as1115.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
46	asperaconsole.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
47	at0325.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
48	at0330.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
49	at0331.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
50	at1115.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
51	at1117.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
306	www.boesfx.net.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
313	www.gist.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
314	www.haivision.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
189	miami1012.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
190	mn0325.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
191	mn0328.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
192	mn0330.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
193	mn1115.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
194	mn1117.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
315	www.marketingops.net.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
317	www.remotesupport.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
320	www.test.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
323	xkm-emg-pautlnk.net.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
25	abc.org	1	3	f	seed	pending	f	f	f	f	f	f	5	medium	{"contains keyword 'abc'","same ASN/provider"}	\N	\N	\N
24	abc.net	1	3	f	seed	pending	f	f	f	f	f	t	10	high	{"manually approved"}	manual	\N	\N
52	autodiscover.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
53	autolink.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
56	baton.mit.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
57	bbir.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
58	beta.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
327	www.abcservices.com	1	3	f	seed	pending	f	f	f	f	f	f	6	medium	{"contains keyword 'abc'","shares IP with known asset"}	\N	\N	2026-04-27 21:28:07.696169
117	emsoundminerdev.net.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
118	emvault.net.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
119	emwebapps.net.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
59	bid48da.865291336m.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
60	blackberry.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
61	blogs.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
62	boesfx.net.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
63	bpl-emg-rcheng1.net.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
64	bvl-mit-graf01.mit.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
65	castle.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
120	emx.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
121	emx.net.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
127	fb11.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
200	mydisney.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
201	myproject.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
204	newsmam.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
205	newsmamdev.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
206	ny0330.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
125	faspex.mit.abc.com	1	2	f	seed	pending	f	f	f	f	f	\N	0	\N	\N	\N	\N	\N
67	cdn.beta.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
68	cdn.media.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
69	cdn.media.oscar.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
72	ch0325.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
73	ch0328.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
79	connect.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
83	dashboard.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
86	design.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
87	dev.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
89	dev.ext.integration.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
90	dev.galaxy.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
92	dev.netbox.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
100	download.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
102	duelthegame.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
122	ets.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
123	etsdev.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
124	facebook.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
129	fcast.cdn.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
130	fcast.qa.cdn.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
136	ftp1.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
137	ftp3.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
139	gambit.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
34	abctech.com	1	3	f	seed	pending	f	f	f	f	f	t	10	high	{"manually approved"}	manual	\N	\N
142	getabc.com	1	3	f	seed	pending	f	f	f	f	f	f	0	low	{"manually rejected"}	manual	\N	\N
26	abc.tech	1	3	f	seed	pending	f	f	f	f	f	f	6	medium	{"contains keyword 'abc'","shares IP with known asset"}	\N	\N	\N
299	www.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
27	abccloud.com	1	3	f	seed	pending	f	f	f	f	f	f	5	medium	{"contains keyword 'abc'","same ASN/provider"}	\N	\N	\N
28	abccorp.com	1	3	f	seed	pending	f	f	f	f	f	f	5	medium	{"contains keyword 'abc'","same ASN/provider"}	\N	\N	\N
29	abcglobal.com	1	3	f	seed	pending	f	f	f	f	f	f	5	medium	{"contains keyword 'abc'","same ASN/provider"}	\N	\N	\N
33	abcservices.com	1	3	f	seed	pending	f	f	f	f	f	f	5	medium	{"contains keyword 'abc'","same ASN/provider"}	\N	\N	2026-04-27 21:30:59.815242
1981	server12053.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
30	abcgroup.com	1	3	f	seed	pending	f	f	f	f	f	f	8	high	{"contains keyword 'abc'","shares IP with known asset","same ASN/provider"}	\N	\N	\N
1982	servername.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1988	smtp.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1989	so.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1996	squid1.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
70	cdn.mktg.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
71	cdn.video.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
74	ch03281.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
75	ch03282.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
159	jss.net.abc.com	1	2	t	seed	pending	f	f	f	f	f	\N	0	\N	\N	\N	\N	\N
300	www.abcnyprod01.abc.com	1	2	f	seed	pending	f	f	f	f	f	\N	0	\N	\N	\N	\N	\N
301	www.abcnyprod02.abc.com	1	2	f	seed	pending	f	f	f	f	f	\N	0	\N	\N	\N	\N	\N
302	www.akarmi.abc.com.abc.com	1	2	f	seed	pending	f	f	f	f	f	\N	0	\N	\N	\N	\N	\N
304	www.autolink.net.abc.com	1	2	f	seed	pending	f	f	f	f	f	\N	0	\N	\N	\N	\N	\N
307	www.emindexdb.net.abc.com	1	2	f	seed	pending	f	f	f	f	f	\N	0	\N	\N	\N	\N	\N
209	origin.vp2.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
210	pak.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
222	remotesupport.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1936	office.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
268	tryabc.com	1	3	f	seed	pending	f	f	f	f	f	f	5	medium	{"contains keyword 'abc'","same ASN/provider"}	\N	\N	\N
211	pl0331.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1938	origin.beta.vp2.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1940	p.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1942	partners.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1943	passport.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1948	pushingdaisies.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1952	qradar-aio.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1956	rds.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1960	revenge.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1965	sandbox.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1974	search-es-log-dev.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
267	try-abc.com	1	3	f	seed	pending	f	f	f	f	f	f	0	low	{"manually rejected"}	manual	\N	\N
91	dev.int.integration.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
2016	tools.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
212	plm.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
93	dev.stratodesk.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
94	dev.sweepstakes.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
223	reset.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
235	scandal.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
239	secureaccess.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
244	sip.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
214	proxy.mit.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
128	fb3.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
131	filemaker01.net.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
132	filemaker03.net.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
133	fonts.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
308	www.emreach-staging.net.abc.com	1	2	f	seed	pending	f	f	f	f	f	\N	0	\N	\N	\N	\N	\N
134	fr0330.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
135	fr0331.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
138	galaxy.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
271	untrusted.plm.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
140	garage.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
309	www.emreach.net.abc.com	1	2	f	seed	pending	f	f	f	f	f	\N	0	\N	\N	\N	\N	\N
143	gist.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
144	gitlab.mit.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
145	gksrv.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
146	haivision.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
147	hfsf-ajkrdl3he1.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
148	hmgw1.haivision.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
149	hmgw2.haivision.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
316	www.newsmamdev.abc.com	1	2	f	seed	pending	f	f	f	f	f	\N	0	\N	\N	\N	\N	\N
272	us1026.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
150	hmgw3.haivision.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
151	icom.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
152	idolvote-test.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
153	idolvote.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
154	injustice.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
273	usas.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
274	usas1018.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
275	usat1010.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
217	qa.int.integration.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
276	usch1017.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
318	www.secure.cdn.media.oscar.abc.com	1	2	t	seed	pending	f	f	f	f	f	\N	0	\N	\N	\N	\N	\N
319	www.solarwinds.mit.abc.com	1	2	t	seed	pending	f	f	f	f	f	\N	0	\N	\N	\N	\N	\N
321	www.vdigate.abc.com	1	2	t	seed	pending	f	f	f	f	f	\N	0	\N	\N	\N	\N	\N
322	www.xvl-mit-trnsfr2.mit.abc.com	1	2	t	seed	pending	f	f	f	f	f	\N	0	\N	\N	\N	\N	\N
245	slingshot.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
246	slingshotdev.net.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
247	solarwinds.mit.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
248	soundminer.net.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
249	sp0330.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1997	ss.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1998	sslvpn.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
2004	stream.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
2006	sv.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
2010	temp.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
2013	test.xxx.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
2015	testprint.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
2021	u003elab.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
2022	u003emc.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
85	deploy.splunk.mit.abc.com	1	2	f	seed	pending	f	f	f	f	f	\N	0	\N	\N	\N	\N	\N
81	cpcalendars.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
82	cpcontacts.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
84	de0331.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
126	fb10.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
250	splunk.mit.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
251	spotfinder-akstest.net.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
263	test.sweepstakes.abc.com	1	2	f	seed	pending	f	f	f	f	f	\N	0	\N	\N	\N	\N	\N
252	spotfinder.net.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
254	storefront.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
255	storefrontdev.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
260	sw88.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
277	usla1018.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
278	usla1019.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
279	vdigate.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
280	vdigate1.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
281	vdigate1qa.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
282	vdigate2.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
283	vdigate2qa.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
284	vdigate3.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
285	vdigate3qa.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
286	vdigate4.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
2033	usweekly.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
2048	veritas-dlo.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
2049	voltage-pp-0000.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
2051	vpn.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
2053	wap.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
2056	webdisk.temp.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
2057	webdisk.test.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
2059	webmail.temp.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
2060	webmail.test.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
2061	whm.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
2063	www.a.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
2072	www.datgpodcast.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
2086	www.temp.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
104	dwtsvote-live.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
105	dwtsvote-test.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
224	robert.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
225	rogue.mit.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
226	rstudio-stgngvm.mit.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
227	rt.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
11	abc-corp.com	1	3	f	seed	pending	f	f	f	f	f	f	6	medium	{"contains keyword 'abc'","shares IP with known asset"}	\N	\N	\N
228	sc0031.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
18	abc.app	1	3	f	seed	pending	f	f	f	f	f	f	6	medium	{"contains keyword 'abc'","shares IP with known asset"}	\N	\N	\N
19	abc.cloud	1	3	f	seed	pending	f	f	f	f	f	f	6	medium	{"contains keyword 'abc'","shares IP with known asset"}	\N	\N	\N
141	get-abc.com	1	3	f	seed	pending	f	f	f	f	f	f	6	medium	{"contains keyword 'abc'","shares IP with known asset"}	\N	\N	\N
40	api.partners.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	2026-04-27 21:28:07.696169
54	autolink.net.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
55	bachelor.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
76	ch0330.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
77	ch0331.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
229	sc0325.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
230	sc0328.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
78	ch1117.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
231	sc03281.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
232	sc03282.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
233	sc0330.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
234	scalari6k.mit.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
237	secure.cdn.media.oscar.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
240	server.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
241	server1.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
242	sfgdsg65xcv.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
324	xkm-emg-qautlnk.net.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
325	xvl-mit-trnsfr2.mit.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
236	secure-abc.com	1	3	f	seed	pending	f	f	f	f	f	f	6	medium	{"contains keyword 'abc'","shares IP with known asset"}	\N	\N	\N
238	secureabc.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"contains keyword 'abc'"}	\N	\N	\N
80	cpanel.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
95	developer.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
96	devemx.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
97	devemx.net.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
310	www.emsoundminerdev.net.abc.com	1	2	f	seed	pending	f	f	f	f	f	\N	0	\N	\N	\N	\N	\N
311	www.emvault.net.abc.com	1	2	f	seed	pending	f	f	f	f	f	\N	0	\N	\N	\N	\N	\N
312	www.faspex.mit.abc.com	1	2	f	seed	pending	f	f	f	f	f	\N	0	\N	\N	\N	\N	\N
98	dmedia.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
99	doctorodysseysweepstakes.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
101	dtcipr-qapw01.net.abc.com	1	2	f	seed	pending	f	f	f	f	f	\N	0	\N	\N	\N	\N	\N
103	dwtsvote-live-test.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
173	m.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
253	stage.cd.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	2026-04-27 21:30:21.830852
213	prod.cd.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	2026-04-27 21:30:21.830852
66	cd.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	2026-04-27 21:30:21.830852
88	dev.cd.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	2026-04-27 21:30:21.830852
216	qa.cd.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	2026-04-27 21:30:21.830852
289	vdigate5qa.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
290	vdigate6.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
208	onceuponatime.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
215	qa.api.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
107	eitsrv04.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
218	r1.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
155	int.integration.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
156	jimmykimmellive.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
157	join-abc.com	1	3	t	seed	pending	f	f	f	f	f	f	5	medium	{"contains keyword 'abc'","same ASN/provider"}	\N	\N	\N
158	joinabc.com	1	3	t	seed	pending	f	f	f	f	f	f	3	low	{"contains keyword 'abc'"}	\N	\N	\N
219	r2.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
220	r3.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
221	redirect.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
160	juicy.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
161	katoli.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
162	katoli2.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
171	ll.media.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
172	lostwiki.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
179	mc.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
180	media.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
181	mediapulsepoc2.abc.com	1	3	t	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
185	mi03281.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
186	mi03282.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
195	modernfamily.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1292	fantasy.espn.com.au	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:29:26.039163
198	my-abc.com	1	3	f	seed	pending	f	f	f	f	f	f	5	medium	{"contains keyword 'abc'","same ASN/provider"}	\N	\N	\N
199	myabc.com	1	3	f	seed	pending	f	f	f	f	f	f	5	medium	{"contains keyword 'abc'","same ASN/provider"}	\N	\N	\N
197	mpowr-aprimo.net.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
202	nationalbingonightgame.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
203	netbox.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
207	nyoffair.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1935	ocsinventory.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
457	fantasy.espn.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:29:26.039163
530	mc.twdcmarketing.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:29:26.039163
573	wbdmedmarket01v.swna.wdpr.disney.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:30:21.830852
1156	us-west-2.aws.hosted.watchdisneyfe.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:01.013868
602	tvsupport.nationalgeographic.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:30:59.815242
597	help.marvel.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:30:59.815242
595	support.disney.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:30:59.815242
600	support.starwars.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:30:59.815242
601	tvsupport.fxnetworks.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:30:59.815242
598	help.moviesanywhere.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:30:59.815242
596	appsupport.disney.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:30:59.815242
599	support.freeform.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:30:59.815242
971	www.abc-global.com	1	3	f	seed	pending	f	f	f	f	f	f	6	medium	{"contains keyword 'abc'","shares IP with known asset"}	\N	\N	2026-04-27 21:28:07.696169
12	abc-global.com	1	3	f	seed	pending	f	f	f	f	f	f	5	medium	{"contains keyword 'abc'","same ASN/provider"}	\N	\N	2026-04-27 21:30:59.815242
1291	fantasy.espn.co.uk	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:29:26.039163
258	support.abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	2026-04-27 21:30:59.815242
1770	cpanel.temp.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1295	us-east-1.aws.hosted.espn.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:29:26.039163
1297	geo.hosted.espn.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:29:26.039163
1673	1.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1679	2.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1680	20squid1.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1681	20www.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1682	220-mail.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1683	68-11832.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1686	a.static.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1687	aaaakkd2dd.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1694	abc.abc.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1706	abc212abc.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1715	abdi.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1716	ac.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1717	admin.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1725	app1.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1731	assets.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1738	autodiscover.temp.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1745	bfhc-cs-1.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1753	cc.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1767	chat.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1771	cpanel.test.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1773	cpcalendars.temp.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1775	cpcontacts.temp.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1777	de.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1792	discourse.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1796	downloads.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1820	eve-ng.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1822	farzin.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1831	firepower-bcul.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1842	gis.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1843	gismap.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1847	gps.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1849	hcp.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1854	host.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1858	imap.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1859	initebs.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1862	inttst.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1863	ipam.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1864	istore.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1870	juniper.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1871	k8s-pipelines-tpl-develop.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1875	kubernetes.default.svc.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1883	lab.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1884	latency.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
984	us-east-1.aws.hosted.watchdisneyfe.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:01.013868
343	fftvfe.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:01.013868
335	blackishtv.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:01.013868
1886	ll.static.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1889	m.hsm.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1890	mail.a.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1892	mail.temp.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1893	mail.test.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1916	moren.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1918	mx.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1923	myservice.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1925	net.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1929	ngrok.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1930	ngrok2.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1931	nodelete.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
1934	oc.abc.com	2	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	\N
998	geo.hosted.watchdisneyfe.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:01.013868
996	cdn.watchdisneyfe.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:01.013868
328	watchdisneyfe.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:01.013868
340	disneynow.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:01.013868
336	freeform.go.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:01.013868
21	abc.com	1	3	f	seed	pending	f	f	f	f	f	t	0	\N	\N	\N	\N	2026-04-27 21:32:01.013868
339	abc.go.com	1	3	f	seed	pending	f	f	f	f	f	f	6	medium	{"contains keyword 'abc'","shares IP with known asset"}	\N	\N	2026-04-27 21:32:01.013868
337	marvelfe.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:01.013868
331	fxnow.fxnetworks.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:01.013868
345	ngtvfe.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:01.013868
344	abc-studios.com	1	3	f	seed	pending	f	f	f	f	f	f	6	medium	{"contains keyword 'abc'","shares IP with known asset"}	\N	\N	2026-04-27 21:32:01.013868
332	abcstudios.go.com	1	3	f	seed	pending	f	f	f	f	f	f	6	medium	{"contains keyword 'abc'","shares IP with known asset"}	\N	\N	2026-04-27 21:32:01.013868
329	freeform.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:01.013868
342	disneynow.go.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:01.013868
1009	showms.freeform.go.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:01.013868
338	marvel.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:01.013868
334	latamtvfe.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:01.013868
333	fxtvfe.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:01.013868
330	oscar.go.com	1	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:01.013868
4613	fan.core.api.espn.com.br	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4574	api.espn.com.co	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4604	fan.api.espn.co.cr	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4559	api.espn.com.do	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4612	fan.core.api.espn.ph	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4611	fan.core.api.espn.com.sg	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4543	api.espn.es	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4519	fan.api.espn.com.ve	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4531	fan.api.espn.com.sg	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4518	api.espn.com.ar	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4571	api.espn.com.br	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4556	api.espn.com.pa	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4606	espn.nl	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4520	fan.api.espn.com.ec	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4573	fan.api.espn.nl	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4545	fan.core.api.espn.com.mx	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4594	api.espn.com.uy	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4538	fan.core.api.espn.com.ar	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4598	fan.core.api.espn.com.ec	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4523	espn.ph	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4536	espn.com.uy	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4526	espn.in	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4557	fan.core.api.espn.com.ve	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4540	espn.com.do	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4546	fan.core.api.espn.com.au	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
4539	api.espn.co.uk	3	3	f	seed	pending	f	f	f	f	f	f	3	low	{"shares IP with known asset"}	\N	\N	2026-04-27 21:32:57.373765
\.


--
-- Data for Name: known_domains; Type: TABLE DATA; Schema: public; Owner: asm
--

COPY public.known_domains (id, domain, source, added_at) FROM stdin;
1	0327.abc.com	\N	2026-04-13 14:26:12.14647
2	0706.abc.com	\N	2026-04-13 14:26:12.14647
3	10gserver.abc.com	\N	2026-04-13 14:26:12.14647
4	1121.abc.com	\N	2026-04-13 14:26:12.14647
5	1127.abc.com	\N	2026-04-13 14:26:12.14647
6	1at0325.abc.com	\N	2026-04-13 14:26:12.14647
7	1mi0325.abc.com	\N	2026-04-13 14:26:12.14647
8	606166e16abc.com	\N	2026-04-13 14:26:12.14647
9	a.abc.com	\N	2026-04-13 14:26:12.14647
10	a.oscar.abc.com	\N	2026-04-13 14:26:12.14647
11	filemaker03.net.abc.com	\N	2026-04-13 14:26:12.14647
12	fonts.abc.com	\N	2026-04-13 14:26:12.14647
13	fr0330.abc.com	\N	2026-04-13 14:26:12.14647
14	fr0331.abc.com	\N	2026-04-13 14:26:12.14647
15	ftp1.abc.com	\N	2026-04-13 14:26:12.14647
16	ftp3.abc.com	\N	2026-04-13 14:26:12.14647
17	galaxy.abc.com	\N	2026-04-13 14:26:12.14647
18	injustice.abc.com	\N	2026-04-13 14:26:12.14647
19	int.integration.abc.com	\N	2026-04-13 14:26:12.14647
20	jimmykimmellive.abc.com	\N	2026-04-13 14:26:12.14647
21	join-abc.com	\N	2026-04-13 14:26:12.14647
22	joinabc.com	\N	2026-04-13 14:26:12.14647
23	jss.net.abc.com	\N	2026-04-13 14:26:12.14647
24	juicy.abc.com	\N	2026-04-13 14:26:12.14647
25	katoli.abc.com	\N	2026-04-13 14:26:12.14647
26	katoli2.abc.com	\N	2026-04-13 14:26:12.14647
27	khanjari.abc.com	\N	2026-04-13 14:26:12.14647
28	la0325.abc.com	\N	2026-04-13 14:26:12.14647
29	la0328.abc.com	\N	2026-04-13 14:26:12.14647
30	la03281.abc.com	\N	2026-04-13 14:26:12.14647
31	la0330.abc.com	\N	2026-04-13 14:26:12.14647
32	la0331.abc.com	\N	2026-04-13 14:26:12.14647
33	la1115.abc.com	\N	2026-04-13 14:26:12.14647
34	la1117.abc.com	\N	2026-04-13 14:26:12.14647
35	ll.media.abc.com	\N	2026-04-13 14:26:12.14647
36	lostwiki.abc.com	\N	2026-04-13 14:26:12.14647
37	m.abc.com	\N	2026-04-13 14:26:12.14647
38	mail.abc.com	\N	2026-04-13 14:26:12.14647
39	mailxi.abc.com	\N	2026-04-13 14:26:12.14647
40	manage.splunk.mit.abc.com	\N	2026-04-13 14:26:12.14647
41	marketingops.net.abc.com	\N	2026-04-13 14:26:12.14647
42	mc-aprimo.net.abc.com	\N	2026-04-13 14:26:12.14647
43	mc.abc.com	\N	2026-04-13 14:26:12.14647
44	media.abc.com	\N	2026-04-13 14:26:12.14647
45	mediapulsepoc2.abc.com	\N	2026-04-13 14:26:12.14647
46	mediascreening.net.abc.com	\N	2026-04-13 14:26:12.14647
47	mi0325.abc.com	\N	2026-04-13 14:26:12.14647
48	mi0328.abc.com	\N	2026-04-13 14:26:12.14647
49	vcip.abc--abc.com	\N	2026-04-13 14:26:12.14647
50	vdigate.abc.com	\N	2026-04-13 14:26:12.14647
51	vdigate1.abc.com	\N	2026-04-13 14:26:12.14647
52	www.secure.cdn.media.oscar.abc.com	\N	2026-04-13 14:26:12.14647
53	www.solarwinds.mit.abc.com	\N	2026-04-13 14:26:12.14647
54	www.test.abc.com	\N	2026-04-13 14:26:12.14647
55	www.vdigate.abc.com	\N	2026-04-13 14:26:12.14647
56	www.xvl-mit-trnsfr2.mit.abc.com	\N	2026-04-13 14:26:12.14647
57	xkm-emg-pautlnk.net.abc.com	\N	2026-04-13 14:26:12.14647
58	xkm-emg-qautlnk.net.abc.com	\N	2026-04-13 14:26:12.14647
59	xvl-mit-trnsfr2.mit.abc.com	\N	2026-04-13 14:26:12.14647
60	zy.abc--abc.com	\N	2026-04-13 14:26:12.14647
\.


--
-- Data for Name: scan_results; Type: TABLE DATA; Schema: public; Owner: asm
--

COPY public.scan_results (scan_id, domain_id, seed) FROM stdin;
1	1	abc.com
1	2	abc.com
1	3	abc.com
1	4	abc.com
1	5	abc.com
1	6	abc.com
1	7	abc.com
1	8	abc.com
1	9	abc.com
1	10	abc.com
1	11	abc.com
1	12	abc.com
1	13	abc.com
1	14	abc.com
1	15	abc.com
1	16	abc.com
1	17	abc.com
1	18	abc.com
1	19	abc.com
1	20	abc.com
1	21	abc.com
1	22	abc.com
1	23	abc.com
1	24	abc.com
1	25	abc.com
1	26	abc.com
1	27	abc.com
1	28	abc.com
1	29	abc.com
1	30	abc.com
1	31	abc.com
1	32	abc.com
1	33	abc.com
1	34	abc.com
1	35	abc.com
1	36	abc.com
1	37	abc.com
1	38	abc.com
1	39	abc.com
1	40	abc.com
1	41	abc.com
1	42	abc.com
1	43	abc.com
1	44	abc.com
1	45	abc.com
1	46	abc.com
1	47	abc.com
1	48	abc.com
1	49	abc.com
1	50	abc.com
1	51	abc.com
1	52	abc.com
1	53	abc.com
1	54	abc.com
1	55	abc.com
1	56	abc.com
1	57	abc.com
1	58	abc.com
1	59	abc.com
1	60	abc.com
1	61	abc.com
1	62	abc.com
1	63	abc.com
1	64	abc.com
1	65	abc.com
1	66	abc.com
1	67	abc.com
1	68	abc.com
1	69	abc.com
1	70	abc.com
1	71	abc.com
1	72	abc.com
1	73	abc.com
1	74	abc.com
1	75	abc.com
1	76	abc.com
1	77	abc.com
1	78	abc.com
1	79	abc.com
1	80	abc.com
1	81	abc.com
1	82	abc.com
1	83	abc.com
1	84	abc.com
1	85	abc.com
1	86	abc.com
1	87	abc.com
1	88	abc.com
1	89	abc.com
1	90	abc.com
1	91	abc.com
1	92	abc.com
1	93	abc.com
1	94	abc.com
1	95	abc.com
1	96	abc.com
1	97	abc.com
1	98	abc.com
1	99	abc.com
1	100	abc.com
1	101	abc.com
1	102	abc.com
1	103	abc.com
1	104	abc.com
1	105	abc.com
1	106	abc.com
1	107	abc.com
1	108	abc.com
1	109	abc.com
1	110	abc.com
1	111	abc.com
1	112	abc.com
1	113	abc.com
1	114	abc.com
1	115	abc.com
1	116	abc.com
1	117	abc.com
1	118	abc.com
1	119	abc.com
1	120	abc.com
1	121	abc.com
1	122	abc.com
1	123	abc.com
1	124	abc.com
1	125	abc.com
1	126	abc.com
1	127	abc.com
1	128	abc.com
1	129	abc.com
1	130	abc.com
1	131	abc.com
1	132	abc.com
1	133	abc.com
1	134	abc.com
1	135	abc.com
1	136	abc.com
1	137	abc.com
1	138	abc.com
1	139	abc.com
1	140	abc.com
1	141	abc.com
1	142	abc.com
1	143	abc.com
1	144	abc.com
1	145	abc.com
1	146	abc.com
1	147	abc.com
1	148	abc.com
1	149	abc.com
1	150	abc.com
1	151	abc.com
1	152	abc.com
1	153	abc.com
1	154	abc.com
1	155	abc.com
1	156	abc.com
1	157	abc.com
1	158	abc.com
1	159	abc.com
1	160	abc.com
1	161	abc.com
1	162	abc.com
1	163	abc.com
1	164	abc.com
1	165	abc.com
1	166	abc.com
1	167	abc.com
1	168	abc.com
1	169	abc.com
1	170	abc.com
1	171	abc.com
1	172	abc.com
1	173	abc.com
1	174	abc.com
1	175	abc.com
1	176	abc.com
1	177	abc.com
1	178	abc.com
1	179	abc.com
1	180	abc.com
1	181	abc.com
1	182	abc.com
1	183	abc.com
1	184	abc.com
1	185	abc.com
1	186	abc.com
1	187	abc.com
1	188	abc.com
1	189	abc.com
1	190	abc.com
1	191	abc.com
1	192	abc.com
1	193	abc.com
1	194	abc.com
1	195	abc.com
1	196	abc.com
1	197	abc.com
1	198	abc.com
1	199	abc.com
1	200	abc.com
1	201	abc.com
1	202	abc.com
1	203	abc.com
1	204	abc.com
1	205	abc.com
1	206	abc.com
1	207	abc.com
1	208	abc.com
1	209	abc.com
1	210	abc.com
1	211	abc.com
1	212	abc.com
1	213	abc.com
1	214	abc.com
1	215	abc.com
1	216	abc.com
1	217	abc.com
1	218	abc.com
1	219	abc.com
1	220	abc.com
1	221	abc.com
1	222	abc.com
1	223	abc.com
1	224	abc.com
1	225	abc.com
1	226	abc.com
1	227	abc.com
1	228	abc.com
1	229	abc.com
1	230	abc.com
1	231	abc.com
1	232	abc.com
1	233	abc.com
1	234	abc.com
1	235	abc.com
1	236	abc.com
1	237	abc.com
1	238	abc.com
1	239	abc.com
1	240	abc.com
1	241	abc.com
1	242	abc.com
1	243	abc.com
1	244	abc.com
1	245	abc.com
1	246	abc.com
1	247	abc.com
1	248	abc.com
1	249	abc.com
1	250	abc.com
1	251	abc.com
1	252	abc.com
1	253	abc.com
1	254	abc.com
1	255	abc.com
1	256	abc.com
1	257	abc.com
1	258	abc.com
1	259	abc.com
1	260	abc.com
1	261	abc.com
1	262	abc.com
1	263	abc.com
1	264	abc.com
1	265	abc.com
1	266	abc.com
1	267	abc.com
1	268	abc.com
1	269	abc.com
1	270	abc.com
1	271	abc.com
1	272	abc.com
1	273	abc.com
1	274	abc.com
1	275	abc.com
1	276	abc.com
1	277	abc.com
1	278	abc.com
1	279	abc.com
1	280	abc.com
1	281	abc.com
1	282	abc.com
1	283	abc.com
1	284	abc.com
1	285	abc.com
1	286	abc.com
1	287	abc.com
1	288	abc.com
1	289	abc.com
1	290	abc.com
1	291	abc.com
1	292	abc.com
1	293	abc.com
1	294	abc.com
1	295	abc.com
1	296	abc.com
1	297	abc.com
1	298	abc.com
1	299	abc.com
1	300	abc.com
1	301	abc.com
1	302	abc.com
1	303	abc.com
1	304	abc.com
1	305	abc.com
1	306	abc.com
1	307	abc.com
1	308	abc.com
1	309	abc.com
1	310	abc.com
1	311	abc.com
1	312	abc.com
1	313	abc.com
1	314	abc.com
1	315	abc.com
1	316	abc.com
1	317	abc.com
1	318	abc.com
1	319	abc.com
1	320	abc.com
1	321	abc.com
1	322	abc.com
1	323	abc.com
1	324	abc.com
1	325	abc.com
2	1	abc.com
2	2	abc.com
2	1673	abc.com
2	3	abc.com
2	4	abc.com
2	5	abc.com
2	6	abc.com
2	7	abc.com
2	1679	abc.com
2	1680	abc.com
2	1681	abc.com
2	1682	abc.com
2	1683	abc.com
2	8	abc.com
2	9	abc.com
2	1686	abc.com
2	1687	abc.com
2	10	abc.com
2	11	abc.com
2	12	abc.com
2	13	abc.com
2	14	abc.com
2	15	abc.com
2	1694	abc.com
2	16	abc.com
2	17	abc.com
2	18	abc.com
2	19	abc.com
2	20	abc.com
2	21	abc.com
2	22	abc.com
2	23	abc.com
2	24	abc.com
2	25	abc.com
2	26	abc.com
2	1706	abc.com
2	27	abc.com
2	28	abc.com
2	29	abc.com
2	30	abc.com
2	31	abc.com
2	32	abc.com
2	33	abc.com
2	34	abc.com
2	1715	abc.com
2	1716	abc.com
2	1717	abc.com
2	35	abc.com
2	36	abc.com
2	37	abc.com
2	38	abc.com
2	39	abc.com
2	40	abc.com
2	41	abc.com
2	1725	abc.com
2	42	abc.com
2	43	abc.com
2	44	abc.com
2	45	abc.com
2	46	abc.com
2	1731	abc.com
2	47	abc.com
2	48	abc.com
2	49	abc.com
2	50	abc.com
2	51	abc.com
2	52	abc.com
2	1738	abc.com
2	53	abc.com
2	54	abc.com
2	55	abc.com
2	56	abc.com
2	57	abc.com
2	58	abc.com
2	1745	abc.com
2	59	abc.com
2	60	abc.com
2	61	abc.com
2	62	abc.com
2	63	abc.com
2	64	abc.com
2	65	abc.com
2	1753	abc.com
2	66	abc.com
2	67	abc.com
2	68	abc.com
2	69	abc.com
2	70	abc.com
2	71	abc.com
2	72	abc.com
2	73	abc.com
2	74	abc.com
2	75	abc.com
2	76	abc.com
2	77	abc.com
2	78	abc.com
2	1767	abc.com
2	79	abc.com
2	80	abc.com
2	1770	abc.com
2	1771	abc.com
2	81	abc.com
2	1773	abc.com
2	82	abc.com
2	1775	abc.com
2	83	abc.com
2	1777	abc.com
2	84	abc.com
2	85	abc.com
2	86	abc.com
2	87	abc.com
2	88	abc.com
2	89	abc.com
2	90	abc.com
2	91	abc.com
2	92	abc.com
2	93	abc.com
2	94	abc.com
2	95	abc.com
2	96	abc.com
2	97	abc.com
2	1792	abc.com
2	98	abc.com
2	99	abc.com
2	100	abc.com
2	1796	abc.com
2	101	abc.com
2	102	abc.com
2	103	abc.com
2	104	abc.com
2	105	abc.com
2	106	abc.com
2	107	abc.com
2	108	abc.com
2	109	abc.com
2	110	abc.com
2	111	abc.com
2	112	abc.com
2	113	abc.com
2	114	abc.com
2	115	abc.com
2	116	abc.com
2	117	abc.com
2	118	abc.com
2	119	abc.com
2	120	abc.com
2	121	abc.com
2	122	abc.com
2	123	abc.com
2	1820	abc.com
2	124	abc.com
2	1822	abc.com
2	125	abc.com
2	126	abc.com
2	127	abc.com
2	128	abc.com
2	129	abc.com
2	130	abc.com
2	131	abc.com
2	132	abc.com
2	1831	abc.com
2	133	abc.com
2	134	abc.com
2	135	abc.com
2	136	abc.com
2	137	abc.com
2	138	abc.com
2	139	abc.com
2	140	abc.com
2	141	abc.com
2	142	abc.com
2	1842	abc.com
2	1843	abc.com
2	143	abc.com
2	144	abc.com
2	145	abc.com
2	1847	abc.com
2	146	abc.com
2	1849	abc.com
2	147	abc.com
2	148	abc.com
2	149	abc.com
2	150	abc.com
2	1854	abc.com
2	151	abc.com
2	152	abc.com
2	153	abc.com
2	1858	abc.com
2	1859	abc.com
2	154	abc.com
2	155	abc.com
2	1862	abc.com
2	1863	abc.com
2	1864	abc.com
2	156	abc.com
2	157	abc.com
2	158	abc.com
2	159	abc.com
2	160	abc.com
2	1870	abc.com
2	1871	abc.com
2	161	abc.com
2	162	abc.com
2	163	abc.com
2	1875	abc.com
2	164	abc.com
2	165	abc.com
2	166	abc.com
2	167	abc.com
2	168	abc.com
2	169	abc.com
2	170	abc.com
2	1883	abc.com
2	1884	abc.com
2	171	abc.com
2	1886	abc.com
2	172	abc.com
2	173	abc.com
2	1889	abc.com
2	1890	abc.com
2	174	abc.com
2	1892	abc.com
2	1893	abc.com
2	175	abc.com
2	176	abc.com
2	177	abc.com
2	178	abc.com
2	179	abc.com
2	180	abc.com
2	181	abc.com
2	182	abc.com
2	183	abc.com
2	184	abc.com
2	185	abc.com
2	186	abc.com
2	187	abc.com
2	188	abc.com
2	189	abc.com
2	190	abc.com
2	191	abc.com
2	192	abc.com
2	193	abc.com
2	194	abc.com
2	195	abc.com
2	196	abc.com
2	1916	abc.com
2	197	abc.com
2	1918	abc.com
2	198	abc.com
2	199	abc.com
2	200	abc.com
2	201	abc.com
2	1923	abc.com
2	202	abc.com
2	1925	abc.com
2	203	abc.com
2	204	abc.com
2	205	abc.com
2	1929	abc.com
2	1930	abc.com
2	1931	abc.com
2	206	abc.com
2	207	abc.com
2	1934	abc.com
2	1935	abc.com
2	1936	abc.com
2	208	abc.com
2	1938	abc.com
2	209	abc.com
2	1940	abc.com
2	210	abc.com
2	1942	abc.com
2	1943	abc.com
2	211	abc.com
2	212	abc.com
2	213	abc.com
2	214	abc.com
2	1948	abc.com
2	215	abc.com
2	216	abc.com
2	217	abc.com
2	1952	abc.com
2	218	abc.com
2	219	abc.com
2	220	abc.com
2	1956	abc.com
2	221	abc.com
2	222	abc.com
2	223	abc.com
2	1960	abc.com
2	224	abc.com
2	225	abc.com
2	226	abc.com
2	227	abc.com
2	1965	abc.com
2	228	abc.com
2	229	abc.com
2	230	abc.com
2	231	abc.com
2	232	abc.com
2	233	abc.com
2	234	abc.com
2	235	abc.com
2	1974	abc.com
2	236	abc.com
2	237	abc.com
2	238	abc.com
2	239	abc.com
2	240	abc.com
2	241	abc.com
2	1981	abc.com
2	1982	abc.com
2	242	abc.com
2	243	abc.com
2	244	abc.com
2	245	abc.com
2	246	abc.com
2	1988	abc.com
2	1989	abc.com
2	247	abc.com
2	248	abc.com
2	249	abc.com
2	250	abc.com
2	251	abc.com
2	252	abc.com
2	1996	abc.com
2	1997	abc.com
2	1998	abc.com
2	253	abc.com
2	254	abc.com
2	255	abc.com
2	256	abc.com
2	257	abc.com
2	2004	abc.com
2	258	abc.com
2	2006	abc.com
2	259	abc.com
2	260	abc.com
2	261	abc.com
2	2010	abc.com
2	262	abc.com
2	263	abc.com
2	2013	abc.com
2	264	abc.com
2	2015	abc.com
2	2016	abc.com
2	265	abc.com
2	266	abc.com
2	267	abc.com
2	268	abc.com
2	2021	abc.com
2	2022	abc.com
2	269	abc.com
2	270	abc.com
2	271	abc.com
2	272	abc.com
2	273	abc.com
2	274	abc.com
2	275	abc.com
2	276	abc.com
2	277	abc.com
2	278	abc.com
2	2033	abc.com
2	279	abc.com
2	280	abc.com
2	281	abc.com
2	282	abc.com
2	283	abc.com
2	284	abc.com
2	285	abc.com
2	286	abc.com
2	287	abc.com
2	288	abc.com
2	289	abc.com
2	290	abc.com
2	291	abc.com
2	292	abc.com
2	2048	abc.com
2	2049	abc.com
2	293	abc.com
2	2051	abc.com
2	294	abc.com
2	2053	abc.com
2	295	abc.com
2	296	abc.com
2	2056	abc.com
2	2057	abc.com
2	297	abc.com
2	2059	abc.com
2	2060	abc.com
2	2061	abc.com
2	298	abc.com
2	2063	abc.com
2	299	abc.com
2	300	abc.com
2	301	abc.com
2	302	abc.com
2	303	abc.com
2	304	abc.com
2	305	abc.com
2	306	abc.com
2	2072	abc.com
2	307	abc.com
2	308	abc.com
2	309	abc.com
2	310	abc.com
2	311	abc.com
2	312	abc.com
2	313	abc.com
2	314	abc.com
2	315	abc.com
2	316	abc.com
2	317	abc.com
2	318	abc.com
2	319	abc.com
2	2086	abc.com
2	320	abc.com
2	321	abc.com
2	322	abc.com
2	323	abc.com
2	324	abc.com
2	325	abc.com
3	1	abc.com
3	2	abc.com
3	1673	abc.com
3	3	abc.com
3	4	abc.com
3	5	abc.com
3	6	abc.com
3	7	abc.com
3	1679	abc.com
3	1680	abc.com
3	1681	abc.com
3	1682	abc.com
3	1683	abc.com
3	8	abc.com
3	9	abc.com
3	1686	abc.com
3	1687	abc.com
3	10	abc.com
3	11	abc.com
3	12	abc.com
3	13	abc.com
3	14	abc.com
3	15	abc.com
3	1694	abc.com
3	16	abc.com
3	17	abc.com
3	18	abc.com
3	19	abc.com
3	20	abc.com
3	21	abc.com
3	22	abc.com
3	23	abc.com
3	24	abc.com
3	25	abc.com
3	26	abc.com
3	1706	abc.com
3	27	abc.com
3	28	abc.com
3	29	abc.com
3	30	abc.com
3	31	abc.com
3	32	abc.com
3	33	abc.com
3	34	abc.com
3	1715	abc.com
3	1716	abc.com
3	1717	abc.com
3	35	abc.com
3	36	abc.com
3	37	abc.com
3	38	abc.com
3	39	abc.com
3	40	abc.com
3	41	abc.com
3	1725	abc.com
3	42	abc.com
3	43	abc.com
3	44	abc.com
3	45	abc.com
3	46	abc.com
3	1731	abc.com
3	47	abc.com
3	48	abc.com
3	49	abc.com
3	50	abc.com
3	51	abc.com
3	52	abc.com
3	1738	abc.com
3	53	abc.com
3	54	abc.com
3	55	abc.com
3	56	abc.com
3	57	abc.com
3	58	abc.com
3	1745	abc.com
3	59	abc.com
3	60	abc.com
3	61	abc.com
3	62	abc.com
3	63	abc.com
3	64	abc.com
3	65	abc.com
3	1753	abc.com
3	66	abc.com
3	67	abc.com
3	68	abc.com
3	69	abc.com
3	70	abc.com
3	71	abc.com
3	72	abc.com
3	73	abc.com
3	74	abc.com
3	75	abc.com
3	76	abc.com
3	77	abc.com
3	78	abc.com
3	1767	abc.com
3	79	abc.com
3	80	abc.com
3	1770	abc.com
3	1771	abc.com
3	81	abc.com
3	1773	abc.com
3	82	abc.com
3	1775	abc.com
3	83	abc.com
3	1777	abc.com
3	84	abc.com
3	86	abc.com
3	87	abc.com
3	88	abc.com
3	89	abc.com
3	90	abc.com
3	91	abc.com
3	92	abc.com
3	93	abc.com
3	94	abc.com
3	95	abc.com
3	96	abc.com
3	97	abc.com
3	1792	abc.com
3	98	abc.com
3	99	abc.com
3	100	abc.com
3	1796	abc.com
3	102	abc.com
3	103	abc.com
3	104	abc.com
3	105	abc.com
3	106	abc.com
3	107	abc.com
3	108	abc.com
3	109	abc.com
3	110	abc.com
3	111	abc.com
3	112	abc.com
3	113	abc.com
3	114	abc.com
3	115	abc.com
3	116	abc.com
3	117	abc.com
3	118	abc.com
3	119	abc.com
3	120	abc.com
3	121	abc.com
3	122	abc.com
3	123	abc.com
3	1820	abc.com
3	124	abc.com
3	1822	abc.com
3	126	abc.com
3	127	abc.com
3	128	abc.com
3	129	abc.com
3	130	abc.com
3	131	abc.com
3	132	abc.com
3	1831	abc.com
3	133	abc.com
3	134	abc.com
3	135	abc.com
3	136	abc.com
3	137	abc.com
3	138	abc.com
3	139	abc.com
3	140	abc.com
3	141	abc.com
3	142	abc.com
3	1842	abc.com
3	1843	abc.com
3	143	abc.com
3	144	abc.com
3	145	abc.com
3	1847	abc.com
3	146	abc.com
3	1849	abc.com
3	147	abc.com
3	148	abc.com
3	149	abc.com
3	150	abc.com
3	1854	abc.com
3	151	abc.com
3	152	abc.com
3	153	abc.com
3	1858	abc.com
3	1859	abc.com
3	154	abc.com
3	155	abc.com
3	1862	abc.com
3	1863	abc.com
3	1864	abc.com
3	156	abc.com
3	157	abc.com
3	158	abc.com
3	160	abc.com
3	1870	abc.com
3	1871	abc.com
3	161	abc.com
3	162	abc.com
3	163	abc.com
3	1875	abc.com
3	164	abc.com
3	165	abc.com
3	166	abc.com
3	167	abc.com
3	168	abc.com
3	169	abc.com
3	170	abc.com
3	1883	abc.com
3	1884	abc.com
3	171	abc.com
3	1886	abc.com
3	172	abc.com
3	173	abc.com
3	1889	abc.com
3	1890	abc.com
3	174	abc.com
3	1892	abc.com
3	1893	abc.com
3	175	abc.com
3	177	abc.com
3	178	abc.com
3	179	abc.com
3	180	abc.com
3	181	abc.com
3	183	abc.com
3	184	abc.com
3	185	abc.com
3	186	abc.com
3	187	abc.com
3	188	abc.com
3	189	abc.com
3	190	abc.com
3	191	abc.com
3	192	abc.com
3	193	abc.com
3	194	abc.com
3	195	abc.com
3	1916	abc.com
3	197	abc.com
3	1918	abc.com
3	198	abc.com
3	199	abc.com
3	200	abc.com
3	201	abc.com
3	1923	abc.com
3	202	abc.com
3	1925	abc.com
3	203	abc.com
3	204	abc.com
3	205	abc.com
3	1929	abc.com
3	1930	abc.com
3	1931	abc.com
3	206	abc.com
3	207	abc.com
3	1934	abc.com
3	1935	abc.com
3	1936	abc.com
3	208	abc.com
3	1938	abc.com
3	209	abc.com
3	1940	abc.com
3	210	abc.com
3	1942	abc.com
3	1943	abc.com
3	211	abc.com
3	212	abc.com
3	213	abc.com
3	214	abc.com
3	1948	abc.com
3	215	abc.com
3	216	abc.com
3	217	abc.com
3	1952	abc.com
3	218	abc.com
3	219	abc.com
3	220	abc.com
3	1956	abc.com
3	221	abc.com
3	222	abc.com
3	223	abc.com
3	1960	abc.com
3	224	abc.com
3	225	abc.com
3	226	abc.com
3	227	abc.com
3	1965	abc.com
3	228	abc.com
3	229	abc.com
3	230	abc.com
3	231	abc.com
3	232	abc.com
3	233	abc.com
3	234	abc.com
3	235	abc.com
3	1974	abc.com
3	236	abc.com
3	237	abc.com
3	238	abc.com
3	239	abc.com
3	240	abc.com
3	241	abc.com
3	1981	abc.com
3	1982	abc.com
3	242	abc.com
3	243	abc.com
3	244	abc.com
3	245	abc.com
3	246	abc.com
3	1988	abc.com
3	1989	abc.com
3	247	abc.com
3	248	abc.com
3	249	abc.com
3	250	abc.com
3	251	abc.com
3	252	abc.com
3	1996	abc.com
3	1997	abc.com
3	1998	abc.com
3	253	abc.com
3	254	abc.com
3	255	abc.com
3	256	abc.com
3	257	abc.com
3	2004	abc.com
3	258	abc.com
3	2006	abc.com
3	259	abc.com
3	260	abc.com
3	261	abc.com
3	2010	abc.com
3	262	abc.com
3	2013	abc.com
3	264	abc.com
3	2015	abc.com
3	2016	abc.com
3	265	abc.com
3	266	abc.com
3	267	abc.com
3	268	abc.com
3	2021	abc.com
3	2022	abc.com
3	269	abc.com
3	270	abc.com
3	271	abc.com
3	272	abc.com
3	273	abc.com
3	274	abc.com
3	275	abc.com
3	276	abc.com
3	277	abc.com
3	278	abc.com
3	2033	abc.com
3	279	abc.com
3	280	abc.com
3	281	abc.com
3	282	abc.com
3	283	abc.com
3	284	abc.com
3	285	abc.com
3	286	abc.com
3	287	abc.com
3	288	abc.com
3	289	abc.com
3	290	abc.com
3	291	abc.com
3	292	abc.com
3	2048	abc.com
3	2049	abc.com
3	293	abc.com
3	2051	abc.com
3	294	abc.com
3	2053	abc.com
3	295	abc.com
3	296	abc.com
3	2056	abc.com
3	2057	abc.com
3	297	abc.com
3	2059	abc.com
3	2060	abc.com
3	2061	abc.com
3	298	abc.com
3	2063	abc.com
3	299	abc.com
3	303	abc.com
3	305	abc.com
3	306	abc.com
3	2072	abc.com
3	313	abc.com
3	314	abc.com
3	315	abc.com
3	317	abc.com
3	2086	abc.com
3	320	abc.com
3	323	abc.com
3	324	abc.com
3	325	abc.com
\.


--
-- Data for Name: scans; Type: TABLE DATA; Schema: public; Owner: asm
--

COPY public.scans (id, scan_time, seed, started_at, completed_at) FROM stdin;
1	2026-04-13 14:11:47.624194	\N	2026-04-13 14:11:47.624194	2026-04-13 14:31:45.477323
2	2026-04-27 18:22:32.571323	\N	2026-04-27 18:22:32.571323	2026-04-27 18:24:49.471153
3	2026-04-27 18:38:55.447748	\N	2026-04-27 18:38:55.447748	2026-04-27 18:56:31.626452
\.


--
-- Data for Name: seed_domains; Type: TABLE DATA; Schema: public; Owner: asm
--

COPY public.seed_domains (id, domain) FROM stdin;
1	abc.com
\.


--
-- Data for Name: sensitive_ports; Type: TABLE DATA; Schema: public; Owner: asm
--

COPY public.sensitive_ports (port, risk, description) FROM stdin;
22	5	\N
80	5	\N
143	5	\N
443	5	\N
993	5	\N
995	5	\N
21	10	\N
3389	10	\N
3306	9	\N
53	6	\N
110	6	\N
8080	4	\N
\.


--
-- Name: domain_dns_id_seq; Type: SEQUENCE SET; Schema: public; Owner: asm
--

SELECT pg_catalog.setval('public.domain_dns_id_seq', 582, true);


--
-- Name: domain_findings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: asm
--

SELECT pg_catalog.setval('public.domain_findings_id_seq', 1, false);


--
-- Name: domains_id_seq; Type: SEQUENCE SET; Schema: public; Owner: asm
--

SELECT pg_catalog.setval('public.domains_id_seq', 10779, true);


--
-- Name: known_domains_id_seq; Type: SEQUENCE SET; Schema: public; Owner: asm
--

SELECT pg_catalog.setval('public.known_domains_id_seq', 60, true);


--
-- Name: scans_id_seq; Type: SEQUENCE SET; Schema: public; Owner: asm
--

SELECT pg_catalog.setval('public.scans_id_seq', 3, true);


--
-- Name: seed_domains_id_seq; Type: SEQUENCE SET; Schema: public; Owner: asm
--

SELECT pg_catalog.setval('public.seed_domains_id_seq', 1, true);


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
-- PostgreSQL database dump complete
--

\unrestrict 9cyTDUJCNpIRnriRbM3Ygn0OT0EplRuchLgK4qS2SLLLVEAeeKTGVe3u70qWbjd

