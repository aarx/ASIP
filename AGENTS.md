# ASIP — Codex Operating Guide

## 1. Project Purpose

ASIP is an in-house Attack Surface Management (ASM) capability built primarily to support penetration-testing reconnaissance and broader security use cases.

The platform is intended to:

- Continuously discover internet-facing assets.
- Identify assets that may be unknown, undocumented, or unmanaged.
- Maintain historical observations across scans.
- Enrich discovered assets with security-relevant context.
- Identify sensitive exposure.
- Highlight assets requiring investigation.
- Identify potential takeover and brand-abuse candidates.
- Support validation and reevaluation of findings from other ASM/security platforms.
- Provide a scalable capability that can eventually support multiple security teams.

ASIP is not intended to blindly replace enterprise ASM products. It provides an internally controlled capability that can be customized around our specific reconnaissance, pentesting, enrichment, investigation, and cross-team requirements.


## 2. High-Level Architecture

Conceptually, ASIP follows this pipeline:

Seeds
  -> Passive Discovery
  -> Certificate / CT Expansion
  -> Domain Inventory
  -> DNS Resolution
  -> HTTP Probing
  -> Certificate Enrichment
  -> Port Scanning
  -> Technology Enrichment
  -> ASN / Provider Enrichment
  -> Takeover / Exposure Analysis
  -> Findings
  -> Deterministic Risk Engine
  -> AI-Assisted Analysis
  -> FastAPI
  -> React Dashboard

PostgreSQL stores asset, scan, state, enrichment, and finding information.

Docker is used for major application components.


## 3. Discovery

Discovery mechanisms may include:

- Subfinder
- Assetfinder
- Findomain
- Amass passive mode
- Certificate Transparency sources
- CertSpotter
- Brand/pattern expansion
- Other passive discovery techniques

Discovery sources should remain independently understandable where practical.

Failure of one external discovery source should not unnecessarily prevent other sources from completing.

Do not remove discovery sources or materially change discovery methodology without explicit approval.


## 4. Scan History and Asset State

ASIP is designed around repeated scans, not only a current snapshot.

Important concepts include:

- domains
- scans
- scan_results / scan_domains
- domain_states
- domain_ports
- domain_asn
- domain_provider
- domain_tech
- domain_findings
- sensitive_ports

Historical information is important for capabilities such as:

- first-seen detection
- newly live/dead assets
- disappeared domains
- exposure trends
- state volatility
- risk analysis

Do not destroy or collapse historical state merely to simplify queries.


## 5. Known vs Shadow Assets

A core ASIP use case is comparing discovered internet-facing assets with the organization's known/documented asset inventory.

An asset classified as unknown/shadow/unmanaged is an investigation indicator.

It does NOT automatically mean:

- malicious
- vulnerable
- compromised
- unauthorized

Preserve this distinction in code, UI text, reports, and AI prompts.


## 6. Enrichment

ASIP enriches discovered assets using information such as:

- DNS / IP resolution
- reverse DNS
- HTTP response
- HTTP status
- redirects
- final URL
- TLS/certificate information
- exposed ports
- sensitive ports
- ASN
- hosting/provider information
- cloud association
- web technology
- findings
- takeover-related indicators

Do not convert an enrichment indicator into a confirmed vulnerability without supporting evidence.


## 7. Asset Naming Exposure

ASIP currently identifies potentially interesting naming patterns in domain names.

Current keywords include concepts such as:

- DEV
- TEST
- UAT
- QA
- ADMIN
- MAIL
- TEMP
- STAGE
- STAGING
- SANDBOX
- PREPROD
- NONPROD
- LAB
- DEMO

Broad substring matching is currently intentional.

STAGE and STAGING are intentionally distinguishable.

These are naming/exposure indicators only.

A keyword in a hostname does not prove the actual purpose, sensitivity, ownership, or security state of that asset.


## 8. Deterministic Risk Engine

CRITICAL ARCHITECTURAL PRINCIPLE:

The deterministic ASM engine is the source of truth for risk scores, priorities, and evidence.

Current risk indicators may include:

- newly observed asset
- HTTP exposure
- resolves to IP but no HTTP response
- sensitive ports
- number of exposed ports
- shadow/unmanaged classification
- cloud/provider association
- asset naming exposure
- historical IP-state volatility
- findings
- high-severity findings

Current scoring and priority thresholds are intentional project behavior.

DO NOT modify:

- scoring weights
- priority thresholds
- meaning of risk reasons
- classification semantics

without explicit approval.

If Codex believes the scoring model should change, document the recommendation and supporting reasoning first.


## 9. AI / LLM Architecture

ASIP currently integrates a locally hosted LLM through Ollama.

Gemma is used as an analysis/explanation layer.

The trust boundary is:

ASM observations
  -> deterministic processing
  -> score / priority / reasons
  -> LLM
  -> human-readable explanation

NOT:

LLM
  -> invented security evidence
  -> risk score

AI MUST NOT independently invent or assert:

- vulnerabilities
- domains
- exploitability
- malicious activity
- business criticality
- ownership
- traffic levels
- application purpose
- authentication mechanisms
- business impact
- attack techniques
- risk scores
- priorities

unless that information is explicitly supported by authoritative ASM context supplied to the model.

Sensitive-port detection means only that a configured sensitive port was detected.

Cloud association means only that infrastructure appears associated with a cloud provider.

HTTP exposure means only that HTTP exposure was observed.

Shadow asset means only that the asset is classified as unknown/unmanaged according to ASIP's inventory logic.

AI output must distinguish investigation indicators from confirmed findings.


## 10. MCP / Investigation Guidance

ASIP may use MCP/investigation guidance for supported finding types.

Investigation guidance should help analysts investigate evidence.

It must not silently convert an indicator into a confirmed vulnerability.

Preserve the separation between:

observation
-> investigation
-> validation
-> confirmed finding


## 11. Backend

The backend uses FastAPI.

Before modifying backend behavior:

1. Trace the endpoint.
2. Identify database dependencies.
3. Identify frontend consumers.
4. Identify worker/pipeline dependencies.
5. Consider scan-history implications.
6. Consider AI/LLM implications where relevant.

Do not assume an apparently unused endpoint is safe to delete without checking consumers.


## 12. Frontend

The dashboard uses React.

The frontend presents ASM information but is not the authoritative source for security calculations.

Presentation changes must not silently alter the underlying meaning of:

- risk
- priority
- findings
- known/shadow status
- exposure
- redirects
- asset naming indicators

Prefer readable analyst-oriented presentation while preserving underlying evidence.


## 13. Database

PostgreSQL is a critical component of ASIP.

Do NOT:

- drop tables
- truncate production/project data
- delete historical scans
- rename columns
- change column types
- alter schema
- run destructive migrations

without explicit approval.

Schema recommendations should first be presented as recommendations.

When proposing schema changes, describe:

- reason
- affected tables
- migration requirements
- compatibility impact
- rollback approach


## 14. Secrets and Configuration

Do not hard-code new:

- passwords
- API keys
- tokens
- credentials
- private endpoints

Prefer environment variables and configuration files excluded from Git.

Never print or commit discovered secrets.

If existing secrets are discovered during audit, report their location without unnecessarily reproducing secret values.


## 15. Generated Data

Files containing scan results, exports, temporary output, caches, or generated data must not automatically be treated as source code.

Before committing generated files, determine whether they are intentionally version-controlled.

Do not overwrite or delete collected scan data without explicit approval.


## 16. Development Rules

Before implementing a meaningful change:

1. Understand the relevant code path.
2. Identify affected components.
3. Explain the proposed change.
4. Preserve existing behavior unless the task explicitly changes it.
5. Make the smallest reasonable change.
6. Test the affected behavior.
7. Report what changed and how it was validated.

Avoid broad refactors while fixing a small bug.

Do not rewrite working components simply because a different style is preferred.


## 17. Architectural Changes

Architectural changes require recommendation before implementation.

Examples include:

- splitting backend modules
- replacing FastAPI
- changing database technology
- replacing React
- replacing Ollama/Gemma
- changing worker orchestration
- changing risk architecture
- changing scan-history design
- introducing queues or distributed workers

Codex may recommend such changes during audit but must not implement them without approval.


## 18. Security Audit Expectations

When auditing ASIP, inspect for:

- hard-coded secrets
- injection risks
- unsafe SQL construction
- unsafe subprocess execution
- command injection
- path traversal
- insecure API exposure
- missing input validation
- excessive exception suppression
- insecure defaults
- dependency risks
- unsafe CORS configuration
- LLM prompt injection / trust-boundary problems
- sensitive information leakage
- dangerous Docker configuration
- unnecessary privileges
- destructive database behavior

Separate confirmed vulnerabilities from hardening recommendations.


## 19. Code Quality Audit Expectations

Review for:

- duplicated logic
- dead code
- oversized modules/functions
- inconsistent error handling
- missing timeouts
- poor resource cleanup
- database connection handling
- inconsistent naming
- frontend/backend contract mismatches
- unnecessary repeated queries
- scalability bottlenecks
- weak observability
- missing tests
- generated files accidentally tracked in Git

Do not refactor these automatically during an audit.


## 20. Audit Mode

When explicitly asked to perform an audit:

DO NOT MODIFY THE REPOSITORY unless the user separately authorizes implementation.

Audit workflow:

1. Map repository structure.
2. Understand architecture from actual code.
3. Compare implementation with this document.
4. Inspect backend.
5. Inspect workers/pipeline.
6. Inspect database access/schema.
7. Inspect frontend.
8. Inspect Docker/configuration.
9. Inspect AI/LLM integration.
10. Inspect security controls.
11. Inspect testing and observability.
12. Produce findings.

For every significant finding provide:

- title
- component/file
- evidence
- impact
- severity or importance
- recommendation

Clearly separate:

- confirmed bug/security issue
- architectural concern
- maintainability issue
- performance/scalability concern
- recommendation
- future enhancement

Do not manufacture findings simply to populate an audit report.


## 21. First Principle

When uncertain about ASIP behavior:

READ AND TRACE THE EXISTING IMPLEMENTATION.

Do not guess.

If a proposed change could materially affect security semantics, historical data, risk scoring, discovery coverage, or AI trust boundaries, stop and request approval.
