# ShadowRecon model-free intelligence catalogue

The MCP service is the existing FastAPI tool surface at `/tools/*` (it is not
an MCP-protocol transport). It uses stored ShadowRecon evidence and does not
require Gemma, Ollama, OpenAI, or another inference provider.

| Analyst question | Support | Tool and sample arguments | Scope / limitation |
|---|---|---|---|
| What is our current attack surface? | Fully supported | `GET /tools/summary` | Latest authoritative scan; separates Known, Shadow, Candidate, and External counts. `live_domains` uses IP-present organizational members. |
| Which assets need the most attention? | Partially supported | `GET /tools/high-risk` | Returns up to 20 canonical High-priority organizational risks, scores, and stored scoring reasons; it does not rank every priority or accept a requested limit. |
| Why is this domain prioritized? | Fully supported for stored facts | `GET /tools/domain?domain=app.example`; UI action `GET /v2/assets/app.example/assistant?action=explain_risk` | Current authoritative scan membership only. The assistant endpoint returns deterministic evidence and suppresses organizational risk outside effective Known/Shadow scope. |
| What Shadow assets were discovered? | Partially supported | `GET /tools/shadow-assets` | Returns at most 50 current-scan Shadow assets with IP evidence; it is not a newly-discovered-only query. Candidate assets remain separate in `/tools/priority-targets`. |
| Which sensitive services were observed? | Fully supported for positive evidence | `GET /tools/evidence?category=ports&scan_id=19&page=1&limit=25` | Scan-scoped, Known/Shadow positive port rows only. No rows do not mean all assets were checked and clear. |
| What DNS Security concerns exist? | Fully supported when schema exists | `GET /tools/dns-security?scan_id=19` | Separates eligible/checked/unchecked assets and check-record outcomes. Missing schema is returned as `SCHEMA_UNAVAILABLE`; no rows are not clear. |
| Which certificates require review? | Partially supported | `GET /tools/evidence?category=certificates&scan_id=19&page=1&limit=25` | Returns recorded certificate observations, including stored scan-time days-to-expiry; it does not re-evaluate historical expiry against today's date. |
| Which technologies and versions were identified? | Fully supported for recorded fingerprints | `GET /tools/evidence?category=technologies&scan_id=19&page=1&limit=25` | Includes stored version/confidence/evidence type where present. Missing version is not evidence of safety. |
| Which scan stages failed or were skipped? | Fully supported when diagnostics exist | `GET /tools/scan-health?scan_id=19` | Uses persisted stage diagnostics; overall SUCCEEDED is not equivalent to complete optional-stage coverage. |
| What changed between scans 18 and 19? | Partially supported | `GET /tools/scan-comparison?before_scan_id=18&after_scan_id=19` | Compares retained membership and HTTP/DNS state values. It does not reconstruct historical risk or historical effective classification. |

## Existing Investigate actions

The dashboard currently calls the same backend route with one of these fixed
actions (domain must be a current authoritative scan member):

```text
GET /v2/assets/{domain}/assistant?action=explain_risk
GET /v2/assets/{domain}/assistant?action=investigation_plan
GET /v2/assets/{domain}/assistant?action=summarize_asset
```

Example: `GET /v2/assets/app.example/assistant?action=investigation_plan`.
These now return a concise `response`, structured `context`, `coverage`,
`limitations`, and `next_actions`, with `mode: "model_free"`. The advisory plan
does not launch checks. No inference provider is called by this route.

Ad hoc campaign execution/history is not exposed as an MCP tool. The backend
has a separate campaign API, but there is no MCP registration for it. Free-form
questions, arbitrary SQL, shell execution, and automatic scan requests are
unsupported by design.
