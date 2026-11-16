# ShadowRecon v0.1.0 Operations Guide

## Status and architecture

ShadowRecon v0.1.0 is an internal alpha. Docker Compose runs PostgreSQL 15, the FastAPI backend/orchestration runtime, the MCP read API, and the React dashboard. The supported scan path is `backend/orchestration.py`; individual workers are not the operator entry point.

Pipeline:

```text
approved seeds
  -> passive discovery / CT and configured brand expansion
  -> scan membership and ownership classification
  -> DNS / HTTP / certificate / authorized ports / technology / provider enrichment
  -> findings and deterministic canonical risk
  -> SUCCEEDED authoritative scan
  -> API / MCP / dashboard / grounded AI explanation
```

## Environment

Copy `.env.example` to `.env`, restrict its permissions, and replace placeholders. Compose reads `.env` automatically.

| Variable | Requirement | Meaning |
| --- | --- | --- |
| `DB_HOST` | Safe default `db` | Compose PostgreSQL service hostname |
| `DB_NAME` | Required | PostgreSQL database; default example is `asm_db` |
| `DB_USER` | Required | PostgreSQL role; v0.1 schema dump expects `asm` |
| `DB_PASSWORD` | Required secret | Set a long random value; no application password fallback exists |
| `LLM_URL` | Optional | Ollama-compatible generate endpoint for AI Assistance |
| `LLM_MODEL` | Optional | Local model identifier; example default is `gemma3:4b` |
| `CERTSPOTTER_API_KEY` | Optional secret | Enables authenticated CertSpotter discovery; empty means skipped |
| `GITHUB_TOKEN` | Optional/reserved secret | Used only by standalone GitHub helper scripts, not current orchestration |
| `CENSYS_API_ID` / `CENSYS_API_SECRET` | Optional/reserved secrets | Loaded by configuration but not used by current orchestration |

Never commit `.env` or paste secret values into issue reports or logs. Credentials that have ever been committed must be revoked/rotated; deleting them only from the current file does not remove Git history.

## Start, stop, and rebuild

The backend image is pinned to an approved committed release and is not built
by Compose. For backend release verification, promotion, or recovery, follow
[Backend release pin](BACKEND_RELEASE.md). A missing pinned image is an
intentional hard failure; do not remove the pin or build from a dirty checkout.

```bash
# Validate interpolation without printing the resolved configuration
docker compose -p asip -f docker-compose.yml config --quiet

# Build only the services that retain Compose build contexts (not the pinned backend)
docker compose -p asip -f docker-compose.yml build mcp frontend

# Start/reconcile using the configured images
docker compose -p asip -f docker-compose.yml up -d
docker compose -p asip -f docker-compose.yml ps

# Logs
docker compose logs -f backend
docker compose logs -f mcp
docker compose logs -f db

# Rebuild MCP/frontend after their code or dependency changes
docker compose -p asip -f docker-compose.yml build mcp frontend
docker compose -p asip -f docker-compose.yml up -d --no-deps mcp frontend

# Restart without rebuilding
docker compose -p asip -f docker-compose.yml restart backend mcp frontend

# Stop containers while preserving the PostgreSQL volume
docker compose -p asip -f docker-compose.yml stop

# Stop and remove containers/network while preserving named volumes
docker compose -p asip -f docker-compose.yml down
```

Never add `--volumes` to `docker compose down` unless intentional database destruction has been separately approved and a verified backup exists.

Local endpoints:

- Dashboard: `http://localhost:3555`
- API: `http://localhost:8555`
- MCP: `http://localhost:8666`

Read-only smoke checks:

```bash
curl -fsS http://localhost:8555/
curl -fsS http://localhost:3555/ >/dev/null
curl -fsS http://localhost:8666/tools/summary
```

## Database bootstrap and migrations

### Fresh empty volume

The `db` service mounts `backend/asm_schema_post_guardrails-schema-only.sql` into PostgreSQL's `/docker-entrypoint-initdb.d`. PostgreSQL executes it once, and only when `asm_pgdata` is empty. The current schema includes scan lifecycle, HTTP observation status, ownership status, and the empty `active_scan_scopes` approval table.

```bash
docker compose up -d db
docker compose logs db
docker compose exec -T db sh -c \
  'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT COUNT(*) AS tables FROM information_schema.tables WHERE table_schema = '\''public'\'';"'
```

The schema-only bootstrap intentionally contains no organizational inventory, seeds, historical scan data, or policy-specific `sensitive_ports` rows. Configure the approved inventory and local sensitive-port policy before relying on those views/signals. Do not use the tracked full historical dump as a fresh-install initializer.

### Existing database

Historical migrations live in `backend/migrations` and must be applied in numeric order to an older database only when absent:

1. `001_add_scan_lifecycle.sql`
2. `002_add_http_observation_status.sql`
3. `003_add_ownership_status.sql`

Migrations 001 and 002 are transactional but not safely re-runnable; migration 003 is guarded. The legacy sequential procedure has no migration-version table. Inspect the target schema and take a verified backup before applying a pending migration. A fresh current-schema database must **not** run these migrations again.

### Explicitly approved optional migrations

Some feature migrations are intentionally optional and may be applied out of numeric order only when the change owner has explicitly approved that migration. The supported optional path is deliberately narrow: `backend/optional_migrations.py` allowlists `015_add_capd_runs`, `016_add_capd_http_header_verify_operation`, `017_add_capd_approval_consumptions`, `018_add_brand_redirect_observations`, `019_add_brand_redirect_scope_level`, and `020_add_brand_redirect_campaign_policy`. Migration 014 (Findings Lifecycle) is not optional through this command and must remain unapplied for the CAPD release. Migration 016 requires the existing `active_scan_scopes.active_scan_scopes_testing_level` constraint and independently checks whether that constraint already permits `CAPD_HTTP_HEADER_VERIFY`. Migration 017 depends only on the existing `scans` and `domains` tables; it does not depend on 014, 015, or 016. Migration 018 adds only the isolated Brand Redirect Intelligence evidence table and references existing scans, domains, and scan membership. Migration 019 adds one operation-specific value to the existing scan-scope constraint without changing stored scope rows or other operation permissions. Migration 020 adds required campaign purpose, eligible discovery-source, and request-budget fields for Brand Redirect scopes and a request-budget termination state. For a CAPD Apache verification release, review and apply 016 before 017 so the operation permission exists before the single-use approval receipt table is used.

The optional-migration ledger (`public.asip_optional_migration_ledger`) records only migrations applied by this mechanism. It records the stable migration ID, source filename, SHA-256 of the exact SQL file bytes, and PostgreSQL application timestamp. It does not backfill or claim that earlier migrations were applied through this runner. SQL and its receipt are committed in the same PostgreSQL transaction; an error rolls back both. An advisory transaction lock serializes concurrent optional-migration attempts.

The runner is part of the backend release. After that release is available, invoke it inside the Compose backend container so it uses the service's existing database configuration; do not copy credentials into a host shell. Before an approved production change, review a read-only plan against the intended database and verify the source revision and backup:

```bash
docker compose -p asip exec -T backend \
  python3 /app/optional_migrations.py plan --migration 015_add_capd_runs
```

The plan prints the migration ID, filename, checksum, pending/applied state, and whether that migration's expected schema state or the ledger already exist. It does not create the ledger. For 016, the expected schema state is the presence of the operation in the named constraint; the runner refuses to proceed if the table/constraint is absent or if that state exists without a matching receipt. Stop if the checksum differs from a prior receipt, if expected schema state exists without a receipt, if the migration is already applied, or if the result is otherwise unexpected. Migration 016 can be reviewed with:

```bash
docker compose -p asip exec -T backend \
  python3 /app/optional_migrations.py plan --migration 016_add_capd_http_header_verify_operation
```

Migration 017 can be reviewed with:

```bash
docker compose -p asip exec -T backend \
  python3 /app/optional_migrations.py plan --migration 017_add_capd_approval_consumptions
```

Migration 018 can be reviewed with:

```bash
docker compose -p asip exec -T backend \
  python3 /app/optional_migrations.py plan --migration 018_add_brand_redirect_observations
```

Migration 019 can be reviewed with:

```bash
docker compose -p asip exec -T backend \
  python3 /app/optional_migrations.py plan --migration 019_add_brand_redirect_scope_level
```

Review the exact SQL and obtain explicit change approval before applying:

```bash
docker compose -p asip exec -T backend \
  python3 /app/optional_migrations.py apply --migration 015_add_capd_runs \
    --approve-sha256 <sha256-from-reviewed-plan>
```

For migration 016, use its exact reviewed checksum and stable ID in the same command. Apply it before 017 for the Apache verification release:

```bash
docker compose -p asip exec -T backend \
  python3 /app/optional_migrations.py apply --migration 016_add_capd_http_header_verify_operation \
    --approve-sha256 <sha256-from-reviewed-plan>
```

For migration 017, use its exact reviewed checksum and stable ID in the same command:

```bash
docker compose -p asip exec -T backend \
  python3 /app/optional_migrations.py apply --migration 017_add_capd_approval_consumptions \
    --approve-sha256 <sha256-from-reviewed-plan>
```

For migration 018, obtain explicit database-change approval, review its plan and SQL, then apply its exact plan checksum:

```bash
docker compose -p asip exec -T backend \
  python3 /app/optional_migrations.py apply --migration 018_add_brand_redirect_observations \
    --approve-sha256 <sha256-from-reviewed-plan>
```

For migration 019, obtain explicit database-change approval and apply the exact checksum from its read-only plan:

```bash
docker compose -p asip exec -T backend \
  python3 /app/optional_migrations.py apply --migration 019_add_brand_redirect_scope_level \
    --approve-sha256 <sha256-from-reviewed-plan>
```

The exact checksum from the reviewed plan is required as the approval token; if the SQL changes between review and application, the command stops. Only IDs compiled into the optional allowlist are accepted. The runner refuses duplicate application, validates a recorded checksum, and rejects untracked pre-existing objects belonging to the selected migration. Never use this command to apply migration 014 or to write synthetic receipts for legacy migrations.

After application, retain the printed receipt with the deployment record and independently verify the ledger checksum/timestamp and expected tables. If execution fails, PostgreSQL rolls back the schema changes and receipt together. Confirm that neither CAPD tables nor a receipt were left behind, correct the cause, rerun the read-only plan, and repeat the approval process. Do not manually edit/delete ledger rows or partially created schema. If a connection is lost during commit and outcome is uncertain, query the ledger and schema read-only before retrying; matching receipt means applied, no receipt and no CAPD objects means the transaction rolled back, and any other state requires operator investigation.

## Inventory, ownership, and authorization

### Brand Redirect Intelligence

Regular orchestration includes `BRAND_REDIRECT_OBSERVATION` in the Compose operation allowlist. The operation is a deployment-level authorization for one bounded monitoring behavior; it does not create or imply permission for Nmap, general HTTP/TLS assessment, technology detection, vulnerability checks, or other active operations. The dedicated worker does not use generic known/scannable-host authorization.

Selection is limited to current-scan `CANDIDATE` members with a `domain_sources` record for `brand_tld` or `brand_pattern` and a non-empty discovery seed. This recorded provenance ties each candidate to a discovery input actually used in that scan, supports lookalikes outside the input seed's DNS suffix, and excludes unrelated inventory candidates. Database `seed_domains` remain ownership/relationship references and are not discovery inputs. Manually rejected candidates and active legacy Brand Redirect exclusions are denied. No campaign row, expiry, individual candidate list, or per-organization activation command is required. Legacy campaign records and migrations remain supported; their active exclusions continue to act as deny rules.

The observer follows HTTP/HTTPS redirects across public hostnames only after rechecking the deployment operation, the running scan, candidate membership/provenance, exclusions, and manual rejection before each request. It uses GET, no automatic retries, maximum three followed redirects, two global workers, one request per host, five-second connection timeout, ten-second overall deadline, and a 2,000-request per-scan budget. It rejects private/special-use addresses, pins validated DNS resolutions, restricts schemes and standard web ports, disables proxy and automatic-redirect behavior, and records out-of-policy Location values without following them. JavaScript, forms, authentication, exploitation, and access-control bypasses are not used. Redirect destinations do not need ownership classification or their own Candidate approval.

Compose mounts migrations 018–020 into PostgreSQL's normal `/docker-entrypoint-initdb.d` initialization sequence after the schema-only baseline, so a fresh database applies them in order during standard initialization. Existing volumes are not reset and init scripts do not rerun on populated databases. For an existing database missing these objects, apply 018–020 using the documented optional migration runner as part of the ordinary database migration procedure; no campaign-activation migration or data rewrite is needed. Existing scope rows and redirect evidence are preserved.

`backend/seeds.txt` contains approved discovery roots. It is mounted read-only into the backend container, so edits are visible to the next orchestration run without rebuilding.

`backend/data/known_domains.csv` is the documented inventory input. Load it with:

```bash
docker compose exec backend python load_known_domains.py
```

Ownership states:

- `CONFIRMED`: ownership has been established.
- `CANDIDATE`: relationship is possible but ownership is unconfirmed.
- `EXTERNAL`: explicitly not treated as organizational.

Asset classes:

- **Known** = `CONFIRMED` and present in documented known inventory.
- **Shadow** = `CONFIRMED` and absent from documented known inventory.
- Candidate and External are neither Known nor Shadow and receive no organizational canonical risk.

Boundaries:

- Discovery does not prove ownership.
- Ownership confirmation does not grant active scanning.
- A redirect destination inherits neither ownership nor active-testing authorization.
- A Review Indicator is evidence for analyst context, not automatically a finding, vulnerability, compromise, or malicious condition.
- AI Assistance is interpretive and is not authoritative ShadowRecon evidence.

T2 active scanning requires all of the existing independent conditions: the asset is `CONFIRMED`, `scannable IS TRUE`, and `validation_source = 'manual'`. Manual approval/rejection is processed by `validation_ingest.py`; ownership review alone never satisfies this gate. Use a separately controlled CSV with columns `domain,validation_status` (`approved` or `rejected`), copy it temporarily into the container, and remove it after processing:

```bash
docker compose cp /secure/operator/asip-validation.csv backend:/tmp/asip-validation.csv
docker compose exec backend python validation_ingest.py /tmp/asip-validation.csv
docker compose exec backend rm /tmp/asip-validation.csv
```

Treat this as a security-sensitive analyst action. Do not approve assets merely to obtain enrichment.

## Run and monitor an orchestration cycle

Start the supported pipeline from the repository root:

```bash
docker compose exec backend python -u orchestration.py
```

The backend image contains passive discovery tools and nmap. Discovery and ordinary observation remain distinct from active T2 scanning; the port worker's explicit authorization predicate remains authoritative.

Follow output:

```bash
docker compose logs -f backend
ls -lt backend/logs/ | head
```

Check lifecycle state without changing data:

```bash
docker compose exec -T db sh -c \
  'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "SELECT id,status,started_at,completed_at FROM scans ORDER BY id DESC LIMIT 10;"'
```

Only `SUCCEEDED` scans are authoritative. `RUNNING`, `FAILED`, and legacy `UNKNOWN` scans never replace the latest successful current state. Comparisons use the preceding `SUCCEEDED` scan, not `scan_id - 1`.

## Backup

Create and verify a timestamped custom-format archive:

```bash
./scripts/backup-db.sh
# Optional explicit non-existing target:
./scripts/backup-db.sh /secure/backups/asip-before-upgrade.dump
```

The script reads the database identity from the protected local `.env`, never prints the password, refuses to overwrite an archive, validates the archive with `pg_restore --list`, and prints its SHA-256. Store the archive and checksum outside the repository and preferably outside the ShadowRecon host. Keep `.env` limited to shell-compatible `KEY=VALUE` entries.

## Restore

`pg_restore` expects an empty target database for a clean, predictable restore. Never restore over the active database without explicit approval, downtime, and a fresh verified backup.

Safe restore test into a disposable database in the existing PostgreSQL container:

```bash
docker compose exec -T db sh -c \
  'dropdb --if-exists -U "$POSTGRES_USER" asip_restore_test && createdb -U "$POSTGRES_USER" asip_restore_test'
cat /secure/backups/asip.dump | docker compose exec -T db sh -c \
  'pg_restore --exit-on-error --no-owner -U "$POSTGRES_USER" -d asip_restore_test'
docker compose exec -T db sh -c \
  'psql -U "$POSTGRES_USER" -d asip_restore_test -c "SELECT COUNT(*) FROM scans;"'
# After verification, explicitly remove only the disposable database:
docker compose exec -T db sh -c \
  'dropdb -U "$POSTGRES_USER" asip_restore_test'
```

For operational recovery, stop `backend` and `mcp`, restore into a newly created empty database, verify it, update `DB_NAME`, then restart the services. This preserves the old database for rollback. In-place drop/recreate is intentionally not automated.

## Troubleshooting

- **Compose reports a missing DB variable:** copy `.env.example` to `.env` and set all required database values. The schema bootstrap expects `DB_USER=asm`.
- **Backend starts before PostgreSQL:** the database healthcheck gates backend and MCP startup; inspect `docker compose logs db` if they remain pending.
- **No current data:** verify at least one scan is `SUCCEEDED`; failed/running scans are not current authority.
- **Another orchestration is running:** the database advisory lock permits only one pipeline. Wait for or investigate the current operator-owned run.
- **No CertSpotter results:** an empty key intentionally marks the source skipped. Other discovery sources continue independently.
- **AI Assistance unavailable:** verify `LLM_URL` from inside the backend container. Deterministic evidence, score, and priority are unaffected.
- **No sensitive-port indicators on a fresh database:** the schema-only bootstrap does not invent organizational policy. Populate `sensitive_ports` from an approved configuration or restore a verified operational backup.
- **Permission errors in `backend/data` or `backend/logs`:** ensure the Docker daemon can write the bind-mounted directories; do not replace or delete runtime evidence as a shortcut.

## Known v0.1.0 limitations

- Redirect chains are not fully persisted; current UI evidence is primarily the final destination/status.
- Brand Perimeter and ownership review depend on discovery producing Candidate/External assets.
- Historical detail for disappeared assets is limited.
- Some delta and indicator views intentionally use bounded result sets.
- Analyst attribution, authentication, and RBAC are not implemented.
- Production security hardening, network isolation, TLS termination, and secret management remain future work.
- Some richer HTTP/DNS negative-evidence semantics remain maturity work; missing/failed evidence must not be read as a negative observation.
- AI output is interpretive, non-authoritative, and can be unavailable independently of deterministic ShadowRecon evidence.
- Migration application is manually tracked in v0.1.0.
- The frontend container uses the Create React App development server; place this internal alpha behind an approved internal access boundary.
- Backend Python and external recon-tool dependencies are not fully version-pinned; rebuilds may require controlled compatibility validation.
- The current locked Create React App dependency tree reports known transitive npm vulnerabilities during `npm ci` (including high/critical advisories). Review and explicitly accept this internal-alpha exposure; dependency modernization is deferred rather than applying an unreviewed breaking upgrade in packaging work.
