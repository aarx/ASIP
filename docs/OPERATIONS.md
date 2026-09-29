# ASIP v0.1.0 Operations Guide

## Status and architecture

ASIP v0.1.0 is an internal alpha. Docker Compose runs PostgreSQL 15, the FastAPI backend/orchestration runtime, the MCP read API, and the React dashboard. The supported scan path is `backend/orchestration.py`; individual workers are not the operator entry point.

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

```bash
# Validate interpolation without printing the resolved configuration
docker compose config --quiet

# Build and start
docker compose build
docker compose up -d
docker compose ps

# Logs
docker compose logs -f backend
docker compose logs -f mcp
docker compose logs -f db

# Rebuild application services after code/dependency changes
docker compose build backend mcp frontend
docker compose up -d --no-deps backend mcp frontend

# Restart without rebuilding
docker compose restart backend mcp frontend

# Stop containers while preserving the PostgreSQL volume
docker compose stop

# Stop and remove containers/network while preserving named volumes
docker compose down
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

The `db` service mounts `backend/asm_schema_post_guardrails-schema-only.sql` into PostgreSQL's `/docker-entrypoint-initdb.d`. PostgreSQL executes it once, and only when `asm_pgdata` is empty. The current schema already includes scan lifecycle, HTTP observation status, and ownership status introduced by migrations 001–003.

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

Migrations 001 and 002 are transactional but not safely re-runnable; migration 003 is guarded. There is no migration-version table in v0.1.0. Inspect the target schema and take a verified backup before applying a pending migration. A fresh current-schema database must **not** run these migrations again.

## Inventory, ownership, and authorization

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
- AI Assistance is interpretive and is not authoritative ASIP evidence.

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

The script reads the database identity from the protected local `.env`, never prints the password, refuses to overwrite an archive, validates the archive with `pg_restore --list`, and prints its SHA-256. Store the archive and checksum outside the repository and preferably outside the ASIP host. Keep `.env` limited to shell-compatible `KEY=VALUE` entries.

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
- AI output is interpretive, non-authoritative, and can be unavailable independently of deterministic ASIP evidence.
- Migration application is manually tracked in v0.1.0.
- The frontend container uses the Create React App development server; place this internal alpha behind an approved internal access boundary.
- Backend Python and external recon-tool dependencies are not fully version-pinned; rebuilds may require controlled compatibility validation.
- The current locked Create React App dependency tree reports known transitive npm vulnerabilities during `npm ci` (including high/critical advisories). Review and explicitly accept this internal-alpha exposure; dependency modernization is deferred rather than applying an unreviewed breaking upgrade in packaging work.
