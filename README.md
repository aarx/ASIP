# ShadowRecon v0.1.0 — Internal Alpha

ShadowRecon is an internally controlled Attack Surface Management capability for repeated passive discovery, evidence enrichment, deterministic risk prioritization, ownership review, change intelligence, and analyst investigation.

This release is an **internal alpha**. It is not internet-hardened or production-ready. Run it only in an approved internal environment and authorize active scanning explicitly.

## Services

| Service | Compose name | Local URL | Purpose |
| --- | --- | --- | --- |
| Dashboard | `frontend` | <http://localhost:3555> | ShadowRecon analyst interface |
| API | `backend` | <http://localhost:8555> | FastAPI application and orchestration runtime |
| MCP | `mcp` | <http://localhost:8666> | Read-only investigation/tool endpoints |
| PostgreSQL | `db` | internal only | Durable scan, asset, evidence, and risk history |

PostgreSQL data is stored in the named Compose volume `asm_pgdata`. Runtime artifacts and logs are bind-mounted from `backend/data` and `backend/logs`.

## Quick start

Prerequisites: Docker Engine with the Compose plugin, Git, and enough network/tool access for the approved discovery sources you intend to use.

The backend uses the approved image pinned in `docker-compose.yml`; Compose
will not build or pull a substitute. Install/verify that release image using
the [backend release instructions](docs/BACKEND_RELEASE.md) before starting a
new host. MCP and frontend retain their Compose build contexts.

```bash
cp .env.example .env
chmod 600 .env
# Edit .env and replace DB_PASSWORD. Configure optional integrations as needed.

docker compose -p asip -f docker-compose.yml config --quiet
docker compose -p asip -f docker-compose.yml build mcp frontend
docker compose -p asip -f docker-compose.yml up -d
docker compose -p asip -f docker-compose.yml ps
```

On the first start of an **empty** `asm_pgdata` volume, PostgreSQL loads the checked-in current schema automatically. Existing volumes are never reinitialized by Compose.

Smoke checks:

```bash
curl -fsS http://localhost:8555/
curl -fsS http://localhost:3555/ >/dev/null
curl -fsS http://localhost:8666/tools/summary
```

The MCP summary requires a healthy database but may legitimately report no authoritative scan on a fresh installation. AI Assistance also requires the optional configured LLM endpoint; the deterministic ShadowRecon application remains authoritative if the LLM is unavailable.

## Configure inventory and run a scan

1. Put approved organizational roots in `backend/seeds.txt`, one domain per line.
2. Put documented inventory domains in `backend/data/known_domains.csv` using its existing `Domains` column.
3. Load the known inventory:

   ```bash
   docker compose exec backend python load_known_domains.py
   ```

4. Start one supported orchestration cycle:

   ```bash
   docker compose exec backend python -u orchestration.py
   ```

Only one orchestration process can hold the database advisory lock. The pipeline creates a `RUNNING` scan, executes discovery and enrichment stages, persists canonical risk, then marks the scan `SUCCEEDED`; a required-stage failure marks it `FAILED`. The latest `SUCCEEDED` scan is the sole authoritative current state.

Scan logs are available through `docker compose logs -f backend` and in `backend/logs/`.

## Documentation

- [Operations guide](docs/OPERATIONS.md): configuration, bootstrap, lifecycle, scans, semantics, backups, restore, and troubleshooting.
- [v0.1.0 release checklist](docs/RELEASE_CHECKLIST.md): internal-alpha readiness and manual smoke validation.

Do not commit `.env`, database archives, runtime logs, generated recon output, or analyst authorization files.
