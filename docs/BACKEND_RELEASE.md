# Backend release pin

The production Compose service is pinned to source revision
`52e4782fe6b9ed2e2303aef951cf002dca653ad5` as
`asip-backend:sr-be-07e-04-d-52e4782-20261114T133344Z`. Its local image resolves
to `sha256:50eb67e92e824f3cf1388cfab727c7d6b1c646a4f68fac956edc302565398872`.
The service has no Compose build context and uses `pull_policy: never`; Compose
therefore fails if this exact local release image is missing instead of silently
building from the working tree or pulling a replacement.

The pinned policy and worker settings are:

- `ASIP_DEFAULT_SCAN_OPERATIONS=HTTP_TLS_OBSERVATION,TECHNOLOGY_HTTP,PORT_SCAN`
- `ASIP_SAN_WORKERS=2`
- `ASIP_HTTP_WORKERS=2`
- `ASIP_NMAP_WORKERS=2`

Migration 010 (`scans.stage_diagnostics`) was applied before this backend
release. Historical scans retain null diagnostics; no historical values were
backfilled.

All database credentials and optional integrations continue to come from the
existing `.env`. Backend ports, mounts, networks, dependencies, and restart
policy remain in `docker-compose.yml`.

## Read-only checks

Run from the repository root. These commands do not recreate containers:

```bash
git rev-parse HEAD
docker inspect --format '{{.Config.Image}} {{.Image}} {{index .Config.Labels "org.opencontainers.image.revision"}}' asm_backend
docker image inspect --format '{{.Id}} {{index .Config.Labels "org.opencontainers.image.revision"}}' asip-backend:sr-be-07e-04-d-52e4782-20261114T133344Z
docker compose -p asip -f docker-compose.yml config --quiet
```

Confirm the image ID equals the recorded digest above and that the running
container's revision label matches the configured release. `config --quiet`
validates interpolation without displaying environment values.

## Building a future backend release

Promotion requires a separately authorized release. It must start from a
committed revision, not the working tree. The archive excludes runtime data,
logs, and seeds before building:

```bash
REV=<full-commit-sha>
CTX=$(mktemp -d)
git archive "$REV" backend \
  ':(exclude)backend/data/**' \
  ':(exclude)backend/logs/**' \
  ':(exclude)backend/seeds.txt' | tar -x -C "$CTX"
docker build \
  --label "org.opencontainers.image.revision=$REV" \
  --tag "asip-backend:$REV" \
  "$CTX/backend"
docker image inspect --format '{{.Id}} {{index .Config.Labels "org.opencontainers.image.revision"}}' "asip-backend:$REV"
```

After reviewing the built image and receiving deployment approval, update the
backend `image` pin in `docker-compose.yml` and this document's expected image
ID. Validate the rendered Compose configuration and image ID before rollout.
Do not enable a Compose build field or remove `pull_policy: never`.

The future authorized backend-only rollout command is:

```bash
docker compose -p asip -f docker-compose.yml up -d \
  --no-deps --force-recreate --no-build --pull never backend
```

This is the backend-only rollout command used for the approved release.

## Restoring the pre-release backend

The pre-release backend is retained as
`asip-backend:rollback-sr-be-07e-04d-20261114T131339Z`, image ID
`sha256:7e9410d2307e5155cce979964081fec7dd8288c9dd62e37d6c015094ada17f37`,
revision `7376ed1ecb1f858dc1753533037e991a0684a715`. Use it only after explicit
operator authorization. For a durable rollback, change the backend `image` pin
to this tag before recreating the service:

```bash
docker image inspect --format '{{.Id}} {{index .Config.Labels "org.opencontainers.image.revision"}}' \
  asip-backend:rollback-sr-be-07e-04d-20261114T131339Z
docker compose -p asip -f docker-compose.yml config --quiet
docker compose -p asip -f docker-compose.yml up -d \
  --no-deps --force-recreate --no-build --pull never backend
docker inspect --format '{{.Config.Image}} {{.Image}} {{index .Config.Labels "org.opencontainers.image.revision"}}' asm_backend
```

Before running these commands, set the backend image line in
`docker-compose.yml` to the rollback tag. The older
`asip-backend:recovery-sr-obs-01d-45f5d1b-20261104` image is also retained.
Keep both images until the replacement release has passed operational
acceptance checks.
