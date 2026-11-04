# Backend release pin

The production Compose service is pinned to the committed release
`9398f3ab92e539361c2d992c82345e97d6008df3`. Its local image must resolve to
`sha256:a4d01befa7d2db107ded5d71c4e6d36cd2633f82c36fb4ab205243a668da4654`.
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
docker image inspect --format '{{.Id}} {{index .Config.Labels "org.opencontainers.image.revision"}}' asip-backend:9398f3ab92e539361c2d992c82345e97d6008df3
docker compose -p asip -f docker-compose.yml config --quiet
```

Confirm the image ID equals the recorded digest above and that the running
container's revision label matches the configured release. `config --quiet`
validates interpolation without displaying environment values.

## Promoting a future backend release

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

After reviewing the built image and authorizing deployment, update the backend
`image` pin in `docker-compose.yml` to `asip-backend:$REV` and update this
document's expected image ID. Validate the rendered Compose configuration and
image ID before any rollout. Do not enable a Compose build field or remove
`pull_policy: never`.

The future authorized backend-only rollout command is:

```bash
docker compose -p asip -f docker-compose.yml up -d \
  --no-deps --force-recreate --no-build --pull never backend
```

That command is documented for a future approved release; it was not run for
this configuration change.

## Restoring the retained recovery image

The pre-release production backend is retained as
`asip-backend:recovery-sr-obs-01d-45f5d1b-20261104`, expected image ID
`sha256:6ee38f0460b0cd0b76ddbbb93768d4b44fe3d6d00da2505e66d51c28dc56d1a3`,
revision `45f5d1b149e808a94908da81fabd02f58b1121aa`. Use it only after explicit
operator authorization. For a durable rollback, change the backend `image`
reference in `docker-compose.yml` to the recovery tag before recreating the
service. This keeps future Compose operations on the recovered release:

```bash
docker image inspect --format '{{.Id}} {{index .Config.Labels "org.opencontainers.image.revision"}}' \
  asip-backend:recovery-sr-obs-01d-45f5d1b-20261104
docker compose -p asip -f docker-compose.yml config --quiet
docker compose -p asip -f docker-compose.yml up -d \
  --no-deps --force-recreate --no-build --pull never backend
docker inspect --format '{{.Config.Image}} {{.Image}} {{index .Config.Labels "org.opencontainers.image.revision"}}' asm_backend
```

Before running these commands, set the backend image line in
`docker-compose.yml` to the recovery tag and commit or otherwise retain that
pin. The recovery procedure was not run for this release. The additive
diagnostics column should remain in place if the application image is rolled
back. Retain both images until the replacement release has passed its
operational acceptance checks.
