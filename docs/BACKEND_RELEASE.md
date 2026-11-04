# Backend release pin

The production Compose service is pinned to the committed release
`45f5d1b149e808a94908da81fabd02f58b1121aa`. Its local image must resolve to
`sha256:6ee38f0460b0cd0b76ddbbb93768d4b44fe3d6d00da2505e66d51c28dc56d1a3`.
The service has no Compose build context and uses `pull_policy: never`; Compose
therefore fails if this exact local release image is missing instead of silently
building from the working tree or pulling a replacement.

The pinned policy and worker settings are:

- `ASIP_DEFAULT_SCAN_OPERATIONS=HTTP_TLS_OBSERVATION,TECHNOLOGY_HTTP,PORT_SCAN`
- `ASIP_SAN_WORKERS=2`
- `ASIP_HTTP_WORKERS=2`
- `ASIP_NMAP_WORKERS=2`

All database credentials and optional integrations continue to come from the
existing `.env`. Backend ports, mounts, networks, dependencies, and restart
policy remain in `docker-compose.yml`.

## Read-only checks

Run from the repository root. These commands do not recreate containers:

```bash
git rev-parse HEAD
docker inspect --format '{{.Config.Image}} {{.Image}} {{index .Config.Labels "org.opencontainers.image.revision"}}' asm_backend
docker image inspect --format '{{.Id}} {{index .Config.Labels "org.opencontainers.image.revision"}}' asip-backend:45f5d1b149e808a94908da81fabd02f58b1121aa
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

The existing recovery image is
`asip-backend:recovery-sr-perf-04e-45f5d1b-20261104`, expected image ID
`sha256:936bcff28abb3a41d9b1060c7f64113c0ece9094163fa35de72d87e2c74e8f43`,
revision `007099a624bb52ae4877f18ed3b0b01adaa22bcc`. Use it only after explicit
operator authorization. A temporary override avoids changing the maintained
release pin:

```bash
cat >/tmp/asip-backend-recovery.yml <<'YAML'
services:
  backend:
    image: asip-backend:recovery-sr-perf-04e-45f5d1b-20261104
    pull_policy: never
YAML

docker image inspect --format '{{.Id}} {{index .Config.Labels "org.opencontainers.image.revision"}}' \
  asip-backend:recovery-sr-perf-04e-45f5d1b-20261104
docker compose -p asip -f docker-compose.yml \
  -f /tmp/asip-backend-recovery.yml config --quiet
docker compose -p asip -f docker-compose.yml \
  -f /tmp/asip-backend-recovery.yml up -d \
  --no-deps --force-recreate --no-build --pull never backend
```

The recovery command is a procedure only; it was not run. Retain both images
until the replacement release has passed its operational acceptance checks.
