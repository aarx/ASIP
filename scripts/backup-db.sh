#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"

if [ ! -f .env ]; then
    echo ".env is required; copy .env.example and configure it first" >&2
    exit 1
fi

set -a
# .env is operator-controlled configuration and must contain shell-compatible KEY=VALUE entries.
. ./.env
set +a
: "${DB_USER:?DB_USER is required in .env}"
: "${DB_NAME:?DB_NAME is required in .env}"

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
archive=${1:-"backups/asip-${timestamp}.dump"}
partial="${archive}.partial.$$"

if [ -e "$archive" ]; then
    echo "Refusing to overwrite existing backup: $archive" >&2
    exit 1
fi

mkdir -p "$(dirname -- "$archive")"
umask 077
trap 'rm -f "$partial"' EXIT HUP INT TERM

docker compose exec -T db \
    pg_dump --format=custom --no-owner -U "$DB_USER" -d "$DB_NAME" \
    > "$partial"

docker compose exec -T db pg_restore --list < "$partial" > /dev/null
mv "$partial" "$archive"
trap - EXIT HUP INT TERM

echo "Backup: $archive"
sha256sum "$archive"
