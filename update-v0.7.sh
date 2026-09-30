#!/usr/bin/env bash
set -euo pipefail
TARGET="${GHAM_TARGET:-/opt/github-audit}"
HERE="$(cd "$(dirname "$0")" && pwd)"
[[ -f "$TARGET/.env" ]] || { echo "Missing $TARGET/.env" >&2; exit 1; }
STAMP="$(date +%Y%m%d-%H%M%S)"
mkdir -p "$TARGET/update-backups/$STAMP"
cp -a "$TARGET/app" "$TARGET/update-backups/$STAMP/app" 2>/dev/null || true
cp -a "$TARGET/docker-compose.yml" "$TARGET/update-backups/$STAMP/docker-compose.yml" 2>/dev/null || true
cp -a "$TARGET/.env" "$TARGET/update-backups/$STAMP/env" 2>/dev/null || true

cd "$TARGET"
sudo docker compose stop
rm -rf "$TARGET/app"
cp -a "$HERE/app" "$TARGET/app"
cp "$HERE/docker-compose.yml" "$TARGET/docker-compose.yml"

# v0.7 makes e-mail rewrite generic. Existing installations can set these before/after update.
grep -q '^EMAIL_DOMAIN_REWRITE_FROM=' "$TARGET/.env" || echo 'EMAIL_DOMAIN_REWRITE_FROM=' >> "$TARGET/.env"
grep -q '^EMAIL_DOMAIN_REWRITE_TO=' "$TARGET/.env" || echo 'EMAIL_DOMAIN_REWRITE_TO=' >> "$TARGET/.env"

sudo docker compose build --pull
sudo docker compose up -d
sleep 3
sudo docker compose ps
printf '\nUpdated to v0.7.0. Existing data/.env/backups were preserved.\n'
printf 'If you need e-mail normalization, set EMAIL_DOMAIN_REWRITE_FROM and EMAIL_DOMAIN_REWRITE_TO in %s/.env and restart.\n' "$TARGET"
