#!/usr/bin/env bash
set -euo pipefail
TARGET="${GHAM_TARGET:-/opt/github-audit}"
HERE="$(cd "$(dirname "$0")" && pwd)"
[[ -f "$TARGET/.env" ]] || { echo "Missing $TARGET/.env" >&2; exit 1; }
STAMP="$(date +%Y%m%d-%H%M%S)"
BK="$TARGET/update-backups/$STAMP"
mkdir -p "$BK"
cp -a "$TARGET/app" "$BK/app" 2>/dev/null || true
cp -a "$TARGET/docker-compose.yml" "$BK/docker-compose.yml" 2>/dev/null || true
cp -a "$TARGET/.env" "$BK/env" 2>/dev/null || true

cd "$TARGET"
sudo docker compose stop
rm -rf "$TARGET/app"
cp -a "$HERE/app" "$TARGET/app"
cp "$HERE/docker-compose.yml" "$TARGET/docker-compose.yml"

add_env(){ local k="$1" v="$2"; grep -q "^${k}=" "$TARGET/.env" || printf '%s=%s\n' "$k" "$v" >> "$TARGET/.env"; }
add_env SECURITY_DB_PATH /data/security.db
add_env MASTER_KEY_PATH /data/security.key
add_env SESSION_COOKIE_SECURE false
add_env SESSION_IDLE_MINUTES 60
add_env SESSION_MAX_HOURS 12
add_env LOGIN_WINDOW_MINUTES 15
add_env LOGIN_MAX_FAILURES 5
add_env LOGIN_BLOCK_MINUTES 15
add_env SETUP_CODE_TTL_HOURS 24
add_env PASSWORD_MIN_LENGTH 14

APP_UID="$(awk -F= '$1=="APP_UID"{print $2}' "$TARGET/.env" | tail -1)"; APP_UID="${APP_UID:-1000}"
APP_GID="$(awk -F= '$1=="APP_GID"{print $2}' "$TARGET/.env" | tail -1)"; APP_GID="${APP_GID:-1000}"
mkdir -p "$TARGET/data" "$TARGET/backups"
if [[ ! -f "$TARGET/data/security.key" ]]; then
  umask 077
  head -c 32 /dev/urandom > "$TARGET/data/security.key"
fi
sudo chown "$APP_UID:$APP_GID" "$TARGET/data/security.key" "$TARGET/data" "$TARGET/backups"
sudo chmod 0600 "$TARGET/data/security.key"

sudo docker compose build --pull
SECURITY_OUT="$(sudo docker compose run --rm --no-deps github-audit-monitor python security_cli.py init)"
SETUP_CODE="$(printf '%s\n' "$SECURITY_OUT" | sed -n 's/^SETUP_CODE=//p' | head -1)"
MIGRATION_OUT="$(sudo docker compose run --rm --no-deps github-audit-monitor python security_cli.py migrate-env || true)"
MIGRATED=0; grep -q '^MIGRATED=1$' <<<"$MIGRATION_OUT" && MIGRATED=1 || true

sudo docker compose up -d
sleep 4
if ! sudo docker compose exec -T github-audit-monitor python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=3).read()"; then
  echo "Health check failed. Previous files are in $BK" >&2
  exit 1
fi
if [[ "$MIGRATED" -eq 1 ]]; then
  TMP="$TARGET/.env.clean.$$"
  awk 'BEGIN{done=0} /^GITHUB_TOKEN=/{if(!done){print "GITHUB_TOKEN=";done=1};next} {print} END{if(!done)print "GITHUB_TOKEN="}' "$TARGET/.env" > "$TMP"
  mv "$TMP" "$TARGET/.env"
  chmod 600 "$TARGET/.env" 2>/dev/null || true
  sudo docker compose up -d --force-recreate >/dev/null
  echo "Legacy GitHub token encrypted and removed from .env."
fi
sudo docker compose ps
printf '\nUpdated Docker/Hyper-V installation to v0.8.0.\n'
if [[ -n "$SETUP_CODE" ]]; then
  printf '\nONE-TIME SETUP CODE:\n%s\n\nOpen the panel /setup page through your SSH tunnel and create the admin account.\n' "$SETUP_CODE"
fi
