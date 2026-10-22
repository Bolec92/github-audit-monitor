#!/usr/bin/env bash
set -euo pipefail
REPO="${GHAM_REPO:-Bolec92/github-audit-monitor}"
CURRENT="$(cat /opt/github-audit-monitor/VERSION 2>/dev/null || echo 0.0.0)"
LATEST="$(python3 - "$REPO" <<'PY'
import json,sys,urllib.request
repo=sys.argv[1]
with urllib.request.urlopen(f'https://api.github.com/repos/{repo}/releases/latest',timeout=15) as r:
    print(json.load(r)['tag_name'])
PY
)"
[[ "v$CURRENT" == "$LATEST" ]] && { echo "Already on $LATEST"; exit 0; }
CURRENT_BASE="${CURRENT%%-*}"
LATEST_VERSION="${LATEST#v}"
if [[ "$CURRENT_BASE" != "$LATEST_VERSION" ]]; then
  NEWEST="$(printf '%s\n%s\n' "$CURRENT_BASE" "$LATEST_VERSION" | sort -V | tail -1)"
  if [[ "$NEWEST" == "$CURRENT_BASE" ]]; then
    echo "Current v$CURRENT is newer than latest stable $LATEST; refusing to downgrade."
    exit 0
  fi
fi
echo "Updating v$CURRENT -> $LATEST"

if [[ -f /var/lib/github-audit-monitor/github-audit.db ]]; then
  BACKUP="$(/usr/local/bin/gham-backup)"
  echo "Portable data backup: $BACKUP"
else
  echo "No application database yet; skipping data backup."
fi

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
BASE="https://github.com/$REPO/releases/download/$LATEST"
curl -fL "$BASE/github-audit-monitor-$LATEST.tar.gz" -o "$TMP/release.tar.gz"
curl -fL "$BASE/SHA256SUMS" -o "$TMP/SHA256SUMS"
( cd "$TMP" && grep "github-audit-monitor-$LATEST.tar.gz" SHA256SUMS | sha256sum -c - )
mkdir "$TMP/release"; tar -xzf "$TMP/release.tar.gz" -C "$TMP/release" --strip-components=1

CONFIG=/etc/github-audit-monitor/config.env
[[ -r "$CONFIG" ]] || { echo "Missing $CONFIG" >&2; exit 1; }
cp -a "$CONFIG" "$TMP/config.env.before-update"
cp -a /opt/github-audit-monitor/app "$TMP/app.rollback"
cp -a /opt/github-audit-monitor/VERSION "$TMP/VERSION.rollback" 2>/dev/null || true

systemctl stop github-audit-monitor-scheduler.service github-audit-monitor-web.service 2>/dev/null || true
rm -rf /opt/github-audit-monitor/app
cp -a "$TMP/release/app" /opt/github-audit-monitor/app
cp "$TMP/release/VERSION" /opt/github-audit-monitor/VERSION
cp "$TMP/release/systemd/"*.service /etc/systemd/system/
install -m 0755 "$TMP/release/scripts/backup.sh" /usr/local/bin/gham-backup
install -m 0755 "$TMP/release/scripts/restore.sh" /usr/local/bin/gham-restore
install -m 0755 "$TMP/release/scripts/status.sh" /usr/local/bin/gham-status
install -m 0755 "$TMP/release/scripts/update.sh" /usr/local/bin/gham-update
install -m 0755 "$TMP/release/scripts/security.sh" /usr/local/bin/gham-security
chown -R root:root /opt/github-audit-monitor/app
find /opt/github-audit-monitor/app -type d -exec chmod 0755 {} +
find /opt/github-audit-monitor/app -type f -exec chmod 0644 {} +

# Add v0.8 security settings without overwriting local values.
add_env(){ local k="$1" v="$2"; grep -q "^${k}=" "$CONFIG" || printf '%s=%s\n' "$k" "$v" >> "$CONFIG"; }
add_env SNAPSHOT_ENABLED true
add_env SECURITY_DB_PATH /var/lib/github-audit-monitor/security.db
add_env MASTER_KEY_PATH /etc/github-audit-monitor/master.key
add_env SESSION_COOKIE_SECURE false
add_env SESSION_IDLE_MINUTES 60
add_env SESSION_MAX_HOURS 12
add_env LOGIN_WINDOW_MINUTES 15
add_env LOGIN_MAX_FAILURES 5
add_env LOGIN_BLOCK_MINUTES 15
add_env SETUP_CODE_TTL_HOURS 24
add_env PASSWORD_MIN_LENGTH 14
chown root:ghamaudit "$CONFIG"
chmod 0640 "$CONFIG"

install -d -o root -g ghamaudit -m 0750 /etc/github-audit-monitor
install -d -o ghamaudit -g ghamaudit -m 0750 /var/lib/github-audit-monitor /var/backups/github-audit-monitor
MASTER_KEY=/etc/github-audit-monitor/master.key
if [[ ! -f "$MASTER_KEY" ]]; then
  umask 077
  head -c 32 /dev/urandom > "$MASTER_KEY"
fi
chown root:ghamaudit "$MASTER_KEY"
chmod 0640 "$MASTER_KEY"

/opt/github-audit-monitor/.venv/bin/pip install --quiet --upgrade -r /opt/github-audit-monitor/app/requirements.txt
systemctl daemon-reload

SECURITY_OUT="$(/usr/local/bin/gham-security init)"
SETUP_CODE="$(printf '%s\n' "$SECURITY_OUT" | sed -n 's/^SETUP_CODE=//p' | head -1)"
MIGRATED=0
if grep -Eq '^GITHUB_TOKEN=.+$' "$CONFIG" && grep -Eq '^GITHUB_ORG=.+$' "$CONFIG"; then
  MIGRATION_OUT="$(/usr/local/bin/gham-security migrate-env || true)"
  grep -q '^MIGRATED=1$' <<<"$MIGRATION_OUT" && MIGRATED=1 || true
fi

systemctl start github-audit-monitor-web.service github-audit-monitor-scheduler.service
sleep 3
set -a; . "$CONFIG"; set +a
if ! curl -fsS "http://127.0.0.1:${PORT:-8080}/health" >/dev/null; then
  echo "Health check failed. Rolling application back." >&2
  systemctl stop github-audit-monitor-scheduler.service github-audit-monitor-web.service 2>/dev/null || true
  rm -rf /opt/github-audit-monitor/app
  cp -a "$TMP/app.rollback" /opt/github-audit-monitor/app
  if [[ -f "$TMP/VERSION.rollback" ]]; then cp "$TMP/VERSION.rollback" /opt/github-audit-monitor/VERSION; fi
  cp -a "$TMP/config.env.before-update" "$CONFIG"
  systemctl start github-audit-monitor-web.service github-audit-monitor-scheduler.service
  exit 1
fi

# Only after a healthy v0.8 start remove the plaintext legacy token from config.env.
if [[ "$MIGRATED" -eq 1 ]]; then
  CLEAN="$TMP/config.clean"
  awk 'BEGIN{done=0} /^GITHUB_TOKEN=/{if(!done){print "GITHUB_TOKEN=";done=1};next} {print} END{if(!done)print "GITHUB_TOKEN="}' "$CONFIG" > "$CLEAN"
  install -o root -g ghamaudit -m 0640 "$CLEAN" "$CONFIG"
  echo "Legacy GitHub token migrated to encrypted security storage and removed from config.env."
fi

echo "Updated successfully to $LATEST"
if [[ -n "$SETUP_CODE" ]]; then
  cat <<OUT

This upgrade introduced mandatory panel authentication.
ONE-TIME SETUP CODE:
$SETUP_CODE

Open http://LXC_IP:${PORT:-8080}/setup and create the local administrator account.
If the code is lost before the first admin is created, run: gham-security setup-code
OUT
fi
