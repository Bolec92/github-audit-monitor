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
echo "Updating v$CURRENT -> $LATEST"
BACKUP="$(/usr/local/bin/gham-backup)"; echo "Database backup: $BACKUP"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
BASE="https://github.com/$REPO/releases/download/$LATEST"
curl -fL "$BASE/github-audit-monitor-$LATEST.tar.gz" -o "$TMP/release.tar.gz"
curl -fL "$BASE/SHA256SUMS" -o "$TMP/SHA256SUMS"
( cd "$TMP" && grep "github-audit-monitor-$LATEST.tar.gz" SHA256SUMS | sha256sum -c - )
mkdir "$TMP/release"; tar -xzf "$TMP/release.tar.gz" -C "$TMP/release" --strip-components=1
systemctl stop github-audit-monitor-scheduler.service github-audit-monitor-web.service
cp -a /opt/github-audit-monitor/app "/opt/github-audit-monitor/app.rollback-$CURRENT"
rm -rf /opt/github-audit-monitor/app
cp -a "$TMP/release/app" /opt/github-audit-monitor/app
cp "$TMP/release/VERSION" /opt/github-audit-monitor/VERSION
cp "$TMP/release/systemd/"*.service /etc/systemd/system/
cp "$TMP/release/scripts/backup.sh" /usr/local/bin/gham-backup
cp "$TMP/release/scripts/restore.sh" /usr/local/bin/gham-restore
cp "$TMP/release/scripts/status.sh" /usr/local/bin/gham-status
cp "$TMP/release/scripts/update.sh" /usr/local/bin/gham-update
chmod 0755 /usr/local/bin/gham-*
chown -R ghamaudit:ghamaudit /opt/github-audit-monitor/app
/opt/github-audit-monitor/.venv/bin/pip install --quiet --upgrade -r /opt/github-audit-monitor/app/requirements.txt
systemctl daemon-reload
systemctl start github-audit-monitor-web.service github-audit-monitor-scheduler.service
sleep 3
set -a; . /etc/github-audit-monitor/config.env; set +a
if ! curl -fsS "http://127.0.0.1:${PORT:-8080}/health" >/dev/null; then
  echo "Health check failed. Rolling app back." >&2
  systemctl stop github-audit-monitor-scheduler.service github-audit-monitor-web.service || true
  rm -rf /opt/github-audit-monitor/app
  mv "/opt/github-audit-monitor/app.rollback-$CURRENT" /opt/github-audit-monitor/app
  printf '%s\n' "$CURRENT" > /opt/github-audit-monitor/VERSION
  systemctl start github-audit-monitor-web.service github-audit-monitor-scheduler.service
  exit 1
fi
rm -rf "/opt/github-audit-monitor/app.rollback-$CURRENT"
echo "Updated successfully to $LATEST"
