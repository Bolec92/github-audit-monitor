#!/usr/bin/env bash
set -euo pipefail

umask 022
export LANG=C.UTF-8
export LC_ALL=C.UTF-8
unset LANGUAGE || true

SOURCE_DIR="${1:-/tmp/gham}"
[[ -d "$SOURCE_DIR/app" ]] || { echo "Release payload not found in $SOURCE_DIR" >&2; exit 1; }
[[ -f /tmp/gham-config.env ]] || { echo "Missing /tmp/gham-config.env" >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends python3 python3-venv python3-pip sqlite3 curl ca-certificates tzdata >/dev/null

if ! id ghamaudit >/dev/null 2>&1; then
  useradd --system --user-group --home /opt/github-audit-monitor --shell /usr/sbin/nologin ghamaudit
fi

install -d -o root -g ghamaudit -m 0750 /etc/github-audit-monitor
install -d -o ghamaudit -g ghamaudit -m 0750 /var/lib/github-audit-monitor /var/backups/github-audit-monitor
install -d -o root -g root -m 0755 /opt/github-audit-monitor

rm -rf /opt/github-audit-monitor/app
cp -a "$SOURCE_DIR/app" /opt/github-audit-monitor/app
cp "$SOURCE_DIR/VERSION" /opt/github-audit-monitor/VERSION
chown -R root:root /opt/github-audit-monitor/app
find /opt/github-audit-monitor/app -type d -exec chmod 0755 {} +
find /opt/github-audit-monitor/app -type f -exec chmod 0644 {} +

if [[ ! -x /opt/github-audit-monitor/.venv/bin/python ]]; then
  python3 -m venv /opt/github-audit-monitor/.venv
fi
/opt/github-audit-monitor/.venv/bin/pip install --quiet --upgrade pip
/opt/github-audit-monitor/.venv/bin/pip install --quiet --upgrade -r /opt/github-audit-monitor/app/requirements.txt

install -o root -g ghamaudit -m 0640 /tmp/gham-config.env /etc/github-audit-monitor/config.env
rm -f /tmp/gham-config.env

# Host-specific AES-256 key. It is intentionally not part of portable backups.
MASTER_KEY=/etc/github-audit-monitor/master.key
if [[ ! -f "$MASTER_KEY" ]]; then
  umask 077
  head -c 32 /dev/urandom > "$MASTER_KEY"
fi
chown root:ghamaudit "$MASTER_KEY"
chmod 0640 "$MASTER_KEY"

cp "$SOURCE_DIR/systemd/github-audit-monitor-web.service" /etc/systemd/system/
cp "$SOURCE_DIR/systemd/github-audit-monitor-scheduler.service" /etc/systemd/system/
install -m 0755 "$SOURCE_DIR/scripts/backup.sh" /usr/local/bin/gham-backup
install -m 0755 "$SOURCE_DIR/scripts/restore.sh" /usr/local/bin/gham-restore
install -m 0755 "$SOURCE_DIR/scripts/status.sh" /usr/local/bin/gham-status
install -m 0755 "$SOURCE_DIR/scripts/update.sh" /usr/local/bin/gham-update
install -m 0755 "$SOURCE_DIR/scripts/security.sh" /usr/local/bin/gham-security
systemctl daemon-reload

if [[ -f /tmp/gham-restore.tar.gz ]]; then
  echo "Restoring supplied portable data archive..."
  /usr/local/bin/gham-restore /tmp/gham-restore.tar.gz
  rm -f /tmp/gham-restore.tar.gz
fi

# Create security DB and one-time first-run code before exposing the panel.
SECURITY_OUT="$(/usr/local/bin/gham-security init)"
SETUP_CODE="$(printf '%s\n' "$SECURITY_OUT" | sed -n 's/^SETUP_CODE=//p' | head -1)"
if [[ -n "$SETUP_CODE" ]]; then
  install -d -o root -g root -m 0700 /run/github-audit-monitor
  printf '%s\n' "$SETUP_CODE" > /run/github-audit-monitor/setup-code
  chmod 0600 /run/github-audit-monitor/setup-code
fi

# One-way migration path for upgrades that still arrive with a legacy token.
if grep -Eq '^GITHUB_TOKEN=.+$' /etc/github-audit-monitor/config.env && grep -Eq '^GITHUB_ORG=.+$' /etc/github-audit-monitor/config.env; then
  MIGRATION_OUT="$(/usr/local/bin/gham-security migrate-env || true)"
  if grep -q '^MIGRATED=1$' <<<"$MIGRATION_OUT"; then
    sed -i 's/^GITHUB_TOKEN=.*/GITHUB_TOKEN=/' /etc/github-audit-monitor/config.env
    chmod 0640 /etc/github-audit-monitor/config.env
  fi
fi

systemctl enable --now github-audit-monitor-web.service
sleep 2
set -a; . /etc/github-audit-monitor/config.env; set +a
for _ in $(seq 1 20); do
  if curl -fsS "http://127.0.0.1:${PORT:-8080}/health" >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -fsS "http://127.0.0.1:${PORT:-8080}/health" >/dev/null
systemctl enable --now github-audit-monitor-scheduler.service

echo "GitHub Audit Monitor installed successfully."
