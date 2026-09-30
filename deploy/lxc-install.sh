#!/usr/bin/env bash
set -euo pipefail
SOURCE_DIR="${1:-/tmp/gham}"
[[ -d "$SOURCE_DIR/app" ]] || { echo "Release payload not found in $SOURCE_DIR" >&2; exit 1; }
[[ -f /tmp/gham-config.env ]] || { echo "Missing /tmp/gham-config.env" >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends python3 python3-venv python3-pip sqlite3 curl ca-certificates tzdata >/dev/null

if ! id ghamaudit >/dev/null 2>&1; then
  useradd --system --home /opt/github-audit-monitor --shell /usr/sbin/nologin ghamaudit
fi
mkdir -p /opt/github-audit-monitor /etc/github-audit-monitor /var/lib/github-audit-monitor /var/backups/github-audit-monitor
rm -rf /opt/github-audit-monitor/app
cp -a "$SOURCE_DIR/app" /opt/github-audit-monitor/app
cp "$SOURCE_DIR/VERSION" /opt/github-audit-monitor/VERSION
python3 -m venv /opt/github-audit-monitor/.venv
/opt/github-audit-monitor/.venv/bin/pip install --quiet --upgrade pip
/opt/github-audit-monitor/.venv/bin/pip install --quiet -r /opt/github-audit-monitor/app/requirements.txt

install -o root -g ghamaudit -m 0640 /tmp/gham-config.env /etc/github-audit-monitor/config.env
rm -f /tmp/gham-config.env
chown -R ghamaudit:ghamaudit /opt/github-audit-monitor/app /var/lib/github-audit-monitor /var/backups/github-audit-monitor

cp "$SOURCE_DIR/systemd/github-audit-monitor-web.service" /etc/systemd/system/
cp "$SOURCE_DIR/systemd/github-audit-monitor-scheduler.service" /etc/systemd/system/
install -m 0755 "$SOURCE_DIR/scripts/backup.sh" /usr/local/bin/gham-backup
install -m 0755 "$SOURCE_DIR/scripts/restore.sh" /usr/local/bin/gham-restore
install -m 0755 "$SOURCE_DIR/scripts/status.sh" /usr/local/bin/gham-status
install -m 0755 "$SOURCE_DIR/scripts/update.sh" /usr/local/bin/gham-update
systemctl daemon-reload

if [[ -f /tmp/gham-restore.tar.gz ]]; then
  echo "Restoring supplied database archive..."
  /usr/local/bin/gham-restore /tmp/gham-restore.tar.gz
  rm -f /tmp/gham-restore.tar.gz
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
