#!/usr/bin/env bash
set -euo pipefail
ARCHIVE="${1:-}"
[[ -n "$ARCHIVE" && -f "$ARCHIVE" ]] || { echo "Usage: gham-restore /path/backup.tar.gz" >&2; exit 1; }
CONFIG=/etc/github-audit-monitor/config.env
[[ -r "$CONFIG" ]] || { echo "Missing $CONFIG" >&2; exit 1; }
set -a; . "$CONFIG"; set +a
DB="${DATABASE_PATH:-/var/lib/github-audit-monitor/github-audit.db}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/github-audit-monitor}"
if tar -tzf "$ARCHIVE" | grep -Eq '(^/|(^|/)\.\.(/|$))'; then echo "Unsafe archive paths" >&2; exit 1; fi
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
tar -xzf "$ARCHIVE" -C "$TMP"
SRC=""
for c in "$TMP/data/github-audit.db" "$TMP/github-audit.db"; do [[ -f "$c" ]] && SRC="$c" && break; done
if [[ -z "$SRC" ]]; then
  SRC="$(find "$TMP" -type f -name 'github-audit.db' -print -quit || true)"
fi
[[ -n "$SRC" && -f "$SRC" ]] || { echo "Backup does not contain github-audit.db" >&2; exit 1; }
mkdir -p "$(dirname "$DB")" "$BACKUP_DIR"
WAS_WEB=0; WAS_SCHED=0
systemctl is-active --quiet github-audit-monitor-web.service && WAS_WEB=1 || true
systemctl is-active --quiet github-audit-monitor-scheduler.service && WAS_SCHED=1 || true
systemctl stop github-audit-monitor-scheduler.service github-audit-monitor-web.service 2>/dev/null || true
if [[ -f "$DB" ]]; then cp -a "$DB" "$BACKUP_DIR/pre-restore-$(date +%Y%m%d-%H%M%S).db"; fi
rm -f "$DB-wal" "$DB-shm"
install -o ghamaudit -g ghamaudit -m 0640 "$SRC" "$DB"
[[ $WAS_WEB -eq 1 ]] && systemctl start github-audit-monitor-web.service || true
[[ $WAS_SCHED -eq 1 ]] && systemctl start github-audit-monitor-scheduler.service || true
echo "Restored: $DB"
