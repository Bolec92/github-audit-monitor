#!/usr/bin/env bash
set -euo pipefail
CONFIG=/etc/github-audit-monitor/config.env
[[ -r "$CONFIG" ]] || { echo "Missing $CONFIG" >&2; exit 1; }
set -a; . "$CONFIG"; set +a
DB="${DATABASE_PATH:-/var/lib/github-audit-monitor/github-audit.db}"
OUTDIR="${BACKUP_DIR:-/var/backups/github-audit-monitor}"
VERSION="$(cat /opt/github-audit-monitor/VERSION 2>/dev/null || echo unknown)"
[[ -f "$DB" ]] || { echo "Database not found: $DB" >&2; exit 1; }
mkdir -p "$OUTDIR"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/data"
sqlite3 "$DB" ".backup '$TMP/data/github-audit.db'"
python3 - "$TMP/manifest.json" "$VERSION" <<'PY'
import json,sys
from datetime import datetime, timezone
path,version=sys.argv[1:]
with open(path,'w',encoding='utf-8') as f:
    json.dump({"application":"GitHub Audit Monitor","app_version":version,"created_at":datetime.now(timezone.utc).isoformat(),"contains_secrets":False},f,indent=2)
PY
STAMP="$(date +%Y%m%d-%H%M%S)"
DEST="$OUTDIR/github-audit-backup-$STAMP.tar.gz"
tar -C "$TMP" -czf "$DEST" manifest.json data
chmod 640 "$DEST"
echo "$DEST"
