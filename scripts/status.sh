#!/usr/bin/env bash
set -euo pipefail
VERSION="$(cat /opt/github-audit-monitor/VERSION 2>/dev/null || echo unknown)"
echo "GitHub Audit Monitor $VERSION"
systemctl --no-pager --full status github-audit-monitor-web.service | sed -n '1,8p' || true
systemctl --no-pager --full status github-audit-monitor-scheduler.service | sed -n '1,8p' || true
CONFIG=/etc/github-audit-monitor/config.env
if [[ -r "$CONFIG" ]]; then
  set -a; . "$CONFIG"; set +a
  echo "Health:"
  curl -fsS "http://127.0.0.1:${PORT:-8080}/health" || true
  echo
fi
