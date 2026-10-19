#!/usr/bin/env bash
set -euo pipefail
CONFIG=/etc/github-audit-monitor/config.env
PY=/opt/github-audit-monitor/.venv/bin/python
CLI=/opt/github-audit-monitor/app/security_cli.py
[[ -r "$CONFIG" ]] || { echo "Missing $CONFIG" >&2; exit 1; }
[[ -x "$PY" && -f "$CLI" ]] || { echo "GitHub Audit Monitor is not installed correctly." >&2; exit 1; }

run_cli() {
  local command="$1"
  runuser -u ghamaudit -- /bin/bash -c 'set -a; . /etc/github-audit-monitor/config.env; set +a; exec /opt/github-audit-monitor/.venv/bin/python /opt/github-audit-monitor/app/security_cli.py "$1"' _ "$command"
}

case "${1:-}" in
  setup-code)
    run_cli rotate-setup-code
    ;;
  init)
    run_cli init
    ;;
  migrate-env)
    run_cli migrate-env
    ;;
  *)
    cat >&2 <<USAGE
Usage:
  gham-security setup-code   Generate a new one-time Setup Code before the first admin exists
  gham-security init         Initialize security storage
  gham-security migrate-env  Encrypt legacy GITHUB_ORG/GITHUB_TOKEN from config.env
USAGE
    exit 2
    ;;
esac
