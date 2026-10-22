#!/usr/bin/env bash
set -euo pipefail
REPO="${GHAM_REPO:-Bolec92/github-audit-monitor}"
RELEASE_TAG="__RELEASE_TAG__"
APP_NAME="GitHub Audit Monitor"

# Lightweight, self-contained visual helpers inspired by the familiar Proxmox
# community-script experience. No external UI framework is downloaded at runtime.
if [[ -t 1 ]]; then
  BOLD='\033[1m'; DIM='\033[2m'; RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[34m'; CYAN='\033[36m'; RESET='\033[0m'
else
  BOLD=''; DIM=''; RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; RESET=''
fi

banner() {
  clear 2>/dev/null || true
  printf '%b\n' "${CYAN}${BOLD}"
  cat <<'BANNER'
   ____ _ _   _   _       _          _            _ _ _
  / ___(_) |_| | | |_   _| |__      / \  _   _ __| (_) |_
 | |  _| | __| |_| | | | | '_ \    / _ \| | | / _` | | __|
 | |_| | | |_|  _  | |_| | |_) |  / ___ \ |_| | (_| | | |_
  \____|_|\__|_| |_|\__,_|_.__/  /_/   \_\__,_|\__,_|_|\__|

                 M O N I T O R
BANNER
  printf '%b\n' "${RESET}${DIM}Secure GitHub access history monitoring for Proxmox VE${RESET}"
  printf '\n'
}

step_info() { printf '%b[%s/10]%b %s\n' "$CYAN" "$1" "$RESET" "$2"; }
msg_info()  { printf '%b[INFO]%b %s\n' "$BLUE" "$RESET" "$1"; }
msg_ok()    { printf '%b[ OK ]%b %s\n' "$GREEN" "$RESET" "$1"; }
msg_warn()  { printf '%b[WARN]%b %s\n' "$YELLOW" "$RESET" "$1"; }
msg_error() { printf '%b[FAIL]%b %s\n' "$RED" "$RESET" "$1" >&2; }

die() { msg_error "$1"; exit 1; }
msg(){ whiptail --title "$APP_NAME" --msgbox "$1" 13 78; }
input(){ whiptail --title "$APP_NAME" --inputbox "$1" 10 78 "$2" 3>&1 1>&2 2>&3; }

[[ "$EUID" -eq 0 ]] || die "Run this installer as root on the Proxmox VE host."
command -v pveversion >/dev/null 2>&1 || die "This installer must run on a Proxmox VE host."
[[ "$RELEASE_TAG" != "__RELEASE_TAG__" ]] || die "Use the installer asset from a published GitHub Release, not the source file from main."
command -v whiptail >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq whiptail; }

banner

NEXTID="$(pvesh get /cluster/nextid 2>/dev/null | tr -dc '0-9')"
HOST_TZ="$(timedatectl show -p Timezone --value 2>/dev/null || echo UTC)"
ROOTFS_STORAGE="$(pvesm status -content rootdir 2>/dev/null | awk 'NR>1 && $3=="active"{print $1; exit}')"
TEMPLATE_STORAGE="$(pvesm status -content vztmpl 2>/dev/null | awk 'NR>1 && $3=="active"{print $1; exit}')"
[[ -n "$ROOTFS_STORAGE" && -n "$TEMPLATE_STORAGE" ]] || die "Could not auto-detect Proxmox storage."

MODE="$(whiptail --title "$APP_NAME" --menu "Installation mode" 15 72 4 "default" "Recommended settings" "advanced" "Choose LXC resources and network" 3>&1 1>&2 2>&3)" || exit 1
CTID="$NEXTID"; HOSTNAME="github-audit"; CORES=2; MEMORY=4096; SWAP=2048; DISK=24; BRIDGE="vmbr0"; NETMODE="dhcp"; IP_CIDR=""; GATEWAY=""
if [[ "$MODE" == "advanced" ]]; then
  CTID="$(input "LXC CT ID" "$CTID")"
  HOSTNAME="$(input "Hostname" "$HOSTNAME")"
  CORES="$(input "CPU cores" "$CORES")"
  MEMORY="$(input "RAM in MB" "$MEMORY")"
  SWAP="$(input "Swap in MB" "$SWAP")"
  DISK="$(input "Disk size in GB" "$DISK")"
  ROOTFS_STORAGE="$(input "Rootfs storage" "$ROOTFS_STORAGE")"
  BRIDGE="$(input "Network bridge" "$BRIDGE")"
  if whiptail --title "$APP_NAME" --yesno "Use DHCP? Choose No to configure a static IPv4 address." 10 72; then
    NETMODE="dhcp"
  else
    NETMODE="static"
    IP_CIDR="$(input "Static IPv4/CIDR, e.g. 192.168.1.50/24" "")"
    GATEWAY="$(input "IPv4 gateway, e.g. 192.168.1.1" "")"
    [[ -n "$IP_CIDR" && -n "$GATEWAY" ]] || { msg "Static IP and gateway are required."; exit 1; }
  fi
fi

TZ="$HOST_TZ"
SUMMARY="CT ID: $CTID\nHostname: $HOSTNAME\nCPU: $CORES\nRAM: ${MEMORY} MB\nSwap: ${SWAP} MB\nDisk: ${DISK} GB\nStorage: $ROOTFS_STORAGE\nBridge: $BRIDGE\nNetwork: $NETMODE\nVersion: $RELEASE_TAG\n\nApplication configuration, GitHub connection, data import, e-mail normalization and snapshot schedule are configured in the panel after first login."
whiptail --title "$APP_NAME" --yesno "Create the LXC with these settings?\n\n$SUMMARY" 24 80 || exit 0

banner
pct status "$CTID" >/dev/null 2>&1 && die "CT $CTID already exists."

step_info 1 "Updating Proxmox template catalog..."
pveam update >/dev/null
msg_ok "Template catalog updated"

TEMPLATE="$(pveam available --section system | awk '$2 ~ /^debian-13-standard_.*amd64\.tar\.(zst|gz)$/ {print $2}' | tail -1)"
if [[ -z "$TEMPLATE" ]]; then TEMPLATE="$(pveam available --section system | awk '$2 ~ /^debian-12-standard_.*amd64\.tar\.(zst|gz)$/ {print $2}' | tail -1)"; fi
[[ -n "$TEMPLATE" ]] || die "No Debian 12/13 LXC template found."
if ! pvesm list "$TEMPLATE_STORAGE" --content vztmpl 2>/dev/null | grep -q ":vztmpl/$TEMPLATE"; then
  step_info 2 "Downloading $TEMPLATE..."
  pveam download "$TEMPLATE_STORAGE" "$TEMPLATE" >/dev/null
  msg_ok "Downloaded $TEMPLATE"
else
  step_info 2 "Using cached template $TEMPLATE"
  msg_ok "Template ready"
fi
TEMPLATE_REF="$TEMPLATE_STORAGE:vztmpl/$TEMPLATE"

if [[ "$NETMODE" == "dhcp" ]]; then NET0="name=eth0,bridge=$BRIDGE,ip=dhcp"; else NET0="name=eth0,bridge=$BRIDGE,ip=$IP_CIDR,gw=$GATEWAY"; fi
step_info 3 "Creating unprivileged LXC $CTID..."
pct create "$CTID" "$TEMPLATE_REF" --ostype debian --hostname "$HOSTNAME" --cores "$CORES" --memory "$MEMORY" --swap "$SWAP" --rootfs "$ROOTFS_STORAGE:$DISK" --net0 "$NET0" --unprivileged 1 --onboot 1 >/dev/null
msg_ok "LXC $CTID created"

step_info 4 "Starting LXC..."
pct start "$CTID"
for _ in $(seq 1 30); do pct exec "$CTID" -- env LANG=C.UTF-8 LC_ALL=C.UTF-8 true >/dev/null 2>&1 && break; sleep 1; done
pct exec "$CTID" -- env LANG=C.UTF-8 LC_ALL=C.UTF-8 true >/dev/null 2>&1 || die "LXC did not become ready."
msg_ok "LXC is running"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
ASSET="github-audit-monitor-$RELEASE_TAG.tar.gz"
if [[ -n "${GHAM_LOCAL_ASSET_DIR:-}" ]]; then
  step_info 5 "Using local release assets from $GHAM_LOCAL_ASSET_DIR..."
  [[ -f "$GHAM_LOCAL_ASSET_DIR/$ASSET" && -f "$GHAM_LOCAL_ASSET_DIR/SHA256SUMS" ]] || die "Missing $ASSET or SHA256SUMS in $GHAM_LOCAL_ASSET_DIR"
  cp "$GHAM_LOCAL_ASSET_DIR/$ASSET" "$TMP/$ASSET"
  cp "$GHAM_LOCAL_ASSET_DIR/SHA256SUMS" "$TMP/SHA256SUMS"
else
  BASE="https://github.com/$REPO/releases/download/$RELEASE_TAG"
  step_info 5 "Downloading immutable release $RELEASE_TAG..."
  curl -fsSL --retry 3 --retry-delay 2 "$BASE/$ASSET" -o "$TMP/$ASSET"
  curl -fsSL --retry 3 --retry-delay 2 "$BASE/SHA256SUMS" -o "$TMP/SHA256SUMS"
fi
( cd "$TMP" && grep -F "  $ASSET" SHA256SUMS | sha256sum -c - >/dev/null )
msg_ok "Release checksum verified"

step_info 6 "Preparing application configuration..."
umask 077
CONFIG="$TMP/config.env"
{
  printf 'GITHUB_ORG=\n'
  printf 'GITHUB_TOKEN=\n'
  printf 'GITHUB_API_VERSION=%s\n' '2026-03-10'
  printf 'TZ=%s\n' "$TZ"
  printf 'SNAPSHOT_ENABLED=%s\n' 'true'
  printf 'SNAPSHOT_HOUR=%s\n' '3'
  printf 'SNAPSHOT_MINUTE=%s\n' '0'
  printf 'RUN_ON_START=%s\n' 'false'
  printf 'BIND_ADDRESS=%s\n' '0.0.0.0'
  printf 'PORT=%s\n' '8080'
  printf 'DATABASE_PATH=%s\n' '/var/lib/github-audit-monitor/github-audit.db'
  printf 'BACKUP_DIR=%s\n' '/var/backups/github-audit-monitor'
  printf 'BACKUP_KEEP=%s\n' '30'
  printf 'SECURITY_DB_PATH=%s\n' '/var/lib/github-audit-monitor/security.db'
  printf 'MASTER_KEY_PATH=%s\n' '/etc/github-audit-monitor/master.key'
  printf 'SESSION_COOKIE_SECURE=%s\n' 'false'
  printf 'SESSION_IDLE_MINUTES=%s\n' '60'
  printf 'SESSION_MAX_HOURS=%s\n' '12'
  printf 'LOGIN_WINDOW_MINUTES=%s\n' '15'
  printf 'LOGIN_MAX_FAILURES=%s\n' '5'
  printf 'LOGIN_BLOCK_MINUTES=%s\n' '15'
  printf 'SETUP_CODE_TTL_HOURS=%s\n' '24'
  printf 'PASSWORD_MIN_LENGTH=%s\n' '14'
  printf 'EMAIL_DOMAIN_REWRITE_FROM=\n'
  printf 'EMAIL_DOMAIN_REWRITE_TO=\n'
} > "$CONFIG"
# Do not let the restrictive secret-file umask leak into pct exec/LXC creation.
umask 022
msg_ok "Secure runtime configuration prepared"

pct push "$CTID" "$TMP/$ASSET" /tmp/gham-release.tar.gz --perms 0600
pct push "$CTID" "$CONFIG" /tmp/gham-config.env --perms 0600
step_info 7 "Fresh database selected; existing data can be imported later in Settings."
msg_ok "Release payload copied to LXC"

step_info 8 "Installing application inside LXC..."
pct exec "$CTID" -- env LANG=C.UTF-8 LC_ALL=C.UTF-8 LANGUAGE= bash -lc 'umask 022; rm -rf /tmp/gham && mkdir /tmp/gham && tar -xzf /tmp/gham-release.tar.gz -C /tmp/gham --strip-components=1 && bash /tmp/gham/deploy/lxc-install.sh /tmp/gham'
msg_ok "Application installed"

step_info 9 "Checking service health..."
pct exec "$CTID" -- env LANG=C.UTF-8 LC_ALL=C.UTF-8 LANGUAGE= bash -lc 'set -a; . /etc/github-audit-monitor/config.env; set +a; curl -fsS "http://127.0.0.1:${PORT:-8080}/health"' >/dev/null
msg_ok "Health check passed"

# DHCP can take a moment even after the service is healthy. Wait for the first
# globally-scoped IPv4 so Default mode always prints a useful panel URL.
IP=""
for _ in $(seq 1 30); do
  IP="$(pct exec "$CTID" -- env LANG=C.UTF-8 LC_ALL=C.UTF-8 ip -4 -o addr show dev eth0 scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)"
  [[ -n "$IP" ]] && break
  sleep 1
done
if [[ -z "$IP" && "$NETMODE" == "static" ]]; then IP="${IP_CIDR%%/*}"; fi

SETUP_CODE="$(pct exec "$CTID" -- env LANG=C.UTF-8 LC_ALL=C.UTF-8 cat /run/github-audit-monitor/setup-code 2>/dev/null | tr -d '\r\n' || true)"
if [[ -n "$SETUP_CODE" ]]; then
  pct exec "$CTID" -- env LANG=C.UTF-8 LC_ALL=C.UTF-8 rm -f /run/github-audit-monitor/setup-code >/dev/null 2>&1 || true
fi

step_info 10 "Installation complete"
printf '\n%b%s%b\n' "$GREEN$BOLD" "============================================================" "$RESET"
printf '%b  GitHub Audit Monitor %s installed successfully%b\n' "$GREEN$BOLD" "$RELEASE_TAG" "$RESET"
printf '%b%s%b\n\n' "$GREEN$BOLD" "============================================================" "$RESET"
printf '  %-13s %s\n' "CT ID:" "$CTID"
printf '  %-13s %s\n' "Hostname:" "$HOSTNAME"
printf '  %-13s %s\n' "IP address:" "${IP:-not detected}"
printf '  %-13s %b%s%b\n' "Panel:" "$CYAN$BOLD" "http://${IP:-LXC_IP}:8080" "$RESET"
printf '  %-13s %b%s%b\n\n' "First setup:" "$CYAN$BOLD" "http://${IP:-LXC_IP}:8080/setup" "$RESET"
printf '%b  ONE-TIME SETUP CODE%b\n' "$YELLOW$BOLD" "$RESET"
printf '  %b%s%b\n\n' "$YELLOW$BOLD" "${SETUP_CODE:-NOT_AVAILABLE_RUN_/usr/local/bin/gham-security_setup-code}" "$RESET"
printf '%b[SECURITY]%b Keep this code private. It is valid only before the first administrator is created and expires automatically.\n\n' "$YELLOW" "$RESET"
printf '  Status:  pct exec %s -- /usr/local/bin/gham-status\n' "$CTID"
printf '  Backup:  pct exec %s -- /usr/local/bin/gham-backup\n' "$CTID"
printf '  Update:  pct exec %s -- /usr/local/bin/gham-update\n' "$CTID"
printf '  New setup code (before first admin only):\n'
printf '           pct exec %s -- /usr/local/bin/gham-security setup-code\n\n' "$CTID"
printf '%bNetwork model:%b HTTP on trusted LAN with mandatory application login. Do not port-forward TCP/8080 to the Internet.\n' "$DIM" "$RESET"
printf 'After login configure GitHub, optional data import, e-mail normalization and snapshot schedule from Settings.\n'
