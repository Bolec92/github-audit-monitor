#!/usr/bin/env bash
set -euo pipefail
REPO="${GHAM_REPO:-Bolec92/github-audit-monitor}"
RELEASE_TAG="__RELEASE_TAG__"
APP_NAME="GitHub Audit Monitor"

if [[ "$EUID" -ne 0 ]]; then echo "Run this installer as root on the Proxmox VE host." >&2; exit 1; fi
command -v pveversion >/dev/null 2>&1 || { echo "This installer must run on a Proxmox VE host." >&2; exit 1; }
if [[ "$RELEASE_TAG" == "__RELEASE_TAG__" ]]; then echo "Use the installer asset from a published GitHub Release, not the source file from main." >&2; exit 1; fi
command -v whiptail >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq whiptail; }

msg(){ whiptail --title "$APP_NAME" --msgbox "$1" 13 78; }
input(){ whiptail --title "$APP_NAME" --inputbox "$1" 10 78 "$2" 3>&1 1>&2 2>&3; }

NEXTID="$(pvesh get /cluster/nextid 2>/dev/null | tr -dc '0-9')"
HOST_TZ="$(timedatectl show -p Timezone --value 2>/dev/null || echo UTC)"
ROOTFS_STORAGE="$(pvesm status -content rootdir 2>/dev/null | awk 'NR>1 && $3=="active"{print $1; exit}')"
TEMPLATE_STORAGE="$(pvesm status -content vztmpl 2>/dev/null | awk 'NR>1 && $3=="active"{print $1; exit}')"
[[ -n "$ROOTFS_STORAGE" && -n "$TEMPLATE_STORAGE" ]] || { echo "Could not auto-detect Proxmox storage." >&2; exit 1; }

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

TZ="$(input "Timezone" "$HOST_TZ")"
EMAIL_FROM=""; EMAIL_TO=""
if whiptail --title "$APP_NAME" --yesno "Configure an exact e-mail domain rewrite?\n\nExample: old-company.com -> new-company.com" 12 72; then
  EMAIL_FROM="$(input "Rewrite FROM domain (without @)" "")"
  EMAIL_TO="$(input "Rewrite TO domain (without @)" "")"
fi
RESTORE_PATH=""
if whiptail --title "$APP_NAME" --yesno "Restore an existing GitHub Audit Monitor portable data backup after installation?\n\nThe backup contains audit/snapshot data only; credentials and GitHub tokens are never restored." 13 76; then
  RESTORE_PATH="$(input "Path to backup .tar.gz on this Proxmox host" "/root/github-audit-backup.tar.gz")"
  [[ -f "$RESTORE_PATH" ]] || { msg "Backup file not found:\n$RESTORE_PATH"; exit 1; }
fi

SUMMARY="CT ID: $CTID\nHostname: $HOSTNAME\nCPU: $CORES\nRAM: ${MEMORY} MB\nSwap: ${SWAP} MB\nDisk: ${DISK} GB\nStorage: $ROOTFS_STORAGE\nBridge: $BRIDGE\nNetwork: $NETMODE\nVersion: $RELEASE_TAG\n\nGitHub organization/token will be configured securely in the panel after first login."
whiptail --title "$APP_NAME" --yesno "Create the LXC with these settings?\n\n$SUMMARY" 24 80 || exit 0

pct status "$CTID" >/dev/null 2>&1 && { echo "CT $CTID already exists." >&2; exit 1; }
echo "[1/10] Updating Proxmox template catalog..."
pveam update >/dev/null
TEMPLATE="$(pveam available --section system | awk '$2 ~ /^debian-13-standard_.*amd64\.tar\.(zst|gz)$/ {print $2}' | tail -1)"
if [[ -z "$TEMPLATE" ]]; then TEMPLATE="$(pveam available --section system | awk '$2 ~ /^debian-12-standard_.*amd64\.tar\.(zst|gz)$/ {print $2}' | tail -1)"; fi
[[ -n "$TEMPLATE" ]] || { echo "No Debian 12/13 LXC template found." >&2; exit 1; }
if ! pvesm list "$TEMPLATE_STORAGE" --content vztmpl 2>/dev/null | grep -q ":vztmpl/$TEMPLATE"; then
  echo "[2/10] Downloading $TEMPLATE..."
  pveam download "$TEMPLATE_STORAGE" "$TEMPLATE" >/dev/null
else
  echo "[2/10] Template already cached: $TEMPLATE"
fi
TEMPLATE_REF="$TEMPLATE_STORAGE:vztmpl/$TEMPLATE"

if [[ "$NETMODE" == "dhcp" ]]; then NET0="name=eth0,bridge=$BRIDGE,ip=dhcp"; else NET0="name=eth0,bridge=$BRIDGE,ip=$IP_CIDR,gw=$GATEWAY"; fi
echo "[3/10] Creating unprivileged LXC $CTID..."
pct create "$CTID" "$TEMPLATE_REF" --ostype debian --hostname "$HOSTNAME" --cores "$CORES" --memory "$MEMORY" --swap "$SWAP" --rootfs "$ROOTFS_STORAGE:$DISK" --net0 "$NET0" --unprivileged 1 --onboot 1 >/dev/null

echo "[4/10] Starting LXC..."
pct start "$CTID"
for _ in $(seq 1 30); do pct exec "$CTID" -- true >/dev/null 2>&1 && break; sleep 1; done
pct exec "$CTID" -- true >/dev/null 2>&1 || { echo "LXC did not become ready." >&2; exit 1; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
BASE="https://github.com/$REPO/releases/download/$RELEASE_TAG"
echo "[5/10] Downloading immutable release $RELEASE_TAG..."
ASSET="github-audit-monitor-$RELEASE_TAG.tar.gz"

curl -fL "$BASE/$ASSET" -o "$TMP/$ASSET"
curl -fL "$BASE/SHA256SUMS" -o "$TMP/SHA256SUMS"

( cd "$TMP" && grep "$ASSET" SHA256SUMS | sha256sum -c - )

echo "[6/10] Preparing application configuration..."
umask 077
CONFIG="$TMP/config.env"
{
  printf 'GITHUB_ORG=\n'
  printf 'GITHUB_TOKEN=\n'
  printf 'GITHUB_API_VERSION=%s\n' '2026-03-10'
  printf 'TZ=%s\n' "$TZ"
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
  printf 'EMAIL_DOMAIN_REWRITE_FROM=%s\n' "$EMAIL_FROM"
  printf 'EMAIL_DOMAIN_REWRITE_TO=%s\n' "$EMAIL_TO"
} > "$CONFIG"

umask 022

pct push "$CTID" "$TMP/$ASSET" /tmp/gham-release.tar.gz --perms 0600
pct push "$CTID" "$CONFIG" /tmp/gham-config.env --perms 0600
if [[ -n "$RESTORE_PATH" ]]; then
  echo "[7/10] Copying portable archive to LXC..."
  pct push "$CTID" "$RESTORE_PATH" /tmp/gham-restore.tar.gz --perms 0600
else
  echo "[7/10] Fresh application database selected."
fi

echo "[8/10] Installing application inside LXC..."
pct exec "$CTID" -- env LANG=C.UTF-8 LC_ALL=C.UTF-8 LANGUAGE= bash -lc 'rm -rf /tmp/gham && mkdir /tmp/gham && tar -xzf /tmp/gham-release.tar.gz -C /tmp/gham --strip-components=1 && bash /tmp/gham/deploy/lxc-install.sh /tmp/gham'

echo "[9/10] Checking service health..."
pct exec "$CTID" -- env LANG=C.UTF-8 LC_ALL=C.UTF-8 LANGUAGE= bash -lc 'set -a; . /etc/github-audit-monitor/config.env; set +a; curl -fsS "http://127.0.0.1:${PORT:-8080}/health"' >/dev/null
IP="$(pct exec "$CTID" -- hostname -I 2>/dev/null | awk '{print $1}')"
SETUP_CODE="$(pct exec "$CTID" -- cat /run/github-audit-monitor/setup-code 2>/dev/null | tr -d '\r\n' || true)"
if [[ -n "$SETUP_CODE" ]]; then
  pct exec "$CTID" -- rm -f /run/github-audit-monitor/setup-code >/dev/null 2>&1 || true
fi

echo "[10/10] Complete."
cat <<OUT

GitHub Audit Monitor $RELEASE_TAG installed successfully.
CT ID:      $CTID
Hostname:   $HOSTNAME
IP:         ${IP:-unknown}
Panel:      http://${IP:-LXC_IP}:8080
Setup:      http://${IP:-LXC_IP}:8080/setup

ONE-TIME SETUP CODE:
${SETUP_CODE:-NOT_AVAILABLE_RUN_gham-security_setup-code}

Create the local administrator account first. Then open Settings -> GitHub connection
and configure the organization and GitHub PAT. No GitHub token is stored in config.env
on a fresh installation.

Status:     pct exec $CTID -- gham-status
Backup:     pct exec $CTID -- gham-backup
Update:     pct exec $CTID -- gham-update
New setup code before first admin only:
            pct exec $CTID -- gham-security setup-code

Network model: HTTP on LAN with mandatory application login. Do not port-forward :8080
to the Internet. HTTPS/reverse-proxy support can be added later; when enabled, set
SESSION_COOKIE_SECURE=true.
OUT
