#!/usr/bin/env bash
set -euo pipefail
REPO="${GHAM_REPO:-Bolec92/github-audit-monitor}"
RELEASE_TAG="__RELEASE_TAG__"
APP_NAME="GitHub Audit Monitor"

if [[ "$EUID" -ne 0 ]]; then echo "Run this installer as root on the Proxmox VE host." >&2; exit 1; fi
command -v pveversion >/dev/null 2>&1 || { echo "This installer must run on a Proxmox VE host." >&2; exit 1; }
if [[ "$RELEASE_TAG" == "__RELEASE_TAG__" ]]; then echo "Use the installer asset from a published GitHub Release, not the source file from main." >&2; exit 1; fi
command -v whiptail >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq whiptail; }

msg(){ whiptail --title "$APP_NAME" --msgbox "$1" 12 74; }
input(){ whiptail --title "$APP_NAME" --inputbox "$1" 10 74 "$2" 3>&1 1>&2 2>&3; }
password(){ whiptail --title "$APP_NAME" --passwordbox "$1" 10 74 3>&1 1>&2 2>&3; }

NEXTID="$(pvesh get /cluster/nextid 2>/dev/null | tr -dc '0-9')"
HOST_TZ="$(timedatectl show -p Timezone --value 2>/dev/null || echo UTC)"
ROOTFS_STORAGE="$(pvesm status -content rootdir 2>/dev/null | awk 'NR>1 && $3=="active"{print $1; exit}')"
TEMPLATE_STORAGE="$(pvesm status -content vztmpl 2>/dev/null | awk 'NR>1 && $3=="active"{print $1; exit}')"
[[ -n "$ROOTFS_STORAGE" && -n "$TEMPLATE_STORAGE" ]] || { echo "Could not auto-detect Proxmox storage." >&2; exit 1; }

MODE="$(whiptail --title "$APP_NAME" --menu "Installation mode" 15 70 4 "default" "Recommended settings" "advanced" "Choose LXC resources and network" 3>&1 1>&2 2>&3)" || exit 1
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
  if whiptail --title "$APP_NAME" --yesno "Use DHCP? Choose No to configure a static IPv4 address." 10 70; then
    NETMODE="dhcp"
  else
    NETMODE="static"
    IP_CIDR="$(input "Static IPv4/CIDR, e.g. 192.168.1.50/24" "")"
    GATEWAY="$(input "IPv4 gateway, e.g. 192.168.1.1" "")"
  fi
fi

ORG="$(input "GitHub organization to monitor" "")"
[[ -n "$ORG" ]] || { msg "GitHub organization is required."; exit 1; }
TOKEN="$(password "GitHub API token (stored only inside the LXC config)")"
[[ -n "$TOKEN" ]] || { msg "GitHub token is required."; exit 1; }
TZ="$(input "Timezone" "$HOST_TZ")"
EMAIL_FROM=""; EMAIL_TO=""
if whiptail --title "$APP_NAME" --yesno "Configure exact e-mail domain rewrite?\n\nExample: old-company.com -> new-company.com" 12 70; then
  EMAIL_FROM="$(input "Rewrite FROM domain (without @)" "")"
  EMAIL_TO="$(input "Rewrite TO domain (without @)" "")"
fi
RESTORE_PATH=""
if whiptail --title "$APP_NAME" --yesno "Restore an existing GitHub Audit Monitor backup after installation?" 10 70; then
  RESTORE_PATH="$(input "Path to backup .tar.gz on this Proxmox host" "/root/github-audit-backup.tar.gz")"
  [[ -f "$RESTORE_PATH" ]] || { msg "Backup file not found:\n$RESTORE_PATH"; exit 1; }
fi

SUMMARY="CT ID: $CTID\nHostname: $HOSTNAME\nCPU: $CORES\nRAM: ${MEMORY} MB\nSwap: ${SWAP} MB\nDisk: ${DISK} GB\nStorage: $ROOTFS_STORAGE\nBridge: $BRIDGE\nNetwork: $NETMODE\nGitHub org: $ORG\nVersion: $RELEASE_TAG"
whiptail --title "$APP_NAME" --yesno "Create the LXC with these settings?\n\n$SUMMARY" 22 78 || exit 0

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
  printf 'GITHUB_ORG=%s\n' "$ORG"
  printf 'GITHUB_TOKEN=%s\n' "$TOKEN"
  printf 'GITHUB_API_VERSION=%s\n' '2026-03-10'
  printf 'TZ=%s\n' "$TZ"
  printf 'SNAPSHOT_HOUR=%s\n' '3'
  printf 'SNAPSHOT_MINUTE=%s\n' '0'
  printf 'RUN_ON_START=%s\n' 'true'
  printf 'BIND_ADDRESS=%s\n' '0.0.0.0'
  printf 'PORT=%s\n' '8080'
  printf 'DATABASE_PATH=%s\n' '/var/lib/github-audit-monitor/github-audit.db'
  printf 'BACKUP_DIR=%s\n' '/var/backups/github-audit-monitor'
  printf 'BACKUP_KEEP=%s\n' '30'
  printf 'EMAIL_DOMAIN_REWRITE_FROM=%s\n' "$EMAIL_FROM"
  printf 'EMAIL_DOMAIN_REWRITE_TO=%s\n' "$EMAIL_TO"
} > "$CONFIG"

umask 022

pct push "$CTID" "$TMP/$ASSET" /tmp/gham-release.tar.gz --perms 0600
pct push "$CTID" "$CONFIG" /tmp/gham-config.env --perms 0600
if [[ -n "$RESTORE_PATH" ]]; then
  echo "[7/10] Copying archive to LXC..."
  pct push "$CTID" "$RESTORE_PATH" /tmp/gham-restore.tar.gz --perms 0600
else
  echo "[7/10] Fresh database selected."
fi

echo "[8/10] Installing application inside LXC..."
pct exec "$CTID" -- bash -lc 'rm -rf /tmp/gham && mkdir /tmp/gham && tar -xzf /tmp/gham-release.tar.gz -C /tmp/gham --strip-components=1 && bash /tmp/gham/deploy/lxc-install.sh /tmp/gham'

echo "[9/10] Checking service health..."
pct exec "$CTID" -- bash -lc 'set -a; . /etc/github-audit-monitor/config.env; set +a; curl -fsS "http://127.0.0.1:${PORT:-8080}/health"' >/dev/null
IP="$(pct exec "$CTID" -- hostname -I 2>/dev/null | awk '{print $1}')"
echo "[10/10] Complete."
cat <<OUT

GitHub Audit Monitor $RELEASE_TAG installed successfully.
CT ID:      $CTID
Hostname:   $HOSTNAME
IP:         ${IP:-unknown}
Panel:      http://${IP:-LXC_IP}:8080
Status:     pct exec $CTID -- gham-status
Backup:     pct exec $CTID -- gham-backup
Update:     pct exec $CTID -- gham-update

Security note: the web UI currently has no built-in authentication. Keep it on a trusted LAN or restrict access with firewall/reverse proxy.
OUT
