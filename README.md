# GitHub Audit Monitor

Self-hosted GitHub organization access monitor focused on the gaps that are awkward to audit on GitHub Team. It combines current REST API snapshots with manually imported GitHub Audit Log history and optional manual identity corrections.

## Highlights

- current organization members, outside collaborators and repository collaborators,
- teams, repository access and effective permission paths,
- readable snapshot transitions such as `Direct Write -> Team platform Read`,
- manual GitHub Audit Log JSON/JSONL import for historical actors and events,
- combined **Change history** view (snapshot + Audit Log),
- user profiles with invitation/removal/access history,
- statistics and CSV export,
- local read-only JSON API protected by the same administrator session,
- SQLite portable data backups and restore archives,
- one-line Proxmox VE LXC installer,
- mandatory first-run administrator setup and authenticated panel,
- GitHub PAT encrypted at rest and managed from the panel.

The old GitHub Audit Mapper importer is no longer exposed in the UI. Existing databases that already contain migrated Mapper data remain compatible and continue to use those records.

## Security model in v0.8

See also [`SECURITY.md`](SECURITY.md) for the deployment threat model and secret-handling details.

The panel is not anonymous. On a fresh installation the Proxmox installer generates a random one-time **Setup Code**. The first browser session must use that code to create the local administrator account before any application data can be viewed.

Security controls include:

- administrator passwords stored only as Argon2id hashes,
- server-side sessions with random tokens; only a token hash is stored in SQLite,
- `HttpOnly` + `SameSite=Strict` session cookies,
- idle and absolute session expiration,
- login brute-force throttling/temporary lockout,
- CSRF protection on modifying requests,
- re-authentication with the current admin password before GitHub PAT changes,
- GitHub PAT encrypted using AES-256-GCM with a host-specific 256-bit master key,
- application/security responses marked `no-store`, clickjacking protection and restrictive browser headers,
- all UI, CSV and `/api/*` routes require login; only the minimal `/health` endpoint is anonymous.

Native LXC secret storage:

```text
/var/lib/github-audit-monitor/github-audit.db   # snapshots/audit/business data
/var/lib/github-audit-monitor/security.db       # admin/session/encrypted secrets
/etc/github-audit-monitor/master.key            # host-specific encryption key
```

`master.key` is not included in portable backups. A portable restore therefore intentionally does not restore the administrator account, sessions or GitHub token.

### HTTP / LAN deployment

The default release intentionally serves HTTP on port `8080` and is designed to be reachable only from a trusted LAN/VLAN. Do **not** port-forward this port to the Internet.

Authentication prevents an unauthenticated LAN client from reading application data, but HTTP does not encrypt traffic in transit. If HTTPS/reverse proxy is added later, set:

```ini
SESSION_COOKIE_SECURE=true
```

## Proxmox VE - one-line LXC install

```bash
bash -c "$(curl -fsSL https://github.com/Bolec92/github-audit-monitor/releases/latest/download/proxmox-install.sh)"
```

Run the command **on the Proxmox VE host as root**.

The wizard is intentionally infrastructure-only. It supports:

- Default or Advanced LXC resources,
- unprivileged Debian LXC,
- storage and bridge selection,
- DHCP or static IPv4 configuration.

Application settings are completed after first login in the panel: GitHub connection, optional old database import, e-mail normalization and snapshot schedule.

A new install does **not** ask for a GitHub PAT. After the LXC is ready the installer prints a one-time Setup Code:

```text
ONE-TIME SETUP CODE:
xxxx-xxxx-xxxx-...
```

Open:

```text
http://LXC_IP:8080/setup
```

Create the local administrator account, then open **Settings**. Configure the GitHub organization/PAT, optionally import an old database, set e-mail normalization and choose the snapshot schedule. A new PAT is tested before it can be saved.

If the Setup Code is lost before the first administrator account is created:

```bash
pct exec CTID -- gham-security setup-code
```

The application is installed natively in the LXC using Python venv + Gunicorn + systemd. Docker inside LXC is not required.

## GitHub connection

GitHub organization and PAT are managed in the authenticated web panel. New installations leave these legacy environment fields empty:

```ini
GITHUB_ORG=
GITHUB_TOKEN=
```

They remain only for one-way migration from v0.7.x. During an upgrade, an existing plaintext `GITHUB_TOKEN` is encrypted into `security.db`; after a successful v0.8 health check the token is removed from `config.env`.

The application collector only implements HTTP `GET` operations against GitHub.

## Configuration

Native LXC config:

```text
/etc/github-audit-monitor/config.env
```

Important non-secret defaults/runtime variables:

```ini
TZ=Europe/Warsaw
SNAPSHOT_ENABLED=true
SNAPSHOT_HOUR=3
SNAPSHOT_MINUTE=0
RUN_ON_START=false
BIND_ADDRESS=0.0.0.0
PORT=8080
DATABASE_PATH=/var/lib/github-audit-monitor/github-audit.db
BACKUP_DIR=/var/backups/github-audit-monitor
SECURITY_DB_PATH=/var/lib/github-audit-monitor/security.db
MASTER_KEY_PATH=/etc/github-audit-monitor/master.key
SESSION_COOKIE_SECURE=false
SESSION_IDLE_MINUTES=60
SESSION_MAX_HOURS=12
LOGIN_MAX_FAILURES=5
LOGIN_BLOCK_MINUTES=15
EMAIL_DOMAIN_REWRITE_FROM=
EMAIL_DOMAIN_REWRITE_TO=
```

E-mail normalization is configured from **Settings -> E-mail normalization**. It is exact-domain only and affects presentation/export only; source records are not destructively rewritten. The environment variables remain only as defaults/legacy fallback.

## Audit Log import

This project keeps Audit Log import manual so it remains useful on GitHub Team plans. Export JSON/JSONL from the organization Audit Log and upload it on **Import Audit Log**.

Recommended filter:

```text
action:org.invite_member action:org.add_member action:org.remove_member action:org.add_outside_collaborator action:org.remove_outside_collaborator action:org.update_default_repository_permission action:team.add_member action:team.remove_member action:team.add_repository action:team.remove_repository action:team.update_repository_permission action:repo.add_member action:repo.update_member action:repo.remove_member
```

The same file can be imported repeatedly; duplicate events are deduplicated.

## Portable backups

Create a portable application-data archive inside the LXC:

```bash
gham-backup
```

Example:

```text
/var/backups/github-audit-monitor/github-audit-backup-20261019-150000.tar.gz
```

The portable archive contains the business SQLite database and manifest. It deliberately excludes:

- GitHub PAT,
- administrator password hash,
- sessions,
- `security.db`,
- `master.key`.

Restore from the authenticated panel under **Settings -> Data and migration** by uploading either a portable `.tar.gz` backup or a raw `github-audit.db`. The panel validates SQLite integrity and creates an automatic safety backup before replacement. `security.db`, administrator credentials and GitHub PAT remain untouched.

CLI restore is also available:

```bash
gham-restore /path/github-audit-backup-20261019-150000.tar.gz
```

## Status, update and security helper

```bash
gham-status
gham-update
gham-security setup-code
```

`gham-update` creates a portable data backup before replacing application code, verifies release SHA-256, updates dependencies and performs a health check. Upgrading from v0.7.x also migrates the legacy PAT into encrypted storage.

## Existing Docker / Hyper-V VM upgrade

The repository retains Docker Compose support for the original test VM.

From the unpacked v0.8 release directory:

```bash
./update-v0.8.sh
```

The script preserves `data/`, `backups/` and `.env`, generates local security storage, encrypts an existing legacy PAT, removes its plaintext value after a healthy start, and prints the one-time Setup Code.

The Docker build remains bound to host loopback by default:

```text
127.0.0.1:8080
```

so the existing SSH tunnel workflow continues to work.

## Publishing a release

The repository contains `.github/workflows/release.yml`.

1. Set `VERSION`, e.g. `0.8.0`.
2. Commit and push to `main`.
3. Create and push the matching tag:

```bash
git tag v0.8.0
git push origin v0.8.0
```

GitHub Actions creates:

- `github-audit-monitor-v0.8.0.tar.gz`
- `proxmox-install.sh`
- `SHA256SUMS`

The release installer is pinned to its exact release tag and verifies the application tarball checksum before installation. Enabling GitHub immutable releases is strongly recommended.

## Data model

1. **GitHub REST snapshot** - current state and access paths.
2. **GitHub Audit Log** - historical actors, invitations, removals and access actions.
3. **Manual overrides** - corrections for incomplete identity data.
4. **Legacy migrated records** - retained internally for databases previously migrated from GitHub Audit Mapper.

GitHub ID is preferred as the stable identity key whenever available.

## License

MIT
