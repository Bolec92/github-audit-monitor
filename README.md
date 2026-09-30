# GitHub Audit Monitor

Self-hosted GitHub organization access monitor. It combines current REST API snapshots with imported GitHub Audit Log history and optional manual corrections.

## Highlights

- current organization members and outside collaborators,
- teams, repository access and effective permission paths,
- readable snapshot transitions such as `Direct Write -> Team platform Read`,
- Audit Log import for historical actors and events,
- combined **Change history** view (snapshot + Audit Log),
- user profiles with invitation/removal/access history,
- statistics, CSV export and local read-only API,
- SQLite backups and portable restore archives,
- one-line Proxmox VE LXC installer.

The old GitHub Audit Mapper importer is no longer exposed in the UI. Existing databases that already contain migrated Mapper data remain fully compatible and continue to use those records.

## Proxmox VE - one-line LXC install

After at least one release is published:

```bash
bash -c "$(curl -fsSL https://github.com/Bolec92/github-audit-monitor/releases/latest/download/proxmox-install.sh)"
```

Run the command **on the Proxmox VE host as root**.

The wizard supports:

- Default or Advanced LXC settings,
- unprivileged Debian LXC,
- DHCP or static IPv4 configuration,
- GitHub organization and API token configuration,
- optional exact e-mail domain rewrite,
- fresh database or restore from an existing `github-audit-backup-*.tar.gz` archive.

The application is installed natively in the LXC with Python venv + systemd. Docker inside LXC is not required.

> Security: the web UI currently has no built-in authentication. Keep port 8080 on a trusted network or restrict it using Proxmox firewall/reverse proxy/SSH tunneling.

## Configuration

Native LXC config:

```text
/etc/github-audit-monitor/config.env
```

Important variables:

```ini
GITHUB_ORG=my-organization
GITHUB_TOKEN=github_token_here
TZ=Europe/Warsaw
SNAPSHOT_HOUR=3
SNAPSHOT_MINUTE=0
RUN_ON_START=true
BIND_ADDRESS=0.0.0.0
PORT=8080
DATABASE_PATH=/var/lib/github-audit-monitor/github-audit.db
BACKUP_DIR=/var/backups/github-audit-monitor
BACKUP_KEEP=30
EMAIL_DOMAIN_REWRITE_FROM=
EMAIL_DOMAIN_REWRITE_TO=
```

E-mail rewriting is optional and exact-domain only. Example:

```ini
EMAIL_DOMAIN_REWRITE_FROM=old-company.com
EMAIL_DOMAIN_REWRITE_TO=new-company.com
```

`user@old-company.com` is displayed/exported as `user@new-company.com`; all other domains remain untouched.

## Audit Log import

Recommended filter:

```text
action:org.invite_member action:org.add_member action:org.remove_member action:org.add_outside_collaborator action:org.remove_outside_collaborator action:org.update_default_repository_permission action:team.add_member action:team.remove_member action:team.add_repository action:team.remove_repository action:team.update_repository_permission action:repo.add_member action:repo.update_member action:repo.remove_member
```

The same JSON/JSONL can be imported repeatedly; duplicate events are deduplicated.

## Backups

Create a portable archive inside the LXC:

```bash
gham-backup
```

Example output:

```text
/var/backups/github-audit-monitor/github-audit-backup-20260929-120000.tar.gz
```

The archive contains the SQLite database and a manifest. It does **not** contain the GitHub token.

Restore:

```bash
gham-restore /path/github-audit-backup-20260929-120000.tar.gz
```

The Proxmox installer can also restore this archive during LXC creation.

## Status and update

```bash
gham-status
gham-update
```

`gham-update` creates a database backup before replacing application code and performs a health check.

## Existing Docker VM upgrade from v0.6

The repository still contains `docker-compose.yml` and `update-v0.7.sh` for the existing test VM.

```bash
./update-v0.7.sh
```

v0.7 makes e-mail rewriting generic. Set the desired domains in `/opt/github-audit/.env`, then restart:

```bash
sudo docker compose up -d
```

Existing `data/`, `backups/`, `.env`, Audit Log data and historical Mapper-derived records are preserved.

## Publishing a release

The repository contains `.github/workflows/release.yml`.

1. Set `VERSION`, e.g. `0.7.0`.
2. Commit and push to `main`.
3. Create and push matching tag:

```bash
git tag v0.7.0
git push origin v0.7.0
```

GitHub Actions creates a release with:

- `github-audit-monitor-v0.7.0.tar.gz`
- `proxmox-install.sh`
- `SHA256SUMS`

The release installer contains the exact release tag and verifies the application tarball checksum before creating the LXC.

For strongest release integrity, enable GitHub release immutability before publishing production releases.

## Data model

1. **GitHub REST snapshot** - current state and current access paths.
2. **GitHub Audit Log** - historical actors, invitations, removals and access actions.
3. **Manual overrides** - corrections for incomplete identity data.
4. **Legacy migrated records** - retained internally for databases previously migrated from GitHub Audit Mapper; there is no longer a Mapper import page.

GitHub ID is preferred as the stable identity key whenever it is available.

## License

MIT
