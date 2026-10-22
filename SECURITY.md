# Security model

GitHub Audit Monitor stores organization access history and may contain personally identifiable information. Treat the LXC as an administrative service.

## Network boundary

The default installer exposes HTTP port `8080` on the LXC so the panel is reachable from the local network. The application requires authentication for all data-bearing routes, CSV exports and `/api/*` endpoints. Only `/health` is anonymous and returns a minimal status.

Do not expose port `8080` directly to the Internet. Prefer Proxmox/network firewall rules that limit access to a trusted administration LAN/VLAN. HTTPS/reverse proxy can be added later; set `SESSION_COOKIE_SECURE=true` only when requests are actually served over HTTPS.

## Local administrator

A fresh installation has no default username or password. The installer creates a high-entropy one-time Setup Code. The code is stored only as a SHA-256 digest, expires, and is invalidated after the first administrator is created.

Administrator passwords are hashed with Argon2id. They are never stored or logged in plaintext.

Sessions use high-entropy random tokens. Only SHA-256 token digests are stored server-side. Sessions have idle and absolute expiration, are bound to the browser User-Agent and are invalidated on password change.

## GitHub PAT

The GitHub PAT is entered only after authentication in `Settings -> GitHub connection`. Sensitive changes require the current administrator password.

At rest, the PAT is protected with AES-256-GCM in `security.db`. The encryption key is a separate host-specific 32-byte key at:

```text
/etc/github-audit-monitor/master.key
```

The application must be able to decrypt the PAT in memory to call GitHub. Therefore, a root compromise of the LXC is outside the protection boundary: root can access both encrypted secrets and the master key.

The collector implements GitHub HTTP GET operations only.

## CSRF and browser controls

State-changing requests require a CSRF token. Cookies use `HttpOnly` and `SameSite=Strict`. Responses include `no-store`, frame denial, MIME-sniffing protection, a restrictive Content Security Policy and a no-referrer policy.

## Backups

`gham-backup` creates a portable business-data backup. It intentionally excludes:

- `security.db`,
- `master.key`,
- administrator credentials,
- active sessions,
- GitHub PAT.

A browser-based business-data import replaces only `github-audit.db`; it validates SQLite integrity and creates a safety backup first. `security.db`, the administrator account, sessions, master key and GitHub PAT are deliberately outside that restore path.

After a portable restore on a new LXC, create a new local administrator and configure the GitHub connection again.

A full Proxmox/PBS backup of the entire LXC will naturally include local security state and must be protected accordingly.

## Token rotation

If a GitHub token expires or is revoked, sign in and use `Settings -> GitHub connection -> Save / replace token`. The previous token is replaced atomically in encrypted storage after the new token successfully passes the connection test.
