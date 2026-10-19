import base64
import hashlib
import hmac
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from argon2.low_level import Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SECURITY_DB_PATH = os.getenv("SECURITY_DB_PATH", "/var/lib/github-audit-monitor/security.db")
MASTER_KEY_PATH = os.getenv("MASTER_KEY_PATH", "/etc/github-audit-monitor/master.key")
SETUP_CODE_TTL_HOURS = int(os.getenv("SETUP_CODE_TTL_HOURS", "24"))
SESSION_IDLE_MINUTES = int(os.getenv("SESSION_IDLE_MINUTES", "60"))
SESSION_MAX_HOURS = int(os.getenv("SESSION_MAX_HOURS", "12"))
LOGIN_WINDOW_MINUTES = int(os.getenv("LOGIN_WINDOW_MINUTES", "15"))
LOGIN_MAX_FAILURES = int(os.getenv("LOGIN_MAX_FAILURES", "5"))
LOGIN_BLOCK_MINUTES = int(os.getenv("LOGIN_BLOCK_MINUTES", "15"))
PASSWORD_MIN_LENGTH = int(os.getenv("PASSWORD_MIN_LENGTH", "14"))

_PASSWORD_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)


def utc_now_dt():
    return datetime.now(timezone.utc)


def utc_now():
    return utc_now_dt().isoformat()


def _parse_dt(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _security_connect():
    path = Path(SECURITY_DB_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_security_db():
    with _security_connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_login_at TEXT,
                last_login_ip TEXT,
                session_version INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS setup_state (
                id INTEGER PRIMARY KEY CHECK (id=1),
                code_hash TEXT,
                expires_at TEXT,
                created_at TEXT,
                used_at TEXT
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                admin_id INTEGER NOT NULL,
                session_version INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                remote_ip TEXT,
                user_agent_hash TEXT,
                FOREIGN KEY(admin_id) REFERENCES admins(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS login_throttle (
                throttle_key TEXT PRIMARY KEY,
                failures INTEGER NOT NULL DEFAULT 0,
                window_started_at TEXT NOT NULL,
                blocked_until TEXT
            );

            CREATE TABLE IF NOT EXISTS app_settings (
                setting_key TEXT PRIMARY KEY,
                setting_value TEXT,
                updated_at TEXT NOT NULL,
                updated_by TEXT
            );

            CREATE TABLE IF NOT EXISTS encrypted_secrets (
                secret_name TEXT PRIMARY KEY,
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL,
                updated_at TEXT NOT NULL,
                updated_by TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_admin ON sessions(admin_id);
            CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
            """
        )


def ensure_master_key(create=False):
    path = Path(MASTER_KEY_PATH)
    if path.exists():
        raw = path.read_bytes()
        if len(raw) != 32:
            raise RuntimeError(f"Invalid master key length at {path}")
        return raw
    if not create:
        raise RuntimeError(f"Master key missing: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = secrets.token_bytes(32)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, raw)
    finally:
        os.close(fd)
    return raw


def _aesgcm():
    return AESGCM(ensure_master_key(create=False))


def _secret_aad(name):
    return ("github-audit-monitor:" + name).encode("utf-8")


def set_secret(name, plaintext, updated_by=None):
    value = str(plaintext or "")
    if not value:
        delete_secret(name)
        return
    nonce = secrets.token_bytes(12)
    ciphertext = _aesgcm().encrypt(nonce, value.encode("utf-8"), _secret_aad(name))
    with _security_connect() as conn:
        conn.execute(
            """INSERT INTO encrypted_secrets(secret_name,nonce,ciphertext,updated_at,updated_by)
               VALUES(?,?,?,?,?)
               ON CONFLICT(secret_name) DO UPDATE SET
                 nonce=excluded.nonce,ciphertext=excluded.ciphertext,
                 updated_at=excluded.updated_at,updated_by=excluded.updated_by""",
            (name, nonce, ciphertext, utc_now(), updated_by),
        )


def get_secret(name):
    with _security_connect() as conn:
        row = conn.execute(
            "SELECT nonce,ciphertext FROM encrypted_secrets WHERE secret_name=?", (name,)
        ).fetchone()
    if not row:
        return None
    try:
        return _aesgcm().decrypt(row["nonce"], row["ciphertext"], _secret_aad(name)).decode("utf-8")
    except Exception as exc:
        raise RuntimeError(f"Unable to decrypt secret {name!r}") from exc


def delete_secret(name):
    with _security_connect() as conn:
        conn.execute("DELETE FROM encrypted_secrets WHERE secret_name=?", (name,))


def set_setting(key, value, updated_by=None):
    text = None if value is None else str(value)
    with _security_connect() as conn:
        conn.execute(
            """INSERT INTO app_settings(setting_key,setting_value,updated_at,updated_by)
               VALUES(?,?,?,?)
               ON CONFLICT(setting_key) DO UPDATE SET
                 setting_value=excluded.setting_value,updated_at=excluded.updated_at,updated_by=excluded.updated_by""",
            (key, text, utc_now(), updated_by),
        )


def get_setting(key, default=None):
    with _security_connect() as conn:
        row = conn.execute("SELECT setting_value FROM app_settings WHERE setting_key=?", (key,)).fetchone()
    return row["setting_value"] if row else default


def has_admin():
    with _security_connect() as conn:
        row = conn.execute("SELECT 1 FROM admins LIMIT 1").fetchone()
    return bool(row)


def admin_count():
    with _security_connect() as conn:
        return int(conn.execute("SELECT COUNT(*) FROM admins").fetchone()[0])


def validate_password(password):
    password = str(password or "")
    if len(password) < PASSWORD_MIN_LENGTH:
        return False, f"Hasło musi mieć co najmniej {PASSWORD_MIN_LENGTH} znaków."
    if len(password) > 1024:
        return False, "Hasło jest zbyt długie."
    return True, None


def _hash_setup_code(code):
    return hashlib.sha256(str(code).encode("utf-8")).hexdigest()


def create_setup_code(force=False):
    init_security_db()
    if has_admin() and not force:
        raise RuntimeError("Administrator account already exists")
    raw = secrets.token_urlsafe(24)
    pretty = "-".join(raw[i:i+4] for i in range(0, len(raw), 4))
    expires = utc_now_dt() + timedelta(hours=SETUP_CODE_TTL_HOURS)
    with _security_connect() as conn:
        conn.execute(
            """INSERT INTO setup_state(id,code_hash,expires_at,created_at,used_at)
               VALUES(1,?,?,?,NULL)
               ON CONFLICT(id) DO UPDATE SET
                 code_hash=excluded.code_hash,expires_at=excluded.expires_at,
                 created_at=excluded.created_at,used_at=NULL""",
            (_hash_setup_code(pretty), expires.isoformat(), utc_now()),
        )
    return pretty


def setup_code_valid(code):
    with _security_connect() as conn:
        row = conn.execute("SELECT * FROM setup_state WHERE id=1").fetchone()
    if not row or not row["code_hash"] or row["used_at"]:
        return False
    expires = _parse_dt(row["expires_at"])
    if not expires or expires <= utc_now_dt():
        return False
    return hmac.compare_digest(row["code_hash"], _hash_setup_code(code))


def create_admin_from_setup(code, username, password):
    username = str(username or "").strip()
    if not (3 <= len(username) <= 64):
        raise ValueError("Login administratora musi mieć od 3 do 64 znaków.")
    ok, message = validate_password(password)
    if not ok:
        raise ValueError(message)
    if has_admin():
        raise RuntimeError("Administrator account already exists")
    if not setup_code_valid(code):
        raise ValueError("Nieprawidłowy lub wygasły kod konfiguracji.")
    password_hash = _PASSWORD_HASHER.hash(password)
    now = utc_now()
    with _security_connect() as conn:
        conn.execute(
            "INSERT INTO admins(username,password_hash,created_at,updated_at) VALUES(?,?,?,?)",
            (username, password_hash, now, now),
        )
        conn.execute("UPDATE setup_state SET used_at=?,code_hash=NULL WHERE id=1", (now,))
    return username


def _throttle_key(namespace, username, remote_ip):
    raw = f"{namespace}\0{str(username or '').strip().lower()}\0{str(remote_ip or '')}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def throttle_status(namespace, username, remote_ip):
    key = _throttle_key(namespace, username, remote_ip)
    now = utc_now_dt()
    with _security_connect() as conn:
        row = conn.execute("SELECT * FROM login_throttle WHERE throttle_key=?", (key,)).fetchone()
    if not row:
        return False, 0
    blocked = _parse_dt(row["blocked_until"])
    if blocked and blocked > now:
        return True, max(1, int((blocked - now).total_seconds()))
    return False, 0


def record_auth_failure(namespace, username, remote_ip):
    key = _throttle_key(namespace, username, remote_ip)
    now = utc_now_dt()
    window_cutoff = now - timedelta(minutes=LOGIN_WINDOW_MINUTES)
    with _security_connect() as conn:
        row = conn.execute("SELECT * FROM login_throttle WHERE throttle_key=?", (key,)).fetchone()
        failures = 1
        window_started = now
        if row:
            old_start = _parse_dt(row["window_started_at"])
            if old_start and old_start >= window_cutoff:
                failures = int(row["failures"] or 0) + 1
                window_started = old_start
        blocked_until = None
        if failures >= LOGIN_MAX_FAILURES:
            blocked_until = (now + timedelta(minutes=LOGIN_BLOCK_MINUTES)).isoformat()
        conn.execute(
            """INSERT INTO login_throttle(throttle_key,failures,window_started_at,blocked_until)
               VALUES(?,?,?,?)
               ON CONFLICT(throttle_key) DO UPDATE SET
                 failures=excluded.failures,window_started_at=excluded.window_started_at,
                 blocked_until=excluded.blocked_until""",
            (key, failures, window_started.isoformat(), blocked_until),
        )


def clear_auth_failures(namespace, username, remote_ip):
    key = _throttle_key(namespace, username, remote_ip)
    with _security_connect() as conn:
        conn.execute("DELETE FROM login_throttle WHERE throttle_key=?", (key,))


def authenticate_admin(username, password, remote_ip=None):
    # Apply both per-IP and per-username+IP throttles so rotating usernames does not
    # bypass brute-force protection on a LAN-exposed login page.
    for namespace, subject in (("login-ip", "*"), ("login-user", username)):
        blocked, wait_seconds = throttle_status(namespace, subject, remote_ip)
        if blocked:
            return None, f"Zbyt wiele prób logowania. Spróbuj ponownie za około {max(1, wait_seconds // 60 + 1)} min."
    with _security_connect() as conn:
        row = conn.execute("SELECT * FROM admins WHERE username=? COLLATE NOCASE", (str(username or "").strip(),)).fetchone()
    if not row:
        record_auth_failure("login-ip", "*", remote_ip)
        record_auth_failure("login-user", username, remote_ip)
        return None, "Nieprawidłowy login lub hasło."
    try:
        _PASSWORD_HASHER.verify(row["password_hash"], str(password or ""))
    except (VerifyMismatchError, InvalidHashError):
        record_auth_failure("login-ip", "*", remote_ip)
        record_auth_failure("login-user", username, remote_ip)
        return None, "Nieprawidłowy login lub hasło."
    clear_auth_failures("login-ip", "*", remote_ip)
    clear_auth_failures("login-user", username, remote_ip)
    if _PASSWORD_HASHER.check_needs_rehash(row["password_hash"]):
        with _security_connect() as conn:
            conn.execute(
                "UPDATE admins SET password_hash=?,updated_at=? WHERE id=?",
                (_PASSWORD_HASHER.hash(password), utc_now(), row["id"]),
            )
    with _security_connect() as conn:
        conn.execute(
            "UPDATE admins SET last_login_at=?,last_login_ip=? WHERE id=?",
            (utc_now(), remote_ip, row["id"]),
        )
    return dict(row), None


def verify_admin_password(admin_id, password):
    with _security_connect() as conn:
        row = conn.execute("SELECT password_hash FROM admins WHERE id=?", (admin_id,)).fetchone()
    if not row:
        return False
    try:
        return bool(_PASSWORD_HASHER.verify(row["password_hash"], str(password or "")))
    except (VerifyMismatchError, InvalidHashError):
        return False


def change_admin_password(admin_id, current_password, new_password):
    if not verify_admin_password(admin_id, current_password):
        raise ValueError("Bieżące hasło jest nieprawidłowe.")
    ok, message = validate_password(new_password)
    if not ok:
        raise ValueError(message)
    now = utc_now()
    with _security_connect() as conn:
        row = conn.execute("SELECT session_version FROM admins WHERE id=?", (admin_id,)).fetchone()
        if not row:
            raise ValueError("Administrator nie istnieje.")
        new_version = int(row["session_version"] or 1) + 1
        conn.execute(
            "UPDATE admins SET password_hash=?,updated_at=?,session_version=? WHERE id=?",
            (_PASSWORD_HASHER.hash(new_password), now, new_version, admin_id),
        )
        conn.execute("DELETE FROM sessions WHERE admin_id=?", (admin_id,))


def _session_token_hash(token):
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()


def _ua_hash(user_agent):
    return hashlib.sha256(str(user_agent or "").encode("utf-8")).hexdigest()


def create_session(admin_id, remote_ip=None, user_agent=None):
    token = secrets.token_urlsafe(48)
    now = utc_now_dt()
    expires = now + timedelta(hours=SESSION_MAX_HOURS)
    with _security_connect() as conn:
        admin = conn.execute("SELECT session_version FROM admins WHERE id=?", (admin_id,)).fetchone()
        if not admin:
            raise ValueError("Administrator does not exist")
        conn.execute("DELETE FROM sessions WHERE expires_at<=?", (now.isoformat(),))
        conn.execute(
            """INSERT INTO sessions(token_hash,admin_id,session_version,created_at,expires_at,last_seen_at,remote_ip,user_agent_hash)
               VALUES(?,?,?,?,?,?,?,?)""",
            (_session_token_hash(token), admin_id, int(admin["session_version"]), now.isoformat(), expires.isoformat(), now.isoformat(), remote_ip, _ua_hash(user_agent)),
        )
    return token, expires


def load_session(token, user_agent=None):
    if not token:
        return None
    token_hash = _session_token_hash(token)
    now = utc_now_dt()
    with _security_connect() as conn:
        row = conn.execute(
            """SELECT s.*,a.username,a.session_version AS current_session_version
               FROM sessions s JOIN admins a ON a.id=s.admin_id
               WHERE s.token_hash=?""", (token_hash,)
        ).fetchone()
        if not row:
            return None
        expires = _parse_dt(row["expires_at"])
        last_seen = _parse_dt(row["last_seen_at"])
        if not expires or expires <= now or not last_seen or last_seen + timedelta(minutes=SESSION_IDLE_MINUTES) <= now:
            conn.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
            return None
        if int(row["session_version"]) != int(row["current_session_version"]):
            conn.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
            return None
        if row["user_agent_hash"] and not hmac.compare_digest(row["user_agent_hash"], _ua_hash(user_agent)):
            conn.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
            return None
        conn.execute("UPDATE sessions SET last_seen_at=? WHERE token_hash=?", (now.isoformat(), token_hash))
    return {"id": row["admin_id"], "username": row["username"], "expires_at": row["expires_at"]}


def revoke_session(token):
    if not token:
        return
    with _security_connect() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash=?", (_session_token_hash(token),))


def revoke_all_sessions(admin_id):
    with _security_connect() as conn:
        conn.execute("DELETE FROM sessions WHERE admin_id=?", (admin_id,))


def github_connection(include_token=True):
    org = (get_setting("github_org") or os.getenv("GITHUB_ORG", "")).strip()
    token = get_secret("github_token") if include_token else None
    with _security_connect() as conn:
        rows = conn.execute(
            "SELECT setting_key,setting_value,updated_at FROM app_settings WHERE setting_key IN ('github_login','github_last_test_at','github_token_fingerprint','github_token_updated_at')"
        ).fetchall()
        secret_exists = bool(conn.execute("SELECT 1 FROM encrypted_secrets WHERE secret_name='github_token'").fetchone())
    meta = {r["setting_key"]: r["setting_value"] for r in rows}
    return {
        "org": org,
        "token": token,
        "configured": bool(org and (bool(token) if include_token else secret_exists)),
        "login": meta.get("github_login"),
        "last_test_at": meta.get("github_last_test_at"),
        "token_fingerprint": meta.get("github_token_fingerprint"),
        "token_updated_at": meta.get("github_token_updated_at"),
    }


def save_github_connection(org, token, login=None, updated_by=None):
    org = str(org or "").strip()
    token = str(token or "").strip()
    if not org:
        raise ValueError("Nazwa organizacji GitHub jest wymagana.")
    if not token:
        raise ValueError("Token GitHub jest wymagany.")
    set_secret("github_token", token, updated_by=updated_by)
    set_setting("github_org", org, updated_by=updated_by)
    set_setting("github_login", login or "", updated_by=updated_by)
    set_setting("github_last_test_at", utc_now(), updated_by=updated_by)
    fingerprint = token[-4:] if len(token) >= 4 else "****"
    set_setting("github_token_fingerprint", fingerprint, updated_by=updated_by)
    set_setting("github_token_updated_at", utc_now(), updated_by=updated_by)


def remove_github_connection(updated_by=None):
    delete_secret("github_token")
    for key in ("github_org", "github_login", "github_last_test_at", "github_token_fingerprint", "github_token_updated_at"):
        set_setting(key, "", updated_by=updated_by)


def migrate_legacy_env_connection():
    """One-way convenience migration for v0.7.x installs. Does not edit the env file."""
    init_security_db()
    try:
        if get_secret("github_token"):
            return False
    except RuntimeError:
        return False
    token = os.getenv("GITHUB_TOKEN", "").strip()
    org = os.getenv("GITHUB_ORG", "").strip()
    if not token or not org:
        return False
    set_secret("github_token", token, updated_by="legacy-env-migration")
    set_setting("github_org", org, updated_by="legacy-env-migration")
    set_setting("github_token_fingerprint", token[-4:] if len(token) >= 4 else "****", updated_by="legacy-env-migration")
    set_setting("github_token_updated_at", utc_now(), updated_by="legacy-env-migration")
    return True
