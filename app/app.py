import csv
import io
import json
import logging
import os
import secrets
import shutil
import tarfile
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from flask import Flask, Response, g, jsonify, redirect, render_template, request, send_file, url_for

from audit import (
    actor_for_direct_repo, actor_for_team_membership, actor_for_team_repo,
    audit_index, identity_from_audit, norm,
)
from collector import collect_snapshot, compare_snapshots, test_connection
from security import (
    authenticate_admin, change_admin_password, clear_auth_failures, create_admin_from_setup,
    create_session, get_setting, github_connection, has_admin, init_security_db, load_session,
    migrate_legacy_env_connection, record_auth_failure, remove_github_connection, revoke_session,
    save_github_connection, set_setting, setup_code_valid, throttle_status, verify_admin_password,
)
from db import (
    backup_database, create_portable_backup, create_snapshot, database_operation_lock,
    delete_user_override, fail_snapshot, finish_snapshot, get_overrides, import_audit_events,
    init_db, latest_snapshot_any, latest_successful_snapshot, list_audit_events,
    list_audit_imports, list_mapper_users, list_changes, list_snapshots,
    restore_database_from_path, save_user_override, set_user_hidden,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
LOG = logging.getLogger("app")
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024 * 1024
run_lock = threading.Lock()
run_state = {"running": False, "progress": "Idle", "last_error": None}
DEFAULT_TZ_NAME = os.getenv("TZ", "Europe/Warsaw")
DEFAULT_SNAPSHOT_HOUR = int(os.getenv("SNAPSHOT_HOUR", "3"))
DEFAULT_SNAPSHOT_MINUTE = int(os.getenv("SNAPSHOT_MINUTE", "0"))
DEFAULT_SNAPSHOT_ENABLED = os.getenv("SNAPSHOT_ENABLED", "true").lower() in {"1", "true", "yes", "on"}
RUN_ON_START = os.getenv("RUN_ON_START", "true").lower() in {"1", "true", "yes", "on"}
PORT = int(os.getenv("PORT", "8080"))
BIND_ADDRESS = os.getenv("BIND_ADDRESS", "0.0.0.0").strip() or "0.0.0.0"
SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "gham_session")
CSRF_COOKIE_NAME = os.getenv("CSRF_COOKIE_NAME", "gham_csrf")
SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").lower() in {"1", "true", "yes", "on"}
SESSION_COOKIE_MAX_AGE = max(300, int(os.getenv("SESSION_MAX_HOURS", "12")) * 3600)
COOKIE_SAMESITE = "Strict"
DEFAULT_EMAIL_DOMAIN_REWRITE_FROM = os.getenv("EMAIL_DOMAIN_REWRITE_FROM", "").strip().lower()
DEFAULT_EMAIL_DOMAIN_REWRITE_TO = os.getenv("EMAIL_DOMAIN_REWRITE_TO", "").strip().lower()
AUDIT_FILTER = "action:org.invite_member action:org.add_member action:org.remove_member action:org.add_outside_collaborator action:org.remove_outside_collaborator action:org.update_default_repository_permission action:team.add_member action:team.remove_member action:team.add_repository action:team.remove_repository action:team.update_repository_permission action:repo.add_member action:repo.update_member action:repo.remove_member"


def _setting_bool(key, default=False):
    value = get_setting(key, None)
    if value is None:
        return bool(default)
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def snapshot_config():
    tz_name = (get_setting("snapshot_timezone", DEFAULT_TZ_NAME) or DEFAULT_TZ_NAME).strip()
    try:
        ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, ValueError):
        tz_name = DEFAULT_TZ_NAME
    try:
        hour = int(get_setting("snapshot_hour", DEFAULT_SNAPSHOT_HOUR))
    except (TypeError, ValueError):
        hour = DEFAULT_SNAPSHOT_HOUR
    try:
        minute = int(get_setting("snapshot_minute", DEFAULT_SNAPSHOT_MINUTE))
    except (TypeError, ValueError):
        minute = DEFAULT_SNAPSHOT_MINUTE
    hour = min(23, max(0, hour))
    minute = min(59, max(0, minute))
    return {
        "enabled": _setting_bool("snapshot_enabled", DEFAULT_SNAPSHOT_ENABLED),
        "timezone": tz_name,
        "hour": hour,
        "minute": minute,
        "time": f"{hour:02d}:{minute:02d}",
    }


def email_rewrite_config():
    source = get_setting("email_domain_rewrite_from", DEFAULT_EMAIL_DOMAIN_REWRITE_FROM)
    target = get_setting("email_domain_rewrite_to", DEFAULT_EMAIL_DOMAIN_REWRITE_TO)
    return {
        "from": str(source or "").strip().lower().lstrip("@"),
        "to": str(target or "").strip().lower().lstrip("@"),
    }


def _valid_domain(value):
    value = str(value or "").strip().lower().lstrip("@")
    if not value:
        return True
    return " " not in value and "@" not in value and "." in value and not value.startswith(".") and not value.endswith(".")


def render_settings(message=None, error=None, data_result=None):
    return render_template(
        "settings.html", org=current_org(), cfg=github_connection(include_token=False),
        email_cfg=email_rewrite_config(), snapshot_cfg=snapshot_config(),
        message=message, error=error, data_result=data_result,
        recent_snapshots=list_snapshots(8),
    )


def _extract_uploaded_database(upload):
    """Return a validated temporary SQLite path from .db or tar/tar.gz without unsafe extraction."""
    if not upload or not upload.filename:
        raise ValueError("Wybierz plik bazy lub backup .tar.gz.")
    workdir = tempfile.mkdtemp(prefix="gham-import-")
    upload_path = Path(workdir) / "upload.bin"
    upload.save(upload_path)
    if upload_path.stat().st_size == 0:
        shutil.rmtree(workdir, ignore_errors=True)
        raise ValueError("Przesłany plik jest pusty.")
    with open(upload_path, "rb") as fh:
        if fh.read(16) == b"SQLite format 3\x00":
            return workdir, str(upload_path)
    try:
        with tarfile.open(upload_path, "r:*") as tf:
            candidates = [m for m in tf.getmembers() if m.isfile() and Path(m.name).name == "github-audit.db"]
            if not candidates:
                raise ValueError("Backup nie zawiera pliku github-audit.db.")
            member = candidates[0]
            if member.size > 240 * 1024 * 1024:
                raise ValueError("Baza w archiwum jest zbyt duża.")
            source = tf.extractfile(member)
            if source is None:
                raise ValueError("Nie udało się odczytać bazy z archiwum.")
            db_path = Path(workdir) / "github-audit.db"
            with open(db_path, "wb") as out:
                shutil.copyfileobj(source, out, length=1024 * 1024)
            return workdir, str(db_path)
    except tarfile.TarError as exc:
        shutil.rmtree(workdir, ignore_errors=True)
        raise ValueError("Obsługiwany jest plik github-audit.db albo backup .tar.gz z GitHub Audit Monitor.") from exc


def current_org():
    try:
        cfg = github_connection(include_token=False)
        return cfg.get("org") or os.getenv("GITHUB_ORG", "").strip() or "Nie skonfigurowano"
    except Exception:
        return os.getenv("GITHUB_ORG", "").strip() or "Nie skonfigurowano"


def client_ip():
    # Do not trust X-Forwarded-For until TRUST_PROXY is explicitly implemented.
    return request.remote_addr or "unknown"


def csrf_token():
    token = request.cookies.get(CSRF_COOKIE_NAME)
    if not token:
        token = getattr(g, "new_csrf_token", None) or secrets.token_urlsafe(32)
        g.new_csrf_token = token
    return token


def _csrf_valid():
    cookie = request.cookies.get(CSRF_COOKIE_NAME)
    supplied = request.form.get("_csrf") or request.headers.get("X-CSRF-Token")
    return bool(cookie and supplied and secrets.compare_digest(str(cookie), str(supplied)))


def _safe_next(value):
    value = str(value or "").strip()
    if value.startswith("/") and not value.startswith("//"):
        return value
    return url_for("index")


def reauthenticate_current_admin(password):
    """Rate-limited password confirmation for sensitive authenticated operations."""
    admin = getattr(g, "current_admin", None) or {}
    subject = str(admin.get("id") or admin.get("username") or "admin")
    blocked, wait_seconds = throttle_status("reauth", subject, client_ip())
    if blocked:
        return False, f"Zbyt wiele nieudanych prób. Spróbuj ponownie za około {max(1, wait_seconds // 60 + 1)} min."
    if not verify_admin_password(admin.get("id"), password):
        record_auth_failure("reauth", subject, client_ip())
        return False, "Bieżące hasło administratora jest nieprawidłowe."
    clear_auth_failures("reauth", subject, client_ip())
    return True, None


@app.before_request
def enforce_authentication():
    g.current_admin = None
    csrf_token()
    endpoint = request.endpoint or ""
    admin_exists = has_admin()

    if endpoint == "health" or endpoint == "static":
        return None

    if not admin_exists:
        if endpoint != "setup":
            if request.path.startswith("/api/"):
                return jsonify({"error": "setup_required"}), 503
            return redirect(url_for("setup"))
        if request.method == "POST" and not _csrf_valid():
            return "Nieprawidłowy token CSRF", 400
        return None

    if endpoint == "setup":
        return redirect(url_for("index"))

    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        try:
            g.current_admin = load_session(token, user_agent=request.headers.get("User-Agent"))
        except Exception:
            LOG.exception("Session validation failed")
            g.current_admin = None

    if endpoint == "login":
        if g.current_admin:
            return redirect(url_for("index"))
        if request.method == "POST" and not _csrf_valid():
            return "Nieprawidłowy token CSRF", 400
        return None

    if not g.current_admin:
        if request.path.startswith("/api/"):
            return jsonify({"error": "authentication_required"}), 401
        return redirect(url_for("login", next=request.full_path if request.query_string else request.path))

    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not _csrf_valid():
        return "Nieprawidłowy token CSRF", 400
    return None


@app.after_request
def security_headers(response):
    if not request.cookies.get(CSRF_COOKIE_NAME):
        response.set_cookie(
            CSRF_COOKIE_NAME, csrf_token(), max_age=12 * 3600, httponly=True,
            secure=SESSION_COOKIE_SECURE, samesite=COOKIE_SAMESITE, path="/"
        )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'none'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    )
    return response


@app.context_processor
def inject_security_context():
    try:
        cfg = github_connection(include_token=False)
        github_configured = bool(cfg.get("configured"))
    except Exception:
        github_configured = False
    return {
        "csrf_token": csrf_token(),
        "current_admin": getattr(g, "current_admin", None),
        "session_cookie_secure": SESSION_COOKIE_SECURE,
        "github_configured": github_configured,
    }


def progress(msg): run_state["progress"] = msg


def execute_snapshot():
    if not run_lock.acquire(blocking=False):
        return False
    run_state.update({"running": True, "progress": "Starting...", "last_error": None})
    snapshot_id = None
    try:
        with database_operation_lock():
            try:
                connection = github_connection(include_token=True)
                if not connection.get("configured"):
                    raise RuntimeError("Połączenie GitHub nie jest skonfigurowane. Ustaw organizację i token w Ustawieniach.")
                org = connection["org"]
                token = connection["token"]
                snapshot_id = create_snapshot(org)
                previous = latest_successful_snapshot(exclude_id=snapshot_id)
                current, login = collect_snapshot(progress=progress, org=org, token=token)
                changes = compare_snapshots(previous.get("data") if previous else None, current)
                finish_snapshot(snapshot_id, current, changes, authenticated_user=login)
                backup = backup_database()
                run_state["progress"] = f"Completed. Changes: {len(changes)}. Backup: {backup}"
                LOG.info(run_state["progress"])
                return True
            except Exception as exc:
                if snapshot_id is not None:
                    fail_snapshot(snapshot_id, exc)
                raise
    except Exception as exc:
        LOG.exception("Snapshot failed")
        run_state["last_error"] = str(exc)
        run_state["progress"] = f"FAILED: {exc}"
        return False
    finally:
        run_state["running"] = False
        run_lock.release()


def start_snapshot_background():
    if run_state["running"]: return False
    threading.Thread(target=execute_snapshot, daemon=True, name="snapshot-now").start(); return True


def scheduler_loop():
    last_slot = None
    while True:
        cfg = snapshot_config()
        try:
            now = datetime.now(ZoneInfo(cfg["timezone"]))
        except (ZoneInfoNotFoundError, ValueError):
            now = datetime.now(ZoneInfo(DEFAULT_TZ_NAME))
        slot = f"{now.date().isoformat()}-{cfg['hour']:02d}:{cfg['minute']:02d}"
        due = cfg["enabled"] and now.hour == cfg["hour"] and now.minute == cfg["minute"]
        if due and slot != last_slot:
            last_slot = slot
            try:
                if github_connection(include_token=False).get("configured"):
                    execute_snapshot()
                else:
                    LOG.info("Scheduled snapshot skipped: GitHub connection is not configured")
            except Exception:
                LOG.exception("Scheduled snapshot preflight failed")
        time.sleep(20)


def latest_data():
    row = latest_successful_snapshot(); return row.get("data") if row else None


def permission_rank(p):
    return {"unknown":0,"read":1,"pull":1,"triage":2,"write":3,"push":3,"maintain":4,"admin":5}.get(str(p or "").lower(),0)


def user_key(github_id=None, login=None):
    if github_id is not None and str(github_id): return "id:" + str(github_id)
    return "login:" + norm(login)


def normalize_email(value):
    """Optionally rewrite one exact e-mail domain for presentation/export; source data stays intact."""
    email = str(value or "").strip()
    if not email or "@" not in email:
        return email or None
    local, domain = email.rsplit("@", 1)
    cfg = email_rewrite_config()
    if cfg["from"] and cfg["to"] and domain.lower() == cfg["from"]:
        return f"{local}@{cfg['to']}"
    return email

def user_status_label(u):
    if u.get("hidden"): return "hidden"
    if u.get("is_outside_collaborator"): return "outside_collaborator"
    if u.get("is_repo_collaborator"): return "repo_collaborator"
    if u.get("is_org_member"): return "org_member"
    return u.get("profile_state") or "historical"


def apply_user_scope(all_users, scope="active", q=""):
    scope=(scope or "active").strip().lower()
    if scope not in {"active","outside","repo_collaborators","historical","all","hidden"}: scope="active"
    if scope=="active": users=[u for u in all_users if u.get("is_org_member") and not u.get("hidden")]
    elif scope=="outside": users=[u for u in all_users if u.get("is_outside_collaborator") and not u.get("hidden")]
    elif scope=="repo_collaborators": users=[u for u in all_users if u.get("is_repo_collaborator") and not u.get("hidden")]
    elif scope=="historical": users=[u for u in all_users if not u.get("current") and not u.get("hidden")]
    elif scope=="hidden": users=[u for u in all_users if u.get("hidden")]
    else: users=[u for u in all_users if not u.get("hidden")]
    q=(q or "").strip().lower()
    if q:
        users=[u for u in users if any(q in str(v or "").lower() for v in [u.get("login"),u.get("email"),u.get("id"),u.get("invited_by"),u.get("removed_by"),u.get("member_type")]) or any(q in str(t).lower() for t in u.get("teams",[])) or any(q in r["repo"].lower() for r in u.get("repo_rows",[]))]
    return users, scope


def change_user_ref(change):
    value=change.get("after") or change.get("before") or {}
    et=change.get("entity_type")
    if et in {"member","outside_collaborator"}: user=value
    elif et in {"team_member","direct_repo","user_repo_access"}: user=value.get("user") or {}
    else: user={}
    gid=user.get("id"); login=user.get("login")
    return gid, login


def _title_permission(value):
    text=str(value or "unknown").strip().lower()
    return {"pull":"Read","push":"Write","read":"Read","write":"Write","triage":"Triage","maintain":"Maintain","admin":"Admin","none":"None","unknown":"Unknown"}.get(text,text.title())


def access_state_label(value):
    if not value:
        return "None"
    grants=value.get("grants") or []
    if not grants:
        return "None"
    parts=[]
    for grant in grants:
        st=grant.get("source_type")
        source=grant.get("source") or "?"
        perm=_title_permission(grant.get("permission"))
        if st=="direct": parts.append(f"Direct {perm}")
        elif st=="team": parts.append(f"Team {source} {perm}")
        elif st=="organization": parts.append(f"Org default {perm}")
        else: parts.append(f"{source} {perm}")
    return " + ".join(parts)


def change_value_label(change, value):
    et=change.get("entity_type")
    if not value:
        return "None"
    if et=="user_repo_access": return access_state_label(value)
    if et=="team_member": return f"Team {value.get('team') or '?'}"
    if et=="direct_repo": return f"Direct {_title_permission(value.get('permission'))}"
    if et=="team_repo": return f"Team {value.get('team') or '?'} {_title_permission(value.get('permission'))}"
    if et=="member": return f"Member {value.get('login') or '?'}"
    if et=="outside_collaborator": return f"Outside collaborator {value.get('login') or '?'}"
    if et=="repository": return value.get("full_name") or "Repo"
    if et=="team": return value.get("slug") or value.get("name") or "Team"
    return str(value)


def change_summary(change):
    before=change.get("before") or {}; after=change.get("after") or {}; value=after or before
    typ=change.get("change_type"); et=change.get("entity_type")
    verb={"added":"Dodano","removed":"Usunięto","changed":"Zmieniono"}.get(typ,typ)
    if et=="user_repo_access":
        repo=value.get("repo") or "?"
        return f"{repo}: {access_state_label(before)} → {access_state_label(after)}"
    if et=="member":
        if typ=="changed":
            bits=[]
            if before.get("login") != after.get("login"): bits.append(f"username {before.get('login') or '—'} → {after.get('login') or '—'}")
            if before.get("type") != after.get("type"): bits.append(f"typ {before.get('type') or '—'} → {after.get('type') or '—'}")
            return "Członek organizacji: " + (", ".join(bits) or "zmieniono dane")
        return f"{verb} członka organizacji"
    if et=="outside_collaborator":
        if typ=="changed":
            bits=[]
            if before.get("login") != after.get("login"): bits.append(f"username {before.get('login') or '—'} → {after.get('login') or '—'}")
            return "Outside collaborator: " + (", ".join(bits) or "zmieniono dane")
        return f"{verb} outside collaboratora"
    if et=="team_member":
        team=value.get("team") or "?"
        return f"{verb} {'do' if typ=='added' else 'z'} teamu {team}" if typ in {"added","removed"} else f"Zmieniono członkostwo w teamie {team}"
    if et=="direct_repo":
        repo=value.get("repo") or "?"
        bp=_title_permission(before.get("permission")); ap=_title_permission(after.get("permission"))
        if typ=="changed": return f"Direct access {repo}: {bp} → {ap}"
        state=after if typ=="added" else before
        return f"{verb} direct access {repo} ({_title_permission(state.get('permission'))})"
    if et=="team_repo":
        repo=value.get("repo") or "?"; team=value.get("team") or "?"
        bp=_title_permission(before.get("permission")); ap=_title_permission(after.get("permission"))
        if typ=="changed": return f"Team {team} → {repo}: {bp} → {ap}"
        return f"{verb} dostęp teamu {team} do {repo} ({_title_permission((after if typ=='added' else before).get('permission'))})"
    if et=="repository": return f"{verb} repozytorium {value.get('full_name') or '?'}"
    if et=="team": return f"{verb} team {value.get('slug') or value.get('name') or '?'}"
    return f"{verb} {et}"


def decorate_changes(changes, users=None):
    users = users if users is not None else build_users(latest_data(), include_hidden=True)
    by_id={str(u.get("id")):u for u in users if u.get("id") not in (None,"")}
    by_login={norm(u.get("login")):u for u in users if u.get("login")}
    out=[]
    for c in changes:
        d=dict(c)
        # v0.6 stored a few direct_repo rows when only GitHub metadata (e.g. affiliation) changed.
        # Hide those historical false positives if the actual user/repo/permission stayed identical.
        if d.get("entity_type")=="direct_repo" and d.get("change_type")=="changed":
            b=d.get("before") or {}; a=d.get("after") or {}
            bu=b.get("user") or {}; au=a.get("user") or {}
            if (b.get("repo")==a.get("repo") and b.get("permission")==a.get("permission") and
                bu.get("id")==au.get("id") and bu.get("login")==au.get("login")):
                continue
        d["summary"]=change_summary(d)
        d["before_label"]=change_value_label(d,d.get("before"))
        d["after_label"]=change_value_label(d,d.get("after"))
        gid,login=change_user_ref(d); u=(by_id.get(str(gid)) if gid not in (None,"") else None) or (by_login.get(norm(login)) if login else None)
        d["user_key"]=u.get("user_key") if u else None
        d["user_login"]=(u.get("login") if u else login) or None
        out.append(d)
    return out


def audit_event_summary(event):
    action=event.get("action") or "unknown"
    actor=event.get("actor") or "GitHub"
    user=event.get("target_username") or event.get("invite_email") or (f"ID {event.get('target_user_id')}" if event.get("target_user_id") else "użytkownika")
    team=event.get("team") or "?"
    repo=event.get("repo") or "?"
    perm=_title_permission(event.get("permission"))
    mapping={
        "org.invite_member": f"{actor} zaprosił {user} do organizacji",
        "org.add_member": f"{actor} dodał {user} do organizacji",
        "org.remove_member": f"{actor} usunął {user} z organizacji",
        "org.add_outside_collaborator": f"{actor} dodał {user} jako outside collaboratora",
        "org.remove_outside_collaborator": f"{actor} usunął outside collaboratora {user}",
        "team.add_member": f"{actor} dodał {user} do teamu {team}",
        "team.remove_member": f"{actor} usunął {user} z teamu {team}",
        "team.add_repository": f"{actor} nadał teamowi {team} dostęp {perm} do {repo}",
        "team.remove_repository": f"{actor} odebrał teamowi {team} dostęp do {repo}",
        "team.update_repository_permission": f"{actor} zmienił dostęp teamu {team} do {repo} na {perm}",
        "repo.add_member": f"{actor} nadał {user} direct access {perm} do {repo}",
        "repo.update_member": f"{actor} zmienił direct access {user} do {repo} na {perm}",
        "repo.remove_member": f"{actor} odebrał {user} direct access do {repo}",
        "org.update_default_repository_permission": f"{actor} zmienił domyślne uprawnienie organizacji na {perm}",
    }
    return mapping.get(action, f"{actor}: {action} · {user}")


def decorate_audit_events(events, users=None):
    users = users if users is not None else build_users(latest_data(), include_hidden=True)
    by_id={str(u.get("id")):u for u in users if u.get("id") not in (None,"")}
    by_login={norm(u.get("login")):u for u in users if u.get("login")}
    out=[]
    for e in events:
        d=dict(e)
        u=(by_id.get(str(d.get("target_user_id"))) if d.get("target_user_id") else None) or (by_login.get(norm(d.get("target_username"))) if d.get("target_username") else None)
        d["summary"]=audit_event_summary(d)
        d["user_key"]=u.get("user_key") if u else None
        d["user_login"]=(u.get("login") if u else d.get("target_username")) or None
        d["source"]="audit"
        d["timestamp"]=str(d.get("created_at") or d.get("imported_at") or "")
        out.append(d)
    return out


def build_combined_history(source="all", q="", limit=500):
    users=build_users(latest_data(), include_hidden=True)
    rows=[]
    if source in {"all","snapshot"}:
        for c in decorate_changes(list_changes(max(limit*2,500)),users):
            rows.append({
                "source":"snapshot","timestamp":str(c.get("detected_at") or ""),"summary":c.get("summary"),
                "actor":None,"user_key":c.get("user_key"),"user_login":c.get("user_login"),
                "team":None,"repo":((c.get("after") or c.get("before") or {}).get("repo")),
                "detail_type":c.get("entity_type"),"change_type":c.get("change_type"),
            })
    if source in {"all","audit"}:
        for e in decorate_audit_events(list_audit_events(max(limit*4,2000)),users):
            rows.append({
                "source":"audit","timestamp":e.get("timestamp"),"summary":e.get("summary"),"actor":e.get("actor"),
                "user_key":e.get("user_key"),"user_login":e.get("user_login"),"team":e.get("team"),"repo":e.get("repo"),
                "detail_type":e.get("action"),"change_type":None,
            })
    q=(q or "").strip().lower()
    if q:
        rows=[r for r in rows if q in " ".join(str(r.get(k) or "") for k in ("summary","actor","user_login","team","repo","detail_type")).lower()]
    rows.sort(key=lambda r:r.get("timestamp") or "",reverse=True)
    return rows[:limit]

def user_api_row(u, detailed=False):
    row={
        "user_key":u.get("user_key"),"github_username":u.get("login"),"email":u.get("email"),
        "github_id":str(u.get("id")) if u.get("id") not in (None,"") else None,
        "status":user_status_label(u),"team_count":u.get("team_count",0),"repo_count":u.get("repo_count",0),
        "invited_by":u.get("invited_by"),"invited_at":u.get("invited_at"),"joined_at":u.get("joined_at"),
        "removed_by":u.get("removed_by"),"removed_at":u.get("removed_at"),"display_name":u.get("display_name"),
    }
    if detailed:
        row.update({"teams":u.get("teams",[]),"repositories":u.get("repo_rows",[]),"profile_source":u.get("profile_source"),"notes":u.get("notes")})
    return row


def build_users(snapshot, include_hidden=False):
    snapshot = snapshot or {"members":[],"outsideCollaborators":[],"teams":[],"repositories":[]}
    events = list_audit_events(50000); aidx = audit_index(events); overrides = get_overrides(); mapper_users = list_mapper_users()
    users = {}

    outside_ids = {str(u.get("id")) for u in snapshot.get("outsideCollaborators",[]) if u.get("id") is not None}
    outside_logins = {norm(u.get("login")) for u in snapshot.get("outsideCollaborators",[]) if u.get("login")}
    member_ids = {str(u.get("id")) for u in snapshot.get("members",[]) if u.get("id") is not None}
    member_logins = {norm(u.get("login")) for u in snapshot.get("members",[]) if u.get("login")}

    def ensure(u, snapshot_role=None):
        gid, login = u.get("id"), u.get("login")
        key = user_key(gid, login)
        if key not in users:
            users[key] = {"user_key":key,"id":gid,"login":login,"source_id":gid,"source_login":login,"teams":[],"repos":{},"snapshot":False,"snapshot_role":None}
        target = users[key]
        if snapshot_role:
            target["snapshot"] = True
            # member beats fallback repository_collaborator; explicit outside beats fallback too.
            old = target.get("snapshot_role")
            if old not in {"member","outside_collaborator"} or snapshot_role in {"member","outside_collaborator"}:
                target["snapshot_role"] = snapshot_role
        return target

    for u in snapshot.get("members", []): ensure(u, "member")
    for u in snapshot.get("outsideCollaborators", []): ensure(u, "outside_collaborator")

    # Keep historical/audit-only identities too (for example a removed user no longer present in today's snapshot).
    for e in events:
        if e.get("action") not in {"org.add_member", "org.remove_member", "org.add_outside_collaborator", "org.remove_outside_collaborator", "team.add_member", "team.remove_member", "repo.add_member", "repo.update_member", "repo.remove_member"}:
            continue
        gid, login = e.get("target_user_id"), e.get("target_username")
        if not gid and not login:
            continue
        existing = None
        if gid:
            existing = next((x for x in users.values() if str(x.get("id") or "") == str(gid)), None)
        if not existing and login:
            existing = next((x for x in users.values() if norm(x.get("login")) == norm(login)), None)
        if not existing:
            k = user_key(gid, login)
            users[k] = {"user_key":k,"id":gid,"login":login,"source_id":gid,"source_login":login,"teams":[],"repos":{},"snapshot":False,"snapshot_role":None}

    for t in snapshot.get("teams", []):
        for u in t.get("members", []): ensure(u, "member")["teams"].append(t.get("slug"))

    team_members = {}
    for t in snapshot.get("teams", []):
        team_members[t.get("id") or t.get("slug")] = {user_key(u.get("id"),u.get("login")) for u in t.get("members",[])}
    for repo in snapshot.get("repositories", []):
        repo_name = repo.get("full_name")
        for t in repo.get("teams", []):
            tid = t.get("id") or t.get("slug")
            for uk in team_members.get(tid,set()):
                if uk in users:
                    users[uk]["repos"].setdefault(repo_name,[]).append({"source":"team","team":t.get("slug"),"permission":t.get("permission") or "unknown"})
        for u in repo.get("directCollaborators", []):
            uid = str(u.get("id")) if u.get("id") is not None else None
            login_norm = norm(u.get("login"))
            affiliation = u.get("affiliation")
            if affiliation == "outside" or (uid and uid in outside_ids) or (login_norm and login_norm in outside_logins):
                role = "outside_collaborator"
            elif (uid and uid in member_ids) or (login_norm and login_norm in member_logins):
                role = "member"
            else:
                # Fallback only if the org-level outside-collaborator endpoint was unavailable/incomplete.
                role = "repository_collaborator"
            target = ensure(u, role)
            target["repos"].setdefault(repo_name,[]).append({"source":"direct","permission":u.get("permission") or "unknown"})

    base_perm = snapshot.get("organizationDefaultPermission")
    if base_perm and str(base_perm).lower() not in {"none","no_permission"}:
        for u in users.values():
            if u.get("snapshot_role") != "member":
                continue
            for repo in snapshot.get("repositories",[]):
                u["repos"].setdefault(repo.get("full_name"),[]).append({"source":"organization","permission":base_perm})

    # Attach migrated identity/history from the old GitHub Audit Mapper. Snapshot keeps current username/access.
    for legacy in mapper_users:
        match = None
        if legacy.get("github_id"):
            match = next((u for u in users.values() if str(u.get("id") or "") == str(legacy["github_id"])), None)
        if not match and legacy.get("username"):
            aliases=set([norm(legacy.get("username"))]) | {norm(x) for x in (legacy.get("aliases") or {}).get("usernames",[]) if x}
            match = next((u for u in users.values() if norm(u.get("login")) in aliases), None)
        if match:
            match["mapper"] = legacy
        else:
            lk = "legacy:" + legacy.get("mapper_key", "unknown")
            users[lk] = {"user_key":lk,"id":legacy.get("github_id"),"login":legacy.get("username"),"source_id":legacy.get("github_id"),"source_login":legacy.get("username"),"teams":[],"repos":{},"snapshot":False,"snapshot_role":None,"mapper":legacy}

    # Attach overrides to current users; unmatched overrides become manual users.
    for ok, ov in overrides.items():
        match = users.get(ok)
        if not match and ov.get("github_id"):
            match = next((u for u in users.values() if str(u.get("id") or "") == str(ov["github_id"])), None)
        if not match and not ov.get("github_id") and ov.get("username"):
            match = next((u for u in users.values() if norm(u.get("login")) == norm(ov["username"])), None)
        if match:
            match["override"] = ov
        else:
            users[ok] = {"user_key":ok,"id":ov.get("github_id"),"login":ov.get("username"),"source_id":None,"source_login":None,"teams":[],"repos":{},"snapshot":False,"snapshot_role":None,"override":ov}

    out=[]
    for u in users.values():
        ov = u.get("override") or {}; legacy = u.get("mapper") or {}
        source_id, source_login = u.get("source_id") or u.get("id"), u.get("source_login") or u.get("login")
        legacy_aliases = (legacy.get("aliases") or {}).get("usernames", [])
        identity = identity_from_audit(aidx, source_id or ov.get("github_id") or legacy.get("github_id"), [source_login, ov.get("username"), legacy.get("username"), *legacy_aliases])
        # Manual override wins. Mapper migration is preferred for identity fields because it may include painstaking manual corrections.
        u["email"] = normalize_email(ov.get("email") or legacy.get("email") or identity.get("email"))
        u["login"] = ov.get("username") or u.get("login") or legacy.get("username")
        u["id"] = ov.get("github_id") or u.get("id") or legacy.get("github_id")
        u["display_name"] = ov.get("display_name")
        u["notes"] = ov.get("notes")
        u["hidden"] = bool(ov.get("hidden"))
        u["invited_by"] = ov.get("invited_by") or identity.get("invited_by") or legacy.get("invited_by")
        u["invited_at"] = ov.get("invited_at") or identity.get("invited_at") or legacy.get("invited_at")
        u["joined_at"] = ov.get("joined_at") or identity.get("joined_at") or legacy.get("joined_at")
        u["removed_at"] = identity.get("removed_at") or legacy.get("removed_at")
        u["removed_by"] = identity.get("removed_by") or legacy.get("removed_by")
        u["audit_events"] = identity.get("events",[])
        u["audit_events_view"] = [dict(e, summary=audit_event_summary(e)) for e in u["audit_events"]]
        u["current"] = bool(u.get("snapshot"))
        role = u.get("snapshot_role")
        u["member_type"] = role
        u["is_org_member"] = role == "member"
        u["is_outside_collaborator"] = role == "outside_collaborator"
        u["is_repo_collaborator"] = role == "repository_collaborator"
        if u["hidden"]:
            u["profile_state"] = "hidden"
        elif u["is_outside_collaborator"]:
            u["profile_state"] = "outside"
        elif u["is_repo_collaborator"]:
            u["profile_state"] = "repo_collaborator"
        elif u["current"]:
            u["profile_state"] = "current"
        elif u["removed_at"] or str(legacy.get("status") or "").lower() == "removed":
            u["profile_state"] = "removed"
        elif str(legacy.get("status") or "").lower() == "pending":
            u["profile_state"] = "pending"
        else:
            u["profile_state"] = "historical"
        u["mapper_status"] = legacy.get("status")
        u["mapper_manual"] = bool(legacy.get("manual"))
        u["historical_usernames"] = [x for x in legacy_aliases if norm(x) != norm(u.get("login"))]
        u["historical_emails"] = sorted({normalize_email(x) for x in (legacy.get("aliases") or {}).get("emails",[]) if normalize_email(x) and norm(normalize_email(x)) != norm(u.get("email"))})
        u["teams"] = sorted(set(filter(None,u["teams"])))
        repo_rows=[]
        for repo_name, grants in sorted(u["repos"].items()):
            enriched=[]
            for g in grants:
                x=dict(g)
                if g["source"]=="team":
                    tm_evt=actor_for_team_membership(aidx,source_id,source_login,g.get("team"))
                    tr_evt=actor_for_team_repo(aidx,g.get("team"),repo_name)
                    x["user_team_actor"] = tm_evt.get("actor") if tm_evt else None; x["user_team_at"] = tm_evt.get("created_at") if tm_evt else None
                    x["team_repo_actor"] = tr_evt.get("actor") if tr_evt else None; x["team_repo_at"] = tr_evt.get("created_at") if tr_evt else None
                elif g["source"]=="direct":
                    dr_evt=actor_for_direct_repo(aidx,source_id,source_login,repo_name)
                    x["actor"] = dr_evt.get("actor") if dr_evt else None; x["at"] = dr_evt.get("created_at") if dr_evt else None
                enriched.append(x)
            eff=max(enriched,key=lambda g:permission_rank(g.get("permission")))
            repo_rows.append({"repo":repo_name,"effective":eff.get("permission"),"grants":enriched})
        u["repo_rows"]=repo_rows; u["repo_count"]=len(repo_rows); u["team_count"]=len(u["teams"])
        parts=[]
        if u.get("snapshot"): parts.append("snapshot")
        if legacy: parts.append("legacy")
        if identity.get("events"): parts.append("audit")
        if ov: parts.append("manual")
        u["profile_source"] = "+".join(parts) or "unknown"
        if include_hidden or not u["hidden"]: out.append(u)
    return sorted(out,key=lambda x:(str(x.get("email") or "").lower(),str(x.get("login") or "").lower()))

def find_user(key):
    return next((u for u in build_users(latest_data(), include_hidden=True) if u["user_key"]==key),None)


def parse_json_upload(file):
    raw=file.read().decode("utf-8-sig").strip()
    if not raw: return []
    try:
        obj=json.loads(raw)
        if isinstance(obj,list): return obj
        if isinstance(obj,dict) and isinstance(obj.get("records"),list): return obj["records"]
        if isinstance(obj,dict): return [obj]
    except json.JSONDecodeError:
        out=[]
        for line in raw.splitlines():
            line=line.strip()
            if line:
                try: out.append(json.loads(line))
                except json.JSONDecodeError: pass
        if out: return out
    raise ValueError("Nie udało się odczytać JSON/JSONL")

def parse_json_object(file):
    raw=file.read().decode("utf-8-sig").strip()
    if not raw: raise ValueError("Plik jest pusty")
    try: return json.loads(raw)
    except json.JSONDecodeError as exc: raise ValueError("Nie udało się odczytać JSON backupu Mappera") from exc


@app.route("/setup", methods=["GET", "POST"])
def setup():
    error = None
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        confirm = request.form.get("password_confirm") or ""
        code = request.form.get("setup_code") or ""
        blocked, wait_seconds = throttle_status("setup", "setup", client_ip())
        if blocked:
            error = f"Zbyt wiele nieudanych prób. Spróbuj ponownie za około {max(1, wait_seconds // 60 + 1)} min."
        elif password != confirm:
            record_auth_failure("setup", "setup", client_ip())
            error = "Hasła nie są identyczne."
        elif not setup_code_valid(code):
            record_auth_failure("setup", "setup", client_ip())
            error = "Nieprawidłowy lub wygasły kod konfiguracji."
        else:
            try:
                create_admin_from_setup(code, username, password)
                clear_auth_failures("setup", "setup", client_ip())
                admin, auth_error = authenticate_admin(username, password, client_ip())
                if not admin:
                    raise RuntimeError(auth_error or "Nie udało się utworzyć sesji administratora.")
                token, _ = create_session(admin["id"], client_ip(), request.headers.get("User-Agent"))
                resp = redirect(url_for("github_settings"))
                resp.set_cookie(SESSION_COOKIE_NAME, token, max_age=SESSION_COOKIE_MAX_AGE, httponly=True, secure=SESSION_COOKIE_SECURE, samesite=COOKIE_SAMESITE, path="/")
                return resp
            except Exception as exc:
                LOG.exception("Initial setup failed")
                error = str(exc)
    return render_template("setup.html", org="GitHub Audit Monitor", error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        admin, error = authenticate_admin(username, password, client_ip())
        if admin:
            token, _ = create_session(admin["id"], client_ip(), request.headers.get("User-Agent"))
            resp = redirect(_safe_next(request.form.get("next") or request.args.get("next")))
            resp.set_cookie(SESSION_COOKIE_NAME, token, max_age=SESSION_COOKIE_MAX_AGE, httponly=True, secure=SESSION_COOKIE_SECURE, samesite=COOKIE_SAMESITE, path="/")
            return resp
    return render_template("login.html", org="GitHub Audit Monitor", error=error, next_target=_safe_next(request.args.get("next")))


@app.post("/logout")
def logout():
    revoke_session(request.cookies.get(SESSION_COOKIE_NAME))
    resp = redirect(url_for("login"))
    resp.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return resp


@app.route("/settings")
def settings_page():
    return render_settings()


@app.route("/settings/github", methods=["GET", "POST"])
def github_settings():
    if request.method == "GET":
        return redirect(url_for("settings_page"))
    action = (request.form.get("action") or "save").strip().lower()
    try:
        if action == "test_saved":
            existing = github_connection(include_token=True)
            if not existing.get("configured"):
                raise ValueError("Połączenie GitHub nie jest jeszcze zapisane.")
            result = test_connection(existing["org"], existing["token"])
            set_setting("github_login", result.get("login") or "", updated_by=g.current_admin["username"])
            set_setting("github_last_test_at", datetime.now(ZoneInfo("UTC")).isoformat(), updated_by=g.current_admin["username"])
            return render_settings(message=f"Zapisane połączenie działa. GitHub: {result.get('login') or 'unknown'} · organizacja: {result.get('organization') or existing['org']}.")

        current_password = request.form.get("current_password") or ""
        reauth_ok, reauth_error = reauthenticate_current_admin(current_password)
        if not reauth_ok:
            return render_settings(error=reauth_error), 429 if "Zbyt wiele" in reauth_error else 400

        if action == "remove":
            remove_github_connection(updated_by=g.current_admin["username"])
            return render_settings(message="Połączenie GitHub zostało usunięte.")

        org = (request.form.get("github_org") or "").strip()
        submitted_token = (request.form.get("github_token") or "").strip()
        existing = github_connection(include_token=True)
        token = submitted_token or existing.get("token") or ""
        if not token:
            raise ValueError("Wprowadź token GitHub.")
        result = test_connection(org, token)
        save_github_connection(org, token, login=result.get("login"), updated_by=g.current_admin["username"])
        return render_settings(message=f"Połączenie przetestowane i zapisane jako {result.get('login') or 'unknown'}.")
    except Exception as exc:
        LOG.warning("GitHub connection update failed: %s", exc)
        return render_settings(error=str(exc)), 400


@app.post("/settings/email")
def email_settings_update():
    source = (request.form.get("email_from") or "").strip().lower().lstrip("@")
    target = (request.form.get("email_to") or "").strip().lower().lstrip("@")
    if bool(source) != bool(target):
        return render_settings(error="Aby włączyć normalizację, podaj obie domeny. Aby wyłączyć, wyczyść oba pola."), 400
    if not _valid_domain(source) or not _valid_domain(target):
        return render_settings(error="Nieprawidłowa domena e-mail."), 400
    set_setting("email_domain_rewrite_from", source, updated_by=g.current_admin["username"])
    set_setting("email_domain_rewrite_to", target, updated_by=g.current_admin["username"])
    if source:
        return render_settings(message=f"Normalizacja e-mail zapisana: @{source} → @{target}. Dane źródłowe w bazie nie są przepisywane.")
    return render_settings(message="Normalizacja domeny e-mail została wyłączona.")


@app.post("/settings/snapshots")
def snapshot_settings_update():
    enabled = request.form.get("snapshot_enabled") == "1"
    time_value = (request.form.get("snapshot_time") or "03:00").strip()
    timezone_name = (request.form.get("snapshot_timezone") or DEFAULT_TZ_NAME).strip()
    try:
        hour_text, minute_text = time_value.split(":", 1)
        hour, minute = int(hour_text), int(minute_text)
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            raise ValueError
    except ValueError:
        return render_settings(error="Nieprawidłowa godzina snapshotu."), 400
    try:
        ZoneInfo(timezone_name)
    except (ZoneInfoNotFoundError, ValueError):
        return render_settings(error="Nieprawidłowa strefa czasowa, np. Europe/Warsaw."), 400
    actor = g.current_admin["username"]
    set_setting("snapshot_enabled", "true" if enabled else "false", updated_by=actor)
    set_setting("snapshot_hour", str(hour), updated_by=actor)
    set_setting("snapshot_minute", str(minute), updated_by=actor)
    set_setting("snapshot_timezone", timezone_name, updated_by=actor)
    return render_settings(message="Harmonogram snapshotów został zapisany. Zmiana działa bez restartu usługi.")


@app.post("/settings/data/export")
def data_export():
    path = create_portable_backup()
    return send_file(path, as_attachment=True, download_name=Path(path).name, mimetype="application/gzip", max_age=0)


@app.post("/settings/data/import")
def data_import():
    current_password = request.form.get("current_password") or ""
    reauth_ok, reauth_error = reauthenticate_current_admin(current_password)
    if not reauth_ok:
        return render_settings(error=reauth_error), 429 if "Zbyt wiele" in reauth_error else 400
    if request.form.get("confirm_replace") != "1":
        return render_settings(error="Potwierdź zastąpienie aktualnych danych."), 400
    upload = request.files.get("database_file")
    workdir = None
    try:
        workdir, db_path = _extract_uploaded_database(upload)
        result = restore_database_from_path(db_path)
        counts = result["live"]["counts"]
        summary = (
            f"Import zakończony. Snapshoty: {counts.get('snapshots', 0)}, "
            f"Audit Log: {counts.get('audit_events', 0)}, ręczne korekty: {counts.get('user_overrides', 0)}."
        )
        if result.get("safety_backup"):
            summary += f" Automatyczna kopia poprzedniej bazy: {Path(result['safety_backup']).name}."
        return render_settings(message=summary, data_result=result)
    except Exception as exc:
        LOG.warning("Business database import failed: %s", exc, exc_info=True)
        return render_settings(error=f"Import bazy nie powiódł się: {exc}"), 400
    finally:
        if workdir:
            shutil.rmtree(workdir, ignore_errors=True)


@app.post("/settings/account/password")
def account_password_change():
    error = None
    message = None
    current_password = request.form.get("current_password") or ""
    new_password = request.form.get("new_password") or ""
    confirm = request.form.get("new_password_confirm") or ""
    if new_password != confirm:
        error = "Nowe hasła nie są identyczne."
    else:
        reauth_ok, reauth_error = reauthenticate_current_admin(current_password)
        if not reauth_ok:
            error = reauth_error
            return render_settings(message=message, error=error), 429 if "Zbyt wiele" in error else 400
        try:
            change_admin_password(g.current_admin["id"], current_password, new_password)
            message = "Hasło zostało zmienione. Zaloguj się ponownie."
            resp = redirect(url_for("login", changed="1"))
            resp.delete_cookie(SESSION_COOKIE_NAME, path="/")
            return resp
        except Exception as exc:
            error = str(exc)
    return render_settings(message=message, error=error), 400


@app.route("/health")
def health():
    return jsonify({"ok": True})

@app.route("/")
def index():
    latest=latest_successful_snapshot(); snapshot=latest.get("data") if latest else None
    all_users=build_users(snapshot, include_hidden=True)
    active=[u for u in all_users if u.get("is_org_member") and not u.get("hidden")]
    outside=[u for u in all_users if u.get("is_outside_collaborator") and not u.get("hidden")]
    repo_collabs=[u for u in all_users if u.get("is_repo_collaborator") and not u.get("hidden")]
    historical=[u for u in all_users if not u.get("current") and not u.get("hidden")]
    hidden=[u for u in all_users if u.get("hidden")]
    sched=snapshot_config()
    schedule=(f"{sched['time']} ({sched['timezone']})" if sched["enabled"] else "wyłączone")
    return render_template("index.html",org=current_org(),latest=latest,snapshot=snapshot,users=active[:20],total_users=len(active),outside_count=len(outside),repo_collab_count=len(repo_collabs),historical_count=len(historical),hidden_count=len(hidden),changes=decorate_changes(list_changes(12), all_users),run_state=run_state,tz=sched["timezone"],schedule=schedule)

@app.route("/users")
def users_page():
    all_users=build_users(latest_data(), include_hidden=True)
    scope=request.args.get("scope","active").strip().lower()
    if scope not in {"active","outside","repo_collaborators","historical","all","hidden"}: scope="active"
    counts={
        "active":sum(1 for u in all_users if u.get("is_org_member") and not u.get("hidden")),
        "outside":sum(1 for u in all_users if u.get("is_outside_collaborator") and not u.get("hidden")),
        "repo_collaborators":sum(1 for u in all_users if u.get("is_repo_collaborator") and not u.get("hidden")),
        "historical":sum(1 for u in all_users if not u.get("current") and not u.get("hidden")),
        "hidden":sum(1 for u in all_users if u.get("hidden")),
    }
    counts["all"]=counts["active"]+counts["outside"]+counts["repo_collaborators"]+counts["historical"]
    q=request.args.get("q","").strip()
    users, scope = apply_user_scope(all_users, scope, q)
    return render_template("users.html",org=current_org(),users=users,q=q,scope=scope,counts=counts,run_state=run_state)

@app.route("/users/<path:key>")
def user_detail(key):
    user=find_user(key)
    if user is None: return "User not found",404
    return render_template("user.html",org=current_org(),user=user,run_state=run_state)

@app.route("/users/<path:key>/edit",methods=["GET","POST"])
def user_edit(key):
    user=find_user(key)
    if user is None: return "User not found",404
    if request.method=="POST":
        save_user_override(key, github_id=request.form.get("github_id") or None, username=request.form.get("username") or None,
            email=((request.form.get("email") or "").strip() or None), joined_at=request.form.get("joined_at") or None, invited_at=request.form.get("invited_at") or None,
            invited_by=request.form.get("invited_by") or None, display_name=request.form.get("display_name") or None, notes=request.form.get("notes") or None,
            hidden=request.form.get("hidden")=="1")
        backup_database(); return redirect(url_for("user_detail",key=key))
    return render_template("user_edit.html",org=current_org(),user=user)

@app.post("/users/<path:key>/reset-override")
def user_reset_override(key):
    delete_user_override(key); backup_database(); return redirect(url_for("user_detail",key=key))

@app.post("/users/<path:key>/hide")
def user_hide(key):
    user=find_user(key)
    if user is None: return "User not found",404
    set_user_hidden(key, True, github_id=user.get("id"), username=user.get("login"))
    backup_database()
    return redirect(url_for("users_page",scope="active"))

@app.post("/users/<path:key>/restore")
def user_restore(key):
    user=find_user(key)
    if user is None: return "User not found",404
    set_user_hidden(key, False, github_id=user.get("id"), username=user.get("login"))
    backup_database()
    return redirect(url_for("user_detail",key=key))

@app.route("/users/add",methods=["GET","POST"])
def user_add():
    if request.method=="POST":
        gid=(request.form.get("github_id") or "").strip(); username=(request.form.get("username") or "").strip()
        if not gid and not username: return "GitHub ID lub username jest wymagany",400
        key=user_key(gid or None,username or None)
        save_user_override(key, github_id=gid or None, username=username or None, email=((request.form.get("email") or "").strip() or None),
            joined_at=request.form.get("joined_at") or None, invited_at=request.form.get("invited_at") or None, invited_by=request.form.get("invited_by") or None,
            display_name=request.form.get("display_name") or None, notes=request.form.get("notes") or None, hidden=False)
        backup_database(); return redirect(url_for("user_detail",key=key))
    return render_template("user_edit.html",org=current_org(),user=None)

@app.route("/audit",methods=["GET","POST"])
def audit_import_page():
    result=None; error=None
    if request.method=="POST":
        try:
            f=request.files.get("file")
            if not f or not f.filename: raise ValueError("Wybierz plik JSON")
            events=parse_json_upload(f); result=import_audit_events(events,f.filename); backup_database()
        except Exception as exc: error=str(exc)
    return render_template("audit.html",org=current_org(),result=result,error=error,imports=list_audit_imports(20),audit_filter=AUDIT_FILTER)

@app.route("/statistics")
def statistics_page():
    invited={}; removed={}
    users=[u for u in build_users(latest_data(), include_hidden=True) if not u.get("hidden")]
    for u in users:
        if u.get("invited_by"):
            invited[u["invited_by"]]=invited.get(u["invited_by"],0)+1
        if u.get("removed_by"):
            removed[u["removed_by"]]=removed.get(u["removed_by"],0)+1
    inviters=sorted(invited.items(),key=lambda x:(-x[1],x[0].lower())); removers=sorted(removed.items(),key=lambda x:(-x[1],x[0].lower()))
    max_inv=max([n for _,n in inviters],default=1); max_rem=max([n for _,n in removers],default=1)
    inviter_bars=[(a,n,round(n/max_inv*100,1)) for a,n in inviters[:10]]
    remover_bars=[(a,n,round(n/max_rem*100,1)) for a,n in removers[:10]]
    recent_joined=sorted([u for u in users if u.get("joined_at")],key=lambda u:str(u.get("joined_at")),reverse=True)[:10]
    recent_removed=sorted([u for u in users if u.get("removed_at")],key=lambda u:str(u.get("removed_at")),reverse=True)[:10]
    total_joined=sum(1 for u in users if u.get("joined_at")); total_removed=sum(1 for u in users if u.get("removed_at"))
    denom=max(1,total_joined+total_removed); added_pct=round(total_joined/denom*100,1)
    return render_template("statistics.html",org=current_org(),inviters=inviters,removers=removers,inviter_bars=inviter_bars,remover_bars=remover_bars,recent_joined=recent_joined,recent_removed=recent_removed,total_joined=total_joined,total_removed=total_removed,added_pct=added_pct)

@app.route("/changes")
def changes_page():
    # Backward-compatible URL: snapshot changes now live inside the combined history view.
    return redirect(url_for("history_page", source="snapshot"), code=302)

@app.route("/history")
def history_page():
    source=(request.args.get("source") or "all").strip().lower()
    if source not in {"all","snapshot","audit"}: source="all"
    q=(request.args.get("q") or "").strip()
    try: limit=min(max(int(request.args.get("limit","500")),50),1000)
    except Exception: limit=500
    rows=build_combined_history(source=source,q=q,limit=limit)
    return render_template("history.html",org=current_org(),rows=rows,source=source,q=q,limit=limit,run_state=run_state)

@app.route("/snapshots")
def snapshots_page(): return render_template("snapshots.html",org=current_org(),snapshots=list_snapshots(100),run_state=run_state)
@app.post("/run-snapshot")
def run_snapshot_now():
    if not github_connection(include_token=False).get("configured"):
        return redirect(url_for("github_settings"))
    start_snapshot_background()
    return redirect(url_for("index"))

@app.route("/users/export.csv")
def users_export_csv():
    scope=request.args.get("scope","active"); q=request.args.get("q","")
    users,_=apply_user_scope(build_users(latest_data(),include_hidden=True),scope,q)
    buf=io.StringIO(newline=""); w=csv.writer(buf,delimiter=";",lineterminator="\r\n")
    w.writerow(["GitHub username","E-mail","GitHub ID","Status","Teamy","Repo","Zaprosił","Data zaproszenia","Data dołączenia","Usunął","Data usunięcia"])
    for u in users:
        w.writerow([u.get("login") or "",u.get("email") or "",u.get("id") or "",user_status_label(u),u.get("team_count",0),u.get("repo_count",0),u.get("invited_by") or "",u.get("invited_at") or "",u.get("joined_at") or "",u.get("removed_by") or "",u.get("removed_at") or ""])
    body="\ufeff"+buf.getvalue()
    return Response(body,mimetype="text/csv; charset=utf-8",headers={"Content-Disposition":f'attachment; filename="github-users-{scope}.csv"'})

@app.route("/api/users")
def api_users():
    scope=request.args.get("scope","active"); q=request.args.get("q","")
    users,scope=apply_user_scope(build_users(latest_data(),include_hidden=True),scope,q)
    latest=latest_successful_snapshot()
    return jsonify({"organization":current_org(),"scope":scope,"count":len(users),"snapshot_id":latest.get("id") if latest else None,"snapshot_finished_at":latest.get("finished_at") if latest else None,"users":[user_api_row(u) for u in users]})

@app.route("/api/users/<path:key>")
def api_user_detail(key):
    user=find_user(key)
    if user is None: return jsonify({"error":"user_not_found"}),404
    return jsonify(user_api_row(user,detailed=True))

@app.route("/api/status")
def api_status(): return jsonify({"run":run_state,"latest":latest_snapshot_any()})

init_db()
init_security_db()
try:
    if migrate_legacy_env_connection():
        LOG.info("Migrated legacy GitHub token from environment into encrypted security storage")
except Exception:
    LOG.warning("Legacy GitHub connection was not migrated during app startup", exc_info=True)

if __name__ == "__main__":
    threading.Thread(target=scheduler_loop,daemon=True,name="scheduler").start()
    if RUN_ON_START:
        try:
            if github_connection(include_token=False).get("configured"):
                threading.Thread(target=execute_snapshot,daemon=True,name="initial-snapshot").start()
            else:
                LOG.info("Initial snapshot skipped: GitHub connection is not configured")
        except Exception:
            LOG.exception("Initial snapshot preflight failed")
    app.run(host=BIND_ADDRESS,port=PORT,debug=False,threaded=True)
