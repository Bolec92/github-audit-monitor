import csv
import io
import json
import logging
import os
import threading
import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from flask import Flask, Response, jsonify, redirect, render_template, request, url_for

from audit import (
    actor_for_direct_repo, actor_for_team_membership, actor_for_team_repo,
    audit_index, identity_from_audit, norm,
)
from collector import ORG, collect_snapshot, compare_snapshots
from db import (
    backup_database, create_snapshot, delete_user_override, fail_snapshot, finish_snapshot,
    get_overrides, import_audit_events, init_db, latest_snapshot_any,
    latest_successful_snapshot, list_audit_events, list_audit_imports,
    list_mapper_users, list_changes, list_snapshots, save_user_override, set_user_hidden,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
LOG = logging.getLogger("app")
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024
run_lock = threading.Lock()
run_state = {"running": False, "progress": "Idle", "last_error": None}
TZ_NAME = os.getenv("TZ", "Europe/Warsaw")
SNAPSHOT_HOUR = int(os.getenv("SNAPSHOT_HOUR", "3"))
SNAPSHOT_MINUTE = int(os.getenv("SNAPSHOT_MINUTE", "0"))
RUN_ON_START = os.getenv("RUN_ON_START", "true").lower() in {"1", "true", "yes", "on"}
PORT = int(os.getenv("PORT", "8080"))
BIND_ADDRESS = os.getenv("BIND_ADDRESS", "0.0.0.0").strip() or "0.0.0.0"
EMAIL_DOMAIN_REWRITE_FROM = os.getenv("EMAIL_DOMAIN_REWRITE_FROM", "").strip().lower()
EMAIL_DOMAIN_REWRITE_TO = os.getenv("EMAIL_DOMAIN_REWRITE_TO", "").strip().lower()
AUDIT_FILTER = "action:org.invite_member action:org.add_member action:org.remove_member action:org.add_outside_collaborator action:org.remove_outside_collaborator action:org.update_default_repository_permission action:team.add_member action:team.remove_member action:team.add_repository action:team.remove_repository action:team.update_repository_permission action:repo.add_member action:repo.update_member action:repo.remove_member"


def progress(msg): run_state["progress"] = msg


def execute_snapshot():
    if not run_lock.acquire(blocking=False): return False
    run_state.update({"running": True, "progress": "Starting...", "last_error": None})
    snapshot_id = None
    try:
        snapshot_id = create_snapshot(ORG)
        previous = latest_successful_snapshot(exclude_id=snapshot_id)
        current, login = collect_snapshot(progress=progress)
        changes = compare_snapshots(previous.get("data") if previous else None, current)
        finish_snapshot(snapshot_id, current, changes, authenticated_user=login)
        backup = backup_database()
        run_state["progress"] = f"Completed. Changes: {len(changes)}. Backup: {backup}"
        LOG.info(run_state["progress"]); return True
    except Exception as exc:
        LOG.exception("Snapshot failed"); run_state["last_error"] = str(exc); run_state["progress"] = f"FAILED: {exc}"
        if snapshot_id is not None: fail_snapshot(snapshot_id, exc)
        return False
    finally:
        run_state["running"] = False; run_lock.release()


def start_snapshot_background():
    if run_state["running"]: return False
    threading.Thread(target=execute_snapshot, daemon=True, name="snapshot-now").start(); return True


def scheduler_loop():
    tz = ZoneInfo(TZ_NAME)
    while True:
        now = datetime.now(tz); next_run = now.replace(hour=SNAPSHOT_HOUR, minute=SNAPSHOT_MINUTE, second=0, microsecond=0)
        if next_run <= now: next_run += timedelta(days=1)
        LOG.info("Next scheduled snapshot: %s", next_run.isoformat())
        time.sleep(max(1, (next_run - now).total_seconds())); execute_snapshot(); time.sleep(2)


def latest_data():
    row = latest_successful_snapshot(); return row.get("data") if row else None


def permission_rank(p):
    return {"unknown":0,"read":1,"pull":1,"triage":2,"write":3,"push":3,"maintain":4,"admin":5}.get(str(p or "").lower(),0)


def user_key(github_id=None, login=None):
    if github_id is not None and str(github_id): return "id:" + str(github_id)
    return "login:" + norm(login)


def normalize_email(value):
    """Optionally rewrite one exact e-mail domain; leave every other domain untouched."""
    email = str(value or "").strip()
    if not email or "@" not in email:
        return email or None
    local, domain = email.rsplit("@", 1)
    if EMAIL_DOMAIN_REWRITE_FROM and EMAIL_DOMAIN_REWRITE_TO and domain.lower() == EMAIL_DOMAIN_REWRITE_FROM:
        return f"{local}@{EMAIL_DOMAIN_REWRITE_TO}"
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


@app.route("/health")
def health(): return jsonify({"ok":True,"running":run_state["running"]})

@app.route("/")
def index():
    latest=latest_successful_snapshot(); snapshot=latest.get("data") if latest else None
    all_users=build_users(snapshot, include_hidden=True)
    active=[u for u in all_users if u.get("is_org_member") and not u.get("hidden")]
    outside=[u for u in all_users if u.get("is_outside_collaborator") and not u.get("hidden")]
    repo_collabs=[u for u in all_users if u.get("is_repo_collaborator") and not u.get("hidden")]
    historical=[u for u in all_users if not u.get("current") and not u.get("hidden")]
    hidden=[u for u in all_users if u.get("hidden")]
    return render_template("index.html",org=ORG,latest=latest,snapshot=snapshot,users=active[:20],total_users=len(active),outside_count=len(outside),repo_collab_count=len(repo_collabs),historical_count=len(historical),hidden_count=len(hidden),changes=decorate_changes(list_changes(12), all_users),run_state=run_state,tz=TZ_NAME,schedule=f"{SNAPSHOT_HOUR:02d}:{SNAPSHOT_MINUTE:02d}")

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
    return render_template("users.html",org=ORG,users=users,q=q,scope=scope,counts=counts,run_state=run_state)

@app.route("/users/<path:key>")
def user_detail(key):
    user=find_user(key)
    if user is None: return "User not found",404
    return render_template("user.html",org=ORG,user=user,run_state=run_state)

@app.route("/users/<path:key>/edit",methods=["GET","POST"])
def user_edit(key):
    user=find_user(key)
    if user is None: return "User not found",404
    if request.method=="POST":
        save_user_override(key, github_id=request.form.get("github_id") or None, username=request.form.get("username") or None,
            email=normalize_email(request.form.get("email")), joined_at=request.form.get("joined_at") or None, invited_at=request.form.get("invited_at") or None,
            invited_by=request.form.get("invited_by") or None, display_name=request.form.get("display_name") or None, notes=request.form.get("notes") or None,
            hidden=request.form.get("hidden")=="1")
        backup_database(); return redirect(url_for("user_detail",key=key))
    return render_template("user_edit.html",org=ORG,user=user)

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
        save_user_override(key, github_id=gid or None, username=username or None, email=normalize_email(request.form.get("email")),
            joined_at=request.form.get("joined_at") or None, invited_at=request.form.get("invited_at") or None, invited_by=request.form.get("invited_by") or None,
            display_name=request.form.get("display_name") or None, notes=request.form.get("notes") or None, hidden=False)
        backup_database(); return redirect(url_for("user_detail",key=key))
    return render_template("user_edit.html",org=ORG,user=None)

@app.route("/audit",methods=["GET","POST"])
def audit_import_page():
    result=None; error=None
    if request.method=="POST":
        try:
            f=request.files.get("file")
            if not f or not f.filename: raise ValueError("Wybierz plik JSON")
            events=parse_json_upload(f); result=import_audit_events(events,f.filename); backup_database()
        except Exception as exc: error=str(exc)
    return render_template("audit.html",org=ORG,result=result,error=error,imports=list_audit_imports(20),audit_filter=AUDIT_FILTER)

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
    return render_template("statistics.html",org=ORG,inviters=inviters,removers=removers,inviter_bars=inviter_bars,remover_bars=remover_bars,recent_joined=recent_joined,recent_removed=recent_removed,total_joined=total_joined,total_removed=total_removed,added_pct=added_pct)

@app.route("/changes")
def changes_page():
    users=build_users(latest_data(), include_hidden=True)
    return render_template("changes.html",org=ORG,changes=decorate_changes(list_changes(500),users),run_state=run_state)

@app.route("/history")
def history_page():
    source=(request.args.get("source") or "all").strip().lower()
    if source not in {"all","snapshot","audit"}: source="all"
    q=(request.args.get("q") or "").strip()
    try: limit=min(max(int(request.args.get("limit","500")),50),1000)
    except Exception: limit=500
    rows=build_combined_history(source=source,q=q,limit=limit)
    return render_template("history.html",org=ORG,rows=rows,source=source,q=q,limit=limit,run_state=run_state)

@app.route("/snapshots")
def snapshots_page(): return render_template("snapshots.html",org=ORG,snapshots=list_snapshots(100),run_state=run_state)
@app.post("/run-snapshot")
def run_snapshot_now(): start_snapshot_background(); return redirect(url_for("index"))

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
    return jsonify({"organization":ORG,"scope":scope,"count":len(users),"snapshot_id":latest.get("id") if latest else None,"snapshot_finished_at":latest.get("finished_at") if latest else None,"users":[user_api_row(u) for u in users]})

@app.route("/api/users/<path:key>")
def api_user_detail(key):
    user=find_user(key)
    if user is None: return jsonify({"error":"user_not_found"}),404
    return jsonify(user_api_row(user,detailed=True))

@app.route("/api/status")
def api_status(): return jsonify({"run":run_state,"latest":latest_snapshot_any()})

init_db()

if __name__ == "__main__":
    threading.Thread(target=scheduler_loop,daemon=True,name="scheduler").start()
    if RUN_ON_START: threading.Thread(target=execute_snapshot,daemon=True,name="initial-snapshot").start()
    app.run(host=BIND_ADDRESS,port=PORT,debug=False,threaded=True)
