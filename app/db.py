import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = os.getenv("DATABASE_PATH", "/data/github-audit.db")
BACKUP_DIR = os.getenv("BACKUP_DIR", "/backups")
BACKUP_KEEP = int(os.getenv("BACKUP_KEEP", "30"))


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def connect():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    with connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                org TEXT NOT NULL,
                authenticated_user TEXT,
                member_count INTEGER DEFAULT 0,
                team_count INTEGER DEFAULT 0,
                repo_count INTEGER DEFAULT 0,
                warning_count INTEGER DEFAULT 0,
                error TEXT,
                data_json TEXT
            );

            CREATE TABLE IF NOT EXISTS changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                snapshot_id INTEGER NOT NULL,
                detected_at TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_key TEXT NOT NULL,
                change_type TEXT NOT NULL,
                before_json TEXT,
                after_json TEXT,
                FOREIGN KEY(snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                event_key TEXT PRIMARY KEY,
                imported_at TEXT NOT NULL,
                created_at TEXT,
                action TEXT NOT NULL,
                actor TEXT,
                actor_id TEXT,
                target_username TEXT,
                target_user_id TEXT,
                invite_email TEXT,
                invitation_id TEXT,
                team TEXT,
                repo TEXT,
                permission TEXT,
                raw_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_imports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                imported_at TEXT NOT NULL,
                total_count INTEGER NOT NULL,
                new_count INTEGER NOT NULL,
                duplicate_count INTEGER NOT NULL,
                recognized_count INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_overrides (
                user_key TEXT PRIMARY KEY,
                github_id TEXT,
                username TEXT,
                email TEXT,
                joined_at TEXT,
                invited_at TEXT,
                invited_by TEXT,
                display_name TEXT,
                notes TEXT,
                hidden INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS mapper_users (
                mapper_key TEXT PRIMARY KEY,
                github_id TEXT,
                username TEXT,
                email TEXT,
                invited_by TEXT,
                invited_at TEXT,
                joined_at TEXT,
                removed_by TEXT,
                removed_at TEXT,
                invitation_id TEXT,
                status TEXT,
                manual INTEGER NOT NULL DEFAULT 0,
                aliases_json TEXT,
                source_filename TEXT,
                source_record_key TEXT,
                raw_json TEXT,
                imported_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS mapper_imports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                imported_at TEXT NOT NULL,
                source_records INTEGER NOT NULL,
                recognized_records INTEGER NOT NULL,
                profile_count INTEGER NOT NULL,
                created_count INTEGER NOT NULL,
                updated_count INTEGER NOT NULL,
                skipped_count INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_changes_snapshot ON changes(snapshot_id);
            CREATE INDEX IF NOT EXISTS idx_changes_detected ON changes(detected_at DESC);
            CREATE INDEX IF NOT EXISTS idx_changes_entity ON changes(entity_type, entity_key);
            CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action);
            CREATE INDEX IF NOT EXISTS idx_audit_userid ON audit_events(target_user_id);
            CREATE INDEX IF NOT EXISTS idx_audit_username ON audit_events(target_username);
            CREATE INDEX IF NOT EXISTS idx_audit_invitation ON audit_events(invitation_id);
            CREATE INDEX IF NOT EXISTS idx_mapper_github_id ON mapper_users(github_id);
            CREATE INDEX IF NOT EXISTS idx_mapper_username ON mapper_users(username);
            CREATE INDEX IF NOT EXISTS idx_mapper_email ON mapper_users(email);
            """
        )


def create_snapshot(org):
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO snapshots(started_at,status,org) VALUES(?,?,?)",
            (utc_now(), "running", org),
        )
        return cur.lastrowid


def finish_snapshot(snapshot_id, data, changes, authenticated_user=None):
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    with connect() as conn:
        conn.execute(
            """
            UPDATE snapshots
            SET finished_at=?, status='success', authenticated_user=?,
                member_count=?, team_count=?, repo_count=?, warning_count=?,
                data_json=?, error=NULL
            WHERE id=?
            """,
            (
                utc_now(), authenticated_user,
                len(data.get("members", [])), len(data.get("teams", [])),
                len(data.get("repositories", [])), len(data.get("warnings", [])),
                payload, snapshot_id,
            ),
        )
        for change in changes:
            conn.execute(
                """INSERT INTO changes(snapshot_id,detected_at,entity_type,entity_key,change_type,before_json,after_json)
                   VALUES(?,?,?,?,?,?,?)""",
                (
                    snapshot_id, utc_now(), change["entity_type"], change["entity_key"], change["change_type"],
                    json.dumps(change.get("before"), ensure_ascii=False) if change.get("before") is not None else None,
                    json.dumps(change.get("after"), ensure_ascii=False) if change.get("after") is not None else None,
                ),
            )


def fail_snapshot(snapshot_id, error):
    with connect() as conn:
        conn.execute("UPDATE snapshots SET finished_at=?, status='failed', error=? WHERE id=?", (utc_now(), str(error)[:4000], snapshot_id))


def latest_successful_snapshot(exclude_id=None):
    sql = "SELECT * FROM snapshots WHERE status='success'"
    params = []
    if exclude_id is not None:
        sql += " AND id<>?"
        params.append(exclude_id)
    sql += " ORDER BY id DESC LIMIT 1"
    with connect() as conn:
        row = conn.execute(sql, params).fetchone()
    if not row:
        return None
    out = dict(row)
    out["data"] = json.loads(out.pop("data_json")) if out.get("data_json") else None
    return out


def latest_snapshot_any():
    with connect() as conn:
        row = conn.execute("SELECT * FROM snapshots ORDER BY id DESC LIMIT 1").fetchone()
    return dict(row) if row else None


def list_snapshots(limit=30):
    with connect() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT id,started_at,finished_at,status,org,authenticated_user,member_count,team_count,repo_count,warning_count,error FROM snapshots ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()]


def list_changes(limit=200):
    with connect() as conn:
        rows = conn.execute("SELECT * FROM changes ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    result = []
    for row in rows:
        d = dict(row)
        d["before"] = json.loads(d.pop("before_json")) if d.get("before_json") else None
        d["after"] = json.loads(d.pop("after_json")) if d.get("after_json") else None
        result.append(d)
    return result


def _event_key(event):
    explicit = event.get("_document_id") or event.get("document_id") or event.get("id")
    if explicit:
        return "doc:" + str(explicit)
    raw = json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _first(event, *names):
    for n in names:
        v = event.get(n)
        if v is not None and v != "":
            return v
    return None


def _normalize_event(event):
    action = str(_first(event, "action", "event") or "").strip()
    target_username = _first(event, "user", "invitee", "target_login", "target_user")
    target_user_id = _first(event, "user_id", "invitee_id", "target_user_id")
    permission = _first(event, "new_repo_permission", "permission", "new_repo_base_role")
    return {
        "event_key": _event_key(event),
        "imported_at": utc_now(),
        "created_at": _first(event, "created_at", "@timestamp", "timestamp"),
        "action": action,
        "actor": _first(event, "actor", "inviter"),
        "actor_id": str(_first(event, "actor_id") or "") or None,
        "target_username": str(target_username) if target_username is not None else None,
        "target_user_id": str(target_user_id) if target_user_id is not None else None,
        "invite_email": _first(event, "invitee_email", "email"),
        "invitation_id": str(_first(event, "invitation_id") or "") or None,
        "team": _first(event, "team", "team_name", "team_slug"),
        "repo": _first(event, "repo", "repository"),
        "permission": str(permission).lower() if permission is not None else None,
        "raw_json": json.dumps(event, ensure_ascii=False, separators=(",", ":")),
    }


def import_audit_events(events, filename="upload.json"):
    rows = [_normalize_event(e) for e in events if isinstance(e, dict) and (e.get("action") or e.get("event"))]
    if events and not rows:
        raise ValueError("Plik nie zawiera surowych eventów GitHub Audit Log.")
    new_count = 0
    with connect() as conn:
        for r in rows:
            cur = conn.execute(
                """INSERT OR IGNORE INTO audit_events(event_key,imported_at,created_at,action,actor,actor_id,target_username,target_user_id,invite_email,invitation_id,team,repo,permission,raw_json)
                   VALUES(:event_key,:imported_at,:created_at,:action,:actor,:actor_id,:target_username,:target_user_id,:invite_email,:invitation_id,:team,:repo,:permission,:raw_json)""", r
            )
            if cur.rowcount:
                new_count += 1
        total = len(rows)
        conn.execute(
            "INSERT INTO audit_imports(filename,imported_at,total_count,new_count,duplicate_count,recognized_count) VALUES(?,?,?,?,?,?)",
            (filename, utc_now(), total, new_count, total - new_count, total),
        )
    return {"total": len(rows), "new": new_count, "duplicates": len(rows) - new_count}


def list_audit_events(limit=10000):
    with connect() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM audit_events ORDER BY COALESCE(created_at, imported_at) DESC, event_key DESC LIMIT ?", (limit,)).fetchall()]


def list_audit_imports(limit=30):
    with connect() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM audit_imports ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]


def get_overrides():
    with connect() as conn:
        return {r["user_key"]: dict(r) for r in conn.execute("SELECT * FROM user_overrides").fetchall()}


def save_user_override(user_key, **fields):
    allowed = ["github_id", "username", "email", "joined_at", "invited_at", "invited_by", "display_name", "notes", "hidden"]
    values = {k: fields.get(k) for k in allowed}
    values["hidden"] = 1 if values.get("hidden") else 0
    values.update({"user_key": user_key, "updated_at": utc_now()})
    with connect() as conn:
        conn.execute(
            """INSERT INTO user_overrides(user_key,github_id,username,email,joined_at,invited_at,invited_by,display_name,notes,hidden,updated_at)
               VALUES(:user_key,:github_id,:username,:email,:joined_at,:invited_at,:invited_by,:display_name,:notes,:hidden,:updated_at)
               ON CONFLICT(user_key) DO UPDATE SET
                 github_id=excluded.github_id, username=excluded.username, email=excluded.email,
                 joined_at=excluded.joined_at, invited_at=excluded.invited_at, invited_by=excluded.invited_by,
                 display_name=excluded.display_name, notes=excluded.notes, hidden=excluded.hidden, updated_at=excluded.updated_at""", values
        )


def delete_user_override(user_key):
    with connect() as conn:
        conn.execute("DELETE FROM user_overrides WHERE user_key=?", (user_key,))


def set_user_hidden(user_key, hidden, github_id=None, username=None):
    """Persist a tombstone without changing source data or other manual fields."""
    with connect() as conn:
        existing = conn.execute("SELECT user_key FROM user_overrides WHERE user_key=?", (user_key,)).fetchone()
        if existing:
            conn.execute(
                "UPDATE user_overrides SET hidden=?, updated_at=? WHERE user_key=?",
                (1 if hidden else 0, utc_now(), user_key),
            )
        else:
            conn.execute(
                """INSERT INTO user_overrides(
                       user_key,github_id,username,email,joined_at,invited_at,invited_by,display_name,notes,hidden,updated_at
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (user_key, str(github_id) if github_id not in (None, "") else None, username or None,
                 None, None, None, None, None, None, 1 if hidden else 0, utc_now()),
            )


def backup_database():
    Path(BACKUP_DIR).mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = Path(BACKUP_DIR) / f"github-audit-{stamp}.db"
    src = connect()
    dst = sqlite3.connect(dest)
    try:
        src.backup(dst)
    finally:
        dst.close(); src.close()
    files = sorted(Path(BACKUP_DIR).glob("github-audit-*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in files[BACKUP_KEEP:]:
        try: old.unlink()
        except OSError: pass
    return str(dest)


def _norm_text(v):
    return str(v or "").strip().lower()


def _mapper_first(record, *names):
    for name in names:
        value = record.get(name)
        if value is not None and value != "":
            return value
    return None


def _mapper_identity_key(record):
    gid = _mapper_first(record, "githubUserId", "github_id", "GitHubUserId", "GitHub ID")
    username = _mapper_first(record, "username", "githubUsername", "GitHubUsername", "GitHub username")
    email = _mapper_first(record, "email", "Email", "E-mail")
    if gid is not None and str(gid).strip():
        return "id:" + str(gid).strip()
    if username is not None and str(username).strip():
        return "login:" + _norm_text(username)
    if email is not None and str(email).strip():
        return "email:" + _norm_text(email)
    return None


def _pick_nonempty(records, names, prefer_manual=True):
    ordered = list(records)
    if prefer_manual:
        ordered.sort(key=lambda r: (bool(r.get("manual") or r.get("csvOverride") or r.get("manualOrigin")), bool(r.get("status") in {"joined","removed"})), reverse=True)
    for r in ordered:
        v = _mapper_first(r, *names)
        if v is not None and str(v).strip() != "":
            return v
    return None


def _pick_date(records, names, newest=False):
    vals=[]
    for r in records:
        v=_mapper_first(r,*names)
        if v:
            vals.append(str(v))
    if not vals:
        return None
    return max(vals) if newest else min(vals)


def _normalize_mapper_group(mapper_key, records, filename):
    gid = _pick_nonempty(records, ["githubUserId","github_id","GitHubUserId","GitHub ID"])
    username = _pick_nonempty(records, ["username","githubUsername","GitHubUsername","GitHub username"])
    email = _pick_nonempty(records, ["email","Email","E-mail"])
    invited_at = _pick_date(records, ["invitedAt","invited_at","InvitationDate","Data zaproszenia"], newest=False)
    joined_at = _pick_date(records, ["joinedAt","joined_at","JoinedDate","Data dołączenia"], newest=True)
    removed_at = _pick_date(records, ["removedAt","removed_at","RemovedDate","Data usunięcia"], newest=True)

    invited_by = None
    if invited_at:
        for r in records:
            if str(_mapper_first(r,"invitedAt","invited_at","InvitationDate","Data zaproszenia") or "") == invited_at:
                invited_by = _mapper_first(r,"invitedBy","invited_by","InvitedBy","Zaprosił") or invited_by
    invited_by = invited_by or _pick_nonempty(records,["invitedBy","invited_by","InvitedBy","Zaprosił"], prefer_manual=False)

    removed_by = None
    if removed_at:
        for r in records:
            if str(_mapper_first(r,"removedAt","removed_at","RemovedDate","Data usunięcia") or "") == removed_at:
                removed_by = _mapper_first(r,"removedBy","removed_by","RemovedBy","Usunął") or removed_by
    removed_by = removed_by or _pick_nonempty(records,["removedBy","removed_by","RemovedBy","Usunął"], prefer_manual=False)

    invitation_id = _pick_nonempty(records,["invitationId","invitation_id","InvitationId","Invitation ID"], prefer_manual=False)
    status = _pick_nonempty(records,["status","Status"], prefer_manual=False)
    manual = 1 if any(r.get("manual") or r.get("csvOverride") or r.get("manualOrigin") for r in records) else 0
    aliases = {
        "usernames": sorted({str(v).strip() for r in records for v in [_mapper_first(r,"username","githubUsername","GitHubUsername","GitHub username")] if v and str(v).strip()}),
        "emails": sorted({str(v).strip() for r in records for v in [_mapper_first(r,"email","Email","E-mail")] if v and str(v).strip()}),
        "record_keys": sorted({str(r.get("key")) for r in records if r.get("key")}),
    }
    source_record_key = next((str(r.get("key")) for r in records if r.get("key")), None)
    return {
        "mapper_key": mapper_key,
        "github_id": str(gid).strip() if gid is not None and str(gid).strip() else None,
        "username": str(username).strip() if username is not None and str(username).strip() else None,
        "email": str(email).strip() if email is not None and str(email).strip() else None,
        "invited_by": str(invited_by).strip() if invited_by is not None and str(invited_by).strip() else None,
        "invited_at": invited_at,
        "joined_at": joined_at,
        "removed_by": str(removed_by).strip() if removed_by is not None and str(removed_by).strip() else None,
        "removed_at": removed_at,
        "invitation_id": str(invitation_id).strip() if invitation_id is not None and str(invitation_id).strip() else None,
        "status": str(status).strip() if status is not None and str(status).strip() else None,
        "manual": manual,
        "aliases_json": json.dumps(aliases, ensure_ascii=False, separators=(",", ":")),
        "source_filename": filename,
        "source_record_key": source_record_key,
        "raw_json": json.dumps(records, ensure_ascii=False, separators=(",", ":")),
        "imported_at": utc_now(),
        "updated_at": utc_now(),
    }


def import_mapper_backup(payload, filename="GitHubAuditMapper_database_latest.json"):
    if isinstance(payload, dict):
        records = payload.get("records")
        if not isinstance(records, list):
            raise ValueError("Plik nie wygląda jak backup GitHub Audit Mapper: brak tablicy records.")
    elif isinstance(payload, list):
        records = payload
    else:
        raise ValueError("Nieobsługiwany format backupu Mappera.")

    candidates=[]
    for r in records:
        if not isinstance(r, dict):
            continue
        if r.get("type") not in {None, "member", "team_only"} and not any(k in r for k in ("githubUserId","username","email")):
            continue
        if _mapper_identity_key(r):
            candidates.append(r)

    # Union records that share any stable/strong identifier. This joins the classic
    # Mapper case where a pending invitation (email + invitation_id) and the later
    # joined record (GitHub ID + username + same email/invitation_id) are separate rows.
    parent=list(range(len(candidates)))
    def find(x):
        while parent[x]!=x:
            parent[x]=parent[parent[x]]; x=parent[x]
        return x
    def union(a,b):
        ra,rb=find(a),find(b)
        if ra!=rb: parent[rb]=ra
    seen={}
    for i,r in enumerate(candidates):
        tokens=[]
        gid=_mapper_first(r,"githubUserId","github_id","GitHubUserId","GitHub ID")
        usr=_mapper_first(r,"username","githubUsername","GitHubUsername","GitHub username")
        email=_mapper_first(r,"email","Email","E-mail")
        inv=_mapper_first(r,"invitationId","invitation_id","InvitationId","Invitation ID")
        if gid is not None and str(gid).strip(): tokens.append("id:"+str(gid).strip())
        if usr is not None and str(usr).strip(): tokens.append("u:"+_norm_text(usr))
        if email is not None and str(email).strip(): tokens.append("e:"+_norm_text(email))
        if inv is not None and str(inv).strip(): tokens.append("inv:"+str(inv).strip())
        for token in tokens:
            if token in seen: union(i,seen[token])
            else: seen[token]=i

    grouped={}
    for i,r in enumerate(candidates): grouped.setdefault(find(i),[]).append(r)
    groups={}
    for recs in grouped.values():
        gid=_pick_nonempty(recs,["githubUserId","github_id","GitHubUserId","GitHub ID"])
        usr=_pick_nonempty(recs,["username","githubUsername","GitHubUsername","GitHub username"])
        email=_pick_nonempty(recs,["email","Email","E-mail"])
        if gid is not None and str(gid).strip(): key="id:"+str(gid).strip()
        elif usr is not None and str(usr).strip(): key="login:"+_norm_text(usr)
        else: key="email:"+_norm_text(email)
        groups[key]=recs

    created=updated=0
    now=utc_now()
    with connect() as conn:
        for key, recs in groups.items():
            row=_normalize_mapper_group(key,recs,filename)
            existing=None
            if row.get("github_id"):
                existing=conn.execute("SELECT * FROM mapper_users WHERE github_id=? LIMIT 1",(row["github_id"],)).fetchone()
            if not existing and row.get("username"):
                existing=conn.execute("SELECT * FROM mapper_users WHERE lower(username)=lower(?) LIMIT 1",(row["username"],)).fetchone()
            if not existing and row.get("email"):
                existing=conn.execute("SELECT * FROM mapper_users WHERE lower(email)=lower(?) LIMIT 1",(row["email"],)).fetchone()
            if existing:
                old=dict(existing)
                mapper_key=old["mapper_key"]
                aliases_old={}
                try: aliases_old=json.loads(old.get("aliases_json") or "{}")
                except Exception: aliases_old={}
                aliases_new=json.loads(row.get("aliases_json") or "{}")
                for k2 in ("usernames","emails","record_keys"):
                    aliases_new[k2]=sorted(set(aliases_old.get(k2,[]))|set(aliases_new.get(k2,[])))
                def coalesce(new,oldv): return new if new not in (None,"") else oldv
                values={
                    "mapper_key":mapper_key,
                    "github_id":coalesce(row.get("github_id"),old.get("github_id")),
                    "username":coalesce(row.get("username"),old.get("username")),
                    "email":coalesce(row.get("email"),old.get("email")),
                    "invited_by":coalesce(row.get("invited_by"),old.get("invited_by")),
                    "invited_at":min([x for x in [row.get("invited_at"),old.get("invited_at")] if x], default=None),
                    "joined_at":max([x for x in [row.get("joined_at"),old.get("joined_at")] if x], default=None),
                    "removed_by":coalesce(row.get("removed_by"),old.get("removed_by")),
                    "removed_at":max([x for x in [row.get("removed_at"),old.get("removed_at")] if x], default=None),
                    "invitation_id":coalesce(row.get("invitation_id"),old.get("invitation_id")),
                    "status":coalesce(row.get("status"),old.get("status")),
                    "manual":1 if row.get("manual") or old.get("manual") else 0,
                    "aliases_json":json.dumps(aliases_new,ensure_ascii=False,separators=(",", ":")),
                    "source_filename":filename,
                    "source_record_key":coalesce(row.get("source_record_key"),old.get("source_record_key")),
                    "raw_json":row.get("raw_json"),
                    "updated_at":now,
                }
                conn.execute("""UPDATE mapper_users SET github_id=:github_id,username=:username,email=:email,invited_by=:invited_by,invited_at=:invited_at,joined_at=:joined_at,removed_by=:removed_by,removed_at=:removed_at,invitation_id=:invitation_id,status=:status,manual=:manual,aliases_json=:aliases_json,source_filename=:source_filename,source_record_key=:source_record_key,raw_json=:raw_json,updated_at=:updated_at WHERE mapper_key=:mapper_key""",values)
                updated+=1
            else:
                conn.execute("""INSERT INTO mapper_users(mapper_key,github_id,username,email,invited_by,invited_at,joined_at,removed_by,removed_at,invitation_id,status,manual,aliases_json,source_filename,source_record_key,raw_json,imported_at,updated_at) VALUES(:mapper_key,:github_id,:username,:email,:invited_by,:invited_at,:joined_at,:removed_by,:removed_at,:invitation_id,:status,:manual,:aliases_json,:source_filename,:source_record_key,:raw_json,:imported_at,:updated_at)""",row)
                created+=1
        skipped=len(records)-len(candidates)
        conn.execute("INSERT INTO mapper_imports(filename,imported_at,source_records,recognized_records,profile_count,created_count,updated_count,skipped_count) VALUES(?,?,?,?,?,?,?,?)",
                     (filename,now,len(records),len(candidates),len(groups),created,updated,skipped))
    return {"records":len(records),"recognized":len(candidates),"profiles":len(groups),"created":created,"updated":updated,"skipped":skipped}


def list_mapper_users():
    with connect() as conn:
        rows=[dict(r) for r in conn.execute("SELECT * FROM mapper_users ORDER BY lower(COALESCE(email,username,github_id,mapper_key))").fetchall()]
    for r in rows:
        try: r["aliases"]=json.loads(r.pop("aliases_json") or "{}")
        except Exception: r["aliases"]={}
    return rows


def list_mapper_imports(limit=30):
    with connect() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM mapper_imports ORDER BY id DESC LIMIT ?",(limit,)).fetchall()]
