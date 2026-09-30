import logging
import os
from datetime import datetime, timezone
from urllib.parse import quote

import requests

LOG = logging.getLogger("collector")

API = "https://api.github.com"
ORG = os.getenv("GITHUB_ORG", "my-organization")
TOKEN = os.getenv("GITHUB_TOKEN", "").strip()
API_VERSION = os.getenv("GITHUB_API_VERSION", "2026-03-10")
TIMEOUT = 30


class GitHubAPIError(RuntimeError):
    pass


def _session():
    if not TOKEN:
        raise GitHubAPIError("GITHUB_TOKEN is empty")
    s = requests.Session()
    s.headers.update(
        {
            "Authorization": f"Bearer {TOKEN}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "github-audit-monitor/0.7.0",
        }
    )
    return s


def github_get(session, path, params=None, allow_status=()):
    """The only GitHub HTTP primitive in this application: GET."""
    url = path if path.startswith("http") else API + path
    r = session.get(url, params=params, timeout=TIMEOUT)
    if r.status_code in allow_status:
        return r
    if r.status_code >= 400:
        body = r.text[:700].replace("\n", " ")
        raise GitHubAPIError(f"GET {path} -> HTTP {r.status_code}: {body}")
    return r


def get_json(session, path, params=None):
    return github_get(session, path, params=params).json()


def get_paged(session, path, params=None, max_pages=200):
    params = dict(params or {})
    params["per_page"] = 100
    out = []
    for page in range(1, max_pages + 1):
        params["page"] = page
        data = get_json(session, path, params=params)
        if not isinstance(data, list):
            raise GitHubAPIError(f"GET {path} did not return a list")
        out.extend(data)
        if len(data) < 100:
            break
    else:
        raise GitHubAPIError(f"Pagination limit reached for {path}")
    return out


def permission_from_object(obj):
    role = str(obj.get("role_name") or obj.get("permission") or "").strip().lower()
    if role:
        return {"pull": "read", "push": "write"}.get(role, role)
    perms = obj.get("permissions") or {}
    for key, label in (
        ("admin", "admin"),
        ("maintain", "maintain"),
        ("push", "write"),
        ("write", "write"),
        ("triage", "triage"),
        ("pull", "read"),
        ("read", "read"),
    ):
        if perms.get(key):
            return label
    return "unknown"


def slim_user(u):
    return {"id": u.get("id"), "login": u.get("login"), "type": u.get("type")}


def collect_snapshot(progress=None):
    def say(msg):
        LOG.info(msg)
        if progress:
            progress(msg)

    session = _session()
    warnings = []
    generated_at = datetime.now(timezone.utc).isoformat()

    say("[0/6] Testing GitHub token...")
    me = get_json(session, "/user")
    login = me.get("login")
    say(f"      Authenticated as: {login}")

    say(f"[1/6] Reading organization and members: {ORG}")
    org_obj = get_json(session, f"/orgs/{quote(ORG)}")
    members_raw = get_paged(session, f"/orgs/{quote(ORG)}/members", {"filter": "all", "role": "all"})
    members = [slim_user(u) for u in members_raw]
    say(f"      Members: {len(members)}")

    say("[2/6] Reading outside collaborators...")
    outside_complete = True
    try:
        outside_raw = get_paged(session, f"/orgs/{quote(ORG)}/outside_collaborators", {"filter": "all"})
        outside_collaborators = [slim_user(u) for u in outside_raw]
        say(f"      Outside collaborators: {len(outside_collaborators)}")
    except Exception as exc:
        outside_complete = False
        outside_collaborators = []
        warnings.append(f"outside collaborators: {exc}")
        say("      Outside collaborators: endpoint unavailable; classification will fall back to repository data")

    outside_ids = {str(u.get("id")) for u in outside_collaborators if u.get("id") is not None}
    member_ids = {str(u.get("id")) for u in members if u.get("id") is not None}

    say("[3/6] Reading teams and team members...")
    teams_raw = get_paged(session, f"/orgs/{quote(ORG)}/teams", {"team_type": "all"})
    teams = []
    for i, t in enumerate(teams_raw, 1):
        slug = t.get("slug") or t.get("name")
        say(f"      Team {i}/{len(teams_raw)}: {slug}")
        try:
            tm = get_paged(session, f"/orgs/{quote(ORG)}/teams/{quote(slug)}/members", {"role": "all"})
        except Exception as exc:
            warnings.append(f"team members {slug}: {exc}")
            tm = []
        teams.append(
            {
                "id": t.get("id"),
                "name": t.get("name"),
                "slug": slug,
                "privacy": t.get("privacy"),
                "parent": (t.get("parent") or {}).get("slug") if isinstance(t.get("parent"), dict) else None,
                "members": [slim_user(u) for u in tm],
            }
        )

    say("[4/6] Reading repositories...")
    repos_raw = get_paged(session, f"/orgs/{quote(ORG)}/repos", {"type": "all", "sort": "full_name", "direction": "asc"})
    say(f"      Repositories: {len(repos_raw)}")

    say("[5/6] Reading repository teams and direct collaborators...")
    repositories = []
    for i, repo in enumerate(repos_raw, 1):
        name = repo.get("name")
        full = repo.get("full_name") or f"{ORG}/{name}"
        if i == 1 or i % 10 == 0 or i == len(repos_raw):
            say(f"      Repo {i}/{len(repos_raw)}: {full}")

        repo_teams = []
        try:
            rt = get_paged(session, f"/repos/{quote(ORG)}/{quote(name)}/teams")
            for t in rt:
                repo_teams.append(
                    {
                        "id": t.get("id"),
                        "name": t.get("name"),
                        "slug": t.get("slug") or t.get("name"),
                        "permission": permission_from_object(t),
                    }
                )
        except Exception as exc:
            warnings.append(f"repo teams {full}: {exc}")

        direct = []
        try:
            dc = get_paged(
                session,
                f"/repos/{quote(ORG)}/{quote(name)}/collaborators",
                {"affiliation": "direct"},
            )
            for u in dc:
                item = slim_user(u)
                item["permission"] = permission_from_object(u)
                uid = str(item.get("id")) if item.get("id") is not None else None
                if uid and uid in outside_ids:
                    item["affiliation"] = "outside"
                elif uid and uid in member_ids:
                    item["affiliation"] = "member_direct"
                else:
                    item["affiliation"] = "unknown_direct"
                direct.append(item)
        except Exception as exc:
            # GitHub requires sufficient repository privileges for this endpoint.
            warnings.append(f"direct collaborators {full}: {exc}")

        repositories.append(
            {
                "id": repo.get("id"),
                "name": name,
                "full_name": full,
                "private": repo.get("private"),
                "visibility": repo.get("visibility"),
                "archived": repo.get("archived"),
                "teams": repo_teams,
                "directCollaborators": direct,
            }
        )

    say("[6/6] Snapshot collected.")
    snapshot = {
        "schemaVersion": 1,
        "generatedAt": generated_at,
        "organization": ORG,
        "authenticatedUser": login,
        "organizationDefaultPermission": org_obj.get("default_repository_permission"),
        "members": members,
        "outsideCollaborators": outside_collaborators,
        "outsideCollaboratorsComplete": outside_complete,
        "teams": teams,
        "repositories": repositories,
        "warnings": warnings,
    }
    return snapshot, login


def _user_key(u):
    return str(u.get("id")) if u.get("id") is not None else f"login:{str(u.get('login') or '').lower()}"


def flatten_state(snapshot):
    """Flatten structural state.

    Direct repository grants are intentionally not emitted here. They are represented
    by user_repo_access below, which lets the UI show a single readable transition
    such as "Direct Write -> Team platform Read" instead of raw JSON changes.
    """
    state = {}

    for u in snapshot.get("members", []):
        k = _user_key(u)
        state[f"member:{k}"] = {"entity_type": "member", "value": u}

    for u in snapshot.get("outsideCollaborators", []):
        k = _user_key(u)
        state[f"outside_collaborator:{k}"] = {"entity_type": "outside_collaborator", "value": u}

    for t in snapshot.get("teams", []):
        tid = str(t.get("id") or f"slug:{t.get('slug')}")
        state[f"team:{tid}"] = {
            "entity_type": "team",
            "value": {"id": t.get("id"), "slug": t.get("slug"), "name": t.get("name"), "parent": t.get("parent")},
        }
        for u in t.get("members", []):
            uk = _user_key(u)
            state[f"team_member:{tid}:{uk}"] = {
                "entity_type": "team_member",
                "value": {"team_id": t.get("id"), "team": t.get("slug"), "user": u},
            }

    for r in snapshot.get("repositories", []):
        rid = str(r.get("id") or f"repo:{r.get('full_name')}")
        state[f"repo:{rid}"] = {
            "entity_type": "repository",
            "value": {"id": r.get("id"), "full_name": r.get("full_name"), "archived": r.get("archived"), "visibility": r.get("visibility")},
        }
        for t in r.get("teams", []):
            tid = str(t.get("id") or f"slug:{t.get('slug')}")
            state[f"team_repo:{tid}:{rid}"] = {
                "entity_type": "team_repo",
                "value": {"team_id": t.get("id"), "team": t.get("slug"), "repo_id": r.get("id"), "repo": r.get("full_name"), "permission": t.get("permission")},
            }

    return state


def _permission_rank(permission):
    return {
        "unknown": 0, "none": 0, "read": 1, "pull": 1, "triage": 2,
        "write": 3, "push": 3, "maintain": 4, "admin": 5,
    }.get(str(permission or "").lower(), 0)


def flatten_user_repo_access(snapshot):
    """Return the access paths each user has to each repository.

    Only fields that materially describe the path are included, so metadata changes
    such as GitHub's collaborator affiliation do not create false positives.
    """
    access = {}
    members = {_user_key(u): u for u in snapshot.get("members", [])}
    team_members = {}
    for team in snapshot.get("teams", []):
        tid = str(team.get("id") or f"slug:{team.get('slug')}")
        team_members[tid] = {_user_key(u): u for u in team.get("members", [])}

    def add(user, repo, grant):
        uk = _user_key(user)
        rid = str(repo.get("id") or f"repo:{repo.get('full_name')}")
        key = f"user_repo_access:{uk}:{rid}"
        row = access.setdefault(key, {
            "user": {"id": user.get("id"), "login": user.get("login"), "type": user.get("type")},
            "repo_id": repo.get("id"),
            "repo": repo.get("full_name"),
            "grants": [],
        })
        normalized = {
            "source_type": grant.get("source_type"),
            "source": grant.get("source"),
            "permission": str(grant.get("permission") or "unknown").lower(),
        }
        if normalized not in row["grants"]:
            row["grants"].append(normalized)

    default_permission = str(snapshot.get("organizationDefaultPermission") or "").lower()
    default_enabled = default_permission not in {"", "none", "no_permission"}

    for repo in snapshot.get("repositories", []):
        if default_enabled:
            for user in members.values():
                add(user, repo, {"source_type": "organization", "source": "Organization default", "permission": default_permission})

        for team in repo.get("teams", []):
            tid = str(team.get("id") or f"slug:{team.get('slug')}")
            for user in team_members.get(tid, {}).values():
                add(user, repo, {"source_type": "team", "source": team.get("slug") or team.get("name") or "?", "permission": team.get("permission")})

        for user in repo.get("directCollaborators", []):
            add(user, repo, {"source_type": "direct", "source": "Direct", "permission": user.get("permission")})

    for row in access.values():
        row["grants"] = sorted(row["grants"], key=lambda g: (g.get("source_type") or "", g.get("source") or "", g.get("permission") or ""))
        row["effective_permission"] = max(
            (g.get("permission") for g in row["grants"]),
            key=_permission_rank,
            default="none",
        )
    return access


def compare_snapshots(previous, current):
    if not previous:
        return []
    before = flatten_state(previous)
    after = flatten_state(current)
    changes = []

    for key in sorted(set(before) | set(after)):
        b = before.get(key)
        a = after.get(key)
        if b is None:
            changes.append({"entity_type": a["entity_type"], "entity_key": key, "change_type": "added", "before": None, "after": a["value"]})
        elif a is None:
            changes.append({"entity_type": b["entity_type"], "entity_key": key, "change_type": "removed", "before": b["value"], "after": None})
        elif b["value"] != a["value"]:
            changes.append({"entity_type": a["entity_type"], "entity_key": key, "change_type": "changed", "before": b["value"], "after": a["value"]})

    # Human-friendly access-path changes per user/repository. This collapses source
    # switches (Direct -> Team, Team -> None, etc.) into one meaningful event.
    before_access = flatten_user_repo_access(previous)
    after_access = flatten_user_repo_access(current)
    for key in sorted(set(before_access) | set(after_access)):
        b = before_access.get(key)
        a = after_access.get(key)
        if b == a:
            continue
        if b is None:
            change_type = "added"
        elif a is None:
            change_type = "removed"
        else:
            change_type = "changed"
        changes.append({
            "entity_type": "user_repo_access",
            "entity_key": key,
            "change_type": change_type,
            "before": b,
            "after": a,
        })

    return changes
