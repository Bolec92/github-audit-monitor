from collections import defaultdict


def norm(v):
    return str(v or "").strip().lower()


def short_team(v):
    x = str(v or "").strip()
    return x.split("/", 1)[1] if "/" in x else x


def audit_index(events):
    idx = {
        "by_id": defaultdict(list), "by_user": defaultdict(list), "by_invitation": defaultdict(list),
        "team_add": {}, "team_remove": {}, "team_repo": {}, "direct_repo": {},
        "invitations": {}, "joins": {}, "removals": {},
    }
    for e in events:
        uid, user, inv = e.get("target_user_id"), norm(e.get("target_username")), e.get("invitation_id")
        if uid: idx["by_id"][str(uid)].append(e)
        if user: idx["by_user"][user].append(e)
        if inv: idx["by_invitation"][str(inv)].append(e)
        action = e.get("action")
        if action == "org.invite_member" and inv:
            idx["invitations"][str(inv)] = e
        elif action == "org.add_member":
            if inv: idx["joins"][str(inv)] = e
        elif action == "org.remove_member":
            key = str(uid) if uid else user
            if key: idx["removals"][key] = e
        elif action in {"team.add_member", "team.remove_member"}:
            keyu = str(uid) if uid else user
            key = (keyu, norm(short_team(e.get("team"))))
            if keyu and key[1]:
                (idx["team_add"] if action == "team.add_member" else idx["team_remove"])[key] = e
        elif action in {"team.add_repository", "team.remove_repository", "team.update_repository_permission"}:
            key = (norm(short_team(e.get("team"))), norm(e.get("repo")))
            if all(key): idx["team_repo"][key] = e
        elif action in {"repo.add_member", "repo.remove_member", "repo.update_member"}:
            keyu = str(uid) if uid else user
            key = (keyu, norm(e.get("repo")))
            if keyu and key[1]: idx["direct_repo"][key] = e
    return idx


def events_for_user(idx, github_id=None, usernames=()):
    out = {}
    if github_id:
        for e in idx["by_id"].get(str(github_id), []): out[e["event_key"]] = e
    for u in usernames:
        if u:
            for e in idx["by_user"].get(norm(u), []): out[e["event_key"]] = e
    # Pull invitation events through org.add_member invitation_id.
    invite_ids = {e.get("invitation_id") for e in out.values() if e.get("invitation_id")}
    for inv in invite_ids:
        for e in idx["by_invitation"].get(str(inv), []): out[e["event_key"]] = e
    return sorted(out.values(), key=lambda e: str(e.get("created_at") or ""), reverse=True)


def identity_from_audit(idx, github_id=None, usernames=()):
    evs = events_for_user(idx, github_id, usernames)
    invitation = None; joined = None; removed = None
    # Prefer invitation linked to an add_member for this identity.
    for e in evs:
        if e.get("action") == "org.add_member" and e.get("invitation_id"):
            inv = idx["invitations"].get(str(e["invitation_id"]))
            if inv:
                invitation = inv
                joined = e
                break
    if not invitation:
        invitations = [e for e in evs if e.get("action") == "org.invite_member"]
        invitation = invitations[0] if invitations else None
    if not joined:
        joins = [e for e in evs if e.get("action") == "org.add_member"]
        joined = joins[0] if joins else None
    rems = [e for e in evs if e.get("action") == "org.remove_member"]
    removed = rems[0] if rems else None
    return {
        "email": invitation.get("invite_email") if invitation else None,
        "invited_by": invitation.get("actor") if invitation else None,
        "invited_at": invitation.get("created_at") if invitation else None,
        "joined_at": joined.get("created_at") if joined else None,
        "removed_at": removed.get("created_at") if removed else None,
        "removed_by": removed.get("actor") if removed else None,
        "events": evs,
    }


def actor_for_team_membership(idx, github_id, username, team):
    key_team = norm(short_team(team))
    for user_key in [str(github_id) if github_id else None, norm(username) if username else None]:
        if not user_key: continue
        e = idx["team_add"].get((user_key, key_team))
        if e: return e
    return None


def actor_for_team_repo(idx, team, repo):
    return idx["team_repo"].get((norm(short_team(team)), norm(repo)))


def actor_for_direct_repo(idx, github_id, username, repo):
    for user_key in [str(github_id) if github_id else None, norm(username) if username else None]:
        if not user_key: continue
        e = idx["direct_repo"].get((user_key, norm(repo)))
        if e: return e
    return None
