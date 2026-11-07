"""Self sign-up: a new account is inert until an administrator approves it."""

import sqlite3

from app import db, security
from tests.conftest import PW


def signup(env, name="newbie", role="viewer", password=PW):
    return env.c.post("/api/auth/signup", json={"username": name, "password": password, "role": role})


def users(env):
    r = env.c.get("/api/admin/users", headers=env.h("admin"))
    assert r.status_code == 200
    return {u["username"]: u for u in r.json()}


def login(env, name, password=PW):
    return env.c.post("/api/auth/login", json={"username": name, "password": password})


def approve(env, name, role=None):
    return env.c.post(
        f"/api/admin/users/{users(env)[name]['id']}/approve",
        headers=env.h("admin"),
        json={"role": role} if role else {},
    )


def test_signup_creates_a_pending_account_that_cannot_sign_in(env):
    r = signup(env)
    assert r.status_code == 202 and r.json() == {"status": "pending"}
    u = users(env)["newbie"]
    assert (u["status"], u["active"], u["role"]) == ("pending", 0, "viewer")
    # Right password: told why. Wrong password: the same generic answer as for any unknown user.
    refused = login(env, "newbie")
    assert refused.status_code == 403 and "approval" in refused.json()["detail"]
    assert login(env, "newbie", "wrong-password-1").status_code == 401
    assert login(env, "no-such-person").status_code == 401


def test_pending_account_is_invisible_and_cannot_be_given_documents(env):
    signup(env)
    nid = users(env)["newbie"]["id"]
    directory = env.c.get("/api/users/directory", headers=env.h("alice")).json()
    assert "newbie" not in [p["username"] for p in directory]
    doc = env.upload("alice")
    r = env.c.put(
        f"/api/documents/{doc}/grants/{nid}", headers=env.h("alice"), json={"permission": "read"}
    )
    assert r.status_code == 422


def test_approval_activates_the_account_and_it_appears_for_sharing(env):
    signup(env, "newbie", "owner")
    assert approve(env, "newbie").status_code == 200
    u = users(env)["newbie"]
    assert (u["status"], u["active"], u["role"]) == ("active", 1, "owner")
    assert login(env, "newbie").status_code == 200
    directory = env.c.get("/api/users/directory", headers=env.h("alice")).json()
    assert "newbie" in [p["username"] for p in directory]


def test_administrator_can_change_the_role_when_approving(env):
    signup(env, "newbie", "owner")
    assert approve(env, "newbie", "viewer").status_code == 200
    assert users(env)["newbie"]["role"] == "viewer"


def test_new_owner_can_send_a_document_to_another_new_account(env):
    signup(env, "sender", "owner")
    signup(env, "receiver", "viewer")
    approve(env, "sender")
    approve(env, "receiver")
    doc = env.upload("sender")
    env.grant("sender", doc, "receiver")
    r = env.c.get(f"/api/documents/{doc}/download", headers=env.h("receiver"))
    assert r.status_code == 200 and r.content == b"secret text"
    # Still true after sign-up: an administrator never gets the content.
    assert env.c.get(f"/api/documents/{doc}/download", headers=env.h("admin")).status_code == 404


def test_rejected_account_cannot_sign_in_and_can_be_approved_later(env):
    signup(env)
    nid = users(env)["newbie"]["id"]
    assert env.c.post(f"/api/admin/users/{nid}/reject", headers=env.h("admin")).status_code == 200
    assert users(env)["newbie"]["status"] == "rejected"
    refused = login(env, "newbie")
    assert refused.status_code == 403 and "not approved" in refused.json()["detail"]
    assert approve(env, "newbie").status_code == 200
    assert login(env, "newbie").status_code == 200


def test_only_administrators_decide(env):
    signup(env)
    nid = users(env)["newbie"]["id"]
    for name in ("alice", "vera"):
        assert env.c.post(f"/api/admin/users/{nid}/approve", headers=env.h(name), json={}).status_code == 403
        assert env.c.post(f"/api/admin/users/{nid}/reject", headers=env.h(name)).status_code == 403
    assert env.c.post(f"/api/admin/users/{nid}/approve", json={}).status_code == 401
    assert users(env)["newbie"]["status"] == "pending"


def test_decisions_apply_only_to_signup_requests(env):
    alice = env.ids["alice"]  # already active
    assert env.c.post(f"/api/admin/users/{alice}/approve", headers=env.h("admin"), json={}).status_code == 404
    assert env.c.post(f"/api/admin/users/{alice}/reject", headers=env.h("admin")).status_code == 404
    assert env.c.post("/api/admin/users/99999/approve", headers=env.h("admin"), json={}).status_code == 404


def test_signup_cannot_choose_admin_or_set_other_fields(env):
    assert signup(env, role="admin").status_code == 422
    for extra in ({"status": "active"}, {"active": 1}, {"owner_id": 1}):
        r = env.c.post("/api/auth/signup", json={"username": "x-user", "password": PW, **extra})
        assert r.status_code == 422, extra
    assert "x-user" not in users(env)


def test_signup_validates_username_and_password(env):
    assert signup(env, password="short").status_code == 422
    assert signup(env, name="ab").status_code == 422
    assert signup(env, name="has space").status_code == 422
    assert signup(env, name="<script>").status_code == 422


def test_username_is_unique_ignoring_case(env):
    assert signup(env, "Alice").status_code == 409  # alice already exists
    assert signup(env, "newbie").status_code == 202
    assert signup(env, "NEWBIE").status_code == 409
    refusals = [r for r in env.audit(action="signup_refused") if r["outcome"] == "denied"]
    assert len(refusals) == 2


def test_signups_are_throttled_per_ip(env):
    codes = [signup(env, f"user{i}").status_code for i in range(security.SIGNUP_MAX + 1)]
    assert codes[: security.SIGNUP_MAX] == [202] * security.SIGNUP_MAX
    assert codes[-1] == 429
    assert env.audit(action="signup_locked")


def test_pending_queue_is_capped(env, monkeypatch):
    monkeypatch.setattr(security, "MAX_PENDING", 2)
    assert signup(env, "one").status_code == 202
    assert signup(env, "two").status_code == 202
    assert signup(env, "three").status_code == 503


def test_every_step_is_in_the_audit_chain(env):
    signup(env, "newbie", "owner")
    approve(env, "newbie", "viewer")
    signup(env, "other")
    env.c.post(f"/api/admin/users/{users(env)['other']['id']}/reject", headers=env.h("admin"))
    actions = [r["action"] for r in env.audit()]
    for expected in ("signup_requested", "user_approved", "user_rejected"):
        assert expected in actions
    approved = next(r for r in env.audit(action="user_approved"))
    assert '"role": "viewer"' in approved["detail"] and '"requested": "owner"' in approved["detail"]
    assert env.c.get("/api/admin/audit/verify", headers=env.h("admin")).json()["valid"] is True


def test_overview_counts_waiting_accounts(env):
    activity = lambda: env.c.get("/api/admin/activity", headers=env.h("admin")).json()
    assert activity()["pending_users"] == 0
    signup(env, "one")
    signup(env, "two")
    assert activity()["pending_users"] == 2
    approve(env, "one")
    assert activity()["pending_users"] == 1


def test_waiting_requests_are_listed_first(env):
    signup(env)
    assert list(users(env).values())[0]["username"] == "newbie"  # newest id, but pending goes first


def test_patch_keeps_status_consistent(env):
    signup(env, "one")
    signup(env, "two")
    h = env.h("admin")
    one, two = users(env)["one"]["id"], users(env)["two"]["id"]
    env.c.patch(f"/api/admin/users/{one}", headers=h, json={"active": True})
    env.c.patch(f"/api/admin/users/{two}", headers=h, json={"active": False})
    assert (users(env)["one"]["status"], users(env)["one"]["active"]) == ("active", 1)
    assert (users(env)["two"]["status"], users(env)["two"]["active"]) == ("rejected", 0)


def test_database_made_before_signup_existed_is_upgraded(tmp_path):
    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.execute(
        "CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE,"
        " pw_hash TEXT NOT NULL, role TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,"
        " must_change_password INTEGER NOT NULL DEFAULT 0, expires_at TEXT, created_at TEXT NOT NULL)"
    )
    old.execute("INSERT INTO users(username,pw_hash,role,created_at) VALUES('legacy','x','owner','t')")
    old.commit()
    old.close()
    db.DB_PATH, db.STORE = str(path), str(tmp_path / "blobs")
    db.init()
    c = db.connect()
    row = c.execute("SELECT status, active FROM users WHERE username='legacy'").fetchone()
    assert (row["status"], row["active"]) == ("active", 1)
    c.close()
