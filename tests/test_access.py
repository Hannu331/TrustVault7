"""Each test maps to an entry in THREATS.md (T-numbers)."""

import sqlite3

import pytest
from app import db


# --- T1 IDOR / T2 every route ---------------------------------------------------
def test_stranger_cannot_use_any_document_route(env):
    d = env.upload("alice")
    h = env.h("bob")
    u = f"/api/documents/{d}"
    for r in [
        env.c.get(u, headers=h),
        env.c.get(u + "/download", headers=h),
        env.c.put(u, headers=h, json={"name": "x.txt"}),
        env.c.put(u + "/content", headers=h, files={"file": ("a.txt", b"hacked")}),
        env.c.delete(u, headers=h),
        env.c.get(u + "/grants", headers=h),
        env.c.get(u + "/audit", headers=h),
        env.c.put(f"{u}/grants/{env.ids['bob']}", headers=h, json={"permission": "edit"}),
        env.c.delete(f"{u}/grants/{env.ids['bob']}", headers=h),
    ]:
        assert r.status_code in (404, 405), (r.request.method, r.request.url, r.status_code)
    assert env.c.get(u + "/download", headers=env.h("alice")).content == b"secret text"  # untouched


def test_unauthenticated_and_garbage_tokens(env):
    d = env.upload("alice")
    assert env.c.get(f"/api/documents/{d}/download").status_code == 401
    assert (
        env.c.get(
            f"/api/documents/{d}/download", headers={"Authorization": "Bearer nope"}
        ).status_code
        == 401
    )


def test_no_direct_file_access_via_static_or_paths(env):
    env.upload("alice")
    for p in ["/data/blobs", "/../data/trustvault.db", "/static/../data/t.db", "/app/db.py"]:
        assert (
            env.c.get(p).status_code in (404, 405, 307)
            and b"secret text" not in env.c.get(p).content
        )


# --- T3 existence oracle ----------------------------------------------------------
def test_missing_and_forbidden_look_identical(env):
    d = env.upload("alice")
    h = env.h("bob")
    a, b = env.c.get(f"/api/documents/{d}", headers=h), env.c.get("/api/documents/99999", headers=h)
    assert (a.status_code, a.json()) == (b.status_code, b.json())


# --- T4 read grant is not edit; viewers are read-only ----------------------------------
def test_read_grant_cannot_edit_delete_or_share(env):
    d = env.upload("alice")
    env.grant("alice", d, "bob", "read")
    h = env.h("bob")
    u = f"/api/documents/{d}"
    assert env.c.get(u + "/download", headers=h).status_code == 200
    assert env.c.put(u, headers=h, json={"name": "z.txt"}).status_code == 404
    assert env.c.delete(u, headers=h).status_code == 404
    assert (
        env.c.put(
            f"{u}/grants/{env.ids['vera']}", headers=h, json={"permission": "read"}
        ).status_code
        == 404
    )


def test_viewer_cannot_upload_or_be_given_edit(env):
    assert (
        env.c.post(
            "/api/documents", headers=env.h("vera"), files={"file": ("a.txt", b"x")}
        ).status_code
        == 403
    )
    d = env.upload("alice")
    r = env.c.put(
        f"/api/documents/{d}/grants/{env.ids['vera'] if 'vera' in env.ids else env.login('vera') and env.ids['vera']}",
        headers=env.h("alice"),
        json={"permission": "edit"},
    )
    assert r.status_code == 422


# --- T5 revocation is immediate -----------------------------------------------------
def test_revoke_grant_takes_effect_on_next_request(env):
    d = env.upload("alice")
    env.grant("alice", d, "vera")
    h = env.h("vera")
    assert env.c.get(f"/api/documents/{d}/download", headers=h).status_code == 200
    assert (
        env.c.delete(
            f"/api/documents/{d}/grants/{env.ids['vera']}", headers=env.h("alice")
        ).status_code
        == 200
    )
    assert (
        env.c.get(f"/api/documents/{d}/download", headers=h).status_code == 404
    )  # same token, now refused
    assert env.c.get("/api/documents", headers=h).json() == []


def test_disabling_user_kills_existing_token(env):
    d = env.upload("alice")
    env.grant("alice", d, "vera")
    h = env.h("vera")
    assert (
        env.c.patch(
            f"/api/admin/users/{env.ids['vera']}", headers=env.h("admin"), json={"active": False}
        ).status_code
        == 200
    )
    assert env.c.get("/api/auth/me", headers=h).status_code == 401


def test_logout_invalidates_token(env):
    h = env.h("alice")
    env.c.post("/api/auth/logout", headers=h)
    assert env.c.get("/api/auth/me", headers=h).status_code == 401


def test_deleted_document_unreachable_even_for_grantees(env):
    d = env.upload("alice")
    env.grant("alice", d, "vera")
    env.c.delete(f"/api/documents/{d}", headers=env.h("alice"))
    assert env.c.get(f"/api/documents/{d}/download", headers=env.h("vera")).status_code == 404


# --- T6 search must not leak -------------------------------------------------------
def test_search_returns_only_accessible_documents(env):
    env.upload("alice", "payroll-2026.txt")
    env.upload("bob", "payroll-bob.txt")
    names = [
        x["name"]
        for x in env.c.get("/api/documents", headers=env.h("bob"), params={"q": "payroll"}).json()
    ]
    assert names == ["payroll-bob.txt"]
    assert env.c.get("/api/documents", headers=env.h("vera"), params={"q": "payroll"}).json() == []
    assert env.c.get("/api/documents", headers=env.h("bob"), params={"owner": "alice"}).json() == []


def test_search_filters_and_like_wildcards_and_sql_injection(env):
    env.upload("alice", "a_b.txt", cat="hr")
    env.upload("alice", "axb.txt", cat="legal")
    g = lambda **p: [
        x["name"] for x in env.c.get("/api/documents", headers=env.h("alice"), params=p).json()
    ]
    assert g(q="a_b") == ["a_b.txt"]
    assert g(category="legal") == ["axb.txt"]
    assert g(q="%") == []
    assert g(q="' OR 1=1 --") == []
    assert (
        env.c.get(
            "/api/documents", headers=env.h("alice"), params={"date_from": "2020-01-01'--"}
        ).status_code
        == 422
    )


# --- T7 admin never reads content ----------------------------------------------------
def test_admin_cannot_read_or_search_content(env):
    d = env.upload("alice")
    h = env.h("admin")
    assert env.c.get(f"/api/documents/{d}/download", headers=h).status_code == 404
    assert env.c.get("/api/documents", headers=h).json() == []
    assert env.c.get("/api/admin/activity", headers=h).status_code == 200  # metadata only


def test_non_admin_cannot_reach_admin_endpoints(env):
    for n in ("alice", "vera"):
        for p in [
            "/api/admin/users",
            "/api/admin/audit",
            "/api/admin/audit/verify",
            "/api/admin/activity",
        ]:
            assert env.c.get(p, headers=env.h(n)).status_code == 403


# --- T8 mass assignment / privilege escalation ----------------------------------------
def test_mass_assignment_rejected(env):
    d = env.upload("alice")
    h = env.h("alice")
    assert (
        env.c.put(
            f"/api/documents/{d}", headers=h, json={"name": "a.txt", "owner_id": env.ids["bob"]}
        ).status_code
        == 422
    )
    assert (
        env.c.put(
            f"/api/documents/{d}/grants/{env.ids['bob']}",
            headers=h,
            json={"permission": "read", "role": "admin"},
        ).status_code
        == 422
    )
    assert (
        env.c.patch(
            f"/api/admin/users/{env.ids['alice']}", headers=h, json={"role": "admin"}
        ).status_code
        == 403
    )


def test_cannot_grant_to_admin_or_self(env):
    d = env.upload("alice")
    h = env.h("alice")
    assert (
        env.c.put(
            f"/api/documents/{d}/grants/{env.ids['admin'] if 'admin' in env.ids else env.login('admin') and env.ids['admin']}",
            headers=h,
            json={"permission": "read"},
        ).status_code
        == 422
    )
    assert (
        env.c.put(
            f"/api/documents/{d}/grants/{env.ids['alice']}", headers=h, json={"permission": "read"}
        ).status_code
        == 422
    )


# --- T9 upload abuse -----------------------------------------------------------------
def test_upload_validation(env):
    h = env.h("alice")
    up = lambda n, b: env.c.post("/api/documents", headers=h, files={"file": (n, b)}).status_code
    assert up("evil.html", b"<script>alert(1)</script>") == 415
    assert up("evil.svg", b"<svg onload=alert(1)>") == 415
    assert up("fake.pdf", b"<script>alert(1)</script>") == 415  # content/extension mismatch
    assert up("empty.txt", b"") == 422
    assert up("big.txt", b"a" * (10 * 1024 * 1024 + 1)) == 413
    assert up("bin.txt", b"abc\x00def") == 415


def test_filename_traversal_is_neutralised(env):
    d = env.upload("alice", "../../etc/passwd.txt")
    r = env.c.get(f"/api/documents/{d}", headers=env.h("alice")).json()
    assert "/" not in r["name"] and ".." not in r["name"].split(".")[0] or r["name"] == "passwd.txt"
    dl = env.c.get(f"/api/documents/{d}/download", headers=env.h("alice"))
    assert (
        dl.headers["content-disposition"].startswith("attachment")
        and dl.headers["x-content-type-options"] == "nosniff"
    )


def test_tampered_blob_is_detected(env):
    d = env.upload("alice")
    c = db.connect()
    key = c.execute("SELECT storage_key FROM documents").fetchone()[0]
    from app import files

    open(files.blob_path(key), "wb").write(b"tampered")
    assert env.c.get(f"/api/documents/{d}/download", headers=env.h("alice")).status_code == 500
    assert any(r["action"] == "download_integrity_failure" for r in env.audit())


# --- T10 audit trail ------------------------------------------------------------------
def test_audit_records_successes_and_refusals(env):
    d = env.upload("alice")
    env.grant("alice", d, "vera")
    env.c.get(f"/api/documents/{d}/download", headers=env.h("vera"))
    env.c.get(f"/api/documents/{d}/download", headers=env.h("bob"))  # refused
    env.c.delete(f"/api/documents/{d}/grants/{env.ids['vera']}", headers=env.h("alice"))
    env.c.post("/api/auth/login", json={"username": "alice", "password": "wrong"})
    acts = {(r["action"], r["outcome"], r["actor_name"]) for r in env.audit()}
    assert {
        ("upload", "ok", "alice"),
        ("grant_set", "ok", "alice"),
        ("download", "ok", "vera"),
        ("read_refused", "denied", "bob"),
        ("grant_revoked", "ok", "alice"),
        ("login_failed", "denied", None),
    } <= acts


def test_audit_cannot_be_updated_or_deleted(env):
    env.upload("alice")
    c = db.connect()
    for sql in ["UPDATE audit_log SET actor_name='nobody'", "DELETE FROM audit_log"]:
        try:
            c.execute(sql)
            raise AssertionError("audit table was modified")
        except sqlite3.DatabaseError as e:
            assert "append-only" in str(e)


def test_audit_chain_detects_tampering_by_someone_who_drops_the_trigger(env):
    env.upload("alice")
    env.upload("alice", "b.txt")
    assert env.c.get("/api/admin/audit/verify", headers=env.h("admin")).json()["valid"] is True
    c = db.connect()
    c.execute("DROP TRIGGER audit_no_update")
    c.execute("UPDATE audit_log SET actor_name='mallory' WHERE seq=2")
    r = env.c.get("/api/admin/audit/verify", headers=env.h("admin")).json()
    assert r["valid"] is False and r["first_bad_seq"] == 2
    c.execute("DROP TRIGGER audit_no_delete")
    c.execute("DELETE FROM audit_log WHERE seq=3")  # silent deletion
    assert env.c.get("/api/admin/audit/verify", headers=env.h("admin")).json()["valid"] is False


# --- T11 brute force --------------------------------------------------------------------
def test_login_lockout_after_repeated_failures(env):
    for _ in range(5):
        assert (
            env.c.post("/api/auth/login", json={"username": "alice", "password": "bad"}).status_code
            == 401
        )
    r = env.c.post("/api/auth/login", json={"username": "alice", "password": "Passw0rd-test-1"})
    assert r.status_code == 429


def test_session_dies_when_role_changes(env):
    h = env.h("bob")
    env.c.patch(
        f"/api/admin/users/{env.ids['bob']}", headers=env.h("admin"), json={"role": "viewer"}
    )
    assert env.c.get("/api/auth/me", headers=h).status_code == 401


# --- T12 defence in depth: each layer must hold even if the other is bypassed ----------------
def test_promoted_admin_who_still_owns_documents_cannot_read_them(env):
    d = env.upload("alice")
    c = db.connect()
    c.execute("UPDATE users SET role='admin' WHERE username='alice'")  # ownership row remains
    env.login("alice")
    assert env.c.get(f"/api/documents/{d}/download", headers=env.h("alice")).status_code == 404


def test_disabled_flag_alone_blocks_token_even_if_sessions_survive(env):
    h = env.h("vera")
    c = db.connect()
    c.execute("UPDATE users SET active=0 WHERE username='vera'")  # sessions NOT deleted
    assert env.c.get("/api/auth/me", headers=h).status_code == 401


def test_grantee_promoted_to_admin_loses_content_access(env):
    d = env.upload("alice")
    env.grant("alice", d, "vera")
    c = db.connect()
    c.execute("UPDATE users SET role='admin' WHERE username='vera'")  # stale grant row remains
    assert env.c.get(f"/api/documents/{d}/download", headers=env.h("vera")).status_code == 404


# --- T21 refused attempts are evidence too, even without a valid login -------------------
def test_unauthenticated_attempt_on_a_document_is_audited(env):
    d = env.upload("alice")
    env.c.get(f"/api/documents/{d}/download")  # no token at all
    env.c.get(f"/api/documents/{d}/download", headers={"Authorization": "Bearer forged"})
    rows = [r for r in env.audit(action="unauthenticated_refused")]
    assert len(rows) == 2 and all(r["doc_id"] == d and r["outcome"] == "denied" for r in rows)


def test_role_refusals_are_audited(env):
    env.c.post("/api/documents", headers=env.h("vera"), files={"file": ("a.txt", b"x")})
    env.c.get("/api/admin/users", headers=env.h("alice"))
    refused = {(r["actor_name"], r["action"]) for r in env.audit(action="role_refused")}
    assert refused == {("vera", "role_refused"), ("alice", "role_refused")}


# --- T22 inputs that could crash the server or leak internals ------------------------------
def test_huge_or_odd_ids_never_cause_a_server_error(env):
    h = env.h("alice")
    for path in [
        "/api/documents/99999999999999999999",
        "/api/documents/0",
        "/api/documents/-1",
        "/api/documents/abc",
    ]:
        assert env.c.get(path, headers=h).status_code in (404, 422), path
    big = f"/api/documents/1/grants/99999999999999999999"
    assert env.c.delete(big, headers=h).status_code == 422
    assert (
        env.c.get("/api/admin/audit", headers=env.h("admin"), params={"doc_id": 10**20}).status_code
        == 422
    )


def test_api_docs_and_schema_are_not_published(env):
    for path in ["/docs", "/redoc", "/openapi.json"]:
        assert env.c.get(path).status_code == 404


# --- T15b the chain alone cannot see deleted NEWEST records; a saved anchor can ----------------
def test_anchor_detects_deletion_of_newest_audit_records(env):
    env.upload("alice")
    head = env.c.get("/api/admin/audit/verify", headers=env.h("admin")).json()
    q = {"anchor_seq": head["head_seq"], "anchor_hash": head["head"]}
    assert (
        env.c.get("/api/admin/audit/verify", headers=env.h("admin"), params=q).json()["valid"]
        is True
    )
    c = db.connect()
    c.execute("DROP TRIGGER audit_no_delete")
    c.execute(
        "DELETE FROM audit_log WHERE seq >= ?", (head["head_seq"] - 1,)
    )  # attacker trims the tail
    assert (
        env.c.get("/api/admin/audit/verify", headers=env.h("admin")).json()["valid"] is True
    )  # chain alone is fooled
    assert (
        env.c.get("/api/admin/audit/verify", headers=env.h("admin"), params=q).json()["valid"]
        is False
    )


def test_schema_file_builds_the_database(tmp_path):
    import sqlite3

    conn = sqlite3.connect(tmp_path / "x.db")
    conn.executescript(db.SCHEMA_FILE.read_text())
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"users", "sessions", "documents", "grants", "audit_log"} <= tables


# --- T30 temporary passwords, password change, first admin, backups --------------------------
def _admin_creates(env, name="newbie", role="owner", pw="Temp-password-1"):
    r = env.c.post(
        "/api/admin/users",
        headers=env.h("admin"),
        json={"username": name, "password": pw, "role": role},
    )
    assert r.status_code == 201, r.text
    return env.c.post("/api/auth/login", json={"username": name, "password": pw}).json()["token"]


def test_new_account_must_change_temporary_password_before_anything_else(env):
    token = _admin_creates(env)
    h = {"Authorization": f"Bearer {token}"}
    assert env.c.get("/api/auth/me", headers=h).json()["must_change_password"] is True
    assert env.c.get("/api/documents", headers=h).status_code == 403
    assert (
        env.c.post("/api/documents", headers=h, files={"file": ("a.txt", b"x")}).status_code == 403
    )
    r = env.c.post(
        "/api/auth/password",
        headers=h,
        json={"current": "Temp-password-1", "new": "My-own-password-9"},
    )
    assert r.status_code == 200
    assert env.c.get("/api/auth/me", headers=h).status_code == 401  # all old sessions ended
    again = env.c.post(
        "/api/auth/login", json={"username": "newbie", "password": "My-own-password-9"}
    ).json()["token"]
    assert (
        env.c.get("/api/documents", headers={"Authorization": f"Bearer {again}"}).status_code == 200
    )


def test_admin_password_reset_forces_a_new_change(env):
    env.c.patch(
        f"/api/admin/users/{env.ids['vera']}",
        headers=env.h("admin"),
        json={"password": "Reset-password-1"},
    )
    token = env.c.post(
        "/api/auth/login", json={"username": "vera", "password": "Reset-password-1"}
    ).json()["token"]
    assert (
        env.c.get("/api/documents", headers={"Authorization": f"Bearer {token}"}).status_code == 403
    )


def test_password_change_needs_current_password_and_is_throttled_and_audited(env):
    h = env.h("alice")
    for _ in range(5):
        r = env.c.post(
            "/api/auth/password",
            headers=h,
            json={"current": "wrong-password-1", "new": "Another-pass-123"},
        )
        assert r.status_code == 403
    assert (
        env.c.post(
            "/api/auth/password", headers=h, json={"current": "x", "new": "Another-pass-123"}
        ).status_code
        == 429
    )
    actions = {r["action"] for r in env.audit(actor="alice")}
    assert {"password_change_failed", "password_change_locked"} <= actions


def test_changing_password_ends_all_sessions_and_old_password_stops_working(env):
    other_session = env.c.post(
        "/api/auth/login", json={"username": "bob", "password": "Passw0rd-test-1"}
    ).json()["token"]
    h = env.h("bob")
    assert (
        env.c.post(
            "/api/auth/password",
            headers=h,
            json={"current": "Passw0rd-test-1", "new": "Brand-new-pass-77"},
        ).status_code
        == 200
    )
    assert (
        env.c.get("/api/auth/me", headers={"Authorization": f"Bearer {other_session}"}).status_code
        == 401
    )
    assert (
        env.c.post(
            "/api/auth/login", json={"username": "bob", "password": "Passw0rd-test-1"}
        ).status_code
        == 401
    )
    assert any(r["action"] == "password_changed" for r in env.audit(actor="bob"))


def test_first_admin_bootstrap_runs_once_and_rejects_weak_passwords(tmp_path, monkeypatch):
    from scripts import bootstrap

    db.DB_PATH, db.STORE = str(tmp_path / "b.db"), str(tmp_path / "blobs")
    db.init()
    monkeypatch.delenv("TV_ADMIN_USER", raising=False)
    monkeypatch.delenv("TV_ADMIN_PASSWORD", raising=False)
    assert bootstrap.ensure_admin().startswith("NO ADMIN")
    monkeypatch.setenv("TV_ADMIN_USER", "boss")
    monkeypatch.setenv("TV_ADMIN_PASSWORD", "short")
    with pytest.raises(SystemExit):
        bootstrap.ensure_admin()
    monkeypatch.setenv("TV_ADMIN_PASSWORD", "a-long-secret-pass")
    assert bootstrap.ensure_admin() == "created administrator boss"
    assert bootstrap.ensure_admin() == "an administrator already exists"
    conn = db.connect()
    assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1
    assert conn.execute("SELECT action FROM audit_log").fetchone()[0] == "first_admin_created"


def test_demo_buttons_only_when_demo_flag_is_set(env, monkeypatch):
    monkeypatch.delenv("TV_DEMO", raising=False)
    assert env.c.get("/api/config").json() == {"demo": False}
    monkeypatch.setenv("TV_DEMO", "1")
    assert env.c.get("/api/config").json() == {"demo": True}


def test_old_database_gets_the_new_column_on_startup(tmp_path):
    db.DB_PATH, db.STORE = str(tmp_path / "old.db"), str(tmp_path / "blobs")
    db.init()
    conn = db.connect()
    conn.execute("ALTER TABLE users DROP COLUMN must_change_password")
    conn.close()
    db.init()
    assert "must_change_password" in {
        r["name"] for r in db.connect().execute("PRAGMA table_info(users)")
    }


def test_backup_contains_database_and_files(env, tmp_path):
    import tarfile
    from scripts import backup

    env.upload("alice")
    with tarfile.open(backup.run(tmp_path / "out")) as tar:
        names = tar.getnames()
    assert "trustvault.db" in names and any(n.startswith("blobs/") and len(n) > 10 for n in names)
