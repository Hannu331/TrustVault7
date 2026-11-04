"""Each test maps to an entry in THREATS.md (T-numbers)."""
import sqlite3
from app import db

# --- T1 IDOR / T2 every route ---------------------------------------------------
def test_stranger_cannot_use_any_document_route(env):
    d = env.upload("alice"); h = env.h("bob"); u = f"/api/documents/{d}"
    for r in [env.c.get(u, headers=h), env.c.get(u + "/download", headers=h), env.c.put(u, headers=h, json={"name": "x.txt"}),
              env.c.put(u + "/content", headers=h, files={"file": ("a.txt", b"hacked")}), env.c.delete(u, headers=h),
              env.c.get(u + "/grants", headers=h), env.c.get(u + "/audit", headers=h),
              env.c.put(f"{u}/grants/{env.ids['bob']}", headers=h, json={"permission": "edit"}),
              env.c.delete(f"{u}/grants/{env.ids['bob']}", headers=h)]:
        assert r.status_code in (404, 405), (r.request.method, r.request.url, r.status_code)
    assert env.c.get(u + "/download", headers=env.h("alice")).content == b"secret text"   # untouched

def test_unauthenticated_and_garbage_tokens(env):
    d = env.upload("alice")
    assert env.c.get(f"/api/documents/{d}/download").status_code == 401
    assert env.c.get(f"/api/documents/{d}/download", headers={"Authorization": "Bearer nope"}).status_code == 401

def test_no_direct_file_access_via_static_or_paths(env):
    env.upload("alice")
    for p in ["/data/blobs", "/../data/trustvault.db", "/static/../data/t.db", "/app/db.py"]:
        assert env.c.get(p).status_code in (404, 405, 307) and b"secret text" not in env.c.get(p).content

# --- T3 existence oracle ----------------------------------------------------------
def test_missing_and_forbidden_look_identical(env):
    d = env.upload("alice"); h = env.h("bob")
    a, b = env.c.get(f"/api/documents/{d}", headers=h), env.c.get("/api/documents/99999", headers=h)
    assert (a.status_code, a.json()) == (b.status_code, b.json())

# --- T4 read grant is not edit; viewers are read-only ----------------------------------
def test_read_grant_cannot_edit_delete_or_share(env):
    d = env.upload("alice"); env.grant("alice", d, "bob", "read"); h = env.h("bob"); u = f"/api/documents/{d}"
    assert env.c.get(u + "/download", headers=h).status_code == 200
    assert env.c.put(u, headers=h, json={"name": "z.txt"}).status_code == 404
    assert env.c.delete(u, headers=h).status_code == 404
    assert env.c.put(f"{u}/grants/{env.ids['vera']}", headers=h, json={"permission": "read"}).status_code == 404

def test_viewer_cannot_upload_or_be_given_edit(env):
    assert env.c.post("/api/documents", headers=env.h("vera"), files={"file": ("a.txt", b"x")}).status_code == 403
    d = env.upload("alice")
    r = env.c.put(f"/api/documents/{d}/grants/{env.ids['vera'] if 'vera' in env.ids else env.login('vera') and env.ids['vera']}",
                  headers=env.h("alice"), json={"permission": "edit"})
    assert r.status_code == 422

# --- T5 revocation is immediate -----------------------------------------------------
def test_revoke_grant_takes_effect_on_next_request(env):
    d = env.upload("alice"); env.grant("alice", d, "vera"); h = env.h("vera")
    assert env.c.get(f"/api/documents/{d}/download", headers=h).status_code == 200
    assert env.c.delete(f"/api/documents/{d}/grants/{env.ids['vera']}", headers=env.h("alice")).status_code == 200
    assert env.c.get(f"/api/documents/{d}/download", headers=h).status_code == 404      # same token, now refused
    assert env.c.get("/api/documents", headers=h).json() == []

def test_disabling_user_kills_existing_token(env):
    d = env.upload("alice"); env.grant("alice", d, "vera"); h = env.h("vera")
    assert env.c.patch(f"/api/admin/users/{env.ids['vera']}", headers=env.h("admin"), json={"active": False}).status_code == 200
    assert env.c.get("/api/auth/me", headers=h).status_code == 401

def test_logout_invalidates_token(env):
    h = env.h("alice"); env.c.post("/api/auth/logout", headers=h)
    assert env.c.get("/api/auth/me", headers=h).status_code == 401

def test_deleted_document_unreachable_even_for_grantees(env):
    d = env.upload("alice"); env.grant("alice", d, "vera")
    env.c.delete(f"/api/documents/{d}", headers=env.h("alice"))
    assert env.c.get(f"/api/documents/{d}/download", headers=env.h("vera")).status_code == 404

# --- T6 search must not leak -------------------------------------------------------
def test_search_returns_only_accessible_documents(env):
    env.upload("alice", "payroll-2026.txt"); env.upload("bob", "payroll-bob.txt")
    names = [x["name"] for x in env.c.get("/api/documents", headers=env.h("bob"), params={"q": "payroll"}).json()]
    assert names == ["payroll-bob.txt"]
    assert env.c.get("/api/documents", headers=env.h("vera"), params={"q": "payroll"}).json() == []
    assert env.c.get("/api/documents", headers=env.h("bob"), params={"owner": "alice"}).json() == []

def test_search_filters_and_like_wildcards_and_sql_injection(env):
    env.upload("alice", "a_b.txt", cat="hr"); env.upload("alice", "axb.txt", cat="legal")
    g = lambda **p: [x["name"] for x in env.c.get("/api/documents", headers=env.h("alice"), params=p).json()]
    assert g(q="a_b") == ["a_b.txt"]; assert g(category="legal") == ["axb.txt"]
    assert g(q="%") == []; assert g(q="' OR 1=1 --") == []
    assert env.c.get("/api/documents", headers=env.h("alice"), params={"date_from": "2020-01-01'--"}).status_code == 422

# --- T7 admin never reads content ----------------------------------------------------
def test_admin_cannot_read_or_search_content(env):
    d = env.upload("alice"); h = env.h("admin")
    assert env.c.get(f"/api/documents/{d}/download", headers=h).status_code == 404
    assert env.c.get("/api/documents", headers=h).json() == []
    assert env.c.get("/api/admin/activity", headers=h).status_code == 200      # metadata only

def test_non_admin_cannot_reach_admin_endpoints(env):
    for n in ("alice", "vera"):
        for p in ["/api/admin/users", "/api/admin/audit", "/api/admin/audit/verify", "/api/admin/activity"]:
            assert env.c.get(p, headers=env.h(n)).status_code == 403

# --- T8 mass assignment / privilege escalation ----------------------------------------
def test_mass_assignment_rejected(env):
    d = env.upload("alice"); h = env.h("alice")
    assert env.c.put(f"/api/documents/{d}", headers=h, json={"name": "a.txt", "owner_id": env.ids["bob"]}).status_code == 422
    assert env.c.put(f"/api/documents/{d}/grants/{env.ids['bob']}", headers=h, json={"permission": "read", "role": "admin"}).status_code == 422
    assert env.c.patch(f"/api/admin/users/{env.ids['alice']}", headers=h, json={"role": "admin"}).status_code == 403

def test_cannot_grant_to_admin_or_self(env):
    d = env.upload("alice"); h = env.h("alice")
    assert env.c.put(f"/api/documents/{d}/grants/{env.ids['admin'] if 'admin' in env.ids else env.login('admin') and env.ids['admin']}", headers=h, json={"permission": "read"}).status_code == 422
    assert env.c.put(f"/api/documents/{d}/grants/{env.ids['alice']}", headers=h, json={"permission": "read"}).status_code == 422

# --- T9 upload abuse -----------------------------------------------------------------
def test_upload_validation(env):
    h = env.h("alice"); up = lambda n, b: env.c.post("/api/documents", headers=h, files={"file": (n, b)}).status_code
    assert up("evil.html", b"<script>alert(1)</script>") == 415
    assert up("evil.svg", b"<svg onload=alert(1)>") == 415
    assert up("fake.pdf", b"<script>alert(1)</script>") == 415          # content/extension mismatch
    assert up("empty.txt", b"") == 422
    assert up("big.txt", b"a" * (10 * 1024 * 1024 + 1)) == 413
    assert up("bin.txt", b"abc\x00def") == 415

def test_filename_traversal_is_neutralised(env):
    d = env.upload("alice", "../../etc/passwd.txt")
    r = env.c.get(f"/api/documents/{d}", headers=env.h("alice")).json()
    assert "/" not in r["name"] and ".." not in r["name"].split(".")[0] or r["name"] == "passwd.txt"
    dl = env.c.get(f"/api/documents/{d}/download", headers=env.h("alice"))
    assert dl.headers["content-disposition"].startswith("attachment") and dl.headers["x-content-type-options"] == "nosniff"

def test_tampered_blob_is_detected(env):
    d = env.upload("alice"); c = db.connect(); key = c.execute("SELECT storage_key FROM documents").fetchone()[0]
    from app import files
    open(files.blob_path(key), "wb").write(b"tampered")
    assert env.c.get(f"/api/documents/{d}/download", headers=env.h("alice")).status_code == 500
    assert any(r["action"] == "download_integrity_failure" for r in env.audit())

# --- T10 audit trail ------------------------------------------------------------------
def test_audit_records_successes_and_refusals(env):
    d = env.upload("alice"); env.grant("alice", d, "vera")
    env.c.get(f"/api/documents/{d}/download", headers=env.h("vera"))
    env.c.get(f"/api/documents/{d}/download", headers=env.h("bob"))            # refused
    env.c.delete(f"/api/documents/{d}/grants/{env.ids['vera']}", headers=env.h("alice"))
    env.c.post("/api/auth/login", json={"username": "alice", "password": "wrong"})
    acts = {(r["action"], r["outcome"], r["actor_name"]) for r in env.audit()}
    assert {("upload", "ok", "alice"), ("grant_set", "ok", "alice"), ("download", "ok", "vera"),
            ("read_refused", "denied", "bob"), ("grant_revoked", "ok", "alice"), ("login_failed", "denied", None)} <= acts

def test_audit_cannot_be_updated_or_deleted(env):
    env.upload("alice"); c = db.connect()
    for sql in ["UPDATE audit_log SET actor_name='nobody'", "DELETE FROM audit_log"]:
        try: c.execute(sql); raise AssertionError("audit table was modified")
        except sqlite3.DatabaseError as e: assert "append-only" in str(e)

def test_audit_chain_detects_tampering_by_someone_who_drops_the_trigger(env):
    env.upload("alice"); env.upload("alice", "b.txt")
    assert env.c.get("/api/admin/audit/verify", headers=env.h("admin")).json()["valid"] is True
    c = db.connect(); c.execute("DROP TRIGGER audit_no_update"); c.execute("UPDATE audit_log SET actor_name='mallory' WHERE seq=2")
    r = env.c.get("/api/admin/audit/verify", headers=env.h("admin")).json()
    assert r["valid"] is False and r["first_bad_seq"] == 2
    c.execute("DROP TRIGGER audit_no_delete"); c.execute("DELETE FROM audit_log WHERE seq=3")   # silent deletion
    assert env.c.get("/api/admin/audit/verify", headers=env.h("admin")).json()["valid"] is False

# --- T11 brute force --------------------------------------------------------------------
def test_login_lockout_after_repeated_failures(env):
    for _ in range(5): assert env.c.post("/api/auth/login", json={"username": "alice", "password": "bad"}).status_code == 401
    r = env.c.post("/api/auth/login", json={"username": "alice", "password": "Passw0rd-test-1"})
    assert r.status_code == 429

def test_session_dies_when_role_changes(env):
    h = env.h("bob"); env.c.patch(f"/api/admin/users/{env.ids['bob']}", headers=env.h("admin"), json={"role": "viewer"})
    assert env.c.get("/api/auth/me", headers=h).status_code == 401

# --- T12 defence in depth: each layer must hold even if the other is bypassed ----------------
def test_promoted_admin_who_still_owns_documents_cannot_read_them(env):
    d = env.upload("alice")
    c = db.connect(); c.execute("UPDATE users SET role='admin' WHERE username='alice'")   # ownership row remains
    env.login("alice")
    assert env.c.get(f"/api/documents/{d}/download", headers=env.h("alice")).status_code == 404

def test_disabled_flag_alone_blocks_token_even_if_sessions_survive(env):
    h = env.h("vera")
    c = db.connect(); c.execute("UPDATE users SET active=0 WHERE username='vera'")        # sessions NOT deleted
    assert env.c.get("/api/auth/me", headers=h).status_code == 401

def test_grantee_promoted_to_admin_loses_content_access(env):
    d = env.upload("alice"); env.grant("alice", d, "vera")
    c = db.connect(); c.execute("UPDATE users SET role='admin' WHERE username='vera'")    # stale grant row remains
    assert env.c.get(f"/api/documents/{d}/download", headers=env.h("vera")).status_code == 404
