"""T35: the sharing model. Admin sends documents, owners share, viewers read or edit."""

from app import db


def _admin_upload(env, name="from-admin.txt", data=b"admin document"):
    r = env.c.post("/api/documents", headers=env.h("admin"), files={"file": (name, data)})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def test_admin_can_upload_and_send_a_document_to_any_account(env):
    d = _admin_upload(env)
    env.grant("admin", d, "vera", "read")
    env.grant("admin", d, "bob", "edit")
    assert (
        env.c.get(f"/api/documents/{d}/download", headers=env.h("vera")).content
        == b"admin document"
    )
    r = env.c.put(
        f"/api/documents/{d}/content",
        headers=env.h("bob"),
        files={"file": ("from-admin.txt", b"bob edit")},
    )
    assert r.status_code == 200
    assert env.c.get(f"/api/documents/{d}/download", headers=env.h("admin")).content == b"bob edit"
    assert env.c.get(f"/api/documents/{d}/download", headers=env.h("wendy")).status_code == 404
    assert [x["name"] for x in env.c.get("/api/documents", headers=env.h("admin")).json()] == [
        "from-admin.txt"
    ]


def test_viewer_with_edit_can_edit_but_never_upload_share_or_delete(env):
    d = env.upload("alice")
    env.grant("alice", d, "vera", "edit")
    h, u = env.h("vera"), f"/api/documents/{d}"
    assert (
        env.c.put(u + "/content", headers=h, files={"file": ("a.txt", b"edited")}).status_code
        == 200
    )
    assert env.c.delete(u, headers=h).status_code == 404
    assert (
        env.c.put(
            f"{u}/grants/{env.ids['wendy']}", headers=h, json={"permission": "read"}
        ).status_code
        == 404
    )
    assert env.c.get(u + "/audit", headers=h).status_code == 404
    assert (
        env.c.post("/api/documents", headers=h, files={"file": ("b.txt", b"x")}).status_code == 403
    )


def test_owner_can_share_with_any_viewer(env):
    d = env.upload("alice")
    for who in ("vera", "wendy"):
        env.grant("alice", d, who, "read")
    names = lambda who: [x["name"] for x in env.c.get("/api/documents", headers=env.h(who)).json()]
    assert names("vera") == names("wendy") == ["a.txt"]


def test_admin_has_no_access_to_other_peoples_documents_by_any_route(env):
    d = env.upload("alice")
    h, u = env.h("admin"), f"/api/documents/{d}"
    responses = [
        env.c.get(u, headers=h),
        env.c.get(u + "/download", headers=h),
        env.c.put(u, headers=h, json={"name": "x.txt"}),
        env.c.put(u + "/content", headers=h, files={"file": ("a.txt", b"x")}),
        env.c.delete(u, headers=h),
        env.c.get(u + "/audit", headers=h),
        env.c.put(f"{u}/grants/{env.ids['admin']}", headers=h, json={"permission": "read"}),
        env.c.put(f"{u}/grants/{env.ids['vera']}", headers=h, json={"permission": "read"}),
    ]
    for r in responses:
        assert r.status_code in (404, 422), (r.request.method, r.request.url, r.status_code)
    assert env.c.get(u + "/download", headers=env.h("alice")).content == b"secret text"


def test_admin_access_list_shows_who_has_what(env):
    d = env.upload("alice")
    env.grant("alice", d, "vera", "read")
    env.grant("alice", d, "bob", "edit")
    rows = env.c.get("/api/admin/access", headers=env.h("admin")).json()
    seen = {(r["person"], r["access"], r["granted_by"]) for r in rows if r["doc_id"] == d}
    assert seen == {("alice", "owner", None), ("vera", "read", "alice"), ("bob", "edit", "alice")}
    assert env.c.get("/api/admin/access", headers=env.h("alice")).status_code == 403


def test_admin_can_remove_anyones_access_immediately_but_not_add_it(env):
    d = env.upload("alice")
    env.grant("alice", d, "vera", "read")
    h = env.h("vera")
    assert env.c.get(f"/api/documents/{d}/download", headers=h).status_code == 200
    assert (
        env.c.delete(f"/api/admin/grants/{d}/{env.ids['vera']}", headers=env.h("admin")).status_code
        == 200
    )
    assert (
        env.c.get(f"/api/documents/{d}/download", headers=h).status_code == 404
    )  # same token, refused at once
    assert (
        env.c.delete(f"/api/admin/grants/{d}/{env.ids['vera']}", headers=env.h("alice")).status_code
        == 403
    )
    assert any(
        r["action"] == "grant_revoked" and r["actor_name"] == "admin" for r in env.audit(doc_id=d)
    )


def test_purge_removes_every_document_and_keeps_accounts_and_audit(env):
    import pytest
    from scripts import purge_documents

    d = env.upload("alice")
    env.grant("alice", d, "vera")
    assert purge_documents.run(confirmed=True) == 1
    assert env.c.get("/api/documents", headers=env.h("alice")).json() == []
    assert env.c.get("/api/admin/access", headers=env.h("admin")).json() == []
    assert env.c.get("/api/auth/me", headers=env.h("vera")).status_code == 200
    assert any(r["action"] == "documents_purged" for r in env.audit()) and env.audit(
        action="upload"
    )
    assert env.c.get("/api/admin/audit/verify", headers=env.h("admin")).json()["valid"] is True
    with pytest.raises(SystemExit):
        purge_documents.run(confirmed=False)


def test_demoted_owner_loses_owner_powers_over_their_old_documents(env):
    d = env.upload("alice")
    env.grant("alice", d, "vera", "read")
    admin = env.h("admin")
    assert (
        env.c.patch(
            f"/api/admin/users/{env.ids['alice']}", headers=admin, json={"role": "viewer"}
        ).status_code
        == 200
    )
    env.login("alice")
    h, u = env.h("alice"), f"/api/documents/{d}"
    assert env.c.delete(u, headers=h).status_code == 404
    assert (
        env.c.put(
            f"{u}/grants/{env.ids['wendy']}", headers=h, json={"permission": "read"}
        ).status_code
        == 404
    )
    assert env.c.get(u + "/audit", headers=h).status_code == 404
    assert (
        env.c.get(u + "/download", headers=env.h("vera")).status_code == 200
    )  # existing grants are untouched
