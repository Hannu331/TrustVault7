"""TrustVault API. Authorisation: security.current_user (who) + authz.authorize (what)."""

import hashlib, json, os, re
from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager
from typing import Annotated, Literal, Optional
from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi import Path as PathParam
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from . import db, files, security
from .authz import authorize
from .db import audit
from .security import current_user, require_role


@asynccontextmanager
async def lifespan(_):
    db.init()
    yield


# Interactive docs are switched off: the API is documented in docs/API.md, not published to strangers.
app = FastAPI(
    title="TrustVault", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None
)

# Ids are bounded so a huge number cannot overflow the database driver and cause a 500.
Id = Annotated[int, PathParam(ge=1, le=2**31 - 1)]


@app.middleware("http")
async def hardening(request: Request, call_next):
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > files.MAX_BYTES + 1_000_000:
        return JSONResponse({"detail": "Request too large"}, status_code=413)
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; frame-ancestors 'none'; object-src 'none'"
    )
    if request.url.path.startswith("/api"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")  # unknown fields (e.g. role, owner_id) are rejected


# ---------------------------------------------------------------- auth
class Login(Strict):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


@app.post("/api/auth/login")
def login(body: Login, request: Request, conn=Depends(db.get_db)):
    ip = request.client.host if request.client else "?"
    if security.throttled(ip, body.username):
        audit(
            conn,
            None,
            "login_locked",
            outcome="denied",
            detail={"username": body.username[:64], "ip": ip},
        )
        raise HTTPException(429, "Too many attempts. Try again later.")
    u = conn.execute("SELECT * FROM users WHERE username=?", (body.username,)).fetchone()
    ok = security.verify_pw(
        body.password, u["pw_hash"] if u else security.DUMMY
    )  # constant work either way
    expired = bool(u and u["expires_at"] and u["expires_at"] <= db.now())
    if not (u and ok and u["active"]) or expired:
        security.record_fail(ip, body.username)
        audit(
            conn,
            None,
            "login_failed",
            outcome="denied",
            detail={"username": body.username[:64], "ip": ip},
        )
        raise HTTPException(401, "Invalid credentials")
    token = security.new_session(conn, u["id"])
    audit(conn, u, "login", detail={"ip": ip})
    return {"token": token, "user": {"id": u["id"], "username": u["username"], "role": u["role"]}}


@app.post("/api/auth/logout")
def logout(request: Request, user=Depends(current_user), conn=Depends(db.get_db)):
    security.drop_session(conn, request.headers["authorization"][7:])
    audit(conn, user, "logout")
    return {"ok": True}


@app.get("/api/auth/me")
def me(user=Depends(current_user)):
    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "must_change_password": bool(user["must_change_password"]),
    }


@app.get("/api/config")
def public_config():
    """The only public setting: whether this is the demo deployment (shows demo sign-in buttons)."""
    return {"demo": os.environ.get("TV_DEMO") == "1"}


class PasswordChange(Strict):
    current: str = Field(max_length=256)
    new: str = Field(min_length=10, max_length=256)


@app.post("/api/auth/password")
def change_password(
    body: PasswordChange,
    request: Request,
    user=Depends(current_user),
    conn=Depends(db.get_db),
):
    ip = request.client.host if request.client else "?"
    if security.throttled(ip, user["username"]):
        audit(conn, user, "password_change_locked", outcome="denied", detail={"ip": ip})
        raise HTTPException(429, "Too many attempts. Try again later.")
    if not security.verify_pw(body.current, user["pw_hash"]):
        security.record_fail(ip, user["username"])
        audit(conn, user, "password_change_failed", outcome="denied", detail={"ip": ip})
        raise HTTPException(
            403, "Current password is incorrect"
        )  # not 401: the session is still valid
    if body.new == body.current:
        raise HTTPException(422, "Choose a different password")
    conn.execute(
        "UPDATE users SET pw_hash=?, must_change_password=0 WHERE id=?",
        (security.hash_pw(body.new), user["id"]),
    )
    security.revoke_user_sessions(
        conn, user["id"]
    )  # every existing session ends, including this one
    audit(conn, user, "password_changed", detail={"ip": ip})
    return {"ok": True}


@app.get("/api/users/directory")
def directory(user=Depends(require_role("owner")), conn=Depends(db.get_db)):
    rows = conn.execute(
        "SELECT id,username,role FROM users WHERE active=1 AND role!='admin' AND id!=? ORDER BY username",
        (user["id"],),
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------- documents
def _pub(r, access=None):
    d = {
        k: r[k]
        for k in ("id", "name", "category", "mime", "size", "version", "created_at", "updated_at")
    }
    d["owner"] = r["owner_name"]
    if access:
        d["access"] = access
    return d


def _load(conn, doc_id, user):
    r = conn.execute(
        "SELECT d.*, u.username owner_name FROM documents d JOIN users u ON u.id=d.owner_id WHERE d.id=?",
        (doc_id,),
    ).fetchone()
    return r


CAT = Field(default="general", min_length=1, max_length=40, pattern=r"^[\w .\-]+$")
DATE = r"^\d{4}-\d{2}-\d{2}$"


@app.post("/api/documents", status_code=201)
async def upload(
    file: UploadFile = File(...),
    category: str = Form("general"),
    user=Depends(require_role("owner")),
    conn=Depends(db.get_db),
):
    if not re.fullmatch(r"[\w .\-]{1,40}", category):
        raise HTTPException(422, "Invalid category")
    try:
        name, mime, data = await files.read_validated(file)
    except HTTPException as e:
        audit(
            conn,
            user,
            "upload_rejected",
            outcome="error",
            detail={"reason": e.detail, "name": (file.filename or "")[:120]},
        )
        raise
    key, digest = files.save_blob(data)
    t = db.now()
    cur = conn.execute(
        "INSERT INTO documents(name,category,owner_id,storage_key,mime,size,sha256,created_at,updated_at)"
        " VALUES(?,?,?,?,?,?,?,?,?)",
        (name, category, user["id"], key, mime, len(data), digest, t, t),
    )
    audit(
        conn,
        user,
        "upload",
        cur.lastrowid,
        detail={"name": name, "size": len(data), "sha256": digest},
    )
    return _pub(_load(conn, cur.lastrowid, user), "owner")


@app.get("/api/documents")
def search(
    q: Optional[str] = Query(None, max_length=100),
    owner: Optional[str] = Query(None, max_length=64),
    category: Optional[str] = Query(None, max_length=40),
    date_from: Optional[str] = Query(None, pattern=DATE),
    date_to: Optional[str] = Query(None, pattern=DATE),
    user=Depends(current_user),
    conn=Depends(db.get_db),
):
    """Authorisation is part of the SQL itself, so unauthorised rows are never read, counted or ranked."""
    if user["role"] == "admin":
        return []
    esc = lambda s: s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    sql = (
        "SELECT d.*, u.username owner_name, CASE WHEN d.owner_id=? THEN 'owner' ELSE g.permission END access "
        "FROM documents d JOIN users u ON u.id=d.owner_id "
        "LEFT JOIN grants g ON g.doc_id=d.id AND g.user_id=? "
        "WHERE d.deleted_at IS NULL AND (d.owner_id=? OR g.user_id IS NOT NULL)"
    )
    args = [user["id"]] * 3
    if q:
        sql += " AND d.name LIKE ? ESCAPE '\\'"
        args.append(f"%{esc(q)}%")
    if owner:
        sql += " AND u.username LIKE ? ESCAPE '\\'"
        args.append(f"%{esc(owner)}%")
    if category:
        sql += " AND d.category=? COLLATE NOCASE"
        args.append(category)
    if date_from:
        sql += " AND d.created_at>=?"
        args.append(date_from)
    if date_to:
        sql += " AND d.created_at<?"
        args.append(date_to + "\uffff")
    rows = conn.execute(sql + " ORDER BY d.created_at DESC LIMIT 200", args).fetchall()
    audit(
        conn,
        user,
        "search",
        detail={"q": q, "owner": owner, "category": category, "results": len(rows)},
    )
    return [_pub(r, r["access"]) for r in rows]


@app.get("/api/documents/{doc_id}")
def get_doc(doc_id: Id, user=Depends(current_user), conn=Depends(db.get_db)):
    authorize(conn, user, doc_id, "read")
    r = _load(conn, doc_id, user)
    out = _pub(
        r,
        (
            "owner"
            if r["owner_id"] == user["id"]
            else conn.execute(
                "SELECT permission FROM grants WHERE doc_id=? AND user_id=?", (doc_id, user["id"])
            ).fetchone()[0]
        ),
    )
    if r["owner_id"] == user["id"]:
        out["grants"] = [
            dict(g)
            for g in conn.execute(
                "SELECT g.user_id, u.username, g.permission, g.created_at FROM grants g JOIN users u ON u.id=g.user_id "
                "WHERE g.doc_id=? ORDER BY u.username",
                (doc_id,),
            )
        ]
    return out


@app.get("/api/documents/{doc_id}/download")
def download(doc_id: Id, user=Depends(current_user), conn=Depends(db.get_db)):
    doc = authorize(conn, user, doc_id, "read")
    path = files.blob_path(doc["storage_key"])
    try:
        with open(path, "rb") as fh:
            ok = hashlib.sha256(fh.read()).hexdigest() == doc["sha256"]
    except FileNotFoundError:
        ok = False
    if not ok:
        audit(conn, user, "download_integrity_failure", doc_id, "error")
        raise HTTPException(500, "Stored file failed its integrity check")
    audit(
        conn, user, "download", doc_id, detail={"version": doc["version"], "sha256": doc["sha256"]}
    )
    return FileResponse(
        path,
        media_type=doc["mime"],
        filename=doc["name"],
        headers={"Content-Disposition": _attachment(doc["name"])},
    )


def _attachment(name: str) -> str:
    return f'attachment; filename="{re.sub(r"[^A-Za-z0-9._ -]", "_", name)}"'


class DocPatch(Strict):
    name: Optional[str] = Field(None, max_length=120)
    category: Optional[str] = Field(None, min_length=1, max_length=40, pattern=r"^[\w .\-]+$")


@app.put("/api/documents/{doc_id}")
def edit_meta(doc_id: Id, body: DocPatch, user=Depends(current_user), conn=Depends(db.get_db)):
    doc = authorize(conn, user, doc_id, "edit")
    name = files.clean_name(body.name) if body.name else doc["name"]
    cat = body.category or doc["category"]
    conn.execute(
        "UPDATE documents SET name=?, category=?, updated_at=? WHERE id=?",
        (name, cat, db.now(), doc_id),
    )
    audit(
        conn,
        user,
        "update_metadata",
        doc_id,
        detail={"old": [doc["name"], doc["category"]], "new": [name, cat]},
    )
    return _pub(_load(conn, doc_id, user))


@app.put("/api/documents/{doc_id}/content")
async def replace_content(
    doc_id: Id, file: UploadFile = File(...), user=Depends(current_user), conn=Depends(db.get_db)
):
    doc = authorize(conn, user, doc_id, "edit")
    name, mime, data = await files.read_validated(file)
    key, digest = files.save_blob(data)
    conn.execute(
        "UPDATE documents SET storage_key=?, mime=?, size=?, sha256=?, version=version+1, name=?, updated_at=? WHERE id=?",
        (key, mime, len(data), digest, name, db.now(), doc_id),
    )
    files.remove_blob(doc["storage_key"])
    audit(
        conn,
        user,
        "content_replaced",
        doc_id,
        detail={"from_version": doc["version"], "old_sha256": doc["sha256"], "new_sha256": digest},
    )
    return _pub(_load(conn, doc_id, user))


@app.delete("/api/documents/{doc_id}")
def delete_doc(doc_id: Id, user=Depends(current_user), conn=Depends(db.get_db)):
    authorize(conn, user, doc_id, "delete")
    conn.execute(
        "UPDATE documents SET deleted_at=? WHERE id=?", (db.now(), doc_id)
    )  # soft delete; blob kept for recovery
    audit(conn, user, "delete", doc_id)
    return {"ok": True}


# ---------------------------------------------------------------- sharing
class GrantBody(Strict):
    permission: Literal["read", "edit"]


@app.put("/api/documents/{doc_id}/grants/{target_id}")
def set_grant(
    doc_id: Id,
    target_id: Id,
    body: GrantBody,
    user=Depends(current_user),
    conn=Depends(db.get_db),
):
    authorize(conn, user, doc_id, "share")
    t = conn.execute("SELECT * FROM users WHERE id=? AND active=1", (target_id,)).fetchone()
    if not t or t["role"] == "admin" or t["id"] == user["id"]:
        raise HTTPException(422, "That person cannot be granted access")
    if body.permission == "edit" and t["role"] != "owner":
        raise HTTPException(422, "Viewers can only be given read access")
    conn.execute(
        "INSERT INTO grants VALUES(?,?,?,?,?) ON CONFLICT(doc_id,user_id) DO UPDATE SET permission=excluded.permission, granted_by=excluded.granted_by",
        (doc_id, target_id, body.permission, user["id"], db.now()),
    )
    audit(
        conn,
        user,
        "grant_set",
        doc_id,
        detail={"target": t["username"], "target_id": target_id, "permission": body.permission},
    )
    return {"ok": True}


@app.delete("/api/documents/{doc_id}/grants/{target_id}")
def revoke_grant(doc_id: Id, target_id: Id, user=Depends(current_user), conn=Depends(db.get_db)):
    authorize(conn, user, doc_id, "share")
    cur = conn.execute("DELETE FROM grants WHERE doc_id=? AND user_id=?", (doc_id, target_id))
    audit(
        conn,
        user,
        "grant_revoked",
        doc_id,
        detail={"target_id": target_id, "existed": cur.rowcount > 0},
    )
    return {"ok": True}


@app.get("/api/documents/{doc_id}/audit")
def doc_audit(doc_id: Id, user=Depends(current_user), conn=Depends(db.get_db)):
    authorize(conn, user, doc_id, "audit")
    return [
        dict(r)
        for r in conn.execute(
            "SELECT seq,ts,actor_name,action,outcome,detail FROM audit_log WHERE doc_id=? ORDER BY seq DESC LIMIT 500",
            (doc_id,),
        )
    ]


# ---------------------------------------------------------------- admin (metadata and people only, never content)
admin = require_role("admin")


class NewUser(Strict):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[\w.\-]+$")
    password: str = Field(min_length=10, max_length=256)
    role: Literal["admin", "owner", "viewer"]
    # True for staff (they choose their own password at first sign-in). False only for
    # shared evaluation accounts, whose password the administrator controls.
    require_password_change: bool = True
    expires_in_days: Optional[int] = Field(None, ge=1, le=365)  # account stops working by itself


class UserPatch(Strict):
    role: Optional[Literal["admin", "owner", "viewer"]] = None
    active: Optional[bool] = None
    password: Optional[str] = Field(None, min_length=10, max_length=256)


@app.get("/api/admin/users")
def list_users(user=Depends(admin), conn=Depends(db.get_db)):
    return [
        dict(r)
        for r in conn.execute(
            "SELECT id,username,role,active,expires_at,created_at FROM users ORDER BY id"
        )
    ]


@app.post("/api/admin/users", status_code=201)
def create_user(body: NewUser, user=Depends(admin), conn=Depends(db.get_db)):
    expires_at = None
    if body.expires_in_days:
        expires_at = (datetime.now(timezone.utc) + timedelta(days=body.expires_in_days)).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
    try:
        cur = conn.execute(
            "INSERT INTO users(username,pw_hash,role,must_change_password,expires_at,created_at) VALUES(?,?,?,?,?,?)",
            (
                body.username,
                security.hash_pw(body.password),
                body.role,
                int(body.require_password_change),
                expires_at,
                db.now(),
            ),
        )
    except Exception:
        raise HTTPException(409, "Username already exists")
    audit(conn, user, "user_created", detail={"username": body.username, "role": body.role})
    return {"id": cur.lastrowid}


@app.patch("/api/admin/users/{uid}")
def patch_user(uid: Id, body: UserPatch, user=Depends(admin), conn=Depends(db.get_db)):
    if uid == user["id"]:
        raise HTTPException(422, "Administrators cannot change their own account here")
    t = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not t:
        raise HTTPException(404, "User not found")
    if body.role:
        conn.execute("UPDATE users SET role=? WHERE id=?", (body.role, uid))
    if body.active is not None:
        conn.execute("UPDATE users SET active=? WHERE id=?", (int(body.active), uid))
    if body.password:
        conn.execute(
            "UPDATE users SET pw_hash=?, must_change_password=1 WHERE id=?",
            (security.hash_pw(body.password), uid),
        )
    if (
        body.role and body.role != t["role"]
    ):  # a role change also removes grants the new role could not hold
        if body.role != "owner":
            conn.execute("DELETE FROM grants WHERE user_id=? AND permission='edit'", (uid,))
    security.revoke_user_sessions(conn, uid)  # immediate: every token issued before now dies
    audit(
        conn,
        user,
        "user_changed",
        detail={
            "target": t["username"],
            "role": body.role,
            "active": body.active,
            "password_reset": bool(body.password),
        },
    )
    return {"ok": True}


@app.get("/api/admin/audit")
def admin_audit(
    action: Optional[str] = Query(None, max_length=40),
    outcome: Optional[Literal["ok", "denied", "error"]] = None,
    actor: Optional[str] = Query(None, max_length=64),
    doc_id: Optional[int] = Query(None, ge=1, le=2**31 - 1),
    limit: int = Query(200, ge=1, le=1000),
    user=Depends(admin),
    conn=Depends(db.get_db),
):
    sql, args = "SELECT * FROM audit_log WHERE 1=1", []
    for col, val in (
        ("action", action),
        ("outcome", outcome),
        ("actor_name", actor),
        ("doc_id", doc_id),
    ):
        if val is not None:
            sql += f" AND {col}=?"
            args.append(val)
    return [dict(r) for r in conn.execute(sql + " ORDER BY seq DESC LIMIT ?", args + [limit])]


@app.get("/api/admin/audit/verify")
def admin_verify(
    anchor_seq: Optional[int] = Query(None, ge=1, le=2**31 - 1),
    anchor_hash: Optional[str] = Query(None, pattern=r"^[0-9a-f]{64}$"),
    user=Depends(admin),
    conn=Depends(db.get_db),
):
    """Verify the chain. Pass a previously saved anchor to also detect deleted newest records."""
    return db.verify_chain(conn, anchor_seq, anchor_hash)


@app.get("/api/admin/activity")
def activity(user=Depends(admin), conn=Depends(db.get_db)):
    """What is worth noticing: refusals, repeated failures, and every permission change."""
    return {
        "by_action_24h": [
            dict(r)
            for r in conn.execute(
                "SELECT action, outcome, COUNT(*) n FROM audit_log WHERE ts>=strftime('%Y-%m-%dT%H:%M:%fZ','now','-1 day') GROUP BY 1,2 ORDER BY n DESC"
            )
        ],
        "notable": [
            dict(r)
            for r in conn.execute(
                "SELECT COALESCE(actor_name,'(unauthenticated)') actor, COUNT(*) refused FROM audit_log WHERE outcome='denied' "
                "AND ts>=strftime('%Y-%m-%dT%H:%M:%fZ','now','-1 day') GROUP BY 1 HAVING refused>=3 ORDER BY refused DESC"
            )
        ],
        "permission_changes": [
            dict(r)
            for r in conn.execute(
                "SELECT seq,ts,actor_name,action,doc_id,detail FROM audit_log WHERE action IN ('grant_set','grant_revoked','user_changed','user_created') ORDER BY seq DESC LIMIT 50"
            )
        ],
        "documents": [
            dict(r)
            for r in conn.execute(
                "SELECT d.id,d.name,d.category,u.username owner,d.size,d.version,d.deleted_at,"
                "(SELECT COUNT(*) FROM grants g WHERE g.doc_id=d.id) grants FROM documents d JOIN users u ON u.id=d.owner_id ORDER BY d.id DESC LIMIT 200"
            )
        ],
    }


app.mount("/", StaticFiles(directory=str(db.ROOT / "app" / "static"), html=True), name="static")
