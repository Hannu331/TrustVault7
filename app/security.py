"""Passwords, sessions, login throttling, and role dependencies."""

import hashlib, hmac, os, secrets, time
from datetime import datetime, timedelta, timezone
import re
from fastapi import Depends, HTTPException, Request
from . import db

SESSION_HOURS = 8
MAX_FAILS, WINDOW = 5, 900
FAILS: dict = {}  # in-memory; see THREATS.md (multi-instance caveat)


def hash_pw(pw: str) -> str:
    salt = os.urandom(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1)
    return salt.hex() + "$" + h.hex()


def verify_pw(pw: str, stored: str) -> bool:
    salt, h = stored.split("$")
    cand = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1)
    return hmac.compare_digest(cand.hex(), h)


DUMMY = hash_pw("dummy-password-for-timing")


def _th(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_session(conn, user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    exp = (datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )
    conn.execute("INSERT INTO sessions VALUES(?,?,?,?)", (_th(token), user_id, db.now(), exp))
    return token  # only the hash is stored


def revoke_user_sessions(conn, user_id: int) -> None:
    conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))


def drop_session(conn, token: str) -> None:
    conn.execute("DELETE FROM sessions WHERE token_hash=?", (_th(token),))


def throttled(ip: str, username: str) -> bool:
    k = (ip, username.lower())
    t = time.time()
    FAILS[k] = [x for x in FAILS.get(k, []) if t - x < WINDOW]
    return len(FAILS[k]) >= MAX_FAILS


def record_fail(ip: str, username: str) -> None:
    FAILS.setdefault((ip, username.lower()), []).append(time.time())


PASSWORD_CHANGE_PATHS = {"/api/auth/me", "/api/auth/password", "/api/auth/logout"}


def _refuse_unauthenticated(request: Request, conn):
    """A refused attempt must still leave a record, even when nobody is signed in."""
    match = re.match(r"/api/documents/(\d{1,9})", request.url.path)
    doc_id = int(match.group(1)) if match else None
    ip = request.client.host if request.client else "?"
    db.audit(
        conn,
        None,
        "unauthenticated_refused",
        doc_id,
        "denied",
        {"ip": ip, "method": request.method, "path": request.url.path[:120]},
    )
    raise HTTPException(401, "Not authenticated")


def current_user(request: Request, conn=Depends(db.get_db)):
    """Resolved from the database on EVERY request: a disabled user, a changed role or a
    deleted session takes effect on the very next call."""
    header = request.headers.get("authorization", "")
    if not header.startswith("Bearer "):
        _refuse_unauthenticated(request, conn)
    row = conn.execute(
        "SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id "
        "WHERE s.token_hash=? AND s.expires_at>? AND u.active=1",
        (_th(header[7:]), db.now()),
    ).fetchone()
    if not row:
        _refuse_unauthenticated(request, conn)
    if row["must_change_password"] and request.url.path not in PASSWORD_CHANGE_PATHS:
        raise HTTPException(403, "You must change your temporary password first")
    return row


def require_role(*roles):
    def dependency(request: Request, user=Depends(current_user), conn=Depends(db.get_db)):
        if user["role"] not in roles:
            db.audit(
                conn,
                user,
                "role_refused",
                None,
                "denied",
                {"method": request.method, "path": request.url.path[:120], "needs": list(roles)},
            )
            raise HTTPException(403, "Forbidden")
        return user

    return dependency
