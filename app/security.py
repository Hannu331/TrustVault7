"""Passwords, sessions, login throttling, and role dependencies."""
import hashlib, hmac, os, secrets, time
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, Request
from . import db

SESSION_HOURS = 8
MAX_FAILS, WINDOW = 5, 900
FAILS: dict = {}   # in-memory; see THREATS.md (multi-instance caveat)

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
    exp = (datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    conn.execute("INSERT INTO sessions VALUES(?,?,?,?)", (_th(token), user_id, db.now(), exp))
    return token   # only the hash is stored

def revoke_user_sessions(conn, user_id: int) -> None:
    conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))

def drop_session(conn, token: str) -> None:
    conn.execute("DELETE FROM sessions WHERE token_hash=?", (_th(token),))

def throttled(ip: str, username: str) -> bool:
    k = (ip, username.lower()); t = time.time()
    FAILS[k] = [x for x in FAILS.get(k, []) if t - x < WINDOW]
    return len(FAILS[k]) >= MAX_FAILS

def record_fail(ip: str, username: str) -> None:
    FAILS.setdefault((ip, username.lower()), []).append(time.time())

def current_user(request: Request, conn=Depends(db.get_db)):
    """Resolved from the database on EVERY request: a disabled user, a changed role or a
    deleted session takes effect on the very next call."""
    h = request.headers.get("authorization", "")
    if not h.startswith("Bearer "):
        raise HTTPException(401, "Not authenticated")
    row = conn.execute(
        "SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id "
        "WHERE s.token_hash=? AND s.expires_at>? AND u.active=1", (_th(h[7:]), db.now())).fetchone()
    if not row:
        raise HTTPException(401, "Not authenticated")
    return row

def require_role(*roles):
    def dep(user=Depends(current_user)):
        if user["role"] not in roles:
            raise HTTPException(403, "Forbidden")
        return user
    return dep
