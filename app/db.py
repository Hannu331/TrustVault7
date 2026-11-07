"""SQLite storage, schema and the tamper-evident audit writer."""

import hashlib, json, os, sqlite3
from pathlib import Path
from datetime import datetime, timezone

ROOT = (
    Path(__file__).resolve().parent.parent
)  # project folder, so paths do not depend on the working directory
DB_PATH = os.environ.get("TV_DB", str(ROOT / "data" / "trustvault.db"))
STORE = os.environ.get("TV_STORE", str(ROOT / "data" / "blobs"))
SCHEMA_FILE = ROOT / "db" / "schema.sql"
GENESIS = "0" * 64


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    c = sqlite3.connect(DB_PATH, isolation_level=None, check_same_thread=False, timeout=15)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA journal_mode=WAL")
    return c


def init() -> None:
    os.makedirs(STORE, exist_ok=True)
    c = connect()
    c.executescript(SCHEMA_FILE.read_text())
    columns = {row["name"] for row in c.execute("PRAGMA table_info(users)")}
    if "must_change_password" not in columns:  # database made before this column existed
        c.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0")
    if "expires_at" not in columns:
        c.execute("ALTER TABLE users ADD COLUMN expires_at TEXT")
    if "status" not in columns:  # database made before self sign-up existed: everyone is active
        c.execute(
            "ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active' "
            "CHECK(status IN ('active','pending','rejected'))"
        )
    c.close()


def get_db():
    c = connect()
    try:
        yield c
    finally:
        c.close()


def _digest(prev, ts, actor_id, actor_name, action, doc_id, outcome, detail) -> str:
    payload = json.dumps(
        [prev, ts, actor_id, actor_name, action, doc_id, outcome, detail],
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def audit(conn, actor, action, doc_id=None, outcome="ok", detail=None) -> None:
    """Append one chained record. BEGIN IMMEDIATE serialises writers across processes,
    so two events can never claim the same predecessor. Committed on its own, so a
    refused request is still recorded even though the request itself then fails."""
    actor_id = actor["id"] if actor else None
    actor_name = actor["username"] if actor else None
    detail = json.dumps(detail, sort_keys=True) if detail is not None else None
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        prev = row["hash"] if row else GENESIS
        ts = now()
        h = _digest(prev, ts, actor_id, actor_name, action, doc_id, outcome, detail)
        conn.execute(
            "INSERT INTO audit_log(ts,actor_id,actor_name,action,doc_id,outcome,detail,prev_hash,hash)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (ts, actor_id, actor_name, action, doc_id, outcome, detail, prev, h),
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


def verify_chain(conn, anchor_seq=None, anchor_hash=None) -> dict:
    """Recompute the whole chain. If the caller supplies a previously saved (seq, hash) anchor,
    also detect truncation: deleting the newest records leaves a valid-looking chain, but the
    anchor will be missing or different."""
    prev = GENESIS
    seen_anchor = anchor_seq is None
    for r in conn.execute("SELECT * FROM audit_log ORDER BY seq"):
        expect = _digest(
            r["prev_hash"],
            r["ts"],
            r["actor_id"],
            r["actor_name"],
            r["action"],
            r["doc_id"],
            r["outcome"],
            r["detail"],
        )
        if r["prev_hash"] != prev or r["hash"] != expect:
            return {"valid": False, "first_bad_seq": r["seq"]}
        if r["seq"] == anchor_seq:
            if r["hash"] != anchor_hash:
                return {"valid": False, "reason": "anchor_mismatch", "first_bad_seq": anchor_seq}
            seen_anchor = True
        prev = r["hash"]
    if not seen_anchor:
        return {
            "valid": False,
            "reason": "records_missing_after_anchor",
            "first_bad_seq": anchor_seq,
        }
    last = conn.execute("SELECT seq FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
    return {"valid": True, "head": prev, "head_seq": last["seq"] if last else 0}
