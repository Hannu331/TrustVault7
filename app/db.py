"""SQLite storage, schema and the tamper-evident audit writer."""
import hashlib, json, os, sqlite3
from datetime import datetime, timezone

DB_PATH = os.environ.get("TV_DB", "data/trustvault.db")
STORE = os.environ.get("TV_STORE", "data/blobs")
GENESIS = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  pw_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','owner','viewer')),
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS documents(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'general',
  owner_id INTEGER NOT NULL REFERENCES users(id),
  storage_key TEXT NOT NULL,
  mime TEXT NOT NULL,
  size INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  deleted_at TEXT);
CREATE TABLE IF NOT EXISTS grants(
  doc_id INTEGER NOT NULL REFERENCES documents(id),
  user_id INTEGER NOT NULL REFERENCES users(id),
  permission TEXT NOT NULL CHECK(permission IN ('read','edit')),
  granted_by INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL,
  PRIMARY KEY(doc_id, user_id));
CREATE TABLE IF NOT EXISTS audit_log(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  actor_id INTEGER,
  actor_name TEXT,
  action TEXT NOT NULL,
  doc_id INTEGER,
  outcome TEXT NOT NULL CHECK(outcome IN ('ok','denied','error')),
  detail TEXT,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
  BEGIN SELECT RAISE(ABORT,'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
  BEGIN SELECT RAISE(ABORT,'audit_log is append-only'); END;
CREATE INDEX IF NOT EXISTS idx_grants_user ON grants(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_doc ON audit_log(doc_id);
"""

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
    c = connect(); c.executescript(SCHEMA); c.close()

def get_db():
    c = connect()
    try: yield c
    finally: c.close()

def _digest(prev, ts, actor_id, actor_name, action, doc_id, outcome, detail) -> str:
    payload = json.dumps([prev, ts, actor_id, actor_name, action, doc_id, outcome, detail],
                         separators=(",", ":"), ensure_ascii=True)
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
        conn.execute("INSERT INTO audit_log(ts,actor_id,actor_name,action,doc_id,outcome,detail,prev_hash,hash)"
                     " VALUES(?,?,?,?,?,?,?,?,?)",
                     (ts, actor_id, actor_name, action, doc_id, outcome, detail, prev, h))
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK"); raise

def verify_chain(conn) -> dict:
    prev = GENESIS
    for r in conn.execute("SELECT * FROM audit_log ORDER BY seq"):
        expect = _digest(r["prev_hash"], r["ts"], r["actor_id"], r["actor_name"], r["action"],
                         r["doc_id"], r["outcome"], r["detail"])
        if r["prev_hash"] != prev or r["hash"] != expect:
            return {"valid": False, "first_bad_seq": r["seq"]}
        prev = r["hash"]
    return {"valid": True, "head": prev}
