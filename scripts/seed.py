"""LOCAL TRIALS ONLY (TV_DEMO=1 via bootstrap): trial accounts and sample documents.

Accounts have published passwords, so never use this on a real system (production uses
scripts/provision.py instead). The sample documents show every kind of access:
  salary-letter.txt     alice -> vera can READ
  supplier-contract.txt bob   -> private to bob
  company-handbook.txt  admin -> alice and vera can READ, bob can EDIT (the admin "sent" it)
"""

import os

from app import db, files, security

USERS = [("admin", "admin"), ("alice", "owner"), ("bob", "owner"), ("vera", "viewer")]
DOCUMENTS = [  # (owner, name, category, content, [(person, permission)])
    ("alice", "salary-letter.txt", "hr", b"Salary letter for Vera.", [("vera", "read")]),
    ("bob", "supplier-contract.txt", "contracts", b"Supplier contract draft. Private.", []),
    (
        "admin",
        "company-handbook.txt",
        "policy",
        b"Company handbook, version 1.",
        [("alice", "read"), ("vera", "read"), ("bob", "edit")],
    ),
]


def run():
    db.init()
    conn = db.connect()
    for name, role in USERS:
        if not conn.execute("SELECT 1 FROM users WHERE username=?", (name,)).fetchone():
            password = os.environ.get(f"TV_PW_{name.upper()}", f"{name}-Demo-2026!")
            conn.execute(
                "INSERT INTO users(username,pw_hash,role,created_at) VALUES(?,?,?,?)",
                (name, security.hash_pw(password), role, db.now()),
            )
    ids = {r["username"]: r["id"] for r in conn.execute("SELECT id, username FROM users")}
    if not conn.execute("SELECT 1 FROM documents").fetchone():
        for owner, name, category, content, shares in DOCUMENTS:
            key, digest = files.save_blob(content)
            now = db.now()
            cursor = conn.execute(
                "INSERT INTO documents(name,category,owner_id,storage_key,mime,size,sha256,created_at,updated_at)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                (name, category, ids[owner], key, "text/plain", len(content), digest, now, now),
            )
            db.audit(
                conn,
                {"id": ids[owner], "username": owner},
                "upload",
                cursor.lastrowid,
                detail={"name": name, "size": len(content), "sha256": digest},
            )
            for person, permission in shares:
                conn.execute(
                    "INSERT INTO grants VALUES(?,?,?,?,?)",
                    (cursor.lastrowid, ids[person], permission, ids[owner], now),
                )
                db.audit(
                    conn,
                    {"id": ids[owner], "username": owner},
                    "grant_set",
                    cursor.lastrowid,
                    detail={"target": person, "target_id": ids[person], "permission": permission},
                )
    conn.close()
    print("seeded accounts and sample documents")


if __name__ == "__main__":
    run()
