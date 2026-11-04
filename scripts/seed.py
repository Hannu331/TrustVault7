"""Seed demo users and documents. Idempotent. Usage: python -m scripts.seed"""
import os
from app import db, security

USERS = [("admin", "admin"), ("alice", "owner"), ("bob", "owner"), ("vera", "viewer")]

def run():
    db.init(); c = db.connect()
    for name, role in USERS:
        if not c.execute("SELECT 1 FROM users WHERE username=?", (name,)).fetchone():
            pw = os.environ.get(f"TV_PW_{name.upper()}", f"{name}-Demo-2026!")
            c.execute("INSERT INTO users(username,pw_hash,role,created_at) VALUES(?,?,?,?)", (name, security.hash_pw(pw), role, db.now()))
    if not c.execute("SELECT 1 FROM documents").fetchone():
        from app import files
        alice = c.execute("SELECT id FROM users WHERE username='alice'").fetchone()[0]
        bob = c.execute("SELECT id FROM users WHERE username='bob'").fetchone()[0]
        vera = c.execute("SELECT id FROM users WHERE username='vera'").fetchone()[0]
        for owner, name, cat, text in [(alice, "salary-letter.txt", "hr", b"Confidential salary letter"),
                                       (bob, "supplier-contract.txt", "contracts", b"Supplier contract draft")]:
            key, dg = files.save_blob(text); t = db.now()
            cur = c.execute("INSERT INTO documents(name,category,owner_id,storage_key,mime,size,sha256,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                            (name, cat, owner, key, "text/plain", len(text), dg, t, t))
            db.audit(c, {"id": owner, "username": "seed"}, "upload", cur.lastrowid, detail={"name": name, "seed": True})
            if owner == alice:
                c.execute("INSERT INTO grants VALUES(?,?,?,?,?)", (cur.lastrowid, vera, "read", alice, t))
    c.close(); print("seeded")

if __name__ == "__main__": run()
