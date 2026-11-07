"""Runs at every start of a deployment (see Dockerfile).

1. Builds or upgrades the database.
2. Creates the FIRST administrator from environment variables, only if no administrator exists.
3. Adds demo users and sample documents only when TV_DEMO=1 (the judges' demo deployment).

A real deployment sets TV_ADMIN_USER and TV_ADMIN_PASSWORD (in the host's secret settings, never in
git) and leaves TV_DEMO unset. Nothing with a published password is ever created there.
"""

import os
import re
import sys

from app import db, security


def ensure_admin() -> str:
    user = os.environ.get("TV_ADMIN_USER", "")
    password = os.environ.get("TV_ADMIN_PASSWORD", "")
    conn = db.connect()
    try:
        if conn.execute("SELECT 1 FROM users WHERE role='admin' LIMIT 1").fetchone():
            return "an administrator already exists"
        if not user or not password:
            return "NO ADMIN: set TV_ADMIN_USER and TV_ADMIN_PASSWORD (or TV_DEMO=1 for the demo)"
        if not re.fullmatch(r"[\w.\-]{3,64}", user):
            raise SystemExit("TV_ADMIN_USER must be 3-64 letters, digits, dot, dash or underscore")
        if len(password) < 12:
            raise SystemExit("TV_ADMIN_PASSWORD must be at least 12 characters")
        conn.execute(
            "INSERT INTO users(username,pw_hash,role,created_at) VALUES(?,?,'admin',?)",
            (user, security.hash_pw(password), db.now()),
        )
        db.audit(conn, None, "first_admin_created", detail={"username": user})
        return f"created administrator {user}"
    finally:
        conn.close()


def main() -> None:
    db.init()
    if os.environ.get("TV_DEMO") == "1":
        from scripts import seed

        seed.run()
    message = ensure_admin()
    print("bootstrap:", message)
    if message.startswith("NO ADMIN"):
        sys.exit(1)  # fail the deployment loudly instead of starting an app nobody can administer


if __name__ == "__main__":
    main()
