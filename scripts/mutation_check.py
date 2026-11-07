"""Proof the tests test something: disable one authorisation check at a time, tests MUST fail."""

import pathlib, subprocess, sys

MUTATIONS = [
    ("app/authz.py", "    if not ok:", "    if False:"),
    (
        "app/authz.py",
        'ok = is_owner or (grant is not None and grant["permission"] in GRANT_FOR[action])',
        "ok = True",
    ),
    ("app/authz.py", 'if user["role"] != "admin":', "if True:"),
    (
        "app/main.py",
        'admin = require_role("admin")',
        'admin = require_role("admin", "owner", "viewer")',
    ),
    ("app/authz.py", 'user["role"] in ("owner", "admin")', "True"),
    ("app/security.py", "AND u.active=1", ""),
    ("app/main.py", "(d.owner_id=? OR g.user_id IS NOT NULL)", "1=1"),
    # the audit of refused attempts must also be tested, not just the refusal itself
    (
        "app/security.py",
        '"unauthenticated_refused"',
        '"unauthenticated_refused" if False else "login"',
    ),
    ("app/security.py", '"role_refused"', '"something_else"'),
    ("app/authz.py", 'f"{action}_refused"', '"read"'),
    ("app/files.py", "if total > MAX_BYTES:", "if False:"),
    (
        "app/security.py",
        'if row["must_change_password"] and',
        'if False and row["must_change_password"] and',
    ),
    (
        "app/main.py",
        "if not security.verify_pw(body.current, user",
        "if False and not security.verify_pw(body.current, user",
    ),
    ("app/main.py", 'security.revoke_user_sessions(\n        conn, user["id"]\n    )', "pass"),
    ("app/files.py", "if not check(data):", "if False:"),
]
bad = 0
for path, old, new in MUTATIONS:
    p = pathlib.Path(path)
    src = p.read_text()
    assert old in src, f"stale mutation {old!r}"
    p.write_text(src.replace(old, new, 1))
    try:
        rc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-x", "tests"], capture_output=True
        ).returncode
    finally:
        p.write_text(src)
    print(("CAUGHT  " if rc else "SURVIVED"), path, "|", old[:50])
    bad += rc == 0
sys.exit(1 if bad else 0)
