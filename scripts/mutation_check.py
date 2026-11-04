"""Proof the tests test something: disable one authorisation check at a time, tests MUST fail."""
import pathlib, subprocess, sys
MUTATIONS = [("app/authz.py", "    if not ok:", "    if False:"),
             ("app/authz.py", 'ok = is_owner or (g is not None and g["permission"] in GRANT_FOR[action])', "ok = True"),
             ("app/authz.py", 'user["role"] != "admin":', "True:"),
             ("app/security.py", "AND u.active=1", ""),
             ("app/main.py", "(d.owner_id=? OR g.user_id IS NOT NULL)", "1=1")]
bad = 0
for path, old, new in MUTATIONS:
    p = pathlib.Path(path); src = p.read_text(); assert old in src, f"stale mutation {old!r}"
    p.write_text(src.replace(old, new, 1))
    try: rc = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "tests"], capture_output=True).returncode
    finally: p.write_text(src)
    print(("CAUGHT  " if rc else "SURVIVED"), path, "|", old[:50]); bad += (rc == 0)
sys.exit(1 if bad else 0)
