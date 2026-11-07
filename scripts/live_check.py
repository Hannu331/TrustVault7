"""Smoke-test a DEPLOYED TrustVault the way a judge would. Standard library only.

    python -m scripts.live_check URL --admin USER:PASS --owner USER:PASS --viewer USER:PASS

(With no account options it uses the published demo accounts, for a TV_DEMO=1 deployment.)
Uploads one small test file, shares it, revokes it and deletes it again.
"""

import json
import sys
import urllib.error
import urllib.request
import uuid

results = []


def call(base, method, path, body=None, token=None, multipart=None):
    headers, data = {}, None
    if token:
        headers["Authorization"] = "Bearer " + token
    if multipart:
        boundary = uuid.uuid4().hex
        name, content = multipart
        data = (
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\n\r\n'
        ).encode()
        data += content + f"\r\n--{boundary}--\r\n".encode()
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    elif body is not None:
        data, headers["Content-Type"] = json.dumps(body).encode(), "application/json"
    request = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            status, raw = response.status, response.read()
    except urllib.error.HTTPError as error:
        status, raw = error.code, error.read()
    try:
        return status, json.loads(raw)
    except ValueError:
        return status, raw.decode("utf-8", "replace")


def check(label, passed, detail=""):
    results.append(bool(passed))
    print(
        ("PASS  " if passed else "FAIL  ")
        + label
        + (f"   [{detail}]" if detail and not passed else "")
    )


def parse_accounts(args):
    accounts = {
        "admin": ("admin", "admin-Demo-2026!"),
        "owner": ("alice", "alice-Demo-2026!"),
        "viewer": ("vera", "vera-Demo-2026!"),
        "other": ("bob", "bob-Demo-2026!"),
    }
    given = dict(zip(args[::2], args[1::2]))
    for flag, key in (
        ("--admin", "admin"),
        ("--owner", "owner"),
        ("--viewer", "viewer"),
        ("--other", "other"),
    ):
        if flag in given:
            accounts[key] = tuple(given[flag].split(":", 1))
    if given and "--other" not in given:
        del accounts["other"]  # a second owner is optional
    return accounts


def main(base, accounts):
    base = base.rstrip("/")
    print(f"Checking {base} (the first request may take a minute while a free host wakes up)\n")
    status, page = call(base, "GET", "/")
    check("site is up and serves TrustVault", status == 200 and "TrustVault" in str(page), status)
    if status != 200:
        sys.exit("Site not reachable; try again in a minute.")
    print("\n-- strangers and exposed internals")
    check(
        "signed-out request to a document is refused (401)",
        call(base, "GET", "/api/documents/1")[0] == 401,
    )
    for path in ("/docs", "/openapi.json", "/data/trustvault.db", "/app/db.py"):
        check(f"{path} is not exposed (404)", call(base, "GET", path)[0] == 404)
    print("\n-- sign in as each role")
    tok, ids, name = {}, {}, {}
    for role, (username, pw) in accounts.items():
        status, out = call(base, "POST", "/api/auth/login", {"username": username, "password": pw})
        ok = status == 200 and "token" in out
        check(f"{role} account can sign in", ok, out if not ok else "")
        if ok:
            tok[role], ids[role], name[role] = out["token"], out["user"]["id"], username
    if not {"admin", "owner", "viewer"} <= set(tok):
        sys.exit("\nCannot continue without admin, owner and viewer accounts.")

    print("\n-- the security story")
    tag = "live-check-" + uuid.uuid4().hex[:6]
    secret = b"live check content " + tag.encode()
    status, doc = call(
        base, "POST", "/api/documents", token=tok["owner"], multipart=(tag + ".txt", secret)
    )
    check("owner uploads a document", status == 201, doc)
    url = f"/api/documents/{doc['id']}"
    get = lambda who, path="/download": call(base, "GET", url + path, token=tok[who])
    check("owner can download it", get("owner")[1] == secret.decode())
    check("viewer (not yet granted) is refused", get("viewer")[0] == 404)
    if "other" in tok:
        check("another owner is refused", get("other")[0] == 404)
        check(
            "another owner's search does not find it",
            call(base, "GET", f"/api/documents?q={tag}", token=tok["other"])[1] == [],
        )
    check(
        "owner grants viewer read access",
        call(base, "PUT", f"{url}/grants/{ids['viewer']}", {"permission": "read"}, tok["owner"])[0]
        == 200,
    )
    check("viewer can now read it", get("viewer")[1] == secret.decode())
    check(
        "viewer cannot edit it", call(base, "PUT", url, {"name": "x.txt"}, tok["viewer"])[0] == 404
    )
    check("viewer cannot delete it", call(base, "DELETE", url, token=tok["viewer"])[0] == 404)
    check(
        "owner removes viewer's access",
        call(base, "DELETE", f"{url}/grants/{ids['viewer']}", token=tok["owner"])[0] == 200,
    )
    check("viewer's SAME token is refused on the very next request", get("viewer")[0] == 404)
    check("admin cannot read document content", get("admin")[0] == 404)
    check(
        "viewer cannot upload",
        call(base, "POST", "/api/documents", token=tok["viewer"], multipart=("a.txt", b"x"))[0]
        == 403,
    )
    check(
        "html upload is rejected",
        call(
            base, "POST", "/api/documents", token=tok["owner"], multipart=("evil.html", b"<b>1</b>")
        )[0]
        == 415,
    )
    check(
        "viewer cannot open admin pages",
        call(base, "GET", "/api/admin/audit", token=tok["viewer"])[0] == 403,
    )

    print("\n-- the administrator sends a document; viewers read or edit")
    status, adoc = call(
        base,
        "POST",
        "/api/documents",
        token=tok["admin"],
        multipart=(tag + "-admin.txt", b"admin doc"),
    )
    check("administrator uploads a document", status == 201, adoc)
    aurl = f"/api/documents/{adoc['id']}"
    check(
        "owner is refused the administrator's unshared document",
        call(base, "GET", aurl + "/download", token=tok["owner"])[0] == 404,
    )
    check(
        "administrator sends it to the viewer (read)",
        call(base, "PUT", f"{aurl}/grants/{ids['viewer']}", {"permission": "read"}, tok["admin"])[0]
        == 200,
    )
    check(
        "viewer can read it",
        call(base, "GET", aurl + "/download", token=tok["viewer"])[1] == "admin doc",
    )
    check(
        "viewer cannot edit with read access",
        call(base, "PUT", aurl, {"name": "x.txt"}, tok["viewer"])[0] == 404,
    )
    check(
        "administrator upgrades the viewer to edit",
        call(base, "PUT", f"{aurl}/grants/{ids['viewer']}", {"permission": "edit"}, tok["admin"])[0]
        == 200,
    )
    check(
        "viewer can now edit it",
        call(base, "PUT", aurl, {"category": "edited"}, tok["viewer"])[0] == 200,
    )
    check(
        "viewer still cannot delete or share it",
        call(base, "DELETE", aurl, token=tok["viewer"])[0] == 404
        and call(
            base, "PUT", f"{aurl}/grants/{ids['owner']}", {"permission": "read"}, tok["viewer"]
        )[0]
        == 404,
    )
    status, rows = call(base, "GET", "/api/admin/access", token=tok["admin"])
    check(
        "access list shows who has what",
        status == 200
        and any(
            r["doc_id"] == adoc["id"] and r["person"] == name["viewer"] and r["access"] == "edit"
            for r in rows
        ),
    )
    check(
        "administrator removes the viewer's access",
        call(base, "DELETE", f"/api/admin/grants/{adoc['id']}/{ids['viewer']}", token=tok["admin"])[
            0
        ]
        == 200,
    )
    check(
        "viewer's SAME token is refused at once",
        call(base, "GET", aurl + "/download", token=tok["viewer"])[0] == 404,
    )
    check(
        "owner cannot use the administrator's document either",
        call(base, "PUT", aurl, {"name": "x.txt"}, tok["owner"])[0] == 404,
    )
    call(base, "DELETE", aurl, token=tok["admin"])

    print("\n-- the audit trail")
    status, rows = call(
        base, "GET", f"/api/admin/audit?doc_id={doc['id']}&limit=200", token=tok["admin"]
    )
    seen = {(r["actor_name"], r["action"], r["outcome"]) for r in rows} if status == 200 else set()
    for who, action, outcome in [
        ("owner", "upload", "ok"),
        ("owner", "grant_set", "ok"),
        ("viewer", "download", "ok"),
        ("owner", "grant_revoked", "ok"),
        ("viewer", "read_refused", "denied"),
    ]:
        check(f"audit has {who} / {action} / {outcome}", (name[who], action, outcome) in seen)
    status, verify = call(base, "GET", "/api/admin/audit/verify", token=tok["admin"])
    check("audit chain verifies", status == 200 and verify.get("valid") is True, verify)
    call(base, "DELETE", url, token=tok["owner"])  # clean up the test file
    print(
        f"\n{sum(results)}/{len(results)} checks passed"
        + ("  -> ALL GOOD" if all(results) else "  -> FIX THE FAILURES ABOVE")
    )
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(
            "usage: python -m scripts.live_check URL [--admin U:P --owner U:P --viewer U:P [--other U:P]]"
        )
    main(sys.argv[1], parse_accounts(sys.argv[2:]))
