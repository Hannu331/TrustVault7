"""Provision a deployed TrustVault for evaluation: accounts, private sample data, README block.

    python -m scripts.provision https://your-service.example.com [days]

Asks for YOUR administrator login (typed locally, never stored). It then creates:
  * one evaluator account per role, with strong random passwords printed once, here;
  * a second owner ("finance.owner") whose password is thrown away, holding private documents
    that evaluators must not be able to reach;
  * a few sample documents and one share, so there is something to try.
Run it once. Re-running skips accounts that already exist and never changes their passwords.
After marking, disable the evaluator accounts on the People page (audit history is kept).
"""

import getpass
import json
import os
import secrets
import string
import sys
import urllib.error
import urllib.request
import uuid

ALPHABET = string.ascii_letters + string.digits


EXPIRY_DAYS = 14


def expiry(name):
    """Evaluator accounts switch themselves off; the private Finance owner has no login anyway."""
    return {"expires_in_days": EXPIRY_DAYS} if name.startswith("evaluator.") else {}


def password(length=18):
    return "".join(secrets.choice(ALPHABET) for _ in range(length))


def call(base, method, path, body=None, token=None, upload=None):
    headers, data = {}, None
    if token:
        headers["Authorization"] = "Bearer " + token
    if upload:
        boundary = uuid.uuid4().hex
        name, content, category = upload
        data = (
            f'--{boundary}\r\nContent-Disposition: form-data; name="category"\r\n\r\n{category}\r\n'
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\n\r\n'
        ).encode()
        data += content + f"\r\n--{boundary}--\r\n".encode()
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    elif body is not None:
        data, headers["Content-Type"] = json.dumps(body).encode(), "application/json"
    request = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            return response.status, json.loads(response.read() or "null")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace")


def main(base):
    global EXPIRY_DAYS
    EXPIRY_DAYS = int(sys.argv[2]) if len(sys.argv) > 2 else EXPIRY_DAYS
    base = base.rstrip("/")
    user = os.environ.get("TV_ADMIN_USER") or input("Your administrator username: ")
    secret = os.environ.get("TV_ADMIN_PASSWORD") or getpass.getpass("Your administrator password: ")
    status, out = call(base, "POST", "/api/auth/login", {"username": user, "password": secret})
    if status != 200 or out["user"]["role"] != "admin":
        sys.exit(f"Sign-in failed or not an administrator ({status}).")
    admin = out["token"]

    people = [  # (username, role, shown in README?)
        ("evaluator.admin", "admin", True),
        ("evaluator.owner", "owner", True),
        ("evaluator.viewer", "viewer", True),
        ("finance.owner", "owner", False),
    ]
    created, tokens, ids = {}, {}, {}
    for name, role, shown in people:
        pw = password()
        status, out = call(
            base,
            "POST",
            "/api/admin/users",
            token=admin,
            body={
                "username": name,
                "password": pw,
                "role": role,
                "require_password_change": False,
                **expiry(name),
            },
        )
        if status == 201:
            created[name] = (role, pw, shown)
        else:
            print(f"  {name}: already exists, left unchanged")
    for name, (role, pw, _) in created.items():
        status, out = call(base, "POST", "/api/auth/login", {"username": name, "password": pw})
        tokens[name], ids[name] = out["token"], out["user"]["id"]

    if "finance.owner" in tokens and "evaluator.owner" in tokens:
        finance, owner = tokens["finance.owner"], tokens["evaluator.owner"]
        docs = [
            (finance, "board-pack-q3.txt", b"Board pack Q3. Private to Finance.", "finance"),
            (finance, "salary-review-2026.txt", b"Salary review 2026. Private to Finance.", "hr"),
            (
                finance,
                "security-policy.txt",
                b"Security policy. Shared read-only with the viewer.",
                "policy",
            ),
            (
                owner,
                "supplier-contract.txt",
                b"Supplier contract. Owned by the evaluator owner.",
                "contracts",
            ),
        ]
        made = {}
        for token, fname, content, category in docs:
            status, out = call(
                base, "POST", "/api/documents", token=token, upload=(fname, content, category)
            )
            made[fname] = out["id"]
        if "evaluator.viewer" in ids:
            call(
                base,
                "PUT",
                f"/api/documents/{made['security-policy.txt']}/grants/{ids['evaluator.viewer']}",
                {"permission": "read"},
                finance,
            )
            call(
                base,
                "PUT",
                f"/api/documents/{made['supplier-contract.txt']}/grants/{ids['evaluator.viewer']}",
                {"permission": "read"},
                owner,
            )

    labels = {"admin": "Administrator", "owner": "Document owner", "viewer": "Viewer"}
    shown = [(labels[r], n, p) for n, (r, p, s) in created.items() if s]
    if shown:
        with open(
            "evaluator-credentials.txt", "w"
        ) as out:  # git-ignored; give this ONLY to the assessors
            out.write(
                f"TrustVault evaluation accounts for {base}\nValid for {EXPIRY_DAYS} days, then they switch off.\n\n"
            )
            for label, name, pw in shown:
                out.write(f"{label}: {name} / {pw}\n")
        print(
            "\nPasswords saved to evaluator-credentials.txt (NOT committed; send it privately with your submission)."
        )
        print(
            f"Accounts expire automatically after {EXPIRY_DAYS} days.\n\nPaste into README.md (usernames only):\n"
        )
        print("| Role | Username |\n|---|---|")
        for label, name, _ in shown:
            print(f"| {label} | {name} |")
    print(
        "\nDone. The accounts switch off by themselves; you can also disable them on the People page."
    )


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        sys.exit("usage: python -m scripts.provision https://your-service.example.com [days]")
    main(sys.argv[1])
