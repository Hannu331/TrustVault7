"""Provision a deployed TrustVault for evaluation: expiring accounts plus seed data.

    python -m scripts.provision https://your-service.example.com [days]

Asks for YOUR administrator login (typed locally, never stored), then creates:
  * evaluator.admin, evaluator.owner, evaluator.viewer: strong random passwords, written to
    evaluator-credentials.txt (git-ignored; give it only to the assessors). They switch
    themselves off after [days] (default 14).
  * finance.owner: a second owner whose password is thrown away. It holds private documents
    the evaluators have NOT been given, so there is something real to try to reach.
Seed documents (every kind of access):
  company-handbook.txt     sent by the administrator: owner can EDIT, viewer can READ
  supplier-contract.txt    owned by the evaluator owner, shared with the viewer: EDIT
  security-policy.txt      owned by finance.owner, shared with the viewer: READ
  board-pack-q3.txt, salary-review-2026.txt   private to finance.owner (nobody is given them)
Run it once. Re-running skips accounts that already exist and never changes their passwords.
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
            (
                f'--{boundary}\r\nContent-Disposition: form-data; name="category"\r\n\r\n{category}\r\n'
                f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\n\r\n'
            ).encode()
            + content
            + f"\r\n--{boundary}--\r\n".encode()
        )
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
    admin_token = out["token"]

    people = [  # (username, role, evaluators receive the password?)
        ("evaluator.admin", "admin", True),
        ("evaluator.owner", "owner", True),
        ("evaluator.viewer", "viewer", True),
        ("finance.owner", "owner", False),
    ]
    created, token, uid = {}, {}, {}
    for name, role, shown in people:
        pw = password()
        extra = {"expires_in_days": EXPIRY_DAYS} if name.startswith("evaluator.") else {}
        status, out = call(
            base,
            "POST",
            "/api/admin/users",
            token=admin_token,
            body={
                "username": name,
                "password": pw,
                "role": role,
                "require_password_change": False,
                **extra,
            },
        )
        if status == 201:
            created[name] = (role, pw, shown)
            status, out = call(base, "POST", "/api/auth/login", {"username": name, "password": pw})
            token[name], uid[name] = out["token"], out["user"]["id"]
        else:
            print(f"  {name}: already exists, left unchanged (no seed data added for it)")

    def put(owner, fname, text, category):
        status, out = call(
            base,
            "POST",
            "/api/documents",
            token=token[owner],
            upload=(fname, text.encode(), category),
        )
        return out["id"]

    def share(owner, doc, person, permission):
        call(
            base,
            "PUT",
            f"/api/documents/{doc}/grants/{uid[person]}",
            {"permission": permission},
            token[owner],
        )

    if len(token) == len(people):
        handbook = put(
            "evaluator.admin", "company-handbook.txt", "Company handbook, version 1.", "policy"
        )
        share("evaluator.admin", handbook, "evaluator.owner", "edit")
        share("evaluator.admin", handbook, "evaluator.viewer", "read")
        contract = put(
            "evaluator.owner", "supplier-contract.txt", "Supplier contract draft.", "contracts"
        )
        share("evaluator.owner", contract, "evaluator.viewer", "edit")
        policy = put(
            "finance.owner", "security-policy.txt", "Security policy, read-only.", "policy"
        )
        share("finance.owner", policy, "evaluator.viewer", "read")
        put("finance.owner", "board-pack-q3.txt", "Board pack Q3. Private to Finance.", "finance")
        put(
            "finance.owner",
            "salary-review-2026.txt",
            "Salary review 2026. Private to Finance.",
            "hr",
        )

    labels = {"admin": "Administrator", "owner": "Document owner", "viewer": "Viewer"}
    shown = [(labels[r], n, p) for n, (r, p, s) in created.items() if s]
    if shown:
        with open("evaluator-credentials.txt", "w") as out:  # git-ignored
            out.write(f"TrustVault evaluation accounts for {base}\n")
            out.write(f"Valid for {EXPIRY_DAYS} days, then they switch off.\n\n")
            for label, name, pw in shown:
                out.write(f"{label}: {name} / {pw}\n")
        print("\nPasswords saved to evaluator-credentials.txt (NOT committed; send it privately).")
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
