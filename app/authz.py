"""THE authorisation point for document content and document management.
Every route that touches a document calls authorize(). Nothing else decides.

The rules, in one place:
  * The OWNER of a document (an owner or an administrator who uploaded it) can read, edit,
    delete, share and see its audit.
  * Anyone else (a viewer or another owner) can only do what a grant on that document says:
    "read" lets them read; "edit" lets them read and edit. Never delete, share or see its audit.
  * An administrator holds no grants and has no access to other people's documents at all.
"""

from fastapi import HTTPException
from .db import audit

GRANT_FOR = {"read": ("read", "edit"), "edit": ("edit",)}  # action -> satisfying grants
OWNER_ONLY = {"delete", "share", "audit"}


def authorize(conn, user, doc_id: int, action: str):
    doc = conn.execute(
        "SELECT * FROM documents WHERE id=? AND deleted_at IS NULL", (doc_id,)
    ).fetchone()
    ok = False
    if doc is not None:
        is_owner = doc["owner_id"] == user["id"] and user["role"] in ("owner", "admin")
        if action in OWNER_ONLY:
            ok = is_owner
        elif action in GRANT_FOR:
            grant = None
            if user["role"] != "admin":  # administrators never hold grants, even stale ones
                grant = conn.execute(
                    "SELECT permission FROM grants WHERE doc_id=? AND user_id=?",
                    (doc_id, user["id"]),
                ).fetchone()
            ok = is_owner or (grant is not None and grant["permission"] in GRANT_FOR[action])
        else:
            raise ValueError(f"unknown action {action}")
    if not ok:
        # Same response whether the document is missing or merely not yours (no existence oracle).
        audit(
            conn,
            user,
            f"{action}_refused",
            doc_id,
            "denied",
            {"reason": "no_such_document" if doc is None else "not_authorised"},
        )
        raise HTTPException(404, "Document not found")
    return doc
