"""THE authorisation point for document content and document management.
Every route that touches a document calls authorize(). Nothing else decides."""
from fastapi import HTTPException
from .db import audit

GRANT_FOR = {"read": ("read", "edit"), "edit": ("edit",)}   # action -> satisfying grants
OWNER_ONLY = {"delete", "share", "audit"}

def authorize(conn, user, doc_id: int, action: str):
    doc = conn.execute("SELECT * FROM documents WHERE id=? AND deleted_at IS NULL", (doc_id,)).fetchone()
    ok = False
    if doc is not None and user["role"] != "admin":          # admins never get content access
        is_owner = doc["owner_id"] == user["id"] and user["role"] == "owner"
        if action in OWNER_ONLY:
            ok = is_owner
        elif action in GRANT_FOR:
            if action == "edit" and user["role"] != "owner":  # viewers are read-only by role
                ok = False
            else:
                g = conn.execute("SELECT permission FROM grants WHERE doc_id=? AND user_id=?",
                                 (doc_id, user["id"])).fetchone()
                ok = is_owner or (g is not None and g["permission"] in GRANT_FOR[action])
        else:
            raise ValueError(f"unknown action {action}")
    if not ok:
        # Same response whether the document is missing or merely not yours (no existence oracle).
        audit(conn, user, f"{action}_refused", doc_id, "denied",
              {"reason": "no_such_document" if doc is None else "not_authorised"})
        raise HTTPException(404, "Document not found")
    return doc
