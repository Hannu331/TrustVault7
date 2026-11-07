
from pathlib import Path
from datetime import datetime

from fastapi import APIRouter, Request, Form
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from ..core.dependencies import require_admin
from ..core.database import get_connection
from ..core.config import UPLOAD_DIR
from ..core.security import verify_password

router = APIRouter()

BASE_DIR = Path(__file__).resolve().parents[4]
TEMPLATES_DIR = BASE_DIR / "frontend" / "templates"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# ---------------------------------------------------------
# COMMON HELPERS
# ---------------------------------------------------------

def rows(sql, params=()):
    connection = get_connection()
    try:
        result = connection.execute(sql, params).fetchall()
        return [dict(row) for row in result]
    finally:
        connection.close()


def add_audit(actor, action, target, details=""):
    connection = get_connection()
    try:
        connection.execute(
            """
            INSERT INTO audit_logs
            (actor, action, target, details, timestamp)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                actor,
                action,
                target,
                details,
                datetime.utcnow().isoformat()
            )
        )
        connection.commit()
    finally:
        connection.close()


def delete_stored_file(stored_name):
    """Delete only files located inside the configured uploads folder."""

    if not stored_name:
        return

    upload_root = UPLOAD_DIR.resolve()
    file_path = (upload_root / stored_name).resolve()

    try:
        if file_path.is_relative_to(upload_root) and file_path.is_file():
            file_path.unlink()
    except (OSError, ValueError):
        pass


def admin_required(request):
    return require_admin(request)


# ---------------------------------------------------------
# ADMIN LOGIN PAGE
# ---------------------------------------------------------

@router.get("/admin/login")
def admin_login_page(request: Request):

    user = request.session.get("user")

    if user and user.get("role") == "administrator":
        return RedirectResponse("/admin", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="admin_login.html",
        context={"error": None}
    )


# ---------------------------------------------------------
# ADMIN LOGIN
# ---------------------------------------------------------

@router.post("/admin/login")
def admin_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):

    connection = get_connection()

    try:
        user = connection.execute(
            """
            SELECT id, username, name, password_hash, role
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()
    finally:
        connection.close()

    if not user:
        return templates.TemplateResponse(
            request=request,
            name="admin_login.html",
            context={
                "error": "Invalid administrator username or password."
            },
            status_code=401
        )

    if user["role"] != "administrator":
        return templates.TemplateResponse(
            request=request,
            name="admin_login.html",
            context={
                "error": "This account does not have administrator access."
            },
            status_code=403
        )

    password_valid = verify_password(password, user["password_hash"])

    if not password_valid:
        return templates.TemplateResponse(
            request=request,
            name="admin_login.html",
            context={
                "error": "Invalid administrator username or password."
            },
            status_code=401
        )

    request.session.clear()

    request.session["user"] = {
        "username": user["username"],
        "name": user["name"],
        "role": user["role"]
    }

    add_audit(
        user["username"],
        "ADMIN_LOGIN",
        user["username"],
        "Administrator logged in"
    )

    return RedirectResponse("/admin", status_code=303)


# ---------------------------------------------------------
# ADMIN LOGOUT
# ---------------------------------------------------------

@router.get("/admin/logout")
def admin_logout(request: Request):

    user = request.session.get("user")

    if user:
        add_audit(
            user["username"],
            "ADMIN_LOGOUT",
            user["username"],
            "Administrator logged out"
        )

    request.session.clear()

    return RedirectResponse("/admin/login", status_code=303)


# ---------------------------------------------------------
# ADMIN DASHBOARD
# ---------------------------------------------------------

@router.get("/admin")
def admin(request: Request):

    user = admin_required(request)

    if not user:
        return RedirectResponse("/admin/login", status_code=303)

    users = rows(
        """
        SELECT id, username, name, role, created_at
        FROM users
        ORDER BY id DESC
        """
    )

    documents = rows(
        """
        SELECT *
        FROM documents
        ORDER BY id DESC
        """
    )

    permissions = rows(
        """
        SELECT *
        FROM permissions
        ORDER BY id DESC
        """
    )

    audit_logs = rows(
        """
        SELECT *
        FROM audit_logs
        ORDER BY id DESC
        LIMIT 10
        """
    )

    dashboard_documents = []

    for document in documents:
        dashboard_documents.append({
            "id": document["id"],
            "name": document["name"],
            "owner": document["owner_username"],
            "category": document["category"],
            "date": document["uploaded_at"],
            "status": document["status"]
        })

    recent_activity = []

    for item in audit_logs:
        recent_activity.append({
            "action": item["action"],
            "actor": item["actor"],
            "target": item["target"],
            "time": item["timestamp"]
        })

    active_documents = sum(
        1 for document in documents
        if document["status"] == "Active"
    )

    context = {
        "request": request,
        "user": user,
        "total_users": len(users),
        "total_documents": len(documents),
        "active_documents": active_documents,
        "total_permissions": len(permissions),
        "documents": dashboard_documents,
        "recent_activity": recent_activity
    }

    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context=context
    )


# ---------------------------------------------------------
# USER MANAGEMENT PAGE
# ---------------------------------------------------------

@router.get("/admin/users")
def admin_users(request: Request):

    user = admin_required(request)

    if not user:
        return RedirectResponse("/admin/login", status_code=303)

    users = rows(
        """
        SELECT
            u.id,
            u.username,
            u.name,
            u.role,
            u.created_at,
            (
                SELECT COUNT(*)
                FROM documents d
                WHERE d.owner_username = u.username
            ) AS owned_count,
            (
                SELECT COUNT(DISTINCT p.document_id)
                FROM permissions p
                WHERE p.username = u.username
            ) AS shared_count
        FROM users u
        ORDER BY u.id DESC
        """
    )

    for item in users:
        item["is_admin"] = item["role"] == "administrator"

    return templates.TemplateResponse(
        request=request,
        name="admin_users.html",
        context={
            "user": user,
            "users": users,
            "total_users": len(users)
        }
    )


# ---------------------------------------------------------
# DELETE USER
# ---------------------------------------------------------

@router.post("/admin/users/{username}/delete")
def delete_user(request: Request, username: str):

    admin = admin_required(request)

    if not admin:
        return RedirectResponse("/admin/login", status_code=303)

    if username == admin["username"]:
        return RedirectResponse("/admin/users", status_code=303)

    connection = get_connection()

    try:
        target_user = connection.execute(
            "SELECT id, role FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if not target_user or target_user["role"] == "administrator":
            return RedirectResponse("/admin/users", status_code=303)

        documents = connection.execute(
            "SELECT id, stored_name FROM documents WHERE owner_username = ?",
            (username,)
        ).fetchall()

        for document in documents:
            versions = connection.execute(
                "SELECT stored_name FROM document_versions WHERE document_id = ?",
                (document["id"],)
            ).fetchall()
            for version in versions:
                delete_stored_file(version["stored_name"])
            delete_stored_file(document["stored_name"])
            connection.execute("DELETE FROM document_versions WHERE document_id = ?", (document["id"],))
            connection.execute("DELETE FROM permissions WHERE document_id = ?", (document["id"],))

        connection.execute(
            "DELETE FROM permissions WHERE username = ?",
            (username,)
        )

        connection.execute(
            "DELETE FROM documents WHERE owner_username = ?",
            (username,)
        )

        connection.execute(
            "DELETE FROM users WHERE username = ?",
            (username,)
        )

        connection.execute(
            """
            INSERT INTO audit_logs
            (actor, action, target, details, timestamp)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                admin["username"],
                "USER_DELETED",
                username,
                "User account and owned documents deleted",
                datetime.utcnow().isoformat()
            )
        )

        connection.commit()

    finally:
        connection.close()

    return RedirectResponse("/admin/users", status_code=303)


# ---------------------------------------------------------
# DOCUMENT MANAGEMENT PAGE
# ---------------------------------------------------------

@router.get("/admin/documents")
def admin_documents(request: Request):

    user = admin_required(request)

    if not user:
        return RedirectResponse("/admin/login", status_code=303)

    documents = rows(
        """
        SELECT
            d.*,
            (
                SELECT COUNT(*)
                FROM permissions p
                WHERE p.document_id = d.id
            ) AS permission_count
        FROM documents d
        ORDER BY d.id DESC
        """
    )

    for document in documents:
        document["owner"] = document["owner_username"]
        document["date"] = document["uploaded_at"]

    return templates.TemplateResponse(
        request=request,
        name="admin_documents.html",
        context={
            "user": user,
            "documents": documents
        }
    )


# ---------------------------------------------------------
# DELETE DOCUMENT
# ---------------------------------------------------------

@router.post("/admin/documents/{document_id}/delete")
def delete_document(request: Request, document_id: int):

    admin = admin_required(request)

    if not admin:
        return RedirectResponse("/admin/login", status_code=303)

    connection = get_connection()

    try:
        document = connection.execute(
            "SELECT * FROM documents WHERE id = ?",
            (document_id,)
        ).fetchone()

        if document:
            versions = connection.execute(
                "SELECT stored_name FROM document_versions WHERE document_id = ?",
                (document_id,)
            ).fetchall()
            for version in versions:
                delete_stored_file(version["stored_name"])
            delete_stored_file(document["stored_name"])
            connection.execute("DELETE FROM document_versions WHERE document_id = ?", (document_id,))
            connection.execute(
                "DELETE FROM permissions WHERE document_id = ?",
                (document_id,)
            )

            connection.execute(
                "DELETE FROM documents WHERE id = ?",
                (document_id,)
            )

            connection.execute(
                """
                INSERT INTO audit_logs
                (actor, action, target, details, timestamp)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    admin["username"],
                    "DOCUMENT_DELETED",
                    str(document_id),
                    "Document and its permissions deleted",
                    datetime.utcnow().isoformat()
                )
            )

            connection.commit()

    finally:
        connection.close()

    return RedirectResponse("/admin/documents", status_code=303)


# ---------------------------------------------------------
# PERMISSION MANAGEMENT PAGE
# ---------------------------------------------------------

@router.get("/admin/permissions")
def admin_permissions(request: Request):

    user = admin_required(request)

    if not user:
        return RedirectResponse("/admin/login", status_code=303)

    documents = rows(
        """
        SELECT id, name, owner_username
        FROM documents
        ORDER BY id DESC
        """
    )

    users = rows(
        """
        SELECT username, name
        FROM users
        WHERE role != 'administrator'
        ORDER BY name
        """
    )

    permissions = rows(
        """
        SELECT
            p.document_id,
            p.username,
            p.access,
            p.granted_by,
            d.name AS document_name,
            u.name AS user_name
        FROM permissions p
        JOIN documents d ON d.id = p.document_id
        JOIN users u ON u.username = p.username
        ORDER BY p.id DESC
        """
    )

    return templates.TemplateResponse(
        request=request,
        name="admin_permissions.html",
        context={
            "user": user,
            "documents": documents,
            "users": users,
            "permissions": permissions
        }
    )


# ---------------------------------------------------------
# GRANT PERMISSION
# ---------------------------------------------------------

@router.post("/admin/permissions/grant")
def admin_grant_permission(
    request: Request,
    document_id: int = Form(...),
    username: str = Form(...),
    access: str = Form(...)
):

    admin = admin_required(request)

    if not admin:
        return RedirectResponse("/admin/login", status_code=303)

    if access not in ("READ", "EDIT"):
        return RedirectResponse("/admin/permissions", status_code=303)

    connection = get_connection()

    try:
        document = connection.execute(
            "SELECT id FROM documents WHERE id = ?",
            (document_id,)
        ).fetchone()

        target_user = connection.execute(
            "SELECT username FROM users WHERE username = ? AND role != 'administrator'",
            (username,)
        ).fetchone()

        if not document or not target_user:
            return RedirectResponse("/admin/permissions", status_code=303)

        connection.execute(
            """
            INSERT INTO permissions
            (document_id, username, access, granted_by, granted_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(document_id, username)
            DO UPDATE SET
                access = excluded.access,
                granted_by = excluded.granted_by,
                granted_at = excluded.granted_at
            """,
            (
                document_id,
                username,
                access,
                admin["username"],
                datetime.utcnow().isoformat()
            )
        )

        connection.execute(
            """
            INSERT INTO audit_logs
            (actor, action, target, details, timestamp)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                admin["username"],
                "PERMISSION_GRANTED",
                str(document_id),
                f"{access} access granted to {username}",
                datetime.utcnow().isoformat()
            )
        )

        connection.commit()

    finally:
        connection.close()

    return RedirectResponse("/admin/permissions", status_code=303)


# ---------------------------------------------------------
# REVOKE PERMISSION
# ---------------------------------------------------------

@router.post("/admin/permissions/{document_id}/{username}/revoke")
def admin_revoke_permission(
    request: Request,
    document_id: int,
    username: str
):

    admin = admin_required(request)

    if not admin:
        return RedirectResponse("/admin/login", status_code=303)

    connection = get_connection()

    try:
        result = connection.execute(
            """
            DELETE FROM permissions
            WHERE document_id = ? AND username = ?
            """,
            (document_id, username)
        )

        if result.rowcount:
            connection.execute(
                """
                INSERT INTO audit_logs
                (actor, action, target, details, timestamp)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    admin["username"],
                    "PERMISSION_REVOKED",
                    str(document_id),
                    f"Access revoked from {username}",
                    datetime.utcnow().isoformat()
                )
            )

        connection.commit()

    finally:
        connection.close()

    return RedirectResponse("/admin/permissions", status_code=303)


# ---------------------------------------------------------
# AUDIT LOG PAGE
# ---------------------------------------------------------

@router.get("/admin/audit")
def admin_audit(request: Request):

    user = admin_required(request)

    if not user:
        return RedirectResponse("/admin/login", status_code=303)

    audit_logs = rows(
        """
        SELECT
            timestamp AS time,
            actor,
            action,
            target,
            details
        FROM audit_logs
        ORDER BY id DESC
        """
    )

    return templates.TemplateResponse(
        request=request,
        name="admin_audit.html",
        context={
            "user": user,
            "audit_logs": audit_logs
        }
    )


# ---------------------------------------------------------
# ADMIN PROFILE PAGE
# ---------------------------------------------------------

@router.get("/admin/profile")
def admin_profile(request: Request):

    user = admin_required(request)

    if not user:
        return RedirectResponse("/admin/login", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="admin_profile.html",
        context={
            "user": user
        }
    )
