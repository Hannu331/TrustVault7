from fastapi import APIRouter, Request, Form
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

from ..core.dependencies import require_login
from ..core.database import get_connection
from ..services.document_service import get_document
from ..services.permission_service import grant_permission, revoke_permission
from ..services.audit_service import log_event

router = APIRouter()

BASE_DIR = Path(__file__).resolve().parents[4]
TEMPLATES_DIR = BASE_DIR / "frontend" / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


@router.get('/permissions')
def permissions(request: Request):
    user = require_login(request)

    if not user:
        return RedirectResponse('/login', status_code=303)

    connection = get_connection()

    if user['role'] == 'administrator':
        rows = connection.execute("""
            SELECT p.*, d.name AS document_name,
                   d.owner_username AS document_owner
            FROM permissions p
            JOIN documents d ON d.id = p.document_id
            ORDER BY p.id DESC
        """).fetchall()

        documents = connection.execute("""
            SELECT id, name, category
            FROM documents
            ORDER BY id DESC
        """).fetchall()

    else:
        rows = connection.execute("""
            SELECT p.*, d.name AS document_name,
                   d.owner_username AS document_owner
            FROM permissions p
            JOIN documents d ON d.id = p.document_id
            WHERE d.owner_username = ?
            ORDER BY p.id DESC
        """, (user['username'],)).fetchall()

        documents = connection.execute("""
            SELECT id, name, category
            FROM documents
            WHERE owner_username = ?
            ORDER BY id DESC
        """, (user['username'],)).fetchall()

    users = connection.execute("""
        SELECT username, name
        FROM users
        WHERE username != ?
        ORDER BY username
    """, (user['username'],)).fetchall()

    connection.close()

    can_manage = user['role'] in ('document_owner', 'administrator')

    return templates.TemplateResponse(
        request=request,
        name="permissions.html",
        context={
            "user": user,
            "permissions": [dict(row) for row in rows],
            "documents": [dict(row) for row in documents],
            "users": [dict(row) for row in users],
            "can_manage": can_manage
        }
    )


@router.post('/admin/permissions/grant')
def grant(
    request: Request,
    document_id: int = Form(...),
    username: str = Form(...),
    access: str = Form('READ')
):
    user = require_login(request)

    if not user:
        return RedirectResponse('/login', status_code=303)

    document = get_document(document_id)

    if not document:
        return JSONResponse(
            {"detail": "Document not found"},
            status_code=404
        )

    if user['role'] != 'administrator' and (
        user['role'] != 'document_owner'
        or document['owner_username'] != user['username']
    ):
        return JSONResponse({"detail": "Forbidden"}, status_code=403)

    if access not in ('READ', 'EDIT'):
        return JSONResponse(
            {"detail": "Invalid permission"},
            status_code=400
        )

    connection = get_connection()
    target_user = connection.execute(
        "SELECT username FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    connection.close()

    if not target_user:
        return JSONResponse(
            {"detail": "User does not exist"},
            status_code=404
        )

    if username == document['owner_username']:
        return JSONResponse(
            {"detail": "The owner already has access"},
            status_code=400
        )

    grant_permission(
        document_id,
        username,
        access,
        user['username']
    )

    log_event(
        user['username'],
        'PERMISSION_GRANTED',
        document['name'],
        f'{username}: {access}'
    )

    return RedirectResponse('/permissions', status_code=303)


@router.post('/admin/permissions/revoke')
def revoke(
    request: Request,
    document_id: int = Form(...),
    username: str = Form(...)
):
    user = require_login(request)

    if not user:
        return RedirectResponse('/login', status_code=303)

    document = get_document(document_id)

    if not document:
        return JSONResponse(
            {"detail": "Document not found"},
            status_code=404
        )

    if user['role'] != 'administrator' and (
        user['role'] != 'document_owner'
        or document['owner_username'] != user['username']
    ):
        return JSONResponse({"detail": "Forbidden"}, status_code=403)

    connection = get_connection()
    existing = connection.execute(
        """
        SELECT username FROM permissions
        WHERE document_id = ? AND username = ?
        """,
        (document_id, username)
    ).fetchone()
    connection.close()

    if not existing:
        return JSONResponse(
            {"detail": "Permission not found"},
            status_code=404
        )

    revoke_permission(document_id, username)

    log_event(
        user['username'],
        'PERMISSION_REVOKED',
        document['name'],
        f'Access revoked for {username}'
    )

    return RedirectResponse('/permissions', status_code=303)