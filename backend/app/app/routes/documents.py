from datetime import datetime
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Request, UploadFile, File, Form
from fastapi.responses import RedirectResponse, JSONResponse, FileResponse
from fastapi.templating import Jinja2Templates

from ..core.config import UPLOAD_DIR, ALLOWED_EXTENSIONS, MAX_FILE_SIZE
from ..core.dependencies import require_login
from ..core.database import get_connection
from ..services.document_service import get_document, can_access, visible_documents
from ..services.audit_service import log_event

router = APIRouter()

BASE_DIR = Path(__file__).resolve().parents[4]
TEMPLATES_DIR = BASE_DIR / "frontend" / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


@router.get('/documents')
def documents(request: Request):
    user = require_login(request)

    if not user:
        return RedirectResponse('/login', status_code=303)

    all_documents = visible_documents(user)

    # My documents shows documents owned by the logged-in user.
    docs = [
        doc for doc in all_documents
        if doc['owner_username'] == user['username']
    ]

    return templates.TemplateResponse(
        request=request,
        name="documents.html",
        context={"user": user, "documents": docs}
    )


@router.get('/shared')
def shared_documents(request: Request):
    user = require_login(request)

    if not user:
        return RedirectResponse('/login', status_code=303)

    connection = get_connection()

    rows = connection.execute(
        """
        SELECT d.*, p.access AS shared_access
        FROM documents d
        JOIN permissions p ON p.document_id = d.id
        WHERE p.username = ?
          AND d.owner_username != ?
        ORDER BY d.id DESC
        """,
        (user['username'], user['username'])
    ).fetchall()

    connection.close()

    return templates.TemplateResponse(
        request=request,
        name="shared.html",
        context={
            "user": user,
            "documents": [dict(row) for row in rows]
        }
    )


@router.get('/upload')
def upload_page(request: Request):
    user = require_login(request)

    if not user:
        return RedirectResponse('/login', status_code=303)

    if user['role'] == 'viewer':
        return JSONResponse(
            {"detail": "Only document owners and administrators can upload"},
            status_code=403
        )

    return templates.TemplateResponse(
        request=request,
        name="upload.html",
        context={"user": user}
    )


@router.post('/upload')
async def upload(
    request: Request,
    file: UploadFile = File(...),
    category: str = Form('General')
):
    user = require_login(request)

    if not user:
        return RedirectResponse('/login', status_code=303)

    if user['role'] == 'viewer':
        return JSONResponse(
            {"detail": "Only document owners and administrators can upload"},
            status_code=403
        )

    if not file.filename:
        return JSONResponse({"detail": "Choose a file"}, status_code=400)

    suffix = Path(file.filename).suffix.lower()

    if suffix not in ALLOWED_EXTENSIONS:
        return JSONResponse(
            {"detail": "File type not allowed"},
            status_code=400
        )

    content = await file.read()

    if len(content) > MAX_FILE_SIZE:
        return JSONResponse(
            {"detail": "File too large"},
            status_code=400
        )

    stored_name = uuid4().hex + suffix
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    (UPLOAD_DIR / stored_name).write_bytes(content)

    connection = get_connection()

    cursor = connection.execute(
        """
        INSERT INTO documents
        (name, owner_username, category, stored_name, uploaded_at, status)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            Path(file.filename).name,
            user['username'],
            category,
            stored_name,
            datetime.utcnow().isoformat(),
            'Active'
        )
    )

    document_id = cursor.lastrowid
    connection.execute(
        "INSERT INTO document_versions "
        "(document_id, version_number, stored_name, edited_by, created_at) "
        "VALUES (?, 1, ?, ?, ?)",
        (document_id, stored_name, user["username"], datetime.utcnow().isoformat())
    )
    connection.commit()
    connection.close()

    log_event(
        user['username'],
        'UPLOAD',
        file.filename,
        f'Document ID {document_id}'
    )

    return RedirectResponse('/documents', status_code=303)


@router.get('/documents/{document_id}')
def open_document(document_id: int, request: Request):
    user = require_login(request)

    if not user:
        return RedirectResponse('/login', status_code=303)

    document = get_document(document_id)

    if not document:
        return JSONResponse(
            {"detail": "Document not found"},
            status_code=404
        )

    if not can_access(user, document_id, 'READ'):
        log_event(
            user['username'],
            'ACCESS_DENIED',
            document['name'],
            'Document access denied'
        )
        return JSONResponse({"detail": "Access denied"}, status_code=403)

    document['owner'] = document['owner_username']
    document['date'] = document['uploaded_at']
    document['file_url'] = f"/documents/{document_id}/preview"
    document['can_edit'] = can_access(user, document_id, 'EDIT')
    connection = get_connection()
    latest_version = connection.execute(
        "SELECT version_number, edited_by FROM document_versions "
        "WHERE document_id = ? ORDER BY version_number DESC LIMIT 1",
        (document_id,)
    ).fetchone()
    connection.close()
    document['version_number'] = latest_version['version_number'] if latest_version else 1
    document['modified_by'] = latest_version['edited_by'] if latest_version else document['owner_username']

    log_event(
        user['username'],
        'DOCUMENT_VIEW',
        document['name'],
        'Document opened'
    )

    return templates.TemplateResponse(
        request=request,
        name="document_details.html",
        context={"user": user, "document": document}
    )


@router.get('/documents/{document_id}/edit')
def edit_document(document_id: int, request: Request):
    user = require_login(request)
    if not user:
        return RedirectResponse('/login', status_code=303)

    document = get_document(document_id)
    if not document:
        return JSONResponse({"detail": "Document not found"}, status_code=404)
    if not can_access(user, document_id, 'EDIT'):
        log_event(user['username'], 'EDIT_DENIED', document['name'], 'Document edit denied')
        return JSONResponse({"detail": "Edit permission required"}, status_code=403)
    if Path(document['name']).suffix.lower() not in ('.txt', '.csv'):
        return JSONResponse({"detail": "In-browser editing is currently supported for TXT and CSV files"}, status_code=415)

    file_path = UPLOAD_DIR / document['stored_name']
    if not file_path.is_file():
        return JSONResponse({"detail": "File not found"}, status_code=404)
    content = file_path.read_text(encoding='utf-8', errors='replace')
    connection = get_connection()
    row = connection.execute(
        "SELECT COALESCE(MAX(version_number), 1) AS version_number "
        "FROM document_versions WHERE document_id = ?", (document_id,)
    ).fetchone()
    connection.close()
    version_number = row['version_number'] or 1
    return templates.TemplateResponse(
        request=request, name="edit_document.html",
        context={"user": user, "document": document, "content": content,
                 "version_number": version_number}
    )


@router.post('/documents/{document_id}/save')
def save_document(document_id: int, request: Request, content: str = Form(...)):
    user = require_login(request)
    if not user:
        return RedirectResponse('/login', status_code=303)

    document = get_document(document_id)
    if not document:
        return JSONResponse({"detail": "Document not found"}, status_code=404)
    if not can_access(user, document_id, 'EDIT'):
        log_event(user['username'], 'EDIT_DENIED', document['name'], 'Document save denied')
        return JSONResponse({"detail": "Edit permission required"}, status_code=403)
    suffix = Path(document['name']).suffix.lower()
    if suffix not in ('.txt', '.csv'):
        return JSONResponse({"detail": "In-browser editing is currently supported for TXT and CSV files"}, status_code=415)
    if len(content.encode('utf-8')) > MAX_FILE_SIZE:
        return JSONResponse({"detail": "Edited file exceeds the 10 MB limit"}, status_code=400)

    connection = get_connection()
    try:
        row = connection.execute(
            "SELECT COALESCE(MAX(version_number), 0) AS version_number "
            "FROM document_versions WHERE document_id = ?", (document_id,)
        ).fetchone()
        next_version = int(row['version_number']) + 1
        new_stored_name = uuid4().hex + suffix
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        (UPLOAD_DIR / new_stored_name).write_text(content, encoding='utf-8')
        now = datetime.utcnow().isoformat()
        connection.execute(
            "INSERT INTO document_versions "
            "(document_id, version_number, stored_name, edited_by, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (document_id, next_version, new_stored_name, user['username'], now)
        )
        connection.execute(
            "UPDATE documents SET stored_name = ? WHERE id = ?",
            (new_stored_name, document_id)
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()

    log_event(user['username'], 'DOCUMENT_EDITED', document['name'],
              f'Saved version {next_version}')
    return RedirectResponse(f'/documents/{document_id}', status_code=303)


@router.get('/documents/{document_id}/preview')
def preview_document(document_id: int, request: Request):
    user = require_login(request)

    if not user:
        return RedirectResponse('/login', status_code=303)

    document = get_document(document_id)

    if not document:
        return JSONResponse(
            {"detail": "Document not found"},
            status_code=404
        )

    if not can_access(user, document_id, 'READ'):
        log_event(
            user['username'],
            'ACCESS_DENIED',
            document['name'],
            'Document preview denied'
        )
        return JSONResponse({"detail": "Access denied"}, status_code=403)

    file_path = UPLOAD_DIR / document['stored_name']

    if not file_path.is_file():
        return JSONResponse(
            {"detail": "File not found"},
            status_code=404
        )

    suffix = Path(document['name']).suffix.lower()

    if suffix not in ('.pdf', '.txt', '.csv'):
        return JSONResponse(
            {"detail": "Preview is not available for this file type"},
            status_code=415
        )

    if suffix == '.pdf':
        media_type = 'application/pdf'
    else:
        media_type = 'text/plain'

    return FileResponse(
        file_path,
        media_type=media_type,
        content_disposition_type='inline'
    )


@router.get('/documents/{document_id}/download')
def download(document_id: int, request: Request):
    user = require_login(request)

    if not user:
        return RedirectResponse('/login', status_code=303)

    document = get_document(document_id)

    if not document:
        return JSONResponse(
            {"detail": "Document not found"},
            status_code=404
        )

    if not can_access(user, document_id, 'READ'):
        log_event(
            user['username'],
            'ACCESS_DENIED',
            document['name'],
            'Download denied'
        )
        return JSONResponse({"detail": "Access denied"}, status_code=403)

    file_path = UPLOAD_DIR / document['stored_name']

    if not file_path.is_file():
        return JSONResponse(
            {"detail": "File not found"},
            status_code=404
        )

    log_event(
        user['username'],
        'DOWNLOAD',
        document['name'],
        'Document downloaded'
    )

    return FileResponse(
        file_path,
        filename=document['name']
    )