from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from ..core.dependencies import require_login
from ..core.database import get_connection

router = APIRouter()

BASE_DIR = Path(__file__).resolve().parents[4]
TEMPLATES_DIR = BASE_DIR / "frontend" / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


@router.get('/audit')
def audit(request: Request):
    user = require_login(request)

    if not user:
        return RedirectResponse('/login', status_code=303)

    connection = get_connection()

    if user['role'] == 'administrator':
        rows = connection.execute("""
            SELECT *
            FROM audit_logs
            ORDER BY id DESC
        """).fetchall()
    else:
        rows = connection.execute("""
            SELECT *
            FROM audit_logs
            WHERE actor = ?
            ORDER BY id DESC
        """, (user['username'],)).fetchall()

    connection.close()

    audit_logs = [dict(row) for row in rows]

    denied_count = sum(
        1 for row in audit_logs
        if 'DENIED' in row['action'].upper()
        or 'FAILED' in row['action'].upper()
    )

    successful_count = len(audit_logs) - denied_count

    return templates.TemplateResponse(
        request=request,
        name="audit_logs.html",
        context={
            "user": user,
            "audit_logs": audit_logs,
            "total_events": len(audit_logs),
            "successful_count": successful_count,
            "denied_count": denied_count
        }
    )