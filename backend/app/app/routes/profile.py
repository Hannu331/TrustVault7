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


@router.get('/profile')
def profile(request: Request):
    user = require_login(request)

    if not user:
        return RedirectResponse('/login', status_code=303)

    connection = get_connection()

    row = connection.execute("""
        SELECT id, username, name, role, created_at
        FROM users
        WHERE username = ?
    """, (user['username'],)).fetchone()

    connection.close()

    if not row:
        return RedirectResponse('/login', status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="profile.html",
        context={
            "user": user,
            "profile": dict(row)
        }
    )