
from datetime import datetime
from pathlib import Path
import sqlite3

from fastapi import APIRouter, Request, Form
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from ..core.database import get_connection
from ..core.security import hash_password
from ..services.auth_service import authenticate
from ..services.audit_service import log_event

router = APIRouter()

BASE_DIR = Path(__file__).resolve().parents[4]
TEMPLATES_DIR = BASE_DIR / "frontend" / "templates"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


@router.get("/")
def home(request: Request):
    return RedirectResponse(
        "/dashboard" if request.session.get("user") else "/login",
        status_code=303
    )


# ---------------- LOGIN ----------------

@router.get("/login")
def login_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "error": request.query_params.get("error"),
            "registered": request.query_params.get("registered")
        }
    )


@router.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    username = username.strip()

    user = authenticate(username, password)

    if not user:
        log_event(
            username,
            "LOGIN_FAILED",
            username,
            "Invalid credentials"
        )

        return RedirectResponse(
            "/login?error=invalid",
            status_code=303
        )

    request.session["user"] = {
        "username": user["username"],
        "name": user["name"],
        "role": user["role"]
    }

    log_event(
        username,
        "LOGIN",
        username,
        "Successful login"
    )

    return RedirectResponse("/dashboard", status_code=303)


# ---------------- REGISTRATION ----------------

@router.get("/register")
def register_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="register.html",
        context={
            "error": request.query_params.get("error"),
            "name": "",
            "username": ""
        }
    )


@router.post("/register")
def register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    name: str = Form(...)
):
    username = username.strip()
    name = name.strip()

    # Validate registration details
    if not username or not name or len(password) < 8:
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={
                "error": "Enter your name and username. Password must contain at least 8 characters.",
                "name": name,
                "username": username
            },
            status_code=400
        )

    c = get_connection()

    try:
        c.execute(
            """
            INSERT INTO users
            (username, password_hash, name, role, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                username,
                hash_password(password),
                name,
                "document_owner",
                datetime.utcnow().isoformat()
            )
        )

        c.commit()

    except sqlite3.IntegrityError:
        c.close()

        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={
                "error": "That username already exists. Choose another username.",
                "name": name,
                "username": username
            },
            status_code=409
        )

    except Exception:
        c.rollback()
        c.close()
        raise

    c.close()

    log_event(
        username,
        "REGISTER",
        username,
        "New document owner registered"
    )

    return RedirectResponse(
        "/login?registered=1",
        status_code=303
    )


# ---------------- LOGOUT ----------------

@router.get("/logout")
def logout(request: Request):
    request.session.clear()

    return RedirectResponse(
        "/login",
        status_code=303
    )
