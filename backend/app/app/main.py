import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from .core.database import init_db
from .routes.auth import router as auth_router
from .routes.dashboard import router as dashboard_router
from .routes.documents import router as documents_router
from .routes.permissions import router as permissions_router
from .routes.audit import router as audit_router
from .routes.profile import router as profile_router
from .routes.admin import router as admin_router

# backend/app/app/main.py -> project root
PROJECT_ROOT = Path(__file__).resolve().parents[3]
load_dotenv(PROJECT_ROOT / ".env")

SECRET_KEY = os.getenv("TRUSTVAULT_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "TRUSTVAULT_SECRET_KEY is missing. Copy .env.example to .env and set a strong secret."
    )

app = FastAPI(title="TrustVault", version="2.0.0")
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    same_site="lax",
    https_only=os.getenv("TRUSTVAULT_HTTPS_ONLY", "false").lower() == "true",
)

STATIC_DIR = PROJECT_ROOT / "frontend" / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Creates only the schema and an administrator when credentials are configured.
init_db()

app.include_router(auth_router)
app.include_router(dashboard_router)
app.include_router(documents_router)
app.include_router(permissions_router)
app.include_router(audit_router)
app.include_router(profile_router)
app.include_router(admin_router)

@app.get("/health")
def health():
    return {"status": "ok", "application": "TrustVault", "version": "2.0.0"}
