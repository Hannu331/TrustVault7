# TrustVault Backend

FastAPI backend baseline for the TrustVault document-sharing application.

Run from the project root with:

    .venv\Scripts\activate
    python -m uvicorn backend.app.main:app --reload --port 8000

This backend includes authentication, document upload/download, access checks, READ/EDIT permissions, audit logging, profile, dashboard and admin routes.

Important: exact integration with the user's existing HTML templates is not verified here; form field names and template rendering may need to be aligned with the current frontend.
