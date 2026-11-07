# TrustVault — Secure Document Sharing

TrustVault is a FastAPI + SQLite document-sharing application with a responsive Jinja2 interface.
The backend is database-backed; the frontend is taken from the supplied `TrustVault-updated.zip` UI.

## Implemented workflows

- Account registration and login with password hashing.
- A first administrator account created from environment variables on initial startup.
- Private-by-default document uploads (PDF, DOC, DOCX, TXT and CSV; maximum 10 MB).
- Owner dashboard, My Documents and Shared With Me views.
- Per-document READ or EDIT grants to registered users; owners can change or revoke grants.
- Admin views for registered accounts, all documents, permissions and audit events.
- Server-side access checks on document detail, preview, download and edit endpoints.
- TXT/CSV editing with version history. Other supported file types can be downloaded; browser editing is currently limited to TXT/CSV.
- Audit events for login, upload, document access, download, edits and permission changes.

No demo users, demo documents, pre-populated database or sample uploads are included. The SQLite database and upload directory are created empty on first run.

## Requirements

- Python 3.10+
- pip

## Setup (Windows PowerShell)

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt
Copy-Item .env.example .env
```

Edit `.env` and set a long random `TRUSTVAULT_SECRET_KEY` and a strong `TRUSTVAULT_ADMIN_PASSWORD` before starting the server.

## Run

From the project root:

```powershell
python -m uvicorn backend.app.app.main:app --reload --port 8000
```

Open `http://127.0.0.1:8000`. Register normal accounts at `/register`; sign in as the configured administrator at `/admin/login`.

The same command works on macOS/Linux after activating the virtual environment.

## Permission model

| Action | Administrator | Owner | Shared user |
|---|---:|---:|---:|
| View all users/documents | Yes | No | No |
| Upload | Yes | Yes | No |
| Read own document | Yes | Yes | If READ or EDIT granted |
| Edit TXT/CSV | Yes | Yes | If EDIT granted |
| Share / change / revoke access | Yes | Own documents | No |
| View all audit events | Yes | Own actor events | No |

A normal registered account can own documents and can also receive documents shared by other accounts. Permissions are checked by the backend on every protected request; hiding a UI action is not treated as authorization.

## Storage and configuration

- SQLite database: `backend/data/trustvault.db` (created automatically)
- Private uploads: `backend/uploads/` (not mounted as public static files)
- Configuration: project-root `.env` (never commit it)
- Health endpoint: `/health`

Back up the database and uploads together. For production deployment, use HTTPS, a strong unique session secret, secure cookie settings, restricted filesystem permissions, database backups and a production ASGI server configuration.

## Notes

- Existing data from the supplied ZIP was intentionally excluded so the delivered project starts without demo records. Keep a separate backup of your original ZIP if you need that data.
- The UI includes document preview/download; DOC/DOCX browser preview and editing are not provided by the current backend. TXT/CSV editing creates a new stored version.
