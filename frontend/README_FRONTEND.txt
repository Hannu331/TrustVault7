TRUSTVAULT FRONTEND

This frontend is wired to the database-backed FastAPI application in backend/app/app.

- templates/: Jinja2 pages for user and administrator workspaces.
- static/css/style.css: responsive TrustVault styling.
- static/js/app.js: navigation, upload field feedback and table search.

The pages render live records supplied by backend routes. There are no bundled sample users or demo documents. Upload validation in the browser is only a convenience; the backend independently validates file extensions, file size, login state and document permissions.

Run the full project from its root directory with:

    python -m uvicorn backend.app.app.main:app --reload --port 8000

Do not expose backend/uploads or backend/data as public static directories.
