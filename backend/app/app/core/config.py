import os
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[3]

STORAGE_ROOT = os.getenv("TRUSTVAULT_STORAGE_DIR")

if STORAGE_ROOT:
    STORAGE_ROOT = Path(STORAGE_ROOT)
    UPLOAD_DIR = STORAGE_ROOT / "uploads"
    DATABASE_FILE = STORAGE_ROOT / "trustvault.db"
else:
    UPLOAD_DIR = BACKEND_DIR / "uploads"
    DATABASE_FILE = BACKEND_DIR / "data" / "trustvault.db"

ALLOWED_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".txt", ".csv"
}

MAX_FILE_SIZE = 10 * 1024 * 1024

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
DATABASE_FILE.parent.mkdir(parents=True, exist_ok=True)