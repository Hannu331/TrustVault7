from pathlib import Path
BASE_DIR = Path(__file__).resolve().parents[3]
UPLOAD_DIR = BASE_DIR / 'uploads'
DATABASE_FILE = BASE_DIR / 'data' / 'trustvault.db'
ALLOWED_EXTENSIONS = {'.pdf','.doc','.docx','.txt','.csv'}
MAX_FILE_SIZE = 10 * 1024 * 1024
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
DATABASE_FILE.parent.mkdir(parents=True, exist_ok=True)
