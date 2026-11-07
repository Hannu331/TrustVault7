from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parents[1]

load_dotenv(BASE_DIR / ".env")

from app.core.database import init_db

if __name__ == "__main__":
    init_db()
    print("TrustVault database initialized successfully.")