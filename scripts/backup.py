"""Consistent backup of the database and all stored files.

    python -m scripts.backup            -> data/backups/trustvault-<time>.tar.gz

The archive contains documents in plain form: keep it somewhere private (see README, Operations).
"""

import sqlite3
import tarfile
import tempfile
import time
from pathlib import Path

from app import db


def run(destination=None) -> Path:
    folder = Path(destination or db.ROOT / "data" / "backups")
    folder.mkdir(parents=True, exist_ok=True)
    archive = folder / f"trustvault-{time.strftime('%Y%m%d-%H%M%S')}.tar.gz"
    with tempfile.TemporaryDirectory() as tmp:
        snapshot = Path(tmp) / "trustvault.db"
        source, target = db.connect(), sqlite3.connect(snapshot)
        source.backup(target)  # SQLite's own online backup: safe while the app is running
        target.close()
        source.close()
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(snapshot, arcname="trustvault.db")
            if Path(db.STORE).exists():
                tar.add(db.STORE, arcname="blobs")
    return archive


if __name__ == "__main__":
    print(run())
