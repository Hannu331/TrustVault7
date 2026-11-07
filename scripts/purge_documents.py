"""Delete EVERY document, grant and stored file (accounts and the audit trail are kept).

    python -m scripts.purge_documents          (asks you to type a confirmation phrase)

Use it once to clear sample or demo documents from a system before real use. The audit log is
append-only and keeps the history, including a record that this purge happened.
Run it where the data lives (on Render: the service's Shell tab).
"""

import shutil
import sys
from pathlib import Path

from app import db

PHRASE = "DELETE ALL DOCUMENTS"


def run(confirmed: bool = False) -> int:
    if not confirmed:
        raise SystemExit("Not confirmed.")
    conn = db.connect()
    count = conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
    conn.execute("DELETE FROM grants")
    conn.execute("DELETE FROM documents")
    conn.close()
    store = Path(db.STORE)
    if store.exists():
        shutil.rmtree(store)
    store.mkdir(parents=True, exist_ok=True)
    conn = db.connect()
    db.audit(conn, None, "documents_purged", detail={"documents": count})
    conn.close()
    return count


if __name__ == "__main__":
    answer = input(f"This permanently deletes every document. Type {PHRASE} to continue: ")
    if answer.strip() != PHRASE:
        sys.exit("Cancelled. Nothing was deleted.")
    print(f"Deleted {run(confirmed=True)} documents.")
