"""Upload validation and private blob storage."""

import hashlib, os, re, uuid
from fastapi import HTTPException, UploadFile
from . import db

MAX_BYTES = 10 * 1024 * 1024


def _text(b: bytes) -> bool:
    try:
        b.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return b"\x00" not in b


_ZIP = lambda b: b.startswith(b"PK\x03\x04")  # never decompressed server-side
_JPG = lambda b: b.startswith(b"\xff\xd8\xff")
TYPES = {  # extension -> (content-type we serve, magic-byte check)
    "pdf": ("application/pdf", lambda b: b.startswith(b"%PDF-")),
    "png": ("image/png", lambda b: b.startswith(b"\x89PNG\r\n\x1a\n")),
    "jpg": ("image/jpeg", _JPG),
    "jpeg": ("image/jpeg", _JPG),
    "docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", _ZIP),
    "xlsx": ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", _ZIP),
    "txt": ("text/plain", _text),
    "csv": ("text/csv", _text),
}


def clean_name(raw: str) -> str:
    name = os.path.basename((raw or "").replace("\\", "/"))
    name = re.sub(r"[^\w.\- ]", "_", name).strip(". ")[:120]
    if not name:
        raise HTTPException(422, "Invalid file name")
    return name


async def read_validated(f: UploadFile):
    name = clean_name(f.filename)
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in TYPES:
        raise HTTPException(415, f"File type not allowed. Allowed: {', '.join(sorted(TYPES))}")
    chunks, total = [], 0
    while True:
        part = await f.read(64 * 1024)
        if not part:
            break
        total += len(part)
        if total > MAX_BYTES:
            raise HTTPException(413, "File exceeds 10 MB")
        chunks.append(part)
    data = b"".join(chunks)
    if total == 0:
        raise HTTPException(422, "File is empty")
    mime, check = TYPES[ext]
    if not check(data):
        raise HTTPException(415, "File content does not match its extension")
    return name, mime, data


def _path(key: str) -> str:
    assert re.fullmatch(r"[0-9a-f]{32}", key)  # keys are server-generated only
    return os.path.join(db.STORE, key[:2], key)


def save_blob(data: bytes):
    key = uuid.uuid4().hex
    p = _path(key)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "xb") as fh:
        fh.write(data)
    return key, hashlib.sha256(data).hexdigest()


def blob_path(key: str) -> str:
    return _path(key)


def remove_blob(key: str) -> None:
    try:
        os.remove(_path(key))
    except FileNotFoundError:
        pass
