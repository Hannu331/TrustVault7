import os
import sqlite3
from datetime import datetime


from .config import DATABASE_FILE
from .security import hash_password


def get_connection():
    c = sqlite3.connect(DATABASE_FILE)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    c = get_connection()
    x = c.cursor()

    # ---------------------------------------------------------
    # USERS
    # ---------------------------------------------------------

    x.execute(
        '''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT "viewer",
            created_at TEXT NOT NULL
        )
        '''
    )

    # ---------------------------------------------------------
    # DOCUMENTS
    # ---------------------------------------------------------

    x.execute(
        '''
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            owner_username TEXT NOT NULL,
            category TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT "Active"
        )
        '''
    )

    # ---------------------------------------------------------
    # PERMISSIONS
    # ---------------------------------------------------------

    x.execute(
        '''
        CREATE TABLE IF NOT EXISTS permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            access TEXT NOT NULL,
            granted_by TEXT NOT NULL,
            granted_at TEXT NOT NULL,
            UNIQUE(document_id, username)
        )
        '''
    )

    # ---------------------------------------------------------
    # DOCUMENT VERSIONS
    # ---------------------------------------------------------

    x.execute(
        '''
        CREATE TABLE IF NOT EXISTS document_versions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id INTEGER NOT NULL,
            version_number INTEGER NOT NULL,
            stored_name TEXT NOT NULL,
            edited_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(document_id, version_number)
        )
        '''
    )

    # ---------------------------------------------------------
    # AUDIT LOGS
    # ---------------------------------------------------------

    x.execute(
        '''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT NOT NULL,
            details TEXT,
            timestamp TEXT NOT NULL
        )
        '''
    )

    c.commit()

    # ---------------------------------------------------------
    # CREATE FIRST ADMINISTRATOR
    # ---------------------------------------------------------

    admin_username = os.getenv(
        "TRUSTVAULT_ADMIN_USERNAME",
        "admin"
    )

    admin_password = os.getenv(
        "TRUSTVAULT_ADMIN_PASSWORD"
    )

    admin_name = os.getenv(
        "TRUSTVAULT_ADMIN_NAME",
        "Administrator"
    )

    if admin_password:
        existing_admin = x.execute(
            """
            SELECT id
            FROM users
            WHERE username = ?
            """,
            (admin_username,)
        ).fetchone()

        if not existing_admin:
            password_hash = hash_password(admin_password)

            x.execute(
                """
                INSERT INTO users
                (
                    username,
                    password_hash,
                    name,
                    role,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    admin_username,
                    password_hash,
                    admin_name,
                    "administrator",
                    datetime.utcnow().isoformat()
                )
            )

            c.commit()

    c.close()