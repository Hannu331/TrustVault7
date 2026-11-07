
from ..core.database import get_connection
from ..core.security import verify_password

def authenticate(username, password):
    c = get_connection()

    try:
        user = c.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()
    finally:
        c.close()

    if not user:
        return None

    user = dict(user)
    valid = verify_password(password, user["password_hash"])

    return user if valid else None
