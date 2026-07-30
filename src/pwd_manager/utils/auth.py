from flask import session
from pwd_manager.models import User


def get_user_encryption_key():
    """Return the current user's Fernet encryption key as bytes."""
    user = User.query.get(session.get("user_id"))
    if user:
        return user.encryption_key.encode()
    return None
