import base64
import hashlib

from cryptography.fernet import Fernet
from flask import current_app, session


def _session_kek() -> bytes:
    """Return the Fernet key used to encrypt the per-session DEK.

    The key is derived deterministically from the app's ``SECRET_KEY`` and
    cached in ``app.config['SESSION_DEK_KEY']``.  If that key isn't present
    (older apps that predate this setting), it is computed on the fly.
    """
    key = current_app.config.get("SESSION_DEK_KEY")
    if key is None:
        return base64.urlsafe_b64encode(
            hashlib.sha256(current_app.config["SECRET_KEY"].encode()).digest()
        )
    return key


def encrypt_session_dek(dek_b64: str) -> str:
    """Encrypt a base64-encoded DEK with the session key for storage in Flask's
    client-side session cookie.
    """
    return Fernet(_session_kek()).encrypt(dek_b64.encode()).decode()


def get_user_encryption_key():
    """Return the current user's Fernet data-encryption key (DEK) as bytes.

    The DEK is kept in the session, encrypted with a key derived from the app's
    ``SECRET_KEY``.  If no DEK is present in the session the user is not logged
    in and ``None`` is returned.
    """
    token = session.get("dek")
    if not token:
        return None
    return Fernet(_session_kek()).decrypt(token.encode())
