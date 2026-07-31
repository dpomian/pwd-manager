import base64

import argon2
from cryptography.fernet import Fernet


def generate_key():
    """Generate a new Fernet key"""
    return Fernet.generate_key()

def derive_kek(password: str, salt_b64: str, time_cost: int) -> bytes:
    """Derive a Fernet-compatible key-encryption key (KEK) from a password.

    Uses Argon2id with the given per-user salt and time cost.  The output is
    a 32-byte raw key encoded with URL-safe base64 so it can be used directly
    with ``cryptography.fernet.Fernet``.
    """
    salt = base64.b64decode(salt_b64)
    raw = argon2.low_level.hash_secret_raw(
        password.encode(),
        salt,
        time_cost=time_cost,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=argon2.Type.ID,
    )
    return base64.urlsafe_b64encode(raw)

def encrypt_data(key, data):
    """Encrypt a password using a Fernet key
    Args:
        key (bytes): A valid Fernet key (32 url-safe base64-encoded bytes)
        data (str): The data to encrypt
    Returns:
        str: The encrypted data
    """
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

def decrypt_data(key, encrypted_data):
    """Decrypt a password using a Fernet key
    Args:
        key (bytes): A valid Fernet key (32 url-safe base64-encoded bytes)
        encrypted_data (str): The encrypted data to decrypt
    Returns:
        str: The decrypted data
    """
    f = Fernet(key)
    return f.decrypt(encrypted_data.encode()).decode()


def encrypt_binary(key, data: bytes) -> bytes:
    """Encrypt binary data using a Fernet key
    Args:
        key (bytes): A valid Fernet key (32 url-safe base64-encoded bytes)
        data (bytes): The binary data to encrypt
    Returns:
        bytes: The encrypted data
    """
    f = Fernet(key)
    return f.encrypt(data)


def decrypt_binary(key, encrypted_data: bytes) -> bytes:
    """Decrypt binary data using a Fernet key
    Args:
        key (bytes): A valid Fernet key (32 url-safe base64-encoded bytes)
        encrypted_data (bytes): The encrypted binary data to decrypt
    Returns:
        bytes: The decrypted binary data
    """
    f = Fernet(key)
    return f.decrypt(encrypted_data)
