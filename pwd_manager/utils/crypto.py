from cryptography.fernet import Fernet
import base64
import os

def generate_key():
    """Generate a new Fernet key"""
    return Fernet.generate_key()

def derive_key(password):
    """Derive a Fernet key from a password"""
    # Pad the password to 32 bytes
    key = password.ljust(32)[:32].encode()
    # Convert to base64 as required by Fernet
    return base64.urlsafe_b64encode(key)

def encrypt_password(key, password):
    """Encrypt a password using a Fernet key
    Args:
        key (bytes): A valid Fernet key (32 url-safe base64-encoded bytes)
        password (str): The password to encrypt
    Returns:
        str: The encrypted password
    """
    f = Fernet(key)
    return f.encrypt(password.encode()).decode()

def decrypt_password(key, encrypted_password):
    """Decrypt a password using a Fernet key
    Args:
        key (bytes): A valid Fernet key (32 url-safe base64-encoded bytes)
        encrypted_password (str): The encrypted password to decrypt
    Returns:
        str: The decrypted password
    """
    f = Fernet(key)
    return f.decrypt(encrypted_password.encode()).decode()
