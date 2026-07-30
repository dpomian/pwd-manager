from cryptography.fernet import Fernet
import base64

def generate_key():
    """Generate a new Fernet key"""
    return Fernet.generate_key()

def derive_key(password):
    """Derive a Fernet key from a password"""
    # Pad the password to 32 bytes
    key = password.ljust(32)[:32].encode()
    # Convert to base64 as required by Fernet
    return base64.urlsafe_b64encode(key)

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
