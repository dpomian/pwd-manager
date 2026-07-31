import os
import uuid
from base64 import b64encode
from datetime import datetime

from pwd_manager import bcrypt, db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    kdf_salt = db.Column(db.String(64), nullable=False)
    kdf_iterations = db.Column(db.Integer, nullable=False)
    wrapped_dek = db.Column(db.String(255), nullable=False)
    # Version marker so future parameter changes can be handled on next login.
    key_version = db.Column(db.Integer, default=1, nullable=False)
    passwords = db.relationship("SecretEntry", backref="owner", lazy=True)
    documents = db.relationship("Document", backref="owner", lazy=True)

    def __init__(self, username, password=None):
        self.username = username
        if password:
            self.set_password(password)
        else:
            # For testing purposes, set a dummy password. The wrapping data
            # will be created by set_password() when the test is ready.
            self.password = "dummy_hash"
            self.wrapped_dek = None
            self.kdf_salt = None
            self.kdf_iterations = None
            self.key_version = 0

    def set_password(self, password):
        """Hash the password and wrap the data-encryption key."""
        from cryptography.fernet import Fernet

        from pwd_manager.utils.crypto import derive_kek

        self.password = bcrypt.generate_password_hash(password).decode("utf-8")
        dek = os.urandom(32)
        salt = os.urandom(16)
        salt_b64 = b64encode(salt).decode("utf-8")
        time_cost = int(os.getenv("ARGON2_TIME_COST", "3"))
        kek = derive_kek(password, salt_b64, time_cost)
        wrapped = Fernet(kek).encrypt(dek)
        self.wrapped_dek = wrapped.decode("utf-8")
        self.kdf_salt = salt_b64
        self.kdf_iterations = time_cost
        self.key_version = 1

    def get_dek(self, password: str) -> str:
        """Return the base64-encoded data-encryption key for the given password."""
        from cryptography.fernet import Fernet

        from pwd_manager.utils.crypto import derive_kek

        if not (self.wrapped_dek and self.kdf_salt and self.kdf_iterations):
            raise ValueError("Key wrapping data is incomplete")
        kek = derive_kek(password, self.kdf_salt, self.kdf_iterations)
        dek = Fernet(kek).decrypt(self.wrapped_dek.encode("utf-8"))
        return b64encode(dek).decode("utf-8")

    def check_password(self, password):
        """Check if the provided password is correct"""
        return bcrypt.check_password_hash(self.password, password)


class Collection(db.Model):
    __tablename__ = "collection"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )
    documents = db.relationship(
        "Document", backref="collection", lazy=True, cascade="all, delete-orphan"
    )


class SecretEntry(db.Model):
    __tablename__ = "password_entry"  # Keep existing table name to preserve data

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    has_login_info = db.Column(db.Boolean, default=False, nullable=False)
    website = db.Column(db.String(100), nullable=True)
    username = db.Column(db.String(100), nullable=True)
    encrypted_password = db.Column(db.String(255), nullable=True)
    tags = db.Column(
        db.String(255), nullable=True
    )  # Store tags as comma-separated string
    notes = db.Column(db.Text, nullable=True)
    attachments = db.relationship(
        "Attachment", backref="secret", lazy=True, cascade="all, delete-orphan"
    )


class Attachment(db.Model):
    """Model for encrypted file attachments linked to secrets"""

    __tablename__ = "attachment"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    secret_entry_id = db.Column(
        db.Integer, db.ForeignKey("password_entry.id"), nullable=False
    )
    original_filename = db.Column(db.String(255), nullable=False)
    mime_type = db.Column(db.String(100), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)  # Size in bytes before encryption
    storage_filename = db.Column(
        db.String(255), nullable=False
    )  # UUID-based filename on disk
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # Maximum file size: 10MB
    MAX_FILE_SIZE = 10 * 1024 * 1024

    # Allowed file extensions
    ALLOWED_EXTENSIONS = frozenset(
        {
            "pdf",
            "doc",
            "docx",
            "txt",
            "rtf",  # Documents
            "png",
            "jpg",
            "jpeg",
            "gif",
            "bmp",
            "webp",  # Images
            "xls",
            "xlsx",
            "csv",  # Spreadsheets
            "json",
            "xml",  # Data files
        }
    )

    @classmethod
    def allowed_file(cls, filename):
        """Check if the file extension is allowed"""
        return (
            "." in filename
            and filename.rsplit(".", 1)[1].lower() in cls.ALLOWED_EXTENSIONS
        )


class Document(db.Model):
    __tablename__ = "document"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    collection_id = db.Column(db.Integer, db.ForeignKey("collection.id"), nullable=True)
    title = db.Column(db.String(200), nullable=False)
    encrypted_content = db.Column(db.Text, nullable=True)
    tags = db.Column(db.String(255), nullable=True)
    is_draft = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )
    attachments = db.relationship(
        "DocumentAttachment",
        backref="document",
        lazy=True,
        cascade="all, delete-orphan",
    )


class DocumentAttachment(db.Model):
    """Model for encrypted file attachments linked to library documents"""

    __tablename__ = "document_attachment"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    document_id = db.Column(db.Integer, db.ForeignKey("document.id"), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    mime_type = db.Column(db.String(100), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    storage_filename = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    MAX_FILE_SIZE = Attachment.MAX_FILE_SIZE
    ALLOWED_EXTENSIONS = Attachment.ALLOWED_EXTENSIONS

    @classmethod
    def allowed_file(cls, filename):
        """Check if the file extension is allowed"""
        return (
            "." in filename
            and filename.rsplit(".", 1)[1].lower() in cls.ALLOWED_EXTENSIONS
        )
