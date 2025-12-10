from pwd_manager import db, bcrypt
import os
import uuid
from datetime import datetime
from base64 import b64encode

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    encryption_key = db.Column(db.String(255), nullable=False)
    passwords = db.relationship('SecretEntry', backref='owner', lazy=True)

    def __init__(self, username, password=None):
        self.username = username
        if password:
            self.set_password(password)
        else:
            # For testing purposes, set a dummy password and encryption key
            self.password = 'dummy_hash'
            self.encryption_key = b64encode(os.urandom(32)).decode('utf-8')

    def set_password(self, password):
        """Hash the password and generate encryption key"""
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')
        # Generate a random encryption key
        self.encryption_key = b64encode(os.urandom(32)).decode('utf-8')

    def check_password(self, password):
        """Check if the provided password is correct"""
        return bcrypt.check_password_hash(self.password, password)

class SecretEntry(db.Model):
    __tablename__ = 'password_entry'  # Keep existing table name to preserve data
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    website = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    encrypted_password = db.Column(db.String(255), nullable=False)
    tags = db.Column(db.String(255), nullable=True)  # Store tags as comma-separated string
    notes = db.Column(db.Text, nullable=True)
    attachments = db.relationship('Attachment', backref='secret', lazy=True, cascade='all, delete-orphan')


class Attachment(db.Model):
    """Model for encrypted file attachments linked to secrets"""
    __tablename__ = 'attachment'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    secret_entry_id = db.Column(db.Integer, db.ForeignKey('password_entry.id'), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    mime_type = db.Column(db.String(100), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)  # Size in bytes before encryption
    storage_filename = db.Column(db.String(255), nullable=False)  # UUID-based filename on disk
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # Maximum file size: 10MB
    MAX_FILE_SIZE = 10 * 1024 * 1024
    
    # Allowed file extensions
    ALLOWED_EXTENSIONS = {
        'pdf', 'doc', 'docx', 'txt', 'rtf',  # Documents
        'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp',  # Images
        'xls', 'xlsx', 'csv',  # Spreadsheets
        'json', 'xml'  # Data files
    }
    
    @classmethod
    def allowed_file(cls, filename):
        """Check if the file extension is allowed"""
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in cls.ALLOWED_EXTENSIONS
