from pwd_manager import db, bcrypt
import os
from base64 import b64encode

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    encryption_key = db.Column(db.String(255), nullable=False)
    passwords = db.relationship('PasswordEntry', backref='owner', lazy=True)

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

class PasswordEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    website = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    encrypted_password = db.Column(db.String(255), nullable=False)
    tags = db.Column(db.String(255), nullable=True)  # Store tags as comma-separated string
