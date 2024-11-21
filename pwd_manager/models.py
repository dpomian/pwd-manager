from pwd_manager import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    encryption_key = db.Column(db.String(255), nullable=False)
    passwords = db.relationship('PasswordEntry', backref='owner', lazy=True)

class PasswordEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    website = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    encrypted_password = db.Column(db.String(255), nullable=False)
    tags = db.Column(db.String(255), nullable=True)  # Store tags as comma-separated string
