from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv
import qrcode
from io import BytesIO
import base64

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(24))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///passwords.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Encryption key generation
def generate_key():
    return Fernet.generate_key()

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    encryption_key = db.Column(db.String(255), nullable=False)

# Password Entry Model
class PasswordEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    website = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    encrypted_password = db.Column(db.String(255), nullable=False)
    tags = db.Column(db.String(255), nullable=True)  # Store tags as comma-separated string

# Encryption Utility
def encrypt_password(key, password):
    f = Fernet(key)
    return f.encrypt(password.encode()).decode()

def decrypt_password(key, encrypted_password):
    f = Fernet(key)
    return f.decrypt(encrypted_password.encode()).decode()

# Helper function for encryption key management
def get_user_encryption_key():
    """Helper function to get user's encryption key"""
    if 'encryption_key' not in session:
        user = User.query.get(session['user_id'])
        if user and user.encryption_key:
            session['encryption_key'] = user.encryption_key
        else:
            # Generate new key if none exists
            encryption_key = generate_key()
            encryption_key_str = encryption_key.decode('utf-8')
            if user:
                user.encryption_key = encryption_key_str
                db.session.commit()
            session['encryption_key'] = encryption_key_str
    return session['encryption_key']

# Routes
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Fetch user's password entries
    entries = PasswordEntry.query.filter_by(user_id=session['user_id']).all()
    
    # Get all unique tags
    all_tags = set()
    for entry in entries:
        if entry.tags:
            all_tags.update(entry.tags.split(','))
    all_tags = sorted(list(all_tags))
    
    return render_template('index.html', entries=entries, all_tags=all_tags)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists')
            return redirect(url_for('register'))
        
        try:
            # Generate encryption key
            encryption_key = generate_key()
            encryption_key_str = encryption_key.decode('utf-8')
            
            # Hash password
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            
            # Create new user
            new_user = User(
                username=username, 
                password=hashed_password, 
                encryption_key=encryption_key_str
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            # Log the user in automatically
            session['user_id'] = new_user.id
            session['encryption_key'] = encryption_key_str
            
            flash('Registration successful')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash('Registration failed. Please try again.')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            # Store both user_id and encryption_key in session
            session['user_id'] = user.id
            session['encryption_key'] = user.encryption_key
            flash('Login successful')
            return redirect(url_for('index'))
        
        flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('encryption_key', None)
    flash('You have been logged out')
    return redirect(url_for('login'))

@app.route('/add_password', methods=['GET', 'POST'])
def add_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        website = request.form['website']
        username = request.form['username']
        password = request.form['password']
        tags = request.form.get('tags', '').lower()
        
        # Clean tags: remove spaces and split by commas
        tags = ','.join([tag.strip() for tag in tags.split(',') if tag.strip()])
        
        try:
            # Get user's encryption key
            encryption_key = get_user_encryption_key()
            
            # Encrypt the password
            encrypted_password = encrypt_password(encryption_key.encode(), password)
            
            # Create new password entry
            new_entry = PasswordEntry(
                user_id=session['user_id'],
                website=website,
                username=username,
                encrypted_password=encrypted_password,
                tags=tags
            )
            
            db.session.add(new_entry)
            db.session.commit()
            
            flash('Password added successfully')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash('Error adding password. Please try again.')
            return redirect(url_for('add_password'))
    
    return render_template('add_password.html')

@app.route('/view_password/<int:entry_id>')
def view_password(entry_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    entry = PasswordEntry.query.get_or_404(entry_id)
    
    if entry.user_id != session['user_id']:
        flash('Unauthorized access')
        return redirect(url_for('index'))
    
    try:
        # Get user's encryption key
        encryption_key = get_user_encryption_key()
        
        # Decrypt the password
        decrypted_password = decrypt_password(encryption_key.encode(), entry.encrypted_password)
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(decrypted_password)
        qr.make(fit=True)
        
        # Create QR code image
        img_buffer = BytesIO()
        qr.make_image(fill_color="black", back_color="white").save(img_buffer)
        img_buffer.seek(0)
        
        # Convert to base64 for embedding in HTML
        qr_base64 = base64.b64encode(img_buffer.getvalue()).decode()
        
        return render_template(
            'view_password.html',
            entry=entry,
            password=decrypted_password,
            qr_code=qr_base64
        )
    except Exception as e:
        flash('Error viewing password. Please try again.')
        return redirect(url_for('index'))

@app.route('/delete_password/<int:entry_id>', methods=['POST'])
def delete_password(entry_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    entry = PasswordEntry.query.get_or_404(entry_id)
    
    # Ensure the entry belongs to the logged-in user
    if entry.user_id != session['user_id']:
        flash('Unauthorized access')
        return redirect(url_for('index'))
    
    db.session.delete(entry)
    db.session.commit()
    
    flash('Password entry deleted successfully')
    return redirect(url_for('index'))

# Create database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
