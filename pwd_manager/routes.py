from flask import Blueprint, render_template, request, redirect, url_for, flash, session, send_file
from pwd_manager import db
from pwd_manager.models import User, PasswordEntry
from pwd_manager.utils.crypto import encrypt_password, decrypt_password
import qrcode
from io import BytesIO
import base64

main_bp = Blueprint('main', __name__)

def get_user_encryption_key():
    user = User.query.get(session.get('user_id'))
    if user:
        return user.encryption_key.encode()
    return None

@main_bp.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        return redirect(url_for('auth.login'))
    
    search_query = request.args.get('search', '').lower()
    tag_filter = request.args.get('tag', '')
    
    passwords = PasswordEntry.query.filter_by(user_id=user.id)
    
    if search_query:
        passwords = passwords.filter(
            (PasswordEntry.website.ilike(f'%{search_query}%')) |
            (PasswordEntry.username.ilike(f'%{search_query}%')) |
            (PasswordEntry.tags.ilike(f'%{search_query}%'))
        )
    
    if tag_filter:
        passwords = passwords.filter(PasswordEntry.tags.ilike(f'%{tag_filter}%'))
    
    # Get all unique tags for the filter dropdown
    all_tags = set()
    entries = passwords.all()
    for entry in entries:
        if entry.tags:
            all_tags.update(tag.strip() for tag in entry.tags.split(','))
    
    return render_template('index.html', entries=entries, all_tags=sorted(all_tags))

@main_bp.route('/add', methods=['GET', 'POST'])
def add_password():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        website = request.form.get('website')
        username = request.form.get('username')
        password = request.form.get('password')
        tags = request.form.get('tags')
        
        if not website or not username or not password:
            flash('All fields except tags are required', 'error')
            return redirect(url_for('main.add_password'))
        
        encryption_key = get_user_encryption_key()
        if not encryption_key:
            flash('Error retrieving encryption key', 'error')
            return redirect(url_for('main.index'))
        
        encrypted_password = encrypt_password(encryption_key, password)
        
        new_entry = PasswordEntry(
            user_id=session['user_id'],
            website=website,
            username=username,
            encrypted_password=encrypted_password,
            tags=tags
        )
        
        db.session.add(new_entry)
        db.session.commit()
        
        flash('Password entry added successfully!', 'success')
        return redirect(url_for('main.index'))
    
    return render_template('add_password.html')

@main_bp.route('/view/<int:entry_id>')
def view_password(entry_id):
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    
    entry = PasswordEntry.query.get_or_404(entry_id)
    
    if entry.user_id != session['user_id']:
        flash('Unauthorized access', 'error')
        return redirect(url_for('main.index'))
    
    encryption_key = get_user_encryption_key()
    if not encryption_key:
        flash('Error retrieving encryption key', 'error')
        return redirect(url_for('main.index'))
    
    try:
        decrypted_password = decrypt_password(encryption_key, entry.encrypted_password)
        
        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(f"Website: {entry.website}\nUsername: {entry.username}\nPassword: {decrypted_password}")
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert QR code to base64 string
        buffered = BytesIO()
        img.save(buffered)
        qr_base64 = base64.b64encode(buffered.getvalue()).decode()
        
        return render_template('view_password.html', 
                             entry=entry, 
                             password=decrypted_password,
                             qr_code=qr_base64)
    except Exception as e:
        flash('Error decrypting password', 'error')
        return redirect(url_for('main.index'))

@main_bp.route('/delete/<int:entry_id>')
def delete_password(entry_id):
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    
    entry = PasswordEntry.query.get_or_404(entry_id)
    
    if entry.user_id != session['user_id']:
        flash('Unauthorized access', 'error')
        return redirect(url_for('main.index'))
    
    db.session.delete(entry)
    db.session.commit()
    
    flash('Password entry deleted successfully', 'success')
    return redirect(url_for('main.index'))
