from flask import Blueprint, render_template, request, redirect, url_for, flash, session, send_file, jsonify, current_app
from pwd_manager import db
from pwd_manager.models import User, SecretEntry, Attachment
from pwd_manager.utils.crypto import encrypt_data, decrypt_data, encrypt_binary, decrypt_binary
import qrcode
from io import BytesIO
from pathlib import Path
import base64
import random
import string
import uuid
import mimetypes

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
    
    passwords = SecretEntry.query.filter_by(user_id=user.id)
    
    if search_query:
        passwords = passwords.filter(
            (SecretEntry.website.ilike(f'%{search_query}%')) |
            (SecretEntry.username.ilike(f'%{search_query}%')) |
            (SecretEntry.tags.ilike(f'%{search_query}%'))
        )
    
    if tag_filter:
        passwords = passwords.filter(SecretEntry.tags.ilike(f'%{tag_filter}%'))
    
    # Get all unique tags for the filter dropdown
    all_tags = set()
    entries = passwords.all()
    for entry in entries:
        if entry.tags:
            all_tags.update(tag.strip() for tag in entry.tags.split(','))
    
    return render_template('index.html', entries=entries, all_tags=sorted(all_tags))

@main_bp.route('/add', methods=['GET', 'POST'])
def add_secret():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        website = request.form.get('website')
        username = request.form.get('username')
        password = request.form.get('password')
        tags = request.form.get('tags')
        notes = request.form.get('notes')
        
        if not website or not username or not password:
            flash('All fields except tags are required', 'error')
            return redirect(url_for('main.add_secret'))
        
        encryption_key = get_user_encryption_key()
        if not encryption_key:
            flash('Error retrieving encryption key', 'error')
            return redirect(url_for('main.index'))
        
        encrypted_password = encrypt_data(encryption_key, password)
        encrypted_notes = encrypt_data(encryption_key, notes) if notes else None
        
        new_entry = SecretEntry(
            user_id=session['user_id'],
            website=website,
            username=username,
            encrypted_password=encrypted_password,
            tags=tags,
            notes=encrypted_notes
        )
        
        db.session.add(new_entry)
        db.session.commit()
        
        flash('Secret entry added successfully!', 'success')
        return redirect(url_for('main.index'))
    
    return render_template('add_secret.html')

@main_bp.route('/view/<int:entry_id>')
def view_secret(entry_id):
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    
    entry = SecretEntry.query.get_or_404(entry_id)
    
    if entry.user_id != session['user_id']:
        flash('Unauthorized access', 'error')
        return redirect(url_for('main.index'))
    
    encryption_key = get_user_encryption_key()
    if not encryption_key:
        flash('Error retrieving encryption key', 'error')
        return redirect(url_for('main.index'))
    
    try:
        decrypted_password = decrypt_data(encryption_key, entry.encrypted_password)
        
        # Generate QR code with just the password
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(decrypted_password)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert QR code to base64 string
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        qr_base64 = base64.b64encode(buffered.getvalue()).decode()
        
        decrypted_notes = decrypt_data(encryption_key, entry.notes) if entry.notes else None
        
        return render_template('view_secret.html', 
                             entry=entry, 
                             password=decrypted_password,
                             notes=decrypted_notes,
                             qr_code=qr_base64)
    except Exception as e:
        current_app.logger.error(f'Error decrypting password for entry {entry_id}: {e}', exc_info=True)
        flash('Error decrypting password', 'error')
        return redirect(url_for('main.index'))

@main_bp.route('/generate_password')
def generate_password_route():
    def generate_group():
        # Define character set: lowercase, uppercase, and numbers
        chars = string.ascii_letters + string.digits
        # Random length between 4 and 6
        length = random.randint(4, 6)
        return ''.join(random.choice(chars) for _ in range(length))
    
    # Generate between 3 to 5 groups
    num_groups = random.randint(3, 5)
    # Generate groups and join them with hyphens
    password = '-'.join(generate_group() for _ in range(num_groups))
    
    return jsonify({'password': password})

@main_bp.route('/edit/<int:entry_id>', methods=['GET', 'POST'])
def edit_secret(entry_id):
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    
    entry = SecretEntry.query.get_or_404(entry_id)
    
    # Ensure the user owns this secret entry
    if entry.user_id != session['user_id']:
        flash('You do not have permission to edit this entry.', 'danger')
        return redirect(url_for('main.index'))
    
    if request.method == 'POST':
        # Get the encryption key
        encryption_key = get_user_encryption_key()
        if not encryption_key:
            flash('Error: Could not retrieve encryption key.', 'danger')
            return redirect(url_for('main.index'))
        
        try:
            # Update the entry
            entry.website = request.form['website']
            entry.username = request.form['username']
            entry.encrypted_password = encrypt_data(encryption_key, request.form['password'])
            entry.tags = request.form['tags']
            notes = request.form.get('notes')
            entry.notes = encrypt_data(encryption_key, notes) if notes else None
            
            db.session.commit()
            flash('Secret entry updated successfully!', 'success')
            return redirect(url_for('main.index'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating secret entry: {str(e)}', 'danger')
            return redirect(url_for('main.edit_secret', entry_id=entry_id))
    
    # For GET request, decrypt the password and notes for display
    encryption_key = get_user_encryption_key()
    decrypted_password = decrypt_data(encryption_key, entry.encrypted_password) if encryption_key else ''
    decrypted_notes = decrypt_data(encryption_key, entry.notes) if encryption_key and entry.notes else ''
    
    return render_template('edit_secret.html', entry=entry, decrypted_password=decrypted_password, decrypted_notes=decrypted_notes)

@main_bp.route('/delete/<int:entry_id>', methods=['POST'])
def delete_secret(entry_id):
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    
    entry = SecretEntry.query.get_or_404(entry_id)
    
    if entry.user_id != session['user_id']:
        flash('Unauthorized access', 'error')
        return redirect(url_for('main.index'))
    
    db.session.delete(entry)
    db.session.commit()
    
    flash('Secret entry deleted successfully', 'success')
    return redirect(url_for('main.index'))

@main_bp.route('/copy_password/<int:entry_id>')
def copy_password(entry_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    entry = SecretEntry.query.get_or_404(entry_id)
    
    if entry.user_id != session['user_id']:
        return jsonify({'error': 'Unauthorized access'}), 403
    
    encryption_key = get_user_encryption_key()
    if not encryption_key:
        return jsonify({'error': 'Error retrieving encryption key'}), 500
    
    try:
        decrypted_password = decrypt_data(encryption_key, entry.encrypted_password)
        return jsonify({'password': decrypted_password})
    except Exception as e:
        return jsonify({'error': 'Error decrypting password'}), 500

@main_bp.route('/qr_code/<int:entry_id>')
def get_qr_code(entry_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    entry = SecretEntry.query.get_or_404(entry_id)
    
    if entry.user_id != session['user_id']:
        return jsonify({'error': 'Unauthorized'}), 401
    
    encryption_key = get_user_encryption_key()
    if not encryption_key:
        return jsonify({'error': 'Error retrieving encryption key'}), 500
    
    try:
        decrypted_password = decrypt_data(encryption_key, entry.encrypted_password)
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(decrypted_password)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert QR code to base64 string
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        qr_base64 = base64.b64encode(buffered.getvalue()).decode()
        
        return jsonify({'qr_code': qr_base64})
    except Exception as e:
        return jsonify({'error': 'Error generating QR code'}), 500


# ============== Attachment Routes ==============

@main_bp.route('/attachment/upload/<int:entry_id>', methods=['POST'])
def upload_attachment(entry_id):
    """Upload and encrypt a file attachment for a secret entry"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    entry = SecretEntry.query.get_or_404(entry_id)
    
    if entry.user_id != session['user_id']:
        return jsonify({'error': 'Unauthorized access'}), 403
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not Attachment.allowed_file(file.filename):
        return jsonify({'error': f'File type not allowed. Allowed types: {", ".join(Attachment.ALLOWED_EXTENSIONS)}'}), 400
    
    # Read file content
    file_content = file.read()
    
    if len(file_content) > Attachment.MAX_FILE_SIZE:
        return jsonify({'error': f'File too large. Maximum size is {Attachment.MAX_FILE_SIZE // (1024*1024)}MB'}), 400
    
    encryption_key = get_user_encryption_key()
    if not encryption_key:
        return jsonify({'error': 'Error retrieving encryption key'}), 500
    
    try:
        # Encrypt the file content
        encrypted_content = encrypt_binary(encryption_key, file_content)
        
        # Generate unique storage filename
        storage_filename = f"{uuid.uuid4()}.enc"
        attachments_dir = Path(current_app.config['ATTACHMENTS_DIR'])
        storage_path = attachments_dir / storage_filename
        
        # Write encrypted file to disk
        storage_path.write_bytes(encrypted_content)
        
        # Determine MIME type
        mime_type = file.content_type or mimetypes.guess_type(file.filename)[0] or 'application/octet-stream'
        
        # Create attachment record
        attachment = Attachment(
            secret_entry_id=entry_id,
            original_filename=file.filename,
            mime_type=mime_type,
            file_size=len(file_content),
            storage_filename=storage_filename
        )
        
        db.session.add(attachment)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'attachment': {
                'id': attachment.id,
                'filename': attachment.original_filename,
                'size': attachment.file_size,
                'mime_type': attachment.mime_type
            }
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error uploading file: {str(e)}'}), 500


@main_bp.route('/attachment/download/<attachment_id>')
def download_attachment(attachment_id):
    """Download and decrypt a file attachment"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    attachment = Attachment.query.get_or_404(attachment_id)
    entry = SecretEntry.query.get_or_404(attachment.secret_entry_id)
    
    if entry.user_id != session['user_id']:
        return jsonify({'error': 'Unauthorized access'}), 403
    
    encryption_key = get_user_encryption_key()
    if not encryption_key:
        return jsonify({'error': 'Error retrieving encryption key'}), 500
    
    try:
        # Read encrypted file from disk
        attachments_dir = Path(current_app.config['ATTACHMENTS_DIR'])
        storage_path = attachments_dir / attachment.storage_filename
        
        if not storage_path.exists():
            return jsonify({'error': 'Attachment file not found'}), 404
        
        encrypted_content = storage_path.read_bytes()
        
        # Decrypt the file content
        decrypted_content = decrypt_binary(encryption_key, encrypted_content)
        
        # Send file to client
        return send_file(
            BytesIO(decrypted_content),
            mimetype=attachment.mime_type,
            as_attachment=True,
            download_name=attachment.original_filename
        )
        
    except Exception as e:
        return jsonify({'error': f'Error downloading file: {str(e)}'}), 500


@main_bp.route('/attachment/delete/<attachment_id>', methods=['POST'])
def delete_attachment(attachment_id):
    """Delete an attachment"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    attachment = Attachment.query.get_or_404(attachment_id)
    entry = SecretEntry.query.get_or_404(attachment.secret_entry_id)
    
    if entry.user_id != session['user_id']:
        return jsonify({'error': 'Unauthorized access'}), 403
    
    try:
        # Delete file from disk
        attachments_dir = Path(current_app.config['ATTACHMENTS_DIR'])
        storage_path = attachments_dir / attachment.storage_filename
        
        if storage_path.exists():
            storage_path.unlink()
        
        # Delete database record
        db.session.delete(attachment)
        db.session.commit()
        
        return jsonify({'success': True})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error deleting attachment: {str(e)}'}), 500


@main_bp.route('/attachment/list/<int:entry_id>')
def list_attachments(entry_id):
    """List all attachments for a secret entry"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    entry = SecretEntry.query.get_or_404(entry_id)
    
    if entry.user_id != session['user_id']:
        return jsonify({'error': 'Unauthorized access'}), 403
    
    attachments = [{
        'id': a.id,
        'filename': a.original_filename,
        'size': a.file_size,
        'mime_type': a.mime_type,
        'created_at': a.created_at.isoformat()
    } for a in entry.attachments]
    
    return jsonify({'attachments': attachments})


@main_bp.route('/attachment/preview/<attachment_id>')
def preview_attachment(attachment_id):
    """Get attachment content for preview - returns JSON for images/text, serves file directly for PDFs"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    attachment = Attachment.query.get_or_404(attachment_id)
    entry = SecretEntry.query.get_or_404(attachment.secret_entry_id)
    
    if entry.user_id != session['user_id']:
        return jsonify({'error': 'Unauthorized access'}), 403
    
    encryption_key = get_user_encryption_key()
    if not encryption_key:
        return jsonify({'error': 'Error retrieving encryption key'}), 500
    
    try:
        # Read encrypted file from disk
        attachments_dir = Path(current_app.config['ATTACHMENTS_DIR'])
        storage_path = attachments_dir / attachment.storage_filename
        
        if not storage_path.exists():
            return jsonify({'error': 'Attachment file not found'}), 404
        
        encrypted_content = storage_path.read_bytes()
        
        # Decrypt the file content
        decrypted_content = decrypt_binary(encryption_key, encrypted_content)
        
        mime_type = attachment.mime_type
        
        # For PDFs, serve the file directly (browsers need this for native PDF rendering)
        if mime_type == 'application/pdf':
            return send_file(
                BytesIO(decrypted_content),
                mimetype=mime_type,
                as_attachment=False,
                download_name=attachment.original_filename
            )
        
        # For images and text, return as base64 JSON (more efficient for inline display)
        content_base64 = base64.b64encode(decrypted_content).decode('utf-8')
        
        return jsonify({
            'success': True,
            'content': content_base64,
            'mime_type': mime_type,
            'filename': attachment.original_filename
        })
        
    except Exception as e:
        return jsonify({'error': f'Error viewing attachment: {str(e)}'}), 500
