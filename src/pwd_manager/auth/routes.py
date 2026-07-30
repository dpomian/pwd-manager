import base64
import os

from cryptography.fernet import Fernet, InvalidToken
from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from pwd_manager import db
from pwd_manager.feature_flags import is_enabled
from pwd_manager.models import User
from pwd_manager.utils.auth import encrypt_session_dek
from pwd_manager.utils.crypto import derive_kek

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not password or not confirm_password:
            flash('All fields are required', 'error')
            return redirect(url_for('auth.register'))

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('auth.register'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            # Use the same success message as a successful registration to
            # avoid revealing which usernames are already taken (L1).
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('auth.login'))

        # Create new user with password
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if not user or not user.check_password(password):
            flash('Invalid username or password', 'error')
            return render_template('login.html')

        if is_enabled('ENABLE_KEY_WRAPPING'):
            if user.key_version == 0:
                # Lazy migration: wrap the existing plaintext DEK with a KEK
                # derived from the user's master password.
                dek = base64.b64decode(user.encryption_key)
                salt = os.urandom(16)
                salt_b64 = base64.b64encode(salt).decode('utf-8')
                time_cost = int(os.getenv('ARGON2_TIME_COST', '3'))
                kek = derive_kek(password, salt_b64, time_cost)
                wrapped = Fernet(kek).encrypt(dek)
                user.wrapped_dek = wrapped.decode('utf-8')
                user.kdf_salt = salt_b64
                user.kdf_iterations = time_cost
                user.key_version = 1
                # Verify the wrap round-trips before committing (C1/C2 safety).
                try:
                    if Fernet(kek).decrypt(wrapped) != dek:
                        db.session.rollback()
                        flash('Invalid username or password', 'error')
                        return render_template('login.html')
                except (ValueError, InvalidToken):
                    db.session.rollback()
                    flash('Invalid username or password', 'error')
                    return render_template('login.html')

            try:
                dek_b64 = user.get_dek(password)
            except (ValueError, InvalidToken):
                flash('Invalid username or password', 'error')
                return render_template('login.html')
        else:
            dek_b64 = user.encryption_key

        if not dek_b64:
            flash('Invalid username or password', 'error')
            return render_template('login.html')

        # Regenerate the session to prevent session fixation (H4):
        # clear the existing session data before assigning the user id
        # so any pre-login session state (e.g. a cookie planted by an
        # attacker) is discarded.
        session.clear()
        session['user_id'] = user.id
        session['dek'] = encrypt_session_dek(dek_b64)
        db.session.commit()
        flash('Login successful!', 'success')
        return redirect(url_for('main.index'))

    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('auth.login'))
