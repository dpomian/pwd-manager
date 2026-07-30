import os
import unittest

from conftest import BaseTestCase
from cryptography.fernet import InvalidToken

from pwd_manager import create_app, db
from pwd_manager.feature_flags import override_flag
from pwd_manager.models import User


class TestAuth(unittest.TestCase):
    def setUp(self):
        """Set up test environment"""
        self.app = create_app('testing')
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
    
    def tearDown(self):
        """Clean up test environment"""
        db.session.remove()
        db.drop_all()
        self.app_context.pop()
    
    def test_register(self):
        """Test user registration"""
        response = self.client.post('/auth/register', data={
            'username': 'testuser',
            'password': 'testpass123',
            'confirm_password': 'testpass123'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        # Check that user was created
        user = User.query.filter_by(username='testuser').first()
        self.assertIsNotNone(user)
    
    def test_login_logout(self):
        """Test login and logout functionality"""
        # Create a test user
        user = User(username='testuser', password='testpass123')
        db.session.add(user)
        db.session.commit()
        
        # Test login
        response = self.client.post('/auth/login', data={
            'username': 'testuser',
            'password': 'testpass123'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        # Test logout
        response = self.client.get('/auth/logout', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
    
    def test_invalid_login(self):
        """Test login with invalid credentials"""
        # Create a test user
        user = User(username='testuser', password='testpass123')
        db.session.add(user)
        db.session.commit()
        
        # Test wrong password
        response = self.client.post('/auth/login', data={
            'username': 'testuser',
            'password': 'wrongpass'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)

class TestKeyWrapping(BaseTestCase):
    """Phase 2: password-derived KEK wrapping of the per-user DEK."""

    def setUp(self):
        # Low Argon2 cost keeps the test suite fast.  The time_cost value is
        # still stored on the user row, so production can use higher defaults.
        os.environ["ARGON2_TIME_COST"] = "1"
        self._flag_ctx = override_flag("ENABLE_KEY_WRAPPING", True)
        self._flag_ctx.__enter__()
        super().setUp()

    def tearDown(self):
        super().tearDown()
        self._flag_ctx.__exit__(None, None, None)
        os.environ.pop("ARGON2_TIME_COST", None)

    def test_wrapped_user_has_no_plaintext_dek(self):
        """New users registered with the flag on store no plaintext DEK."""
        self.assertEqual(self.user.key_version, 1)
        self.assertIsNone(self.user.encryption_key)
        self.assertIsNotNone(self.user.wrapped_dek)
        self.assertIsNotNone(self.user.kdf_salt)
        self.assertIsNotNone(self.user.kdf_iterations)

    def test_get_dek_round_trip(self):
        """get_dek reproduces the same DEK used to wrap the key."""
        self.assertEqual(
            self.user.get_dek(self.PASSWORD).encode(),
            self.key,
        )

    def test_wrong_password_cannot_decrypt_wrapped_key(self):
        """An incorrect password cannot recover the wrapped DEK."""
        with self.assertRaises(InvalidToken):
            self.user.get_dek("wrong-password")

    def test_login_sets_session_dek(self):
        """After login the encrypted DEK token is placed in the session."""
        self.login()
        with self.client.session_transaction() as sess:
            self.assertIn("dek", sess)
            self.assertIsNotNone(sess["dek"])

    def test_logout_clears_session_dek(self):
        """Logging out removes the DEK from the session."""
        self.login()
        self.logout()
        with self.client.session_transaction() as sess:
            self.assertIsNone(sess.get("dek"))

    def test_legacy_user_migrates_on_login(self):
        """A legacy (key_version=0) user is wrapped on first login."""
        # Create a legacy user under the old scheme.
        with override_flag("ENABLE_KEY_WRAPPING", False):
            legacy = User(username="legacyuser", password="legacypass")
            db.session.add(legacy)
            db.session.commit()

        # Pre-seed a secret so we can verify the DEK hasn't changed.
        legacy_key = legacy.get_dek("legacypass").encode()

        # Now log in with key wrapping enabled.
        resp = self.client.post(
            "/auth/login",
            data={"username": "legacyuser", "password": "legacypass"},
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)

        db.session.refresh(legacy)
        self.assertEqual(legacy.key_version, 1)
        self.assertIsNotNone(legacy.wrapped_dek)
        # The DEK itself has not changed, so old ciphertext remains valid.
        self.assertEqual(legacy.get_dek("legacypass").encode(), legacy_key)


if __name__ == '__main__':
    unittest.main()
