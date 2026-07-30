import unittest

from conftest import BaseTestCase
from cryptography.fernet import InvalidToken

from pwd_manager import create_app, db
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

class TestWrappedDek(BaseTestCase):
    """Phase 3: all accounts store a wrapped DEK and the plaintext column is gone."""

    def test_user_has_wrapped_dek(self):
        """New users always store a wrapped DEK, never a plaintext one."""
        self.assertEqual(self.user.key_version, 1)
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


if __name__ == '__main__':
    unittest.main()
