import unittest
from pwd_manager import create_app, db
from pwd_manager.models import User, PasswordEntry
from pwd_manager.utils.crypto import encrypt_password
import json

class TestRoutes(unittest.TestCase):
    def setUp(self):
        """Set up test environment"""
        self.app = create_app('testing')
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        
        # Create test user
        self.test_user = User(username='testuser')
        self.test_user.set_password('testpass123')
        db.session.add(self.test_user)
        db.session.commit()
        
    def tearDown(self):
        """Clean up test environment"""
        db.session.remove()
        db.drop_all()
        self.app_context.pop()
    
    def login(self):
        """Helper function to log in test user"""
        return self.client.post('/auth/login', data={
            'username': 'testuser',
            'password': 'testpass123'
        }, follow_redirects=True)
    
    def test_password_generation_endpoint(self):
        """Test the password generation endpoint"""
        response = self.client.get('/generate_password')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('password', data)
    
    def test_add_password(self):
        """Test adding a new password entry"""
        self.login()
        response = self.client.post('/add', data={
            'website': 'example.com',
            'username': 'user123',
            'password': 'pass123',
            'tags': 'test,website'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        # Verify password was added
        entry = PasswordEntry.query.filter_by(website='example.com').first()
        self.assertIsNotNone(entry)
        self.assertEqual(entry.username, 'user123')
    
    def test_view_password(self):
        """Test viewing a password entry"""
        self.login()
        
        # Add a password entry
        encryption_key = self.test_user.encryption_key.encode()
        encrypted_password = encrypt_password(encryption_key, 'testpass123')
        entry = PasswordEntry(
            user_id=self.test_user.id,
            website='test.com',
            username='testuser',
            encrypted_password=encrypted_password,
            tags='test'
        )
        db.session.add(entry)
        db.session.commit()
        
        # Try to view the password
        response = self.client.get(f'/view/{entry.id}')
        self.assertEqual(response.status_code, 200)
    
    def test_delete_password(self):
        """Test deleting a password entry"""
        self.login()
        
        # Add a password entry
        encryption_key = self.test_user.encryption_key.encode()
        encrypted_password = encrypt_password(encryption_key, 'testpass123')
        entry = PasswordEntry(
            user_id=self.test_user.id,
            website='delete-test.com',
            username='testuser',
            encrypted_password=encrypted_password,
            tags='test'
        )
        db.session.add(entry)
        db.session.commit()
        
        # Delete the entry
        response = self.client.post(f'/delete/{entry.id}', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        # Verify entry was deleted
        deleted_entry = PasswordEntry.query.get(entry.id)
        self.assertIsNone(deleted_entry)

if __name__ == '__main__':
    unittest.main()
