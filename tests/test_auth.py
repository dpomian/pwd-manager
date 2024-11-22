import unittest
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

if __name__ == '__main__':
    unittest.main()
