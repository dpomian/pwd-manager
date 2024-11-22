import unittest
from pwd_manager.utils.password_generator import generate_password

class TestPasswordGenerator(unittest.TestCase):
    def test_password_format(self):
        """Test if generated password follows the required format"""
        # Generate a password
        password = generate_password()
        
        # Split password into groups
        groups = password.split('-')
        
        # Test number of groups (should be between 3 and 5)
        self.assertTrue(3 <= len(groups) <= 5)
        
        # Test each group's length (should be between 4 and 6)
        for group in groups:
            self.assertTrue(4 <= len(group) <= 6)
            
        # Test character set (should only contain letters and numbers)
        allowed_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
        for char in password.replace('-', ''):
            self.assertIn(char, allowed_chars)
    
    def test_multiple_passwords_are_different(self):
        """Test that multiple generated passwords are different"""
        # Generate multiple passwords
        passwords = set()
        for _ in range(10):
            password = generate_password()
            passwords.add(password)
        
        # All passwords should be unique
        self.assertEqual(len(passwords), 10)

if __name__ == '__main__':
    unittest.main()
