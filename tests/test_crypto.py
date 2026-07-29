import unittest

from cryptography.fernet import Fernet

from pwd_manager.utils.crypto import (
    decrypt_data,
    derive_key,
    encrypt_data,
    generate_key,
)


class TestCrypto(unittest.TestCase):
    def setUp(self):
        """Set up test cases"""
        self.test_key = generate_key()  # Generate a proper Fernet key
        self.test_passwords = [
            'simple password',
            'Complex-Password-123',
            '!@#$%^&*()',
            'a' * 100,  # long password
            ''  # empty password
        ]
    
    def test_encryption_decryption(self):
        """Test that encryption followed by decryption returns the original password"""
        for password in self.test_passwords:
            encrypted = encrypt_data(self.test_key, password)
            decrypted = decrypt_data(self.test_key, encrypted)
            self.assertEqual(password, decrypted)
    
    def test_different_passwords_different_encryption(self):
        """Test that different passwords produce different encrypted results"""
        encrypted_passwords = set()
        for password in self.test_passwords:
            encrypted = encrypt_data(self.test_key, password)
            encrypted_passwords.add(encrypted)
        
        # Each password should produce a unique encryption
        self.assertEqual(len(encrypted_passwords), len(self.test_passwords))
    
    def test_wrong_key_fails(self):
        """Test that decryption with wrong key fails"""
        wrong_key = generate_key()  # Generate another valid key
        password = 'test password'
        encrypted = encrypt_data(self.test_key, password)
        
        # Attempting to decrypt with wrong key should raise InvalidToken
        from cryptography.fernet import InvalidToken

        with self.assertRaises(InvalidToken):
            decrypt_data(wrong_key, encrypted)
    
    def test_derive_key(self):
        """Test that derived keys are valid Fernet keys"""
        test_passwords = [
            'short',
            'exactly32characters1234567890123',
            'longer_than_32_characters_should_be_truncated'
        ]
        
        for password in test_passwords:
            key = derive_key(password)
            # Test that we can create a Fernet instance with the key
            f = Fernet(key)
            # Test that we can encrypt and decrypt with the key
            message = b'test message'
            encrypted = f.encrypt(message)
            decrypted = f.decrypt(encrypted)
            self.assertEqual(message, decrypted)

if __name__ == '__main__':
    unittest.main()
