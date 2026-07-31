import base64
import os
import unittest

from cryptography.fernet import Fernet, InvalidToken

from pwd_manager.utils.crypto import (
    decrypt_binary,
    decrypt_data,
    derive_kek,
    encrypt_binary,
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

        with self.assertRaises(InvalidToken):
            decrypt_data(wrong_key, encrypted)

    def test_binary_round_trip(self):
        """Binary attachments can be encrypted and decrypted."""
        data = b"some binary data"
        encrypted = encrypt_binary(self.test_key, data)
        self.assertEqual(decrypt_binary(self.test_key, encrypted), data)


class TestKDF(unittest.TestCase):
    def setUp(self):
        self.salt = base64.b64encode(os.urandom(16)).decode("utf-8")
        self.time_cost = 1  # Keep tests fast

    def test_derive_kek_produces_fernet_key(self):
        """derive_kek returns a value that Fernet can use."""
        kek = derive_kek("my password", self.salt, self.time_cost)
        f = Fernet(kek)
        encrypted = f.encrypt(b"secret")
        self.assertEqual(f.decrypt(encrypted), b"secret")

    def test_derive_kek_is_deterministic(self):
        """Same password, salt and cost should always produce the same KEK."""
        kek1 = derive_kek("my password", self.salt, self.time_cost)
        kek2 = derive_kek("my password", self.salt, self.time_cost)
        self.assertEqual(kek1, kek2)

    def test_derive_kek_different_salts_produce_different_keys(self):
        """Different salts must produce different KEKs."""
        salt2 = base64.b64encode(os.urandom(16)).decode("utf-8")
        kek1 = derive_kek("my password", self.salt, self.time_cost)
        kek2 = derive_kek("my password", salt2, self.time_cost)
        self.assertNotEqual(kek1, kek2)

    def test_derive_kek_different_passwords_produce_different_keys(self):
        """Different passwords must produce different KEKs."""
        kek1 = derive_kek("password one", self.salt, self.time_cost)
        kek2 = derive_kek("password two", self.salt, self.time_cost)
        self.assertNotEqual(kek1, kek2)


if __name__ == '__main__':
    unittest.main()
