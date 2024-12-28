import unittest
import os
from Crypto.PublicKey import RSA
from server import KeyManager


class TestKeyManager(unittest.TestCase):
    def setUp(self):
        self.private_key_file = "test_private_key.pem"
        self.public_key_file = "test_public_key.pem"

    def tearDown(self):
        # Clean up test files
        if os.path.exists(self.private_key_file):
            os.remove(self.private_key_file)
        if os.path.exists(self.public_key_file):
            os.remove(self.public_key_file)

    def test_generate_rsa_keys(self):
        private_key, public_key = KeyManager.generate_rsa_keys()
        self.assertIsInstance(private_key, RSA.RsaKey)
        self.assertIsInstance(public_key, RSA.RsaKey)

    def test_save_and_load_key(self):
        private_key, public_key = KeyManager.generate_rsa_keys()
        KeyManager.save_key_to_file(private_key, self.private_key_file)
        KeyManager.save_key_to_file(public_key, self.public_key_file)

        loaded_private_key = KeyManager.load_key_from_file(self.private_key_file)
        loaded_public_key = KeyManager.load_key_from_file(self.public_key_file)

        self.assertEqual(private_key.export_key(), loaded_private_key.export_key())
        self.assertEqual(public_key.export_key(), loaded_public_key.export_key())


if __name__ == "__main__":
    unittest.main()
