import unittest
from Crypto.Hash import SHA256
from server import AuthenticationModule


class TestAuthenticationModule(unittest.TestCase):
    def setUp(self):
        self.auth_module = AuthenticationModule()

    def test_add_user(self):
        self.auth_module.add_user("test_user", "password123")
        self.assertIn("test_user", self.auth_module.user_credentials)

    def test_duplicate_user(self):
        self.auth_module.add_user("test_user", "password123")
        with self.assertRaises(ValueError):
            self.auth_module.add_user("test_user", "password456")

    def test_authenticate_success(self):
        self.auth_module.add_user("test_user", "password123")
        self.assertTrue(self.auth_module.authenticate("test_user", "password123"))

    def test_authenticate_failure(self):
        self.auth_module.add_user("test_user", "password123")
        self.assertFalse(self.auth_module.authenticate("test_user", "wrongpassword"))


if __name__ == "__main__":
    unittest.main()
