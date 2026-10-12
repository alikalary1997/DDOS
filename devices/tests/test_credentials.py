import os
import secrets
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase

from devices.services.credentials import CredentialError, decrypt_password, encrypt_password


class CredentialTests(SimpleTestCase):
    def setUp(self):
        self.key = Fernet.generate_key().decode("ascii")
        self.password = secrets.token_urlsafe(32) + "\u0627\u0644\u064a"
        self.environment = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": self.key})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_round_trip_and_authenticated_ciphertext(self):
        token = encrypt_password(self.password)
        self.assertNotIn(self.password, token)
        self.assertEqual(decrypt_password(token), self.password)
        self.assertEqual(Fernet(self.key).decrypt(token.encode()).decode(), self.password)

    def test_repeated_encryption_uses_different_ciphertext(self):
        self.assertNotEqual(encrypt_password(self.password), encrypt_password(self.password))

    def test_missing_key_fails_closed(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ImproperlyConfigured):
                encrypt_password(self.password)
            with self.assertRaises(ImproperlyConfigured):
                decrypt_password(self.password)

    def test_malformed_key_has_safe_error(self):
        invalid_key = secrets.token_urlsafe(7)
        with patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": invalid_key}):
            with self.assertRaises(ImproperlyConfigured) as caught:
                encrypt_password(self.password)
        self.assertNotIn(invalid_key, str(caught.exception))
        self.assertNotIn(self.password, str(caught.exception))

    def test_wrong_key_cannot_decrypt(self):
        token = encrypt_password(self.password)
        with patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()}):
            with self.assertRaises(CredentialError) as caught:
                decrypt_password(token)
        self.assertNotIn(token, str(caught.exception))
        self.assertNotIn(self.password, str(caught.exception))

    def test_tampered_token_cannot_decrypt(self):
        token = encrypt_password(self.password)
        replacement = "A" if token[30] != "A" else "B"
        token = token[:30] + replacement + token[31:]
        with self.assertRaises(CredentialError):
            decrypt_password(token)

    def test_plaintext_and_invalid_tokens_have_safe_errors(self):
        for value in (self.password, "", None, 123, "\u0627"):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(CredentialError) as caught:
                    decrypt_password(value)
                self.assertNotIn(self.password, str(caught.exception))

    def test_empty_and_non_string_passwords_are_rejected(self):
        for value in ("", None, 123, b"value"):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(CredentialError):
                    encrypt_password(value)
