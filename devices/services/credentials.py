"""Fernet credentials; the key is supplied only by the server environment."""
import os

from cryptography.fernet import Fernet, InvalidToken
from django.core.exceptions import ImproperlyConfigured
from django.views.decorators.debug import sensitive_variables


class CredentialError(Exception):
    """Safe to display: messages never contain keys, tokens or passwords."""


@sensitive_variables()
def _fernet():
    key = os.environ.get("NETSHIELD_DEVICE_ENCRYPTION_KEY")
    if not key:
        raise ImproperlyConfigured(
            "NETSHIELD_DEVICE_ENCRYPTION_KEY must be configured for device credentials."
        )
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, TypeError, UnicodeError):
        raise ImproperlyConfigured(
            "NETSHIELD_DEVICE_ENCRYPTION_KEY must be a valid Fernet key."
        ) from None


@sensitive_variables()
def encrypt_password(password):
    if not isinstance(password, str) or not password:
        raise CredentialError("A non-empty device password is required.")
    try:
        return _fernet().encrypt(password.encode("utf-8")).decode("ascii")
    except UnicodeError:
        raise CredentialError("Device password cannot be encoded.") from None


@sensitive_variables()
def decrypt_password(encrypted_password):
    cipher = _fernet()
    try:
        if not isinstance(encrypted_password, str) or not encrypted_password:
            raise CredentialError("Device credentials could not be decrypted.")
        return cipher.decrypt(encrypted_password.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, TypeError, UnicodeError):
        raise CredentialError("Device credentials could not be decrypted.") from None


@sensitive_variables()
def validate_encrypted_password(value):
    # Authentication of the token rejects plaintext, tampering and the wrong key.
    decrypt_password(value)
