"""Explicit one-time provisioning and non-disclosing credential verification."""
import os
import secrets

from cryptography.fernet import Fernet, InvalidToken
from django.core.management.base import BaseCommand, CommandError
from django.views.decorators.debug import sensitive_variables

from devices.models import Device

KEY_NAME = "NETSHIELD_DEVICE_ENCRYPTION_KEY"


@sensitive_variables()
def read_user_key():
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as registry:
            value, _ = winreg.QueryValueEx(registry, KEY_NAME)
            return value
    except FileNotFoundError:
        return None


@sensitive_variables()
def write_user_key(key):
    import winreg
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, "Environment", access=winreg.KEY_SET_VALUE) as registry:
        winreg.SetValueEx(registry, KEY_NAME, 0, winreg.REG_SZ, key)


class Command(BaseCommand):
    help = "Verify device encryption without revealing secrets; optionally provision a persistent Windows user key."

    def add_arguments(self, parser):
        parser.add_argument("--persist-windows-user", action="store_true", help="Explicit one-time setup; reuse any existing key.")

    @sensitive_variables()
    def handle(self, *args, **options):
        try:
            self.configure(options["persist_windows_user"])
        except CommandError:
            raise
        except Exception:
            raise CommandError("Device encryption setup failed. Check environment access and database availability.") from None

    @sensitive_variables()
    def configure(self, persist):
        process_key = os.environ.get(KEY_NAME)
        user_key = None
        if persist:
            if os.name != "nt":
                raise CommandError("Persistent user setup is supported on Windows only; use your server's secret manager.")
            user_key = read_user_key()
            if process_key and user_key and process_key != user_key:
                raise CommandError("Process and persistent device keys differ. Resolve configuration without replacing existing keys.")
        key = process_key or user_key
        created = False
        if not key:
            if not persist:
                raise CommandError("Device encryption key is missing. Run configure_device_encryption --persist-windows-user for one-time Windows setup.")
            if Device.objects.exists():
                raise CommandError("Existing device credentials require the original key. Restore it; no replacement key was generated.")
            key = Fernet.generate_key().decode("ascii")
            created = True
        try:
            cipher = Fernet(key.encode("ascii"))
            probe = secrets.token_bytes(32)
            if cipher.decrypt(cipher.encrypt(probe)) != probe:
                raise ValueError
        except (ValueError, TypeError, UnicodeError, InvalidToken):
            raise CommandError("Device encryption key is invalid. Supply a valid Fernet key without displaying it.") from None
        try:
            for token in Device.objects.values_list("encrypted_password", flat=True).iterator():
                cipher.decrypt(token.encode("ascii"))
        except (ValueError, TypeError, UnicodeError, InvalidToken):
            raise CommandError("The configured key cannot decrypt existing device credentials. Restore the original key.") from None
        if persist and not user_key:
            write_user_key(key)
            if read_user_key() != key:
                raise CommandError("Persistent device encryption configuration could not be verified.")
        os.environ[KEY_NAME] = key
        if persist:
            self.stdout.write("Created persistent Windows user encryption key." if created else "Reused existing persistent Windows user encryption key.")
        self.stdout.write("Device encryption verified. No key or credential values were displayed.")
