import os
import secrets
from io import StringIO
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from devices.models import Device

MODULE = "devices.management.commands.configure_device_encryption"
KEY_NAME = "NETSHIELD_DEVICE_ENCRYPTION_KEY"


class EncryptionSetupTests(TestCase):
    def setUp(self):
        self.key = Fernet.generate_key().decode()
        environment = patch.dict(os.environ, {KEY_NAME: self.key})
        environment.start()
        self.addCleanup(environment.stop)

    def verify(self, persist=False):
        output = StringIO()
        call_command("configure_device_encryption", persist_windows_user=persist, stdout=output)
        text = output.getvalue()
        self.assertTrue(self.key not in text, "Encryption key was exposed.")
        return text

    def saved_device(self):
        device = Device(name="Existing", management_ip="192.0.2.40", username="api-user")
        device.set_password(secrets.token_urlsafe(32))
        device.save()
        return device

    def test_verification_does_not_reveal_key_or_generate_new_one(self):
        self.saved_device()
        with patch(MODULE + ".Fernet.generate_key") as generate:
            self.assertIn("Device encryption verified", self.verify())
        generate.assert_not_called()

    def test_missing_key_without_explicit_setup_fails_closed(self):
        with patch.dict(os.environ, {}, clear=True), patch(MODULE + ".Fernet.generate_key") as generate:
            with self.assertRaises(CommandError):
                self.verify()
        generate.assert_not_called()

    def test_existing_persistent_key_is_reused_without_writing(self):
        with patch(MODULE + ".read_user_key", return_value=self.key), patch(MODULE + ".write_user_key") as write:
            with patch.dict(os.environ, {}, clear=True):
                self.assertIn("Reused existing", self.verify(persist=True))
            with patch.dict(os.environ, {}, clear=True):
                self.assertIn("Reused existing", self.verify(persist=True))
        write.assert_not_called()

    def test_one_time_generation_persists_and_is_reused_on_fresh_process_environment(self):
        store = {}
        with patch(MODULE + ".read_user_key", side_effect=lambda: store.get("key")), patch(MODULE + ".write_user_key", side_effect=lambda key: store.update(key=key)) as write:
            with patch.dict(os.environ, {}, clear=True):
                self.assertIn("Created persistent", self.verify(persist=True))
                first = os.environ[KEY_NAME]
            with patch.dict(os.environ, {}, clear=True):
                self.assertIn("Reused existing", self.verify(persist=True))
                self.assertTrue(os.environ[KEY_NAME] == first)
        self.assertEqual(write.call_count, 1)

    def test_existing_credentials_prevent_missing_key_regeneration(self):
        self.saved_device()
        with patch.dict(os.environ, {}, clear=True), patch(MODULE + ".read_user_key", return_value=None), patch(MODULE + ".Fernet.generate_key") as generate:
            with self.assertRaises(CommandError):
                self.verify(persist=True)
        generate.assert_not_called()

    def test_invalid_key_is_not_persisted_or_displayed(self):
        malformed = secrets.token_urlsafe(7)
        with patch.dict(os.environ, {KEY_NAME: malformed}), patch(MODULE + ".read_user_key", return_value=None), patch(MODULE + ".write_user_key") as write:
            with self.assertRaises(CommandError) as caught:
                self.verify(persist=True)
        self.assertTrue(malformed not in str(caught.exception))
        write.assert_not_called()

    def test_wrong_key_cannot_be_used_for_existing_credentials(self):
        self.saved_device()
        with patch.dict(os.environ, {KEY_NAME: Fernet.generate_key().decode()}):
            with self.assertRaises(CommandError):
                self.verify()

    def test_conflicting_process_and_persistent_keys_are_not_overwritten(self):
        with patch(MODULE + ".read_user_key", return_value=Fernet.generate_key().decode()), patch(MODULE + ".write_user_key") as write:
            with self.assertRaises(CommandError) as caught:
                self.verify(persist=True)
        self.assertTrue(self.key not in str(caught.exception))
        write.assert_not_called()

    def test_existing_process_key_is_persisted_without_replacing_it(self):
        with patch(MODULE + ".read_user_key", side_effect=[None, self.key]), patch(MODULE + ".write_user_key") as write:
            self.assertIn("Reused existing", self.verify(persist=True))
        self.assertEqual(write.call_count, 1)
        self.assertTrue(write.call_args.args[0] == self.key)
