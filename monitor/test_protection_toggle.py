"""Per-device DDoS Protection Enable/Disable button on the Devices page."""
import os
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from devices.models import Device
from devices.services.credentials import encrypt_password
from monitor.models import DeviceDDoSProtection


class ProtectionToggleTests(TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start(); self.addCleanup(env.stop)
        self.admin = get_user_model().objects.create_user(username="toggle-admin", is_staff=True)
        self.client.force_login(self.admin)
        self.device = Device.objects.create(name="Toggle router", management_ip="10.20.30.80", username="u",
                                            encrypted_password=encrypt_password("p"))
        self.url = reverse("device_ddos_protection_toggle", args=[self.device.pk])
        self.devices_url = reverse("devices")

    def state(self):
        return DeviceDDoSProtection.objects.get(device=self.device).enabled

    def test_button_renders_disabled_red_by_default(self):
        page = self.client.get(self.devices_url).content.decode()
        self.assertIn('data-state="disabled"', page)
        self.assertIn("Disabled", page)

    def test_toggle_on_then_off(self):
        self.assertRedirects(self.client.post(self.url), self.devices_url)
        self.assertTrue(self.state())
        self.assertRedirects(self.client.post(self.url), self.devices_url)
        self.assertFalse(self.state())

    def test_enabled_button_is_green_and_shows_enabled(self):
        self.client.post(self.url)
        html = self.client.get(self.devices_url).content.decode()
        self.assertIn('data-state="enabled"', html)
        self.assertIn("Enabled", html)
        # The submit posts the opposite target value so one click flips it.
        self.assertIn('name="enabled" value="0"', html)

    def test_explicit_value_is_idempotent(self):
        self.client.post(self.url, {"enabled": "1"})
        self.client.post(self.url, {"enabled": "1"})
        self.assertTrue(self.state())
        self.client.post(self.url, {"enabled": "0"})
        self.assertFalse(self.state())

    def test_reader_cannot_toggle(self):
        self.client.force_login(get_user_model().objects.create_user(username="toggle-reader"))
        self.assertEqual(self.client.post(self.url).status_code, 403)
        self.assertFalse(DeviceDDoSProtection.objects.exists())

    def test_get_is_rejected(self):
        self.assertEqual(self.client.get(self.url).status_code, 405)

    def test_toggle_does_not_touch_settings_or_detection(self):
        from monitor.models import DeviceDDoSThreshold, DetectionState
        self.client.post(self.url, {"sos_public": "ignored", "rule_name": ["x"]})
        protection = DeviceDDoSProtection.objects.get(device=self.device)
        self.assertEqual(protection.sos_public, "")  # toggle never writes other fields
        self.assertEqual(protection.rules.count(), 0)
        self.assertFalse(DeviceDDoSThreshold.objects.filter(device=self.device).exists())
        self.assertFalse(DetectionState.objects.exists())
