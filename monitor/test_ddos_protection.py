"""DDoS Protection section on the device Settings page: NAT list + SOS Public (storage only)."""
import os
from decimal import Decimal
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from devices.models import Device
from devices.services.credentials import encrypt_password
from monitor.models import DeviceDDoSProtection, DeviceDDoSProtectionRule


class DDoSProtectionTests(TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start(); self.addCleanup(env.stop)
        self.admin = get_user_model().objects.create_user(username="protect-admin", is_staff=True)
        self.client.force_login(self.admin)
        self.device = Device.objects.create(name="Protect router", management_ip="10.20.30.70", username="u",
                                            encrypted_password=encrypt_password("p"))
        self.page_url = reverse("device_sensors", args=[self.device.pk])
        self.save_url = reverse("device_ddos_protection", args=[self.device.pk])

    def save(self, names, values, sos="8.8.8.8"):
        return self.client.post(self.save_url, {"rule_name": names, "rule_value": values, "sos_public": sos})

    def test_section_renders_empty_on_first_load(self):
        page = self.client.get(self.page_url)
        self.assertContains(page, "DDoS Protection")
        self.assertContains(page, "SOS Public")
        self.assertContains(page, "Add Row")
        self.assertContains(page, "id=\"natRulesBody\"")
        self.assertFalse(DeviceDDoSProtection.objects.filter(device=self.device).exists())

    def test_save_persists_whole_list_and_sos_public(self):
        response = self.save(["1", "2", "4"], ["25", "30", "40"], sos="example-host")
        self.assertRedirects(response, self.page_url)
        protection = DeviceDDoSProtection.objects.get(device=self.device)
        self.assertEqual(protection.sos_public, "example-host")
        rows = list(protection.rules.values_list("name", "value"))
        self.assertEqual(rows, [("1", Decimal("25")), ("2", Decimal("30")), ("4", Decimal("40"))])

    def test_saving_again_replaces_the_list_without_duplicating(self):
        self.save(["1", "2"], ["10", "20"])
        self.save(["9"], ["99"])
        protection = DeviceDDoSProtection.objects.get(device=self.device)
        self.assertEqual(list(protection.rules.values_list("name", "value")), [("9", Decimal("99"))])
        self.assertEqual(DeviceDDoSProtectionRule.objects.count(), 1)

    def test_blank_rows_are_dropped(self):
        self.save(["1", "", ""], ["25", "", ""])
        self.assertEqual(list(DeviceDDoSProtection.objects.get(device=self.device).rules.values_list("name", "value")),
                         [("1", Decimal("25"))])

    def test_rendered_values_round_trip(self):
        self.save(["1"], ["25.5"])
        page = self.client.get(self.page_url)
        html = page.content.decode()
        self.assertIn('name="rule_name" value="1"', html)
        self.assertRegex(html, r'name="rule_value" value="25\.50?0?"')
        self.assertIn('value="8.8.8.8"', html)

    def test_non_numeric_value_rejects_save_and_keeps_input(self):
        self.save(["1"], ["25"])
        before = list(DeviceDDoSProtection.objects.get(device=self.device).rules.values_list("name", "value"))
        response = self.save(["1", "2"], ["25", "abc"])
        self.assertEqual(response.status_code, 400)
        self.assertContains(response, "Value must be a number", status_code=400)
        self.assertEqual(list(DeviceDDoSProtection.objects.get(device=self.device).rules.values_list("name", "value")), before)

    def test_reader_cannot_save(self):
        reader = get_user_model().objects.create_user(username="protect-reader")
        self.client.force_login(reader)
        self.assertEqual(self.save(["1"], ["25"]).status_code, 403)
        self.assertFalse(DeviceDDoSProtection.objects.exists())
        self.assertContains(self.client.get(self.page_url), "Administrator access is required", status_code=200)

    def test_does_not_touch_ddos_thresholds_or_detection(self):
        from monitor.models import DeviceDDoSThreshold, DetectionState
        self.save(["1"], ["25"])
        self.assertFalse(DeviceDDoSThreshold.objects.filter(device=self.device).exists())
        self.assertFalse(DetectionState.objects.exists())
