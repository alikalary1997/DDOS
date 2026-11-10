"""DDoS Protection section on the device Settings page: NAT list (names) + SOS Public (storage only)."""
import os
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

    def save(self, names, sos="8.8.8.8"):
        return self.client.post(self.save_url, {"rule_name": names, "sos_public": sos})

    def test_section_renders_empty_on_first_load(self):
        page = self.client.get(self.page_url)
        self.assertContains(page, "DDoS Protection")
        self.assertContains(page, "SOS Public")
        self.assertContains(page, "Add Row")
        self.assertContains(page, 'id="natRulesBody"')
        self.assertFalse(DeviceDDoSProtection.objects.filter(device=self.device).exists())

    def test_nat_list_is_name_only(self):
        page = self.client.get(self.page_url)
        self.assertContains(page, "<th scope=\"col\">Name</th>")
        self.assertNotContains(page, 'name="rule_value"')
        self.assertNotContains(page, ">Value<")

    def test_save_persists_names_and_sos_public(self):
        response = self.save(["1", "2", "4"], sos="example-host")
        self.assertRedirects(response, self.page_url)
        protection = DeviceDDoSProtection.objects.get(device=self.device)
        self.assertEqual(protection.sos_public, "example-host")
        self.assertEqual(list(protection.rules.values_list("name", flat=True)), ["1", "2", "4"])
        self.assertTrue(all(rule.value is None for rule in protection.rules.all()))

    def test_saving_again_replaces_the_list_without_duplicating(self):
        self.save(["1", "2"])
        self.save(["9"])
        self.assertEqual(list(DeviceDDoSProtection.objects.get(device=self.device).rules.values_list("name", flat=True)), ["9"])
        self.assertEqual(DeviceDDoSProtectionRule.objects.count(), 1)

    def test_blank_rows_are_dropped(self):
        self.save(["1", "", "  ", "7"])
        self.assertEqual(list(DeviceDDoSProtection.objects.get(device=self.device).rules.values_list("name", flat=True)),
                         ["1", "7"])

    def test_positions_follow_order(self):
        self.save(["a", "b", "c"])
        rules = DeviceDDoSProtection.objects.get(device=self.device).rules.order_by("position")
        self.assertEqual([(r.position, r.name) for r in rules], [(0, "a"), (1, "b"), (2, "c")])

    def test_rendered_values_round_trip(self):
        self.save(["uplink"], sos="8.8.8.8")
        page = self.client.get(self.page_url)
        self.assertContains(page, 'name="rule_name" value="uplink"')
        self.assertContains(page, 'value="8.8.8.8"')

    def test_reader_cannot_save(self):
        reader = get_user_model().objects.create_user(username="protect-reader")
        self.client.force_login(reader)
        self.assertEqual(self.save(["1"]).status_code, 403)
        self.assertFalse(DeviceDDoSProtection.objects.exists())
        self.assertContains(self.client.get(self.page_url), "Administrator access is required", status_code=200)

    def test_does_not_touch_ddos_thresholds_or_detection(self):
        from monitor.models import DeviceDDoSThreshold, DetectionState
        self.save(["1"])
        self.assertFalse(DeviceDDoSThreshold.objects.filter(device=self.device).exists())
        self.assertFalse(DetectionState.objects.exists())
