"""A Cisco switch gets the SNMP sensor page, but none of the RouterOS-only device settings.

Cisco devices have no RouterOS API, so the Devices page's Settings link must still open a
usable sensor page for them. The DDoS Settings and DDoS Protection panels are RouterOS-only
and must not appear.
"""
import os
import secrets
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from devices.models import Device
from devices.services.credentials import encrypt_password
from sensors.models import Sensor


class CiscoSensorPageTests(TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start(); self.addCleanup(env.stop)
        self.admin = get_user_model().objects.create_user(username="cisco-admin", is_staff=True)
        self.client.force_login(self.admin)
        # A Cisco switch is stored with no credentials at all.
        self.cisco = Device.objects.create(name="SW-Site-1", management_ip="10.10.10.15",
                                           device_type=Device.DeviceType.CISCO)
        self.mikrotik = Device.objects.create(
            name="RB-1", management_ip="10.20.30.40", username="api-user",
            encrypted_password=encrypt_password(secrets.token_urlsafe(16)))

    def page(self, device, query=""):
        return self.client.get(reverse("device_sensors", args=[device.pk]) + query)

    def test_the_settings_link_target_opens_for_a_cisco_switch(self):
        # This is the URL the Devices table's Settings button points at.
        response = self.page(self.cisco, "?view=settings")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "SW-Site-1")

    def test_a_cisco_switch_has_no_device_settings_view(self):
        response = self.page(self.cisco, "?view=settings")
        self.assertNotContains(response, "Device Settings")
        self.assertNotContains(response, "DDoS Settings")
        self.assertNotContains(response, "DDoS Protection")
        # Asking for the settings view still lands on the sensor view.
        self.assertEqual(response.context["active_view"], "sensors")
        self.assertFalse(response.context["has_device_settings"])

    def test_a_cisco_switch_still_offers_the_add_sensor_flow(self):
        html = self.page(self.cisco).content.decode()
        self.assertIn("data-open-sensor", html)
        self.assertIn("No sensors", html)

    def test_a_mikrotik_device_keeps_both_views(self):
        response = self.page(self.mikrotik)
        self.assertContains(response, "Device Settings")
        self.assertTrue(response.context["has_device_settings"])
        settings = self.page(self.mikrotik, "?view=settings")
        self.assertContains(settings, "DDoS Settings")
        self.assertEqual(settings.context["active_view"], "settings")

    def test_a_cisco_switch_lists_its_own_sensors(self):
        Sensor.objects.create(device=self.cisco, kind="cpu", name="CPU", enabled=True, interval=60)
        html = self.page(self.cisco).content.decode()
        self.assertIn("CPU", html)

    def test_other_device_types_still_have_no_sensor_page(self):
        other = Device.objects.create(name="Random box", management_ip="10.10.10.99",
                                      device_type=Device.DeviceType.OTHER)
        self.assertEqual(self.page(other).status_code, 404)
