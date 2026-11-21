"""The device page must never leak credentials, and readers must not get management actions.

These used to drive the retired Fleet Table / Router Grid page. The device page replaced it, so
the same guarantees are asserted against the payload the page actually renders from.
"""
import json
import os
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from devices.models import Device


def payload(html, script_id):
    """Parse one of the page's embedded JSON payloads."""
    marker = f'<script id="{script_id}" type="application/json">'
    if marker not in html:
        return []
    return json.loads(html.split(marker, 1)[1].split('</script>', 1)[0])


class DevicePageTests(TestCase):
    def setUp(self):
        self.actor = get_user_model().objects.create_user(username="noc-admin", is_staff=True)
        self.client.force_login(self.actor)
        with patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()}):
            self.device = Device(name="Actual router", management_ip="10.3.15.122",
                                 username="private-api-user", incoming_monitoring_interface="ether7")
            self.device.set_password("private-api-password")
            self.device.save()

    def test_the_device_rows_come_from_the_server_without_router_calls(self):
        with patch("routeros_api.RouterOsApiPool") as pool:
            response = self.client.get(reverse("devices"))
        pool.assert_not_called()
        rows = payload(response.content.decode(), "ref-devices")
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["id"], self.device.pk)
        self.assertEqual(row["name"], "Actual router")
        self.assertEqual(row["ip"], "10.3.15.122")
        self.assertEqual(row["status_label"], "NOT TESTED")

    def test_the_payload_never_carries_credentials(self):
        html = self.client.get(reverse("devices")).content.decode()
        for secret in ("private-api-user", "private-api-password", self.device.encrypted_password):
            with self.subTest(secret=secret[:12]):
                self.assertNotIn(secret, html)

    def test_a_reader_gets_no_management_actions(self):
        reader = get_user_model().objects.create_user(username="noc-reader")
        self.client.force_login(reader)
        html = self.client.get(reverse("devices")).content.decode()
        config = payload(html, "ref-config")
        self.assertFalse(config["canAdd"], "a reader cannot add devices")
        self.assertFalse(config["canDelete"], "a reader cannot delete devices")

    def test_a_staff_user_gets_management_actions(self):
        config = payload(self.client.get(reverse("devices")).content.decode(), "ref-config")
        self.assertTrue(config["canAdd"])
        self.assertTrue(config["canDelete"])
