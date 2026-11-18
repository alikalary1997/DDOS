"""Add Device is an inline card (reference layout) with the requested field set."""
import os
import secrets
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from devices.models import Device, Group
from devices.services.credentials import encrypt_password


class AddDeviceInlineFormTests(TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start(); self.addCleanup(env.stop)
        self.admin = get_user_model().objects.create_user(username="add-admin", is_staff=True)
        self.client.force_login(self.admin)

    def page(self):
        return self.client.get(reverse("devices")).content.decode()

    def test_the_form_is_inline_and_hidden_until_opened(self):
        html = self.page()
        self.assertIn('id="addDeviceForm"', html)
        self.assertIn("ref-device-form", html)
        self.assertIn("hidden", html.split('id="addDeviceForm"')[1][:200])
        # The button that reveals it, and the cancel control that hides it.
        self.assertIn("data-ref-add-device", html)
        self.assertIn('id="cancelDeviceDialog"', html)

    def test_no_modal_dialog_is_used_for_adding_a_device(self):
        html = self.page()
        self.assertNotIn('id="addDeviceDialog"', html, "the reference uses an inline card, not a modal")

    def test_form_offers_every_required_field(self):
        html = self.page()
        for field in ("name", "management_ip", "device_type", "api_port", "use_ssl", "username",
                      "password", "incoming_monitoring_interface", "group", "topology_parent",
                      "description"):
            with self.subTest(field=field):
                self.assertIn(f'name="{field}"', html)

    def test_device_type_is_a_required_select_with_real_choices(self):
        # It is required by the form, so it must be present or the save fails validation.
        form = self.page().split('id="addDeviceForm"')[1]
        marker = form.find('name="device_type"')
        self.assertGreaterEqual(marker, 0, "Device type must be offered")
        snippet = form[marker:marker + 400]
        for choice in ("MikroTik", "Cisco", "Other"):
            self.assertIn(choice, snippet)

    def test_adding_a_device_records_the_chosen_device_type(self):
        self.client.post(reverse("device_add"), {
            "name": "Cisco-Core", "management_ip": "10.55.1.1", "device_type": "cisco",
            "api_port": "8729", "use_ssl": "true", "username": "api", "password": "secret123",
            "incoming_monitoring_interface": "", "group": "", "topology_parent": "",
            "description": "",
        })
        device = Device.objects.get(name="Cisco-Core")
        self.assertEqual(device.device_type, "cisco")

    def test_model_field_is_not_offered(self):
        self.assertNotIn('name="model"', self.page())

    def test_a_cisco_switch_needs_only_a_name_and_ip_address(self):
        response = self.client.post(reverse("device_add"), {
            "name": "SW-Tower-1", "management_ip": "10.60.0.10", "device_type": "cisco",
            "group": "", "topology_parent": "", "description": "",
        })
        self.assertEqual(response.status_code, 302, "no credentials were required")
        device = Device.objects.get(name="SW-Tower-1")
        self.assertEqual(device.device_type, "cisco")
        self.assertEqual(device.username, "")
        self.assertEqual(device.encrypted_password, "")
        self.assertEqual(device.incoming_monitoring_interface, "")
        # Stored defaults still let the record behave normally in the fleet.
        self.assertEqual(device.api_port, 8729)
        device.full_clean()  # a credential-less Cisco switch is a valid record

    def test_a_mikrotik_device_still_requires_credentials(self):
        response = self.client.post(reverse("device_add"), {
            "name": "RB-NoCred", "management_ip": "10.60.0.11", "device_type": "mikrotik",
            "group": "", "topology_parent": "", "description": "",
        })
        # 400 is how the tree view redraws the form with its errors.
        self.assertEqual(response.status_code, 400, "the form is redisplayed with errors")
        self.assertFalse(Device.objects.filter(name="RB-NoCred").exists())

    def test_cisco_fields_are_marked_so_the_ui_can_hide_them(self):
        form = self.page().split('id="addDeviceForm"')[1]
        # API port/SSL/user/password/interface are RouterOS-only and hidden for Cisco.
        for field in ("api_port", "use_ssl", "username", "password", "incoming_monitoring_interface"):
            with self.subTest(field=field):
                marker = form.find(f'name="{field}"')
                self.assertGreaterEqual(marker, 0)
                self.assertIn("data-api-field", form[max(0, marker - 300):marker],
                              f"{field} must be grouped with the API-only fields")

    def test_group_and_topology_pickers_list_real_options(self):
        Group.objects.create(name="Ali")
        Device.objects.create(name="RB-1", management_ip="10.9.9.1", username="u",
                              encrypted_password=encrypt_password(secrets.token_urlsafe(8)))
        html = self.page()
        form = html.split('id="addDeviceForm"')[1]
        self.assertIn("Ali", form, "the group tag picker lists real groups")
        self.assertIn("RB-1 (10.9.9.1)", form, "the topology picker lists real devices")
        self.assertIn("Top level", form)

    def test_labels_match_the_reference_wording(self):
        form = self.page().split('id="addDeviceForm"')[1]
        for label in ("Device name", "IP address", "API port", "User", "Interface",
                      "Group (agent)", "Connect to topology"):
            with self.subTest(label=label):
                self.assertIn(label, form)

    def test_inline_form_still_creates_a_device(self):
        response = self.client.post(reverse("device_add"), {
            "name": "New-Router", "management_ip": "10.55.0.1", "device_type": "mikrotik",
            "api_port": "8729", "use_ssl": "true", "username": "api", "password": "secret123",
            "incoming_monitoring_interface": "ether1", "group": "", "topology_parent": "",
            "description": "added inline",
        })
        self.assertEqual(response.status_code, 302)
        device = Device.objects.get(name="New-Router")
        self.assertEqual(str(device.management_ip), "10.55.0.1")
        self.assertEqual(device.incoming_monitoring_interface, "ether1")

    def test_a_reader_never_sees_the_add_form(self):
        reader = get_user_model().objects.create_user(username="add-reader")
        self.client.force_login(reader)
        html = self.page()
        self.assertNotIn('id="addDeviceForm"', html)
        self.assertNotIn("data-ref-add-device", html)
