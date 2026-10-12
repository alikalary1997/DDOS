import os
import secrets
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.db import DatabaseError, IntegrityError, connection
from django.test import Client, TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse

from devices.models import Device


class AddDeviceInventoryTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        users = get_user_model()
        cls.admin = users.objects.create_user(username="administrator", password=secrets.token_urlsafe(32), is_staff=True)
        cls.reader = users.objects.create_user(username="reader", password=secrets.token_urlsafe(32))
        cls.superuser = users.objects.create_user(username="supervisor", password=secrets.token_urlsafe(32), is_superuser=True)
        cls.inactive = users.objects.create_user(username="inactive", password=secrets.token_urlsafe(32), is_staff=True, is_active=False)

    def setUp(self):
        self.key = Fernet.generate_key().decode()
        self.password = secrets.token_urlsafe(32)
        self.api_username = secrets.token_urlsafe(16)
        environment = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": self.key})
        environment.start()
        self.addCleanup(environment.stop)
        self.payload = {
            "name": "Branch Router", "management_ip": "192.0.2.20", "device_type": "mikrotik",
            "api_port": "8729", "use_ssl": "true", "username": self.api_username,
            "password": self.password, "description": "Branch network",
        }

    def add(self, payload=None, **kwargs):
        return self.client.post(reverse("device_add"), self.payload if payload is None else payload, **kwargs)

    def assert_no_credentials(self, response, token=None):
        body = response.content.decode()
        for value in (self.key, self.password, self.api_username, token):
            if value:
                self.assertTrue(value not in body, "A credential value was exposed.")

    def test_anonymous_inventory_redirects_to_device_login(self):
        response = self.client.get(reverse("devices"))
        self.assertRedirects(response, reverse("device_login") + "?next=/devices/")

    def test_anonymous_add_does_not_save(self):
        response = self.add()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(Device.objects.count(), 0)
        self.assertTrue(self.password not in response.url)

    def test_authenticated_reader_can_view_but_has_no_add_controls(self):
        self.client.force_login(self.reader)
        response = self.client.get(reverse("devices"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'id="addDeviceForm"')
        self.assertNotContains(response, 'data-open-device')

    def test_reader_cannot_add_even_by_direct_post(self):
        self.client.force_login(self.reader)
        response = self.add()
        self.assertEqual(response.status_code, 403)
        self.assertEqual(Device.objects.count(), 0)
        self.assert_no_credentials(response)

    def test_inactive_administrator_cannot_save(self):
        self.client.force_login(self.inactive)
        response = self.add()
        self.assertIn(response.status_code, (302, 403))
        self.assertEqual(Device.objects.count(), 0)

    def test_administrator_save_commits_ciphertext_and_shows_success(self):
        self.client.force_login(self.admin)
        response = self.add(follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Device saved successfully.")
        self.assertContains(response, "Branch Router")
        device = Device.objects.get()
        self.assertTrue(device.encrypted_password != self.password)
        self.assertTrue(device.get_password() == self.password)
        self.assertTrue(device.use_ssl)
        self.assert_no_credentials(response, device.encrypted_password)

    def test_superuser_can_add_without_staff_flag(self):
        self.client.force_login(self.superuser)
        self.assertEqual(self.add().status_code, 302)
        self.assertEqual(Device.objects.count(), 1)

    def test_plain_api_configuration_is_saved(self):
        self.client.force_login(self.admin)
        self.assertEqual(self.add({**self.payload, "use_ssl": "false", "api_port": "8728"}).status_code, 302)
        device = Device.objects.get()
        self.assertFalse(device.use_ssl)
        self.assertEqual(device.api_port, 8728)

    def test_required_fields_are_validated_without_saving(self):
        self.client.force_login(self.admin)
        for field in ("name", "management_ip", "device_type", "api_port", "use_ssl", "username", "password"):
            with self.subTest(field=field):
                response = self.add({**self.payload, field: ""})
                self.assertEqual(response.status_code, 400)
                self.assertIn(field, response.context["add_device_form"].errors)
                self.assertNotContains(response, "Device saved successfully.", status_code=400)
                self.assertTrue(self.password not in response.content.decode())
                self.assertContains(response, 'data-has-errors="true"', status_code=400)
        self.assertEqual(Device.objects.count(), 0)

    def test_invalid_ip_port_type_and_transport_are_rejected(self):
        self.client.force_login(self.admin)
        for field, value in (("management_ip", "router.example"), ("management_ip", "300.1.1.1"),
                             ("management_ip", "fe80::1%eth0"), ("api_port", "0"),
                             ("api_port", "65536"), ("api_port", "abc"),
                             ("device_type", "invalid"), ("use_ssl", "invalid")):
            with self.subTest(field=field, value=value):
                self.assertEqual(self.add({**self.payload, field: value}).status_code, 400)
        self.assertEqual(Device.objects.count(), 0)

    def test_duplicate_endpoint_rejected_and_different_port_allowed(self):
        self.client.force_login(self.admin)
        self.assertEqual(self.add().status_code, 302)
        response = self.add({**self.payload, "name": "Duplicate"})
        self.assertContains(response, "this management IP and API port already exists", status_code=400)
        self.assertNotContains(response, "Device saved successfully.", status_code=400)
        self.assertEqual(Device.objects.count(), 1)
        self.assertEqual(self.add({**self.payload, "api_port": "8728", "use_ssl": "false"}).status_code, 302)
        self.assertEqual(Device.objects.count(), 2)

    def test_ipv6_and_mapped_ipv4_duplicates_are_normalized(self):
        self.client.force_login(self.admin)
        self.assertEqual(self.add().status_code, 302)
        self.assertEqual(self.add({**self.payload, "management_ip": "::ffff:192.0.2.20"}).status_code, 400)
        self.assertEqual(self.add({**self.payload, "management_ip": "2001:0db8:0:0:0:0:0:1"}).status_code, 302)
        self.assertEqual(self.add({**self.payload, "management_ip": "2001:db8::1"}).status_code, 400)

    def test_csrf_rejects_missing_and_incorrect_tokens(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.admin)
        self.assertEqual(client.post(reverse("device_add"), self.payload).status_code, 403)
        client.get(reverse("devices"))
        self.assertEqual(client.post(reverse("device_add"), self.payload, HTTP_X_CSRFTOKEN=secrets.token_hex(16)).status_code, 403)
        self.assertEqual(Device.objects.count(), 0)

    def test_csrf_accepts_real_form_token(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.admin)
        client.get(reverse("devices"))
        token = client.cookies["csrftoken"].value
        response = client.post(reverse("device_add"), {**self.payload, "csrfmiddlewaretoken": token})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(Device.objects.count(), 1)

    def test_add_requires_post_and_inventory_is_read_only(self):
        self.client.force_login(self.admin)
        for method in ("get", "put", "delete", "patch"):
            with self.subTest(method=method):
                self.assertEqual(getattr(self.client, method)(reverse("device_add")).status_code, 405)
        self.assertEqual(self.client.post(reverse("devices"), self.payload).status_code, 405)
        self.assertEqual(Device.objects.count(), 0)

    def test_missing_key_prevents_save_with_safe_error(self):
        self.client.force_login(self.admin)
        with patch.dict(os.environ, {}, clear=True):
            response = self.add()
        self.assertContains(response, "credential encryption is unavailable", status_code=400)
        self.assertTrue(self.password not in response.content.decode())
        self.assertEqual(Device.objects.count(), 0)

    def test_invalid_key_prevents_save_without_echoing_key(self):
        self.client.force_login(self.admin)
        invalid_key = secrets.token_urlsafe(7)
        with patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": invalid_key}):
            response = self.add()
        self.assertEqual(response.status_code, 400)
        self.assertTrue(invalid_key not in response.content.decode())
        self.assertEqual(Device.objects.count(), 0)

    def test_save_failure_never_issues_success_or_exposes_exception(self):
        self.client.force_login(self.admin)
        with patch("devices.forms.AddDeviceForm.save", side_effect=DatabaseError(self.password)):
            response = self.add()
        self.assertContains(response, "Please try again", status_code=503)
        self.assertNotContains(response, "Device saved successfully.", status_code=503)
        self.assertTrue(self.password not in response.content.decode())
        self.assertEqual(Device.objects.count(), 0)

    def test_duplicate_race_is_handled_safely(self):
        self.client.force_login(self.admin)
        with patch("devices.forms.AddDeviceForm.save", side_effect=IntegrityError(self.password)):
            response = self.add()
        self.assertEqual(response.status_code, 400)
        self.assertTrue(self.password not in response.content.decode())
        self.assertEqual(Device.objects.count(), 0)

    def test_inventory_projects_only_safe_fields_and_uses_real_rows(self):
        self.client.force_login(self.admin)
        self.add()
        device = Device.objects.get()
        with CaptureQueriesContext(connection) as queries:
            response = self.client.get(reverse("devices"))
        self.assertEqual(response.context["total_devices"], 1)
        row = response.context["device_rows"][0]
        self.assertEqual(row["name"], device.name)
        self.assertEqual(row["status"], "Not Tested")
        self.assertFalse({"username", "encrypted_password", "password"} & set(row))
        inventory_sql = [q["sql"] for q in queries if 'FROM "devices_device"' in q["sql"]]
        self.assertTrue(inventory_sql)
        self.assertTrue(all("encrypted_password" not in sql and "username" not in sql for sql in inventory_sql))
        self.assert_no_credentials(response, device.encrypted_password)
        self.assertContains(response, "Not available")
        self.assertContains(response, reverse("device_edit", args=[device.pk]))
        self.assertContains(response, reverse("device_delete", args=[device.pk]))

    def test_disabled_device_status_reflects_configuration(self):
        self.client.force_login(self.admin)
        self.add()
        Device.objects.update(enabled=False)
        response = self.client.get(reverse("devices"))
        self.assertEqual(response.context["device_rows"][0]["status_filter"], "disabled")

    def test_inventory_available_without_encryption_key(self):
        self.client.force_login(self.admin)
        self.add()
        with patch.dict(os.environ, {}, clear=True):
            response = self.client.get(reverse("devices"))
        self.assertEqual(response.status_code, 200)
        self.assert_no_credentials(response, Device.objects.get().encrypted_password)

    def test_inventory_escapes_router_names_and_models(self):
        self.client.force_login(self.admin)
        self.add({**self.payload, "name": "<script>alert(1)</script>"})
        response = self.client.get(reverse("devices"))
        self.assertContains(response, "&lt;script&gt;")
        self.assertNotContains(response, "<script>alert(1)</script>")

    def test_add_and_inventory_make_no_router_connections(self):
        self.client.force_login(self.admin)
        with patch("routeros_api.RouterOsApiPool") as pool:
            self.assertEqual(self.add().status_code, 302)
            self.assertEqual(self.client.get(reverse("devices")).status_code, 200)
        pool.assert_not_called()

    def test_unexpected_submitted_fields_cannot_override_model_state(self):
        self.client.force_login(self.admin)
        response = self.add({**self.payload, "enabled": "false", "model": "Invented model", "last_connection_error": self.password, "encrypted_password": self.password})
        self.assertEqual(response.status_code, 302)
        device = Device.objects.get()
        self.assertTrue(device.enabled)
        self.assertEqual(device.model, "")
        self.assertEqual(device.last_connection_error, "")
        self.assertTrue(device.get_password() == self.password)

    def test_login_accepts_regular_user_and_returns_to_inventory(self):
        password = secrets.token_urlsafe(32)
        self.reader.set_password(password)
        self.reader.save()
        response = self.client.post(reverse("device_login"), {"username": self.reader.username, "password": password}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.request["PATH_INFO"], reverse("devices"))
        self.assertTrue(password not in response.content.decode())

    def test_inventory_does_not_allow_browser_caching(self):
        self.client.force_login(self.admin)
        response = self.client.get(reverse("devices"))
        self.assertIn("no-store", response.headers["Cache-Control"])
