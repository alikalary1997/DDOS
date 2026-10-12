import os
import secrets
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import DatabaseError, IntegrityError, connection, transaction
from django.db.models.deletion import ProtectedError
from django.test import Client, TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse

from devices.models import Device
from public_ips.models import PublicIP


class PublicIPTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        users = get_user_model()
        cls.admin = users.objects.create_user(username="ip-admin", is_staff=True)
        cls.reader = users.objects.create_user(username="ip-reader")
        cls.superuser = users.objects.create_user(username="ip-superuser", is_superuser=True)
        cls.inactive = users.objects.create_user(username="ip-inactive", is_staff=True, is_active=False)

    def setUp(self):
        self.key = Fernet.generate_key().decode()
        self.password = secrets.token_urlsafe(32)
        self.username = secrets.token_urlsafe(16)
        environment = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": self.key})
        environment.start()
        self.addCleanup(environment.stop)
        self.device = Device(name="Saved MikroTik", management_ip="172.26.241.16", username=self.username, incoming_monitoring_interface="customer-uplink", raw_provisioning_enabled=False)
        self.device.set_password(self.password)
        self.device.save()
        self.payload = {"address": "8.8.8.8", "device": str(self.device.pk), "description": "Customer address", "incoming_monitoring_interface": "customer-uplink"}
        self.client.force_login(self.admin)

    def add(self, payload=None, **kwargs):
        return self.client.post(reverse("public_ip_add"), self.payload if payload is None else payload, **kwargs)

    def assert_safe(self, response):
        self.assertTrue(all(secret not in response.content.decode() for secret in (
            self.key, self.password, self.username, self.device.encrypted_password)), "A credential was exposed.")

    def test_add_commits_relationship_and_success(self):
        response = self.add(follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Public IP saved successfully.")
        ip = PublicIP.objects.get()
        self.assertEqual(ip.address, self.payload["address"])
        self.assertEqual(ip.device_id, self.device.pk)
        self.assertEqual(ip.description, self.payload["description"])
        self.assertIsNotNone(ip.created_at)
        self.assertIsNotNone(ip.updated_at)
        self.assertContains(response, "Not Monitored")
        self.assert_safe(response)

    def test_multiple_addresses_one_device_and_devices_page(self):
        self.assertEqual(self.add().status_code, 302)
        self.assertEqual(self.add({**self.payload, "address": "1.1.1.1"}).status_code, 302)
        self.assertEqual(self.device.public_ips.count(), 2)
        response = self.client.get(reverse("devices"))
        self.assertContains(response, "Assigned Public IPs (2)")
        self.assertContains(response, "8.8.8.8")
        self.assertContains(response, "1.1.1.1")
        self.assert_safe(response)

    def test_duplicate_is_global_across_devices(self):
        self.add()
        other = Device(name="Second router", management_ip="172.26.241.17", username=self.username, incoming_monitoring_interface="customer-uplink")
        other.set_password(self.password)
        other.save()
        response = self.add({**self.payload, "device": str(other.pk)})
        self.assertEqual(response.status_code, 400)
        self.assertContains(response, "already assigned", status_code=400)
        self.assertNotContains(response, "Public IP saved successfully.", status_code=400)
        self.assertEqual(PublicIP.objects.count(), 1)

    def test_database_uniqueness_enforced(self):
        self.add()
        with self.assertRaises(IntegrityError), transaction.atomic():
            PublicIP.objects.bulk_create([PublicIP(address="8.8.8.8", device=self.device)])

    def test_required_fields_and_description_length(self):
        for field in ("address", "device"):
            with self.subTest(field=field):
                response = self.add({**self.payload, field: ""})
                self.assertEqual(response.status_code, 400)
                self.assertIn(field, response.context["add_ip_form"].errors)
        self.assertEqual(self.add({**self.payload, "description": "x" * 1001}).status_code, 400)
        self.assertEqual(PublicIP.objects.count(), 0)

    def test_ipv4_public_validation_rejects_invalid_and_reserved_addresses(self):
        for address in ("invalid", "999.1.1.1", "::ffff:8.8.8.8", "2001:4860:4860::8888",
                        "192.168.1.1", "172.26.241.16", "127.0.0.1", "0.0.0.0",
                        "224.0.0.1", "255.255.255.255", "192.0.2.1", "100.64.0.1", "008.8.8.8"):
            with self.subTest(address=address):
                self.assertEqual(self.add({**self.payload, "address": address}).status_code, 400)
        self.assertEqual(PublicIP.objects.count(), 0)

    def test_optional_description_and_whitespace_normalization(self):
        response = self.add({**self.payload, "address": " 8.8.8.8 ", "description": ""})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(PublicIP.objects.get().address, "8.8.8.8")
        self.assertEqual(PublicIP.objects.get().description, "")

    def test_assignment_requires_saved_mikrotik(self):
        self.assertEqual(self.add({**self.payload, "device": "999999"}).status_code, 400)
        Device.objects.filter(pk=self.device.pk).update(device_type="cisco")
        self.assertEqual(self.add().status_code, 400)
        response = self.client.get(reverse("public_ips"))
        self.assertEqual(response.context["available_devices"], [])
        self.assertEqual(PublicIP.objects.count(), 0)

    def test_model_enforces_address_and_mikrotik_validation(self):
        for address in ("::1", "192.168.1.1"):
            with self.assertRaises(ValidationError):
                PublicIP(address=address, device=self.device).save()
        Device.objects.filter(pk=self.device.pk).update(device_type="cisco")
        with self.assertRaises(ValidationError):
            PublicIP(address="8.8.8.8", device=self.device).save()

    def test_protected_device_preserves_assignments(self):
        self.add()
        with self.assertRaises(ProtectedError):
            self.device.delete()
        self.assertTrue(Device.objects.filter(pk=self.device.pk).exists())
        self.assertEqual(PublicIP.objects.count(), 1)

    def test_authentication_and_reader_authorization(self):
        self.client.logout()
        response = self.client.get(reverse("public_ips"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("/devices/login/?next=/public-ips/", response.url)
        self.assertEqual(self.add().status_code, 302)
        self.client.force_login(self.reader)
        response = self.client.get(reverse("public_ips"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'id="addPublicIPForm"')
        self.assertNotContains(response, 'data-open-ip="addIpDialog"')
        self.assertEqual(self.add().status_code, 403)
        self.assertEqual(PublicIP.objects.count(), 0)

    def test_superuser_allowed_and_inactive_user_denied(self):
        self.client.force_login(self.inactive)
        self.assertIn(self.add().status_code, (302, 403))
        self.assertEqual(PublicIP.objects.count(), 0)
        self.client.force_login(self.superuser)
        self.assertEqual(self.add().status_code, 302)

    def test_state_changes_require_post(self):
        for method in ("get", "put", "patch", "delete"):
            self.assertEqual(getattr(self.client, method)(reverse("public_ip_add")).status_code, 405)
        self.assertEqual(self.client.post(reverse("public_ips")).status_code, 405)
        self.assertEqual(PublicIP.objects.count(), 0)

    def test_csrf_missing_invalid_and_valid(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.admin)
        self.assertEqual(client.post(reverse("public_ip_add"), self.payload).status_code, 403)
        client.get(reverse("public_ips"))
        self.assertEqual(client.post(reverse("public_ip_add"), self.payload,
                                    HTTP_X_CSRFTOKEN=secrets.token_hex(16)).status_code, 403)
        self.assertEqual(client.post(reverse("public_ip_add"), self.payload,
                                    HTTP_X_CSRFTOKEN=client.cookies["csrftoken"].value).status_code, 302)

    def test_credential_free_queries_and_responses(self):
        self.add()
        with CaptureQueriesContext(connection) as queries:
            response = self.client.get(reverse("public_ips"))
        sql = [q["sql"] for q in queries if "devices_device" in q["sql"]]
        self.assertTrue(sql)
        self.assertTrue(all("username" not in query and "encrypted_password" not in query for query in sql))
        self.assert_safe(response)
        self.assertIn("no-store", response.headers["Cache-Control"])

    def test_no_router_calls_no_device_mutation_and_no_encryption_requirement(self):
        ciphertext = self.device.encrypted_password
        with patch("routeros_api.RouterOsApiPool") as pool, patch("devices.views.probe_device") as probe:
            with patch.dict(os.environ, {}, clear=True):
                self.assertEqual(self.add().status_code, 302)
                self.assertEqual(self.client.get(reverse("public_ips")).status_code, 200)
                self.assertEqual(self.client.get(reverse("devices")).status_code, 200)
        pool.assert_not_called()
        probe.assert_not_called()
        self.device.refresh_from_db()
        self.assertEqual(self.device.encrypted_password, ciphertext)
        self.assertIsNone(self.device.last_connection_test)

    def test_extra_fields_cannot_enable_monitoring_or_override_relation(self):
        self.assertEqual(self.add({**self.payload, "enabled": "true", "username": "override",
                                  "device__management_ip": "8.8.4.4", "created_at": "2000-01-01"}).status_code, 302)
        self.device.refresh_from_db()
        self.assertEqual(self.device.management_ip, "172.26.241.16")
        self.assertEqual(PublicIP.objects.get().device_id, self.device.pk)

    def test_html_is_escaped(self):
        response = self.add({**self.payload, "description": "<script>alert(1)</script>"}, follow=True)
        self.assertContains(response, "&lt;script&gt;")
        self.assertNotContains(response, "<script>alert(1)</script>")

    def test_database_save_failure_does_not_issue_success(self):
        with patch("public_ips.forms.AddPublicIPForm.save", side_effect=DatabaseError(self.password)):
            response = self.add()
        self.assertEqual(response.status_code, 503)
        self.assert_safe(response)
        self.assertNotContains(response, "Public IP saved successfully.", status_code=503)
        self.assertEqual(PublicIP.objects.count(), 0)

    def test_duplicate_race_handled_safely(self):
        with patch("public_ips.forms.AddPublicIPForm.save", side_effect=IntegrityError(self.password)):
            response = self.add()
        self.assertEqual(response.status_code, 400)
        self.assert_safe(response)
        self.assertEqual(PublicIP.objects.count(), 0)

    def test_no_example_addresses_seeded_and_empty_devices_assignment(self):
        self.assertEqual(PublicIP.objects.count(), 0)
        response = self.client.get(reverse("devices"))
        self.assertContains(response, "No public IPs assigned")
        self.assertEqual(response.context["device_rows"][0]["assigned_public_ips"], [])
