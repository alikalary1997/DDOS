import os
import secrets
import socket
import ssl
from unittest.mock import MagicMock, patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.db import DatabaseError
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from routeros_api import exceptions

from devices.models import Device
from devices.services.connection import probe_device


@override_settings(DEVICE_CONNECTION_ALLOWED_NETWORKS=("172.26.241.0/24",), DEVICE_CONNECTION_TIMEOUT=3)
class ConnectionTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.admin = get_user_model().objects.create_user(username="connection-admin", is_staff=True)
        cls.reader = get_user_model().objects.create_user(username="connection-reader")

    def setUp(self):
        self.key = Fernet.generate_key().decode()
        self.password = secrets.token_urlsafe(32)
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": self.key})
        env.start()
        self.addCleanup(env.stop)
        self.device = Device(name="Router", management_ip="172.26.241.10", api_port=8729,
                             use_ssl=True, username=secrets.token_urlsafe(16))
        self.device.set_password(self.password)
        self.device.save()
        factory = patch("devices.services.connection.routeros_api.RouterOsApiPool")
        self.pool = factory.start()
        self.addCleanup(factory.stop)
        self.connection = self.pool.return_value
        self.api = self.connection.get_api.return_value
        self.identity = MagicMock()
        self.resource = MagicMock()
        self.identity.get.return_value = [{"name": "Real router"}]
        self.resource.get.return_value = [{"version": "7.20", "board-name": "RB5009", "uptime": "3d",
                                          "cpu-load": "0", "total-memory": "1048576", "free-memory": "262144"}]
        self.api.get_resource.side_effect = lambda name: {
            "/system/identity": self.identity, "/system/resource": self.resource
        }[name]
        self.url = reverse("device_test_connection", args=[self.device.pk])

    def assert_safe(self, response):
        body = response.content.decode()
        self.assertTrue(all(secret not in body for secret in (
            self.key, self.password, self.device.username, self.device.encrypted_password)),
            "A credential was exposed.")

    def test_read_only_probe_with_verified_tls_and_timeout(self):
        result = probe_device(self.device)
        self.assertTrue(result.success)
        self.assertEqual(result.information["cpu_usage"], 0)
        self.assertEqual(result.information["total_memory"], 1048576)
        self.assertEqual([call.args[0] for call in self.api.get_resource.call_args_list],
                         ["/system/identity", "/system/resource"])
        options = self.pool.call_args.kwargs
        self.assertTrue(options["ssl_verify"] and options["ssl_verify_hostname"] and options["use_ssl"])
        self.assertEqual(options["ssl_context"].verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(options["ssl_context"].check_hostname)
        self.connection.set_timeout.assert_called_once_with(3)
        self.assertLess([call[0] for call in self.connection.mock_calls].index("set_timeout"),
                        [call[0] for call in self.connection.mock_calls].index("get_api"))
        self.connection.disconnect.assert_called_once()

    def test_explicit_plaintext_api_supported(self):
        self.device.use_ssl = False
        self.assertTrue(probe_device(self.device).success)
        self.assertFalse(self.pool.call_args.kwargs["use_ssl"])
        self.assertIsNone(self.pool.call_args.kwargs["ssl_context"])

    def test_failures_are_sanitized_and_connections_closed(self):
        failures = [
            (socket.timeout(self.password), "timeout"),
            (exceptions.RouterOsApiConnectionError(socket.timeout(self.password)), "timeout"),
            (ConnectionRefusedError(self.password), "connection_refused"),
            (ssl.SSLCertVerificationError(self.password), "tls_verification"),
            (ssl.SSLError(self.password), "tls_failed"),
            (exceptions.RouterOsApiCommunicationError("rejected", self.password), "api_rejected"),
            (RuntimeError(self.password), "connection_failed"),
        ]
        for error, code in failures:
            with self.subTest(code=code):
                self.pool.reset_mock()
                self.connection.get_api.side_effect = error
                result = probe_device(self.device)
                self.assertFalse(result.success)
                self.assertEqual(result.code, code)
                self.assertTrue(self.password not in result.error)
                self.pool.assert_called_once()
                self.connection.disconnect.assert_called_once()

    def test_allowlist_rejects_other_targets_before_decryption_or_network(self):
        for target in ("192.168.1.1", "8.8.8.8", "127.0.0.1", "172.26.241.0",
                       "172.26.241.255", "fe80::1%eth0", "router.example", "172.26.242.1"):
            with self.subTest(target=target):
                self.device.management_ip = target
                with patch.object(self.device, "get_password") as decrypt:
                    result = probe_device(self.device)
                self.assertFalse(result.success)
                decrypt.assert_not_called()
                self.pool.assert_not_called()

    def test_invalid_configuration_fails_closed(self):
        for config in ((), ("bad-cidr",), ("172.26.241.1/24",)):
            with override_settings(DEVICE_CONNECTION_ALLOWED_NETWORKS=config):
                self.assertFalse(probe_device(self.device).success)
        for timeout in (0, 100, float("nan")):
            with override_settings(DEVICE_CONNECTION_TIMEOUT=timeout):
                self.assertFalse(probe_device(self.device).success)
        self.pool.assert_not_called()

    def test_missing_or_wrong_key_makes_no_connection(self):
        for key in ("", Fernet.generate_key().decode()):
            with patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": key}):
                self.assertEqual(probe_device(self.device).code, "credentials_unavailable")
        self.pool.assert_not_called()

    def test_invalid_ca_makes_no_connection(self):
        with override_settings(DEVICE_CONNECTION_CA_FILE="missing-ca-file.pem"):
            self.assertEqual(probe_device(self.device).code, "tls_configuration")
        self.pool.assert_not_called()

    def test_missing_and_invalid_metrics_are_not_invented(self):
        self.resource.get.return_value = [{"cpu-load": "999", "total-memory": "10", "free-memory": "11"}]
        result = probe_device(self.device)
        self.assertTrue(result.success)
        self.assertIsNone(result.information["cpu_usage"])
        self.assertIsNone(result.information["total_memory"])
        self.assertIsNone(result.information["free_memory"])
        self.resource.get.return_value = []
        self.assertEqual(probe_device(self.device).code, "invalid_response")

    def test_router_reflected_secrets_are_redacted(self):
        self.identity.get.return_value = [{"name": self.password + self.device.username + self.key}]
        self.resource.get.return_value = [{"version": self.device.encrypted_password}]
        result = probe_device(self.device)
        rendered = str(result.information)
        self.assertTrue(all(value not in rendered for value in (
            self.password, self.device.username, self.key, self.device.encrypted_password)))

    def test_authentication_authorization_and_post_required(self):
        self.assertEqual(self.client.post(self.url).status_code, 401)
        self.client.force_login(self.reader)
        self.assertEqual(self.client.post(self.url).status_code, 403)
        self.client.force_login(self.admin)
        self.assertEqual(self.client.get(self.url).status_code, 405)
        self.pool.assert_not_called()

    def test_csrf_required_and_valid_token_accepted(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.admin)
        self.assertEqual(client.post(self.url).status_code, 403)
        self.pool.assert_not_called()
        client.get(reverse("devices"))
        token = client.cookies["csrftoken"].value
        self.assertEqual(client.post(self.url, HTTP_X_CSRFTOKEN=token).status_code, 200)

    def test_saved_target_only_and_missing_device(self):
        self.client.force_login(self.admin)
        self.assertEqual(self.client.post(self.url, {"management_ip": "8.8.8.8"}).status_code, 400)
        self.assertEqual(self.client.post(self.url, "{}", content_type="application/json").status_code, 400)
        self.assertEqual(self.client.post(reverse("device_test_connection", args=[99999])).status_code, 404)
        self.pool.assert_not_called()

    def test_view_validates_and_connects_to_current_database_ip_not_a_stale_object(self):
        self.client.force_login(self.admin)
        Device.objects.filter(pk=self.device.pk).update(management_ip="172.26.241.44")
        self.assertEqual(self.device.management_ip, "172.26.241.10")
        response = self.client.post(self.url)
        self.assertTrue(response.json()["ok"])
        self.assertEqual(self.pool.call_args.args[0], "172.26.241.44")
        self.assertEqual(response.json()["device"]["management_ip"], "172.26.241.44")

    def test_policy_diagnostics_are_not_exposed_to_unauthorized_callers(self):
        self.client.force_login(self.reader)
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 403)
        self.assertNotIn("172.26.241.0/24", response.content.decode())
        self.pool.assert_not_called()

    def test_success_persists_real_snapshot_without_changing_credentials(self):
        self.client.force_login(self.admin)
        ciphertext = self.device.encrypted_password
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 200)
        self.assert_safe(response)
        row = response.json()["device"]
        self.assertEqual(row["status"], "Online")
        self.assertEqual(row["used_memory"], 786432)
        self.assertEqual(row["cpu_display"], "0%")
        self.assertIn("last test", row["status_note"])
        self.device.refresh_from_db()
        self.assertEqual(self.device.encrypted_password, ciphertext)
        self.assertEqual(self.device.router_identity, "Real router")
        self.assertIsNotNone(self.device.last_successful_connection)

    def test_failed_test_clears_snapshot_but_preserves_success_history(self):
        self.client.force_login(self.admin)
        self.client.post(self.url)
        self.device.refresh_from_db()
        previous_success = self.device.last_successful_connection
        self.connection.get_api.side_effect = socket.timeout(self.password)
        response = self.client.post(self.url)
        self.assert_safe(response)
        self.assertEqual(response.json()["device"]["status"], "Offline")
        self.assertEqual(response.json()["device"]["cpu_display"], "Not available")
        self.device.refresh_from_db()
        self.assertEqual(self.device.last_successful_connection, previous_success)
        self.assertIsNone(self.device.cpu_usage)
        self.assertIsNone(self.device.total_memory)
        self.assertIsNotNone(self.device.last_connection_test)

    def test_inventory_is_not_a_live_connection_and_never_exposes_credentials(self):
        self.client.force_login(self.admin)
        response = self.client.get(reverse("devices"))
        self.assert_safe(response)
        self.assertEqual(response.context["device_rows"][0]["status"], "Not Tested")
        self.pool.assert_not_called()

    def test_disabled_and_non_mikrotik_devices_cannot_be_probed(self):
        self.client.force_login(self.admin)
        Device.objects.filter(pk=self.device.pk).update(enabled=False)
        self.assertEqual(self.client.post(self.url).status_code, 400)
        Device.objects.filter(pk=self.device.pk).update(enabled=True, device_type="other")
        self.assertEqual(self.client.post(self.url).status_code, 400)
        self.pool.assert_not_called()

    def test_inactive_administrator_denied_and_superuser_allowed(self):
        user = get_user_model().objects.create_user(username="inactive-probe", is_staff=True, is_active=False)
        self.client.force_login(user)
        self.assertEqual(self.client.post(self.url).status_code, 401)
        self.pool.assert_not_called()
        user = get_user_model().objects.create_user(username="super-probe", is_superuser=True)
        self.client.force_login(user)
        self.assertTrue(self.client.post(self.url).json()["ok"])

    def test_database_failure_never_claims_success_or_leaks_credentials(self):
        self.client.force_login(self.admin)
        with patch("django.db.models.query.QuerySet.update", side_effect=DatabaseError(self.password)):
            response = self.client.post(self.url)
        self.assertEqual(response.status_code, 503)
        self.assertFalse(response.json()["ok"])
        self.assert_safe(response)
        self.device.refresh_from_db()
        self.assertIsNone(self.device.last_connection_test)
