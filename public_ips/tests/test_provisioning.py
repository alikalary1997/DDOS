import os
import secrets
import socket
import tempfile
from copy import deepcopy
from unittest.mock import MagicMock, patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.db import DatabaseError
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from devices.models import Device
from devices.services.router_lock import RouterBusy, router_lock
from public_ips.models import ProvisioningAttempt, PublicIP
from public_ips.services.provisioning import provision_public_ip
from public_ips.services.rules import expected_rules


class ProvisioningTests(TestCase):
    def test_new_device_defaults_to_automatic_save_and_retry_without_checkbox(self):
        from devices.services.connection import ProbeResult
        other = Device(name="Default-enabled router", management_ip="172.26.241.55",
                       username=self.device.username, encrypted_password=self.device.encrypted_password,
                       incoming_monitoring_interface="wan-uplink")
        other.save()
        self.assertTrue(other.raw_provisioning_enabled)
        self.assertIsNone(other.raw_provisioning_authorized_at)
        self.client.force_login(self.admin)
        with patch("public_ips.services.provisioning.ROUTER_WRITES_RELEASED", False), patch(
                "devices.services.provisioning_authorization.probe_device", return_value=ProbeResult(True)):
            response = self.client.post(reverse("public_ip_add"), {"address": "9.9.9.9", "device": other.pk})
            self.assertEqual(response.status_code, 302)
            assignment = PublicIP.objects.get(address="9.9.9.9")
            self.assertEqual(assignment.provisioning_status, "verified")
            self.assertEqual(self.raw.add.call_count, 3)
            self.client.post(reverse("public_ip_provision", args=[assignment.pk]))
            self.assertEqual(self.raw.add.call_count, 3)

    def test_existing_device_enablement_migration_only_updates_database(self):
        import importlib
        from types import SimpleNamespace
        from django.apps import apps
        from django.db import connection
        migration = importlib.import_module("devices.migrations.0007_alter_device_raw_provisioning_enabled")
        migration.enable_existing(apps, SimpleNamespace(connection=connection))
        self.device.refresh_from_db()
        self.assertTrue(self.device.raw_provisioning_enabled)
        self.pool.assert_not_called()

    def test_save_authorizes_selected_device_after_preflight_and_provisions_future_ips(self):
        from devices.services.connection import ProbeResult
        from public_ips.services.device_approval import device_writes_enabled
        self.client.force_login(self.admin)
        with patch("public_ips.services.provisioning.ROUTER_WRITES_RELEASED", False), patch(
                "devices.services.provisioning_authorization.probe_device", return_value=ProbeResult(True)):
            response = self.client.post(reverse("public_ip_add"), {
                "address": "9.9.9.9", "device": self.device.pk,
                "authorize_provisioning": "on", "incoming_monitoring_interface": "ignored"})
            self.assertEqual(response.status_code, 302)
            self.device.refresh_from_db()
            self.assertTrue(device_writes_enabled(self.device))
            assignment = PublicIP.objects.get(address="9.9.9.9")
            self.assertEqual(assignment.provisioning_status, "verified")
            self.assertEqual(assignment.incoming_monitoring_interface, "wan-uplink")
            self.assertEqual(len(self.rows) - len(self.original), 3)
            self.client.post(reverse("public_ip_provision", args=[assignment.pk]))
            self.assertEqual(len(self.rows) - len(self.original), 3)
            self.client.post(reverse("public_ip_add"), {"address": "4.4.4.4", "device": self.device.pk})
            self.assertEqual(PublicIP.objects.get(address="4.4.4.4").provisioning_status, "verified")
            self.assertEqual(len(self.rows) - len(self.original), 6)

    def test_save_failed_authorization_retains_assignment_without_writes(self):
        from devices.services.connection import ProbeResult
        self.client.force_login(self.admin)
        with patch("public_ips.services.provisioning.ROUTER_WRITES_RELEASED", False), patch(
                "devices.services.provisioning_authorization.probe_device",
                return_value=ProbeResult(False, error="API login rejected")):
            response = self.client.post(reverse("public_ip_add"), {
                "address": "9.9.9.9", "device": self.device.pk, "authorize_provisioning": "on"})
        self.assertEqual(response.status_code, 302)
        assignment = PublicIP.objects.get(address="9.9.9.9")
        self.assertEqual(assignment.provisioning_status, "failed")
        self.assertEqual(assignment.provisioning_message, "API login rejected")
        self.device.refresh_from_db()
        self.assertFalse(self.device.raw_provisioning_enabled)
        self.pool.assert_not_called()
        self.raw.add.assert_not_called()

    @classmethod
    def setUpTestData(cls):
        users = get_user_model()
        cls.admin = users.objects.create_user(username="provision-admin", is_staff=True)
        cls.reader = users.objects.create_user(username="provision-reader")

    def setUp(self):
        self.key = Fernet.generate_key().decode()
        self.password = secrets.token_urlsafe(32)
        environment = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": self.key})
        environment.start()
        self.addCleanup(environment.stop)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        settings = override_settings(
            DEVICE_CONNECTION_ALLOWED_NETWORKS=("172.26.241.0/24",),
            NETSHIELD_RAW_PROVISIONING_ENABLED=True,
            NETSHIELD_ROUTER_LOCK_DIRECTORY=directory.name,
        )
        settings.enable()
        self.addCleanup(settings.disable)
        release = patch("public_ips.services.provisioning.ROUTER_WRITES_RELEASED", True)
        release.start()
        self.addCleanup(release.stop)
        self.device = Device(name="Router", management_ip="172.26.241.16", raw_provisioning_enabled=False,
                             username=secrets.token_urlsafe(20), incoming_monitoring_interface="wan-uplink")
        self.device.set_password(self.password)
        self.device.save()
        self.ip = PublicIP.objects.create(address="8.8.8.8", device=self.device)
        self.rows = [{"id": "*A", "chain": "prerouting", "action": "drop", "comment": "Unrelated policy"}]
        self.original = deepcopy(self.rows)
        self.interfaces = [{"id": "*1", "name": "wan-uplink", "disabled": "false"}]
        factory = patch("devices.services.router_session.routeros_api.RouterOsApiPool")
        self.pool = factory.start()
        self.addCleanup(factory.stop)
        self.raw = MagicMock()
        self.raw.get.side_effect = lambda: deepcopy(self.rows)
        self.raw.add.side_effect = self.add_rule
        self.api = self.pool.return_value.get_api.return_value
        self.interface_resource = MagicMock()
        self.interface_resource.get.side_effect = lambda: deepcopy(self.interfaces)
        self.api.get_resource.side_effect = lambda name: {
            "/interface": self.interface_resource, "/ip/firewall/raw": self.raw
        }[name]

    def add_rule(self, **arguments):
        row = dict(arguments)
        anchor = row.pop("place-before", None)
        row["id"] = "*" + format(16 + len(self.rows), "X")
        if anchor:
            index = next(i for i, item in enumerate(self.rows) if item["id"] == anchor)
            self.rows.insert(index, row)
        else:
            self.rows.append(row)
        return []

    def provision(self):
        return provision_public_ip(self.ip.pk, self.admin)

    def seed(self, count=3):
        specifications = expected_rules(self.ip.address, "wan-uplink")
        for specification in reversed(specifications[:count]):
            self.add_rule(**specification, **{"place-before": self.rows[0]["id"]})

    def assert_no_mutation_calls(self):
        self.raw.set.assert_not_called()
        self.raw.remove.assert_not_called()
        self.assertTrue(all(call[0] in ("get", "add") for call in self.raw.mock_calls))
        self.assertEqual(next(row for row in self.rows if row["id"] == "*A"), self.original[0])

    def test_gate_blocks_network_even_with_environment_or_browser_overrides(self):
        with override_settings(NETSHIELD_RAW_PROVISIONING_ENABLED=False):
            result = self.provision()
        self.assertEqual(result.code, "approval_required")
        self.pool.assert_not_called()
        self.assertEqual(ProvisioningAttempt.objects.get().status, "awaiting_approval")
        self.ip.refresh_from_db()
        self.assertEqual(self.ip.provisioning_status, "awaiting_approval")

    def test_code_release_gate_blocks_even_when_setting_true(self):
        with patch("public_ips.services.provisioning.ROUTER_WRITES_RELEASED", False):
            self.assertEqual(self.provision().code, "approval_required")
        self.pool.assert_not_called()

    def test_only_missing_exact_passthrough_rules_created_and_verified(self):
        result = self.provision()
        self.assertTrue(result.success)
        self.assertEqual(self.raw.add.call_count, 3)
        for call in self.raw.add.call_args_list:
            self.assertEqual(call.kwargs["action"], "passthrough")
            self.assertEqual(call.kwargs["chain"], "prerouting")
            if call.kwargs["comment"] == "MONITOR-8.8.8.8":
                self.assertEqual(call.kwargs["in-interface"], "wan-uplink")
            else:
                self.assertNotIn("in-interface", call.kwargs)
            self.assertEqual(call.kwargs["dst-address"], "8.8.8.8")
            self.assertIn("place-before", call.kwargs)
        self.assert_no_mutation_calls()
        self.ip.refresh_from_db()
        self.assertEqual(self.ip.provisioning_status, "verified")
        audit = ProvisioningAttempt.objects.get()
        self.assertEqual(len(audit.requested_rule_comments), 3)
        self.assertEqual(len(audit.created_rule_ids), 3)
        self.assertEqual(len(audit.verified_rule_ids), 3)
        self.pool.return_value.disconnect.assert_called_once()

    def test_device_approval_enables_save_and_retry_without_global_release(self):
        self.authorize_device()
        self.client.force_login(self.admin)
        with patch("public_ips.services.provisioning.ROUTER_WRITES_RELEASED", False):
            response = self.client.post(reverse("public_ip_add"),
                {"address": "1.1.1.1", "device": self.device.pk, "description": ""})
            self.assertEqual(response.status_code, 302)
            assignment = PublicIP.objects.get(address="1.1.1.1")
            self.assertEqual(assignment.provisioning_status, "verified")
            self.assertEqual(self.raw.add.call_count, 3)
            self.raw.add.reset_mock()
            self.client.post(reverse("public_ip_provision", args=[assignment.pk]))
            self.raw.add.assert_not_called()
            self.assert_no_mutation_calls()

    def test_changed_endpoint_validation_failure_blocks_writes_and_retains_enablement(self):
        from devices.services.connection import ProbeResult
        self.authorize_device()
        self.pool.reset_mock()
        Device.objects.filter(pk=self.device.pk).update(api_port=9999)
        with patch("public_ips.services.provisioning.ROUTER_WRITES_RELEASED", False), patch(
                "devices.services.provisioning_authorization.probe_device", return_value=ProbeResult(False, error="API timeout")):
            self.assertEqual(self.provision().code, "preflight_failed")
        self.pool.assert_not_called()
        self.device.refresh_from_db()
        self.assertTrue(self.device.raw_provisioning_enabled)

    def test_saved_device_changes_automatically_revalidate_on_new_save_and_retry(self):
        from devices.services.connection import ProbeResult
        from public_ips.services.device_approval import device_writes_enabled
        self.authorize_device()
        self.device.api_port = 1122
        self.device.incoming_monitoring_interface = "new-uplink"
        self.device.save()
        self.interfaces = [{"name": "new-uplink", "disabled": "true"}]
        self.client.force_login(self.admin)
        self.pool.reset_mock()
        with patch("public_ips.services.provisioning.ROUTER_WRITES_RELEASED", False), patch(
                "devices.services.provisioning_authorization.probe_device", return_value=ProbeResult(True)):
            response = self.client.post(reverse("public_ip_add"), {"address": "9.9.9.9", "device": self.device.pk})
            self.assertEqual(response.status_code, 302)
            new_ip = PublicIP.objects.get(address="9.9.9.9")
            self.assertEqual(new_ip.provisioning_status, "verified")
            self.assertEqual(new_ip.incoming_monitoring_interface, "new-uplink")
            self.assertEqual(self.raw.add.call_count, 3)
            self.client.post(reverse("public_ip_provision", args=[new_ip.pk]))
            self.assertEqual(self.raw.add.call_count, 3)
        self.device.refresh_from_db()
        self.assertTrue(device_writes_enabled(self.device))
        self.assertTrue(all(call.kwargs["port"] == 1122 for call in self.pool.call_args_list))

    def test_renewal_cannot_override_explicit_disable_during_preflight(self):
        from devices.services.provisioning_authorization import authorize_provisioning, disable_provisioning
        from django.core.exceptions import ValidationError
        self.authorize_device()
        fingerprint = self.device.raw_preflight_fingerprint
        disable_provisioning(self.device.pk, self.admin)
        with self.assertRaisesMessage(ValidationError, "disabled during validation"):
            authorize_provisioning(self.device.pk, self.admin, confirmed=True,
                                  fingerprint=fingerprint, renew_existing=True)
        self.device.refresh_from_db()
        self.assertFalse(self.device.raw_provisioning_enabled)
        self.raw.add.assert_not_called()

    def authorize_device(self):
        from devices.services.connection import ProbeResult
        from devices.services.provisioning_authorization import authorize_provisioning, validate_provisioning
        with patch("devices.services.provisioning_authorization.probe_device", return_value=ProbeResult(True)):
            validate_provisioning(self.device.pk, self.ip.address, self.admin)
        self.device.refresh_from_db()
        authorize_provisioning(self.device.pk, self.admin, confirmed=True,
                              fingerprint=self.device.raw_preflight_fingerprint)
        self.device.refresh_from_db()

    def test_new_devices_default_disabled_and_preflight_alone_never_enables_writes(self):
        from devices.services.connection import ProbeResult
        from devices.services.provisioning_authorization import validate_provisioning
        self.assertFalse(self.device.raw_provisioning_enabled)
        with patch("devices.services.provisioning_authorization.probe_device", return_value=ProbeResult(True)):
            validate_provisioning(self.device.pk, self.ip.address, self.admin)
        self.device.refresh_from_db()
        self.assertIsNotNone(self.device.raw_preflight_at)
        self.assertFalse(self.device.raw_provisioning_enabled)
        self.raw.add.assert_not_called()
        self.pool.reset_mock()
        with patch("public_ips.services.provisioning.ROUTER_WRITES_RELEASED", False):
            self.assertEqual(self.provision().code, "approval_required")
        self.pool.assert_not_called()

    def test_new_device_from_add_form_can_be_authorized_without_source_configuration(self):
        self.client.force_login(self.admin)
        original_device_id = self.device.pk
        self.assertEqual(self.client.post(reverse("device_add"), {
            "name": "New Home", "management_ip": "172.26.241.99", "api_port": 1122,
            "use_ssl": "false", "device_type": "mikrotik", "username": self.device.username,
            "password": self.password, "incoming_monitoring_interface": "wan-uplink",
            "raw_provisioning_enabled": "true", "description": "",
        }).status_code, 302)
        self.device = Device.objects.get(name="New Home")
        self.assertTrue(self.device.raw_provisioning_enabled)
        self.ip = PublicIP.objects.create(address="1.1.1.1", device=self.device)
        self.authorize_device()
        with patch("public_ips.services.provisioning.ROUTER_WRITES_RELEASED", False):
            self.assertEqual(self.client.post(reverse("public_ip_add"), {
                "address": "9.9.9.9", "device": self.device.pk, "description": "",
            }).status_code, 302)
        created = PublicIP.objects.get(address="9.9.9.9")
        self.assertEqual(created.device_id, self.device.pk)
        self.assertEqual(created.incoming_monitoring_interface, "wan-uplink")
        self.assertEqual(created.provisioning_status, "verified")
        self.assertEqual(self.raw.add.call_count, 3)
        self.assertFalse(Device.objects.get(pk=original_device_id).raw_provisioning_enabled)

    def test_authorization_requires_validation_confirmation_and_administrator(self):
        from django.core.exceptions import PermissionDenied, ValidationError
        from devices.services.provisioning_authorization import authorize_provisioning
        with self.assertRaises(ValidationError):
            authorize_provisioning(self.device.pk, self.admin, confirmed=False, fingerprint="")
        with self.assertRaises(ValidationError):
            authorize_provisioning(self.device.pk, self.admin, confirmed=True, fingerprint="")
        with self.assertRaises(PermissionDenied):
            authorize_provisioning(self.device.pk, self.reader, confirmed=True, fingerprint="")
        self.pool.assert_not_called()

    def test_authorization_is_persisted_with_actor_and_configuration_and_no_api_writes(self):
        from devices.models import DeviceChange
        from public_ips.services.device_approval import device_writes_enabled
        self.authorize_device()
        self.assertTrue(device_writes_enabled(Device.objects.get(pk=self.device.pk)))
        self.assertEqual(self.device.raw_provisioning_authorized_by_id, self.admin.pk)
        self.assertIsNotNone(self.device.raw_provisioning_authorized_at)
        self.assertTrue(DeviceChange.objects.filter(action="provision_enable", actor=self.admin).exists())
        self.raw.add.assert_not_called()
        self.assert_no_mutation_calls()

    def test_authorization_does_not_enable_another_new_device(self):
        from public_ips.services.device_approval import device_writes_enabled
        self.authorize_device()
        other = Device(name="New MikroTik", management_ip=self.device.management_ip,
                       api_port=1122, username=self.device.username,
                       encrypted_password=self.device.encrypted_password,
                       incoming_monitoring_interface="wan-uplink", raw_provisioning_enabled=False)
        other.save()
        self.assertFalse(device_writes_enabled(other))
        other_ip = PublicIP.objects.create(address="1.1.1.1", device=other)
        self.pool.reset_mock()
        with patch("public_ips.services.provisioning.ROUTER_WRITES_RELEASED", False):
            self.assertEqual(provision_public_ip(other_ip.pk, self.admin).code, "approval_required")
        self.pool.assert_not_called()

    def test_device_authorized_missing_rules_and_duplicate_prevention(self):
        self.seed(1)
        self.authorize_device()
        self.raw.add.reset_mock()
        with patch("public_ips.services.provisioning.ROUTER_WRITES_RELEASED", False):
            self.assertTrue(self.provision().success)
            self.assertEqual(self.raw.add.call_count, 2)
            self.raw.add.reset_mock()
            self.assertTrue(self.provision().success)
            self.raw.add.assert_not_called()
        self.assertEqual(len(self.rows), 4)

    def test_api_failure_after_device_authorization_retains_assignment_for_retry(self):
        self.authorize_device()
        self.pool.return_value.get_api.side_effect = socket.timeout()
        with patch("public_ips.services.provisioning.ROUTER_WRITES_RELEASED", False):
            self.assertEqual(self.provision().code, "timeout")
        self.ip.refresh_from_db()
        self.assertEqual(self.ip.provisioning_status, "failed")
        self.assertEqual(self.ip.device_id, self.device.pk)
        self.raw.add.assert_not_called()

    def test_failed_connection_or_raw_conflict_cannot_be_authorized(self):
        from django.core.exceptions import ValidationError
        from devices.services.connection import ProbeResult
        from devices.services.provisioning_authorization import validate_provisioning, authorize_provisioning
        for result in (ProbeResult(False, error="API login rejected"), ProbeResult(True)):
            if result.success:
                self.seed(1)
                self.rows[0]["action"] = "drop"
            with patch("devices.services.provisioning_authorization.probe_device", return_value=result):
                with self.assertRaises(ValidationError):
                    validate_provisioning(self.device.pk, self.ip.address, self.admin)
            with self.assertRaises(ValidationError):
                authorize_provisioning(self.device.pk, self.admin, confirmed=True, fingerprint="")
        self.device.refresh_from_db()
        self.assertIsNone(self.device.raw_preflight_at)
        self.assertFalse(self.device.raw_provisioning_enabled)
        self.raw.add.assert_not_called()

    def test_authorization_expires_before_enabling_and_configuration_change_requires_revalidation(self):
        from datetime import timedelta
        from django.utils import timezone
        from django.core.exceptions import ValidationError
        from devices.services.provisioning_authorization import authorize_provisioning
        self.authorize_device()
        Device.objects.filter(pk=self.device.pk).update(raw_preflight_at=timezone.now() - timedelta(minutes=16))
        with self.assertRaises(ValidationError):
            authorize_provisioning(self.device.pk, self.admin, confirmed=True,
                                  fingerprint=self.device.raw_preflight_fingerprint)
        self.device.incoming_monitoring_interface = "other-uplink"
        self.device.save()
        self.device.refresh_from_db()
        self.assertTrue(self.device.raw_provisioning_enabled)
        from public_ips.services.device_approval import device_writes_enabled
        self.assertFalse(device_writes_enabled(self.device))
        self.assertIsNone(self.device.raw_preflight_at)

    def test_authorization_page_requires_explicit_post_and_disable_never_changes_rules(self):
        self.client.force_login(self.admin)
        url = reverse("device_raw_provisioning", args=[self.device.pk])
        response = self.client.get(url)
        self.assertContains(response, "Authorization unavailable")
        self.pool.assert_not_called()
        self.assertEqual(self.client.post(url, {"action": "enable", "authorize": "yes"}).status_code, 400)
        self.authorize_device()
        self.pool.reset_mock()
        response = self.client.post(url, {"action": "disable"})
        self.assertEqual(response.status_code, 302)
        self.device.refresh_from_db()
        self.assertFalse(self.device.raw_provisioning_enabled)
        self.pool.assert_not_called()

    def test_authorization_http_workflow_is_read_only_until_confirmed(self):
        from devices.services.connection import ProbeResult
        self.client.force_login(self.admin)
        url = reverse("device_raw_provisioning", args=[self.device.pk])
        with patch("devices.services.provisioning_authorization.probe_device", return_value=ProbeResult(True)):
            self.assertEqual(self.client.post(url, {"action": "validate", "public_ip": self.ip.address}).status_code, 302)
        self.device.refresh_from_db()
        self.assertFalse(self.device.raw_provisioning_enabled)
        response = self.client.get(url)
        self.assertContains(response, "Authorize and enable for Router")
        self.assertContains(response, self.device.management_ip)
        self.assertContains(response, "wan-uplink")
        self.assertContains(response, "MONITOR-SYN-" + self.ip.address)
        for secret in (self.password, self.key, self.device.username, self.device.encrypted_password):
            self.assertNotIn(secret, response.content.decode())
        self.pool.reset_mock()
        self.assertEqual(self.client.post(url, {"action": "enable", "fingerprint": self.device.raw_preflight_fingerprint}).status_code, 400)
        self.assertEqual(self.client.post(url, {"action": "enable", "authorize": "yes",
                            "fingerprint": self.device.raw_preflight_fingerprint}).status_code, 302)
        self.device.refresh_from_db()
        self.assertTrue(self.device.raw_provisioning_enabled)
        self.raw.add.assert_not_called()
        self.pool.assert_not_called()

    def test_authorization_endpoint_blocks_readers_and_csrf_failures(self):
        self.client.force_login(self.reader)
        url = reverse("device_raw_provisioning", args=[self.device.pk])
        self.assertEqual(self.client.get(url).status_code, 403)
        self.assertEqual(self.client.post(url, {"action": "enable", "authorize": "yes"}).status_code, 403)
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.admin)
        self.assertEqual(csrf_client.post(url, {"action": "enable", "authorize": "yes"}).status_code, 403)
        self.pool.assert_not_called()

    def test_saved_interface_change_retains_enablement_without_router_calls(self):
        self.authorize_device()
        self.pool.reset_mock()
        self.client.force_login(self.admin)
        response = self.client.post(reverse("device_monitoring_interface", args=[self.device.pk]),
                                    {"incoming_monitoring_interface": "new-uplink"})
        self.assertEqual(response.status_code, 302)
        self.device.refresh_from_db()
        self.assertTrue(self.device.raw_provisioning_enabled)
        self.assertIsNone(self.device.raw_preflight_at)
        self.pool.assert_not_called()

    def test_router_error_message_is_shown_with_credentials_redacted(self):
        from routeros_api.exceptions import RouterOsApiCommunicationError
        self.raw.get.side_effect = RouterOsApiCommunicationError("trap", {
            "message": "not enough permissions " + self.password})
        result = self.provision()
        self.assertIn("not enough permissions", result.message)
        self.assertNotIn(self.password, result.message)
        self.ip.refresh_from_db()
        self.assertEqual(self.ip.provisioning_status, "failed")

    def test_retry_reuses_existing_rules_without_duplicates(self):
        self.assertTrue(self.provision().success)
        self.raw.add.reset_mock()
        self.assertTrue(self.provision().success)
        self.raw.add.assert_not_called()
        self.assertEqual(len(self.rows), 4)
        self.assertEqual(ProvisioningAttempt.objects.count(), 2)

    def test_transient_syn_readback_does_not_stop_before_udp(self):
        transient = set()
        def read_rows():
            rows = deepcopy(self.rows)
            for row in rows:
                if row.get("comment") == "MONITOR-SYN-" + self.ip.address and row["id"] not in transient:
                    transient.add(row["id"])
                    row["invalid"] = "true"
            return rows
        self.raw.get.side_effect = read_rows
        with patch("public_ips.services.provisioning.time.sleep"):
            result = self.provision()
        self.assertTrue(result.success)
        self.assertEqual(self.raw.add.call_count, 3)
        self.assertEqual(len(result.verified), 3)
        self.assert_no_mutation_calls()

    def test_persistent_syn_readback_conflict_still_fails_without_adding_udp(self):
        def read_rows():
            rows = deepcopy(self.rows)
            for row in rows:
                if row.get("comment") == "MONITOR-SYN-" + self.ip.address:
                    row["protocol"] = "udp"
            return rows
        self.raw.get.side_effect = read_rows
        with patch("public_ips.services.provisioning.time.sleep"):
            result = self.provision()
        self.assertFalse(result.success)
        self.assertEqual(result.code, "rule_conflict")
        self.assertEqual(self.raw.add.call_count, 2)
        self.assert_no_mutation_calls()

    def test_partial_existing_set_creates_only_missing_rules(self):
        self.seed(1)
        self.raw.add.reset_mock()
        result = self.provision()
        self.assertTrue(result.success)
        self.assertEqual(self.raw.add.call_count, 2)

    def test_all_matching_existing_rules_reused_including_host_prefix(self):
        self.seed()
        for row in self.rows[:-1]:
            row["dst-address"] += "/32"
        self.raw.add.reset_mock()
        self.assertTrue(self.provision().success)
        self.raw.add.assert_not_called()

    def test_all_conflicts_are_checked_before_any_write(self):
        self.seed()
        for key, value in (("action", "drop"), ("dst-address", "1.1.1.1"), ("chain", "output"),
                           ("in-interface", "wrong"), ("disabled", "true"), ("src-address", "1.1.1.1"),
                           ("protocol", "udp"), ("log", "true")):
            with self.subTest(key=key):
                original = deepcopy(self.rows)
                self.rows[0][key] = value
                self.assertEqual(self.provision().code, "rule_conflict")
                self.raw.add.assert_not_called()
                self.rows = original

    def test_duplicate_expected_comments_fail_without_writes(self):
        self.seed()
        duplicate = dict(self.rows[0], id="*FF")
        self.rows.insert(0, duplicate)
        self.assertEqual(self.provision().code, "rule_conflict")
        self.raw.add.assert_not_called()

    def test_existing_rule_after_terminating_rule_conflicts(self):
        self.seed()
        self.rows.insert(0, self.rows.pop())
        self.assertEqual(self.provision().code, "rule_conflict")
        self.raw.add.assert_not_called()

    def test_missing_or_wrong_interface_blocks_writes(self):
        for interfaces in ([], [{"name": "another"}]):
            self.interfaces = interfaces
            self.assertEqual(self.provision().code, "rule_conflict")
        self.raw.add.assert_not_called()

    def test_disabled_saved_interface_allows_rules_without_enabling_interface(self):
        self.interfaces = [{"name": "wan-uplink", "disabled": "true"}]
        self.assertTrue(self.provision().success)
        self.assertEqual(self.raw.add.call_count, 3)
        self.interface_resource.set.assert_not_called()
        self.interface_resource.call.assert_not_called()
        self.assertEqual(self.interfaces[0]["disabled"], "true")
        self.assertTrue(self.provision().success)
        self.assertEqual(self.raw.add.call_count, 3)

    def test_timeout_after_add_is_uncertain_but_retry_does_not_duplicate(self):
        def uncertain(**arguments):
            self.add_rule(**arguments)
            raise socket.timeout(self.password)
        self.raw.add.side_effect = uncertain
        result = self.provision()
        self.assertEqual(result.code, "timeout")
        self.assertEqual(PublicIP.objects.count(), 1)
        self.assertEqual(len(self.rows), 2)
        audit = ProvisioningAttempt.objects.get()
        self.assertEqual(len(audit.requested_rule_comments), 1)
        self.assertNotIn(self.password, audit.message)
        self.raw.add.side_effect = self.add_rule
        self.raw.add.reset_mock()
        self.assertTrue(self.provision().success)
        self.assertEqual(self.raw.add.call_count, 2)
        self.assertEqual(len(self.rows), 4)

    def test_unverifiable_add_fails_without_claiming_success(self):
        self.raw.add.side_effect = lambda **kwargs: None
        self.assertEqual(self.provision().code, "rule_conflict")
        self.ip.refresh_from_db()
        self.assertIsNone(self.ip.provisioning_verified_at)
        self.assertFalse(self.ip.monitoring_enabled)

    def test_allowlist_tls_and_missing_key(self):
        self.device.management_ip = "8.8.4.4"
        self.device.save()
        self.assertEqual(self.provision().code, "target_policy")
        self.pool.assert_not_called()
        self.device.management_ip = "172.26.241.16"
        self.device.save()
        with patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": ""}):
            self.assertEqual(self.provision().code, "credentials_unavailable")
        self.pool.assert_not_called()
        self.assertTrue(self.provision().success)
        args = self.pool.call_args.kwargs
        self.assertTrue(args["ssl_verify"] and args["ssl_verify_hostname"])
        self.pool.return_value.set_timeout.assert_called_with(3)

    def test_audit_failure_prevents_router_access(self):
        with patch("public_ips.services.provisioning.ProvisioningAttempt.objects.create", side_effect=DatabaseError):
            with self.assertRaises(DatabaseError):
                self.provision()
        self.pool.assert_not_called()

    def test_per_device_lock_prevents_overlapping_attempts(self):
        with router_lock(self.device.pk):
            result = self.provision()
            self.assertEqual(result.code, "device_busy")
        self.pool.assert_not_called()
        with router_lock(self.device.pk):
            with self.assertRaises(RouterBusy):
                with router_lock(self.device.pk):
                    pass

    def test_permissions_and_csrf_protect_retry(self):
        url = reverse("public_ip_provision", args=[self.ip.pk])
        self.assertEqual(self.client.post(url).status_code, 302)
        self.client.force_login(self.reader)
        self.assertEqual(self.client.post(url).status_code, 403)
        self.client.force_login(self.admin)
        self.assertEqual(self.client.get(url).status_code, 405)
        csrf = Client(enforce_csrf_checks=True)
        csrf.force_login(self.admin)
        self.assertEqual(csrf.post(url).status_code, 403)
        self.pool.assert_not_called()

    def test_assignment_save_automatically_calls_disabled_provisioning_and_retains_record(self):
        self.client.force_login(self.admin)
        with override_settings(NETSHIELD_RAW_PROVISIONING_ENABLED=False):
            response = self.client.post(reverse("public_ip_add"), {
                "address": "1.1.1.1", "device": self.device.pk, "description": ""
            }, follow=True)
        self.assertContains(response, "Public IP saved successfully.")
        self.assertContains(response, "Provisioning pending")
        self.assertEqual(PublicIP.objects.count(), 2)
        self.pool.assert_not_called()
        self.assertEqual(ProvisioningAttempt.objects.count(), 1)

    def test_interface_selection_is_local_and_preserves_credentials(self):
        self.client.force_login(self.admin)
        ciphertext = self.device.encrypted_password
        response = self.client.post(reverse("device_monitoring_interface", args=[self.device.pk]),
                                    {"incoming_monitoring_interface": "new-uplink"})
        self.assertEqual(response.status_code, 302)
        self.pool.assert_not_called()
        self.device.refresh_from_db()
        self.assertEqual(self.device.incoming_monitoring_interface, "new-uplink")
        self.assertEqual(self.device.encrypted_password, ciphertext)

    def test_interface_discovery_is_read_only_and_admin_only(self):
        url = reverse("device_monitoring_interfaces", args=[self.device.pk])
        self.client.force_login(self.reader)
        self.assertEqual(self.client.post(url).status_code, 403)
        self.pool.assert_not_called()
        self.client.force_login(self.admin)
        response = self.client.post(url)
        self.assertEqual(response.json()["interfaces"], ["wan-uplink"])
        self.assertEqual([call.args[0] for call in self.api.get_resource.call_args_list], ["/interface"])
        self.raw.add.assert_not_called()
        self.assertTrue(all(secret not in response.content.decode() for secret in (
            self.password, self.key, self.device.username, self.device.encrypted_password)))

    def test_service_rejects_non_administrator(self):
        self.assertEqual(provision_public_ip(self.ip.pk, self.reader).code, "permission_denied")
        self.pool.assert_not_called()

    def test_automatic_provisioning_on_add_is_verified_with_mocked_router(self):
        self.client.force_login(self.admin)
        response = self.client.post(reverse("public_ip_add"), {
            "address": "1.1.1.1", "device": self.device.pk, "description": ""
        }, follow=True)
        self.assertEqual(response.status_code, 200)
        created = PublicIP.objects.get(address="1.1.1.1")
        self.assertEqual(created.provisioning_status, "verified")
        self.assertEqual(self.raw.add.call_count, 3)
        audit = ProvisioningAttempt.objects.get(public_ip=created)
        self.assertEqual(audit.device_id, self.device.pk)
        self.assertEqual(audit.address_snapshot, "1.1.1.1")
        self.assertEqual(audit.interface_snapshot, "wan-uplink")
        self.assert_no_mutation_calls()

    def test_multiple_public_ips_get_distinct_rule_sets_on_same_device(self):
        self.assertTrue(self.provision().success)
        other = PublicIP.objects.create(address="1.1.1.1", device=self.device)
        self.assertTrue(provision_public_ip(other.pk, self.admin).success)
        self.assertEqual(len(self.rows), 7)
        self.assertEqual(len({row.get("comment") for row in self.rows}), 7)
        self.assert_no_mutation_calls()

    def test_valid_csrf_retry_succeeds_only_on_mock_transport(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.admin)
        client.get(reverse("public_ips"))
        response = client.post(reverse("public_ip_provision", args=[self.ip.pk]),
                               HTTP_X_CSRFTOKEN=client.cookies["csrftoken"].value)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.raw.add.call_count, 3)

    def test_malformed_interface_response_is_sanitized_without_debug_leaks(self):
        self.client.force_login(self.admin)
        self.interface_resource.get.side_effect = lambda: [self.password]
        response = self.client.post(reverse("device_monitoring_interfaces", args=[self.device.pk]))
        self.assertEqual(response.status_code, 503)
        self.assertTrue(all(secret not in response.content.decode() for secret in (
            self.password, self.key, self.device.username, self.device.encrypted_password)))

    def test_exact_final_templates_independent_of_generated_test_fixture(self):
        self.assertEqual(expected_rules("8.8.8.8", "customer-uplink"), [
            {"chain": "prerouting", "action": "passthrough", "comment": "MONITOR-8.8.8.8",
             "dst-address": "8.8.8.8", "in-interface": "customer-uplink"},
            {"chain": "prerouting", "action": "passthrough", "comment": "MONITOR-SYN-8.8.8.8",
             "dst-address": "8.8.8.8", "protocol": "tcp", "tcp-flags": "syn"},
            {"chain": "prerouting", "action": "passthrough", "comment": "MONITOR-UDP-8.8.8.8",
             "dst-address": "8.8.8.8", "protocol": "udp"},
        ])

    def test_legacy_interface_restricted_protocol_rules_report_conflict_without_changes(self):
        self.seed()
        for row in self.rows:
            if row.get("protocol"):
                row["in-interface"] = "wan-uplink"
        before = deepcopy(self.rows)
        self.assertEqual(self.provision().code, "rule_conflict")
        self.raw.add.assert_not_called()
        self.assertEqual(self.rows, before)

    def test_read_only_preflight_works_with_write_release_gate_disabled(self):
        from io import StringIO
        from django.core.management import call_command
        output = StringIO()
        with patch("public_ips.services.provisioning.ROUTER_WRITES_RELEASED", False):
            call_command("check_raw_provisioning", self.device.pk, self.ip.address, stdout=output)
        self.assertIn("PASS", output.getvalue())
        self.assertIn("missing rules: 3", output.getvalue())
        self.raw.add.assert_not_called()
        self.assertEqual(self.rows, self.original)
        self.assertEqual(ProvisioningAttempt.objects.count(), 0)
        self.assertTrue(all(call[0] == "get" for call in self.raw.mock_calls))

    def test_read_only_preflight_missing_key_never_connects(self):
        from django.core.management import call_command
        from django.core.management.base import CommandError
        with patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": ""}):
            with self.assertRaisesMessage(CommandError, "Encryption key unavailable"):
                call_command("check_raw_provisioning", self.device.pk, self.ip.address)
        self.pool.assert_not_called()

    def test_read_only_preflight_missing_interface_or_unsafe_order_fails(self):
        from django.core.management import call_command
        from django.core.management.base import CommandError
        self.interfaces = []
        with self.assertRaisesMessage(CommandError, "does not exist"):
            call_command("check_raw_provisioning", self.device.pk, self.ip.address)
        self.interfaces = [{"name": "wan-uplink"}]
        self.seed()
        self.rows.insert(0, self.rows.pop())
        with self.assertRaisesMessage(CommandError, "potentially terminating"):
            call_command("check_raw_provisioning", self.device.pk, self.ip.address)
        self.raw.add.assert_not_called()

    def test_malformed_interface_listing_blocks_provisioning_without_writes(self):
        self.interfaces = [self.password]
        result = self.provision()
        self.assertFalse(result.success)
        self.assertEqual(result.code, "rule_conflict")
        self.assertNotIn(self.password, result.message)
        self.raw.add.assert_not_called()

    def test_add_needs_only_address_device_and_uses_saved_encrypted_profile(self):
        self.client.force_login(self.admin)
        response = self.client.post(reverse("public_ip_add"), {
            "address": "1.1.1.1", "device": self.device.pk,
            "incoming_monitoring_interface": "ignored-browser-override",
        }, follow=True)
        self.assertContains(response, "All three RAW monitoring rules are verified.")
        ip = PublicIP.objects.get(address="1.1.1.1")
        self.assertEqual(ip.incoming_monitoring_interface, "wan-uplink")
        self.assertEqual(self.pool.call_args.args, (self.device.management_ip,))
        self.assertEqual(self.pool.call_args.kwargs["username"], self.device.username)
        self.assertEqual(self.pool.call_args.kwargs["password"], self.password)
        self.assertEqual(self.pool.call_args.kwargs["port"], self.device.api_port)
        self.assertEqual(self.raw.add.call_count, 3)
        for call in self.raw.add.call_args_list:
            self.assertEqual(call.kwargs["dst-address"], "1.1.1.1")
            self.assertTrue(call.kwargs["comment"].endswith("1.1.1.1"))
            self.assertEqual(call.kwargs.get("in-interface"), "wan-uplink" if call.kwargs["comment"] == "MONITOR-1.1.1.1" else None)
        self.assert_no_mutation_calls()

    def test_connecting_state_is_persisted_before_api_connection(self):
        original = self.pool.return_value.get_api.side_effect
        def connect():
            self.ip.refresh_from_db()
            self.assertEqual(self.ip.provisioning_status, "connecting")
            self.assertEqual(ProvisioningAttempt.objects.get().status, "connecting")
            return self.api
        self.pool.return_value.get_api.side_effect = connect
        self.assertTrue(self.provision().success)
        self.pool.return_value.get_api.side_effect = original

    def test_web_retry_uses_only_server_approved_target_with_global_gate_off(self):
        self.client.force_login(self.admin)
        other = PublicIP.objects.create(address="1.1.1.1", device=self.device)
        with patch("public_ips.services.provisioning.ROUTER_WRITES_RELEASED", False), \
             override_settings(NETSHIELD_RAW_PROVISIONING_ENABLED=False), \
             patch("public_ips.services.controlled_test.CONTROLLED_LIVE_TEST_RELEASED", True), \
             patch("public_ips.services.controlled_test.APPROVED_LIVE_TEST_TARGET", (self.ip.pk, self.admin.pk, self.device.pk, self.ip.address, "wan-uplink")):
            response = self.client.post(reverse("public_ip_provision", args=[self.ip.pk]), follow=True)
            self.assertContains(response, "Provisioned: RAW rules verified")
            self.assertEqual(self.raw.add.call_count, 3)
            self.pool.reset_mock()
            self.client.post(reverse("public_ip_provision", args=[other.pk]))
            other.refresh_from_db()
            self.assertEqual(other.provisioning_code, "approval_required")
            self.pool.assert_not_called()
            # A second web retry verifies and reuses the same three rules.
            self.client.post(reverse("public_ip_provision", args=[self.ip.pk]))
            self.assertEqual(self.raw.add.call_count, 3)
        self.assert_no_mutation_calls()

    def test_controlled_command_preview_is_read_only_and_apply_remains_blocked(self):
        from io import StringIO
        from django.core.management import call_command
        from django.core.management.base import CommandError
        output = StringIO()
        with override_settings(NETSHIELD_RAW_PROVISIONING_ENABLED=False):
            call_command("test_raw_provisioning_once", self.ip.pk, stdout=output)
            self.assertIn("Preview only", output.getvalue())
            with self.assertRaisesMessage(CommandError, "has not been explicitly authorized"):
                call_command("test_raw_provisioning_once", self.ip.pk, apply=True, actor_id=self.admin.pk,
                    confirm_device_id=self.device.pk, confirm_address=self.ip.address,
                    confirm_interface="wan-uplink", stdout=StringIO())
        self.pool.assert_not_called()
        self.assertFalse(ProvisioningAttempt.objects.exists())

    def test_scoped_command_only_provisions_selected_record_and_keeps_global_writes_off(self):
        from io import StringIO
        from django.core.management import call_command
        from public_ips.services.provisioning import writes_enabled
        with patch("public_ips.services.provisioning.ROUTER_WRITES_RELEASED", False), \
             override_settings(NETSHIELD_RAW_PROVISIONING_ENABLED=False), \
             patch("public_ips.services.controlled_test.CONTROLLED_LIVE_TEST_RELEASED", True), \
             patch("public_ips.services.controlled_test.APPROVED_LIVE_TEST_TARGET", (self.ip.pk, self.admin.pk, self.device.pk, self.ip.address, "wan-uplink")):
            call_command("test_raw_provisioning_once", self.ip.pk, apply=True, actor_id=self.admin.pk,
                confirm_device_id=self.device.pk, confirm_address=self.ip.address,
                confirm_interface="wan-uplink", stdout=StringIO())
            self.assertFalse(writes_enabled())
            self.assertEqual(self.raw.add.call_count, 3)
            self.pool.reset_mock()
            self.assertEqual(self.provision().code, "approval_required")
            self.pool.assert_not_called()
        self.assert_no_mutation_calls()

    def test_scoped_approval_is_bound_to_profile_and_rejects_another_ip(self):
        from public_ips.services.controlled_test import controlled_test_scope
        other = PublicIP.objects.create(address="1.1.1.1", device=self.device)
        with patch("public_ips.services.provisioning.ROUTER_WRITES_RELEASED", False), \
             override_settings(NETSHIELD_RAW_PROVISIONING_ENABLED=False), \
             patch("public_ips.services.controlled_test.CONTROLLED_LIVE_TEST_RELEASED", True), \
             patch("public_ips.services.controlled_test.APPROVED_LIVE_TEST_TARGET", (self.ip.pk, self.admin.pk, self.device.pk, self.ip.address, "wan-uplink")):
            with controlled_test_scope(self.ip, self.admin):
                self.assertEqual(provision_public_ip(other.pk, self.admin).code, "approval_required")
                Device.objects.filter(pk=self.device.pk).update(api_port=8730)
                self.assertEqual(self.provision().code, "approval_required")
        self.pool.assert_not_called()

    def test_scoped_test_never_performs_historical_cleanup(self):
        from public_ips.models import AssignmentReview
        from public_ips.services.controlled_test import controlled_test_scope
        AssignmentReview.objects.create(public_ip=self.ip, actor=self.admin, action="edit", previous_address="8.8.4.4",
            previous_device_id_snapshot=self.device.pk, previous_interface="wan-uplink",
            previous_provisioning_status="verified", cleanup_required=True)
        with patch("public_ips.services.provisioning.ROUTER_WRITES_RELEASED", False), \
             override_settings(NETSHIELD_RAW_PROVISIONING_ENABLED=False), \
             patch("public_ips.services.controlled_test.CONTROLLED_LIVE_TEST_RELEASED", True), \
             patch("public_ips.services.controlled_test.APPROVED_LIVE_TEST_TARGET", (self.ip.pk, self.admin.pk, self.device.pk, self.ip.address, "wan-uplink")):
            with controlled_test_scope(self.ip, self.admin):
                self.assertEqual(self.provision().code, "review_required")
        self.pool.assert_not_called()

    def test_scoped_command_rejects_wrong_confirmation_and_non_admin_actor(self):
        from io import StringIO
        from django.core.management import call_command
        from django.core.management.base import CommandError
        with override_settings(NETSHIELD_RAW_PROVISIONING_ENABLED=False), \
             patch("public_ips.services.controlled_test.CONTROLLED_LIVE_TEST_RELEASED", True), \
             patch("public_ips.services.controlled_test.APPROVED_LIVE_TEST_TARGET", (self.ip.pk, self.admin.pk, self.device.pk, self.ip.address, "wan-uplink")):
            with self.assertRaisesMessage(CommandError, "Confirm the exact"):
                call_command("test_raw_provisioning_once", self.ip.pk, apply=True, actor_id=self.admin.pk,
                    confirm_device_id=self.device.pk, confirm_address="1.1.1.1",
                    confirm_interface="wan-uplink", stdout=StringIO())
            with self.assertRaisesMessage(CommandError, "Administrator authorization"):
                call_command("test_raw_provisioning_once", self.ip.pk, apply=True, actor_id=self.reader.pk,
                    confirm_device_id=self.device.pk, confirm_address=self.ip.address,
                    confirm_interface="wan-uplink", stdout=StringIO())
        self.pool.assert_not_called()

    def test_diagnostics_trace_approved_mock_workflow_without_secrets(self):
        with self.assertLogs("netshield.provisioning", level="INFO") as logs:
            result = self.provision()
        self.assertTrue(result.success)
        output = "\n".join(logs.output)
        for stage in ("provisioning_triggered", "write_gate", "encryption_key", "password_decryption", "api_connection", "raw_read", "rule_creation", "final_verification", "provisioning_final"):
            self.assertIn("stage=" + stage, output)
        self.assertIn(f"public_ip_id={self.ip.pk}", output)
        self.assertIn(f"device_id={self.device.pk}", output)
        for secret in (self.key, self.password, self.device.username, self.device.encrypted_password):
            self.assertNotIn(secret, output)

    def test_diagnostics_report_gate_stop_and_pending_state_without_api_attempt(self):
        with patch("public_ips.services.provisioning.ROUTER_WRITES_RELEASED", False), self.assertLogs("netshield.provisioning", level="INFO") as logs:
            self.assertEqual(self.provision().code, "approval_required")
        output = "\n".join(logs.output)
        self.assertIn("triggered=True", output)
        self.assertIn("live_enabled=False", output)
        self.assertIn("result=approval_required", output)
        self.assertNotIn("stage=api_connection", output)
        self.ip.refresh_from_db(); self.assertEqual(self.ip.provisioning_status, "awaiting_approval")
        self.client.force_login(self.admin)
        self.assertContains(self.client.get(reverse("public_ips")), "Pending: approval required")
        # Pending approval must not be mistaken for an active, locked operation.
        with patch("routeros_api.RouterOsApiPool") as pool:
            self.assertEqual(self.client.post(reverse("public_ip_delete", args=[self.ip.pk]), {"confirm": "yes"}).status_code, 302)
        pool.assert_not_called()

    def test_diagnostics_do_not_log_raw_transport_errors_containing_secrets(self):
        self.pool.return_value.get_api.side_effect = socket.timeout(self.password + self.key)
        with self.assertLogs("netshield.provisioning", level="INFO") as logs:
            self.assertEqual(self.provision().code, "timeout")
        output = "\n".join(logs.output)
        self.assertIn("stage=api_connection", output)
        self.assertIn("result=timeout", output)
        self.assertNotIn(self.password, output); self.assertNotIn(self.key, output)

    def test_status_endpoint_exposes_provisioning_state_without_credentials(self):
        self.provision()
        self.client.force_login(self.admin)
        response = self.client.get(reverse("public_ip_monitoring_data"))
        row = response.json()["rows"][0]
        self.assertEqual(row["provisioning_status"], "verified")
        self.assertEqual(row["provisioning_code"], "verified")
        for secret in (self.key, self.password, self.device.username, self.device.encrypted_password):
            self.assertNotIn(secret, response.content.decode())

    def test_connection_refusal_logs_safe_reason_and_errno_without_exception_text(self):
        self.pool.return_value.get_api.side_effect = ConnectionRefusedError(10061, self.password)
        with self.assertLogs("netshield.provisioning", level="INFO") as logs:
            result = self.provision()
        self.assertEqual(result.code, "api_failed")
        self.assertIn("refused", result.message)
        output = "\n".join(logs.output)
        self.assertIn("reason=connection_refused", output)
        self.assertIn("errno=10061", output)
        self.assertNotIn(self.password, output)
