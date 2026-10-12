import os
import secrets
from unittest.mock import patch
from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.db import DatabaseError
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone
from devices.models import Device, DeviceChange
from devices.services.connection import ProbeResult
from devices.services.router_lock import RouterBusy
from public_ips.models import AssignmentReview, FirewallSample, ProvisioningAttempt, PublicIP


class DeviceManagementTests(TestCase):
    def setUp(self):
        self.admin = get_user_model().objects.create_user(username="management-admin", is_staff=True)
        self.reader = get_user_model().objects.create_user(username="management-reader")
        self.client.force_login(self.admin)
        self.password = secrets.token_urlsafe(32)
        self.key = Fernet.generate_key().decode()
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": self.key})
        env.start(); self.addCleanup(env.stop)
        self.device = Device(name="Saved router", management_ip="172.26.241.16", username="api-account", incoming_monitoring_interface="ether1")
        self.device.set_password(self.password); self.device.save()
        self.other = Device(name="Other router", management_ip="172.26.241.17", username="second-account")
        self.other.set_password(secrets.token_urlsafe(32)); self.other.save()
        self.edit = reverse("device_edit", args=[self.device.pk])
        self.delete = reverse("device_delete", args=[self.device.pk])
        self.payload = {"edit-name": "Updated router", "edit-management_ip": self.device.management_ip, "edit-api_port": self.device.api_port,
            "edit-use_ssl": "true", "edit-username": self.device.username, "edit-password": "", "edit-incoming_monitoring_interface": "ether1", "edit-description": "Updated notes"}

    def assert_safe(self, response, *extra):
        for secret in (self.password, self.device.encrypted_password, self.key, *extra):
            self.assertNotIn(secret, response.content.decode())

    def test_actions_and_prefilled_edit_form_never_display_password(self):
        page = self.client.get(reverse("devices"))
        self.assertContains(page, self.edit); self.assertContains(page, self.delete)
        self.assertContains(page, "Add Sensor")
        self.assertNotContains(page, "Test Connection")
        response = self.client.get(self.edit)
        self.assertContains(response, 'value="Saved router"')
        self.assertContains(response, 'value="172.26.241.16"')
        self.assertContains(response, "Leave blank to keep")
        self.assertContains(response, 'name="edit-password"')
        self.assert_safe(response)

    def test_blank_password_keeps_exact_ciphertext_and_no_router_calls(self):
        original = self.device.encrypted_password
        with patch("routeros_api.RouterOsApiPool") as pool, patch("devices.views.probe_device") as probe:
            response = self.client.post(self.edit, self.payload, HTTP_ACCEPT="application/json")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["ok"])
        self.device.refresh_from_db()
        self.assertEqual(self.device.encrypted_password, original)
        self.assertEqual(self.device.get_password(), self.password)
        self.assertEqual(self.device.name, "Updated router")
        pool.assert_not_called(); probe.assert_not_called()
        self.assert_safe(response)
        self.assertNotIn("username", response.json()["device"])
        self.assertNotIn("encrypted_password", response.json()["device"])
        self.assertEqual(DeviceChange.objects.get().changed_fields, ["name", "description"])

    def test_password_replacement_is_encrypted_and_not_returned(self):
        replacement = secrets.token_urlsafe(32)
        response = self.client.post(self.edit, {**self.payload, "edit-password": replacement}, HTTP_ACCEPT="application/json")
        self.assertEqual(response.status_code, 200)
        self.device.refresh_from_db()
        self.assertEqual(self.device.get_password(), replacement)
        self.assertNotEqual(self.device.encrypted_password, replacement)
        self.assert_safe(response, replacement)
        self.assertIn("password", DeviceChange.objects.get().changed_fields)
        self.assertNotIn(replacement, str(DeviceChange.objects.values().get()))

    def test_missing_encryption_key_fails_closed_without_modifying_ciphertext(self):
        original = self.device.encrypted_password
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(self.client.post(self.edit, self.payload).status_code, 400)
        self.device.refresh_from_db(); self.assertEqual(self.device.encrypted_password, original)
        self.assertEqual(self.device.name, "Saved router")

    def test_encryption_failure_rolls_back_and_password_is_not_redisplayed(self):
        replacement = secrets.token_urlsafe(32)
        with patch("devices.models.encrypt_password", side_effect=ImproperlyConfigured(replacement)):
            response = self.client.post(self.edit, {**self.payload, "edit-password": replacement})
        self.assertEqual(response.status_code, 400)
        self.assert_safe(response, replacement)
        self.device.refresh_from_db(); self.assertEqual(self.device.name, "Saved router")
        self.assertFalse(DeviceChange.objects.exists())

    def test_invalid_inputs_and_duplicate_endpoint_do_not_change_device(self):
        for changes in ({"edit-name": ""}, {"edit-management_ip": "invalid"}, {"edit-management_ip": "fe80::1%ether1"},
            {"edit-api_port": "0"}, {"edit-api_port": "65536"}, {"edit-use_ssl": "invalid"}, {"edit-username": ""},
            {"edit-incoming_monitoring_interface": "ether1\ninvalid"}, {"edit-description": "x"*1001}, {"edit-management_ip": self.other.management_ip}):
            response = self.client.post(self.edit, {**self.payload, **changes}, HTTP_ACCEPT="application/json")
            self.assertEqual(response.status_code, 400)
            self.assert_safe(response)
            self.device.refresh_from_db(); self.assertEqual(self.device.name, "Saved router")
        self.assertFalse(DeviceChange.objects.exists())

    def test_transport_change_invalidates_connection_and_assigned_ip_verification(self):
        completed = timezone.now()
        Device.objects.filter(pk=self.device.pk).update(last_connection_test=completed, last_connection_test_succeeded=True,
            last_successful_connection=completed, model="Old model", cpu_usage=10, total_memory=100, free_memory=80)
        ip = PublicIP.objects.create(address="8.8.8.8", device=self.device, provisioning_status="verified", provisioning_verified_at=completed, monitoring_enabled=True)
        audit = ProvisioningAttempt.objects.create(public_ip=ip, device=self.device, actor=self.admin, address_snapshot=ip.address,
            interface_snapshot="ether1", status="verified", verified_rule_ids=["*1", "*2", "*3"])
        FirewallSample.objects.create(device=self.device, rows=[{"id": ip.pk, "pps": 100}])
        with patch("routeros_api.RouterOsApiPool") as pool:
            response = self.client.post(self.edit, {**self.payload, "edit-management_ip": "172.26.241.18", "edit-incoming_monitoring_interface": "ether2", "edit-use_ssl": "false", "edit-api_port": "8728"}, HTTP_ACCEPT="application/json")
        self.assertEqual(response.status_code, 200); pool.assert_not_called()
        self.device.refresh_from_db(); ip.refresh_from_db(); audit.refresh_from_db()
        self.assertIsNone(self.device.last_connection_test)
        self.assertIsNone(self.device.cpu_usage)
        self.assertFalse(self.device.use_ssl); self.assertEqual(self.device.api_port, 8728)
        self.assertEqual(ip.device_id, self.device.pk)
        self.assertEqual(ip.provisioning_status, "review_required")
        self.assertFalse(ip.monitoring_enabled)
        self.assertIsNone(ip.provisioning_verified_at)
        self.assertEqual(FirewallSample.objects.get(device=self.device).rows, [])
        review = AssignmentReview.objects.get()
        self.assertEqual(review.previous_management_ip, "172.26.241.16")
        self.assertEqual(review.previous_interface, "ether1")
        self.assertEqual(review.rule_references[0]["verified_rule_ids"], audit.verified_rule_ids)
        self.assertTrue(review.cleanup_required)
        dashboard = self.client.get(reverse("monitoring_data")).json()["rules"][0]
        self.assertIsNone(dashboard["pps"])
        self.assertEqual(dashboard["management_ip"], "172.26.241.18")

    def test_name_description_edits_do_not_stop_valid_monitoring(self):
        ip = PublicIP.objects.create(address="8.8.8.8", device=self.device, provisioning_status="verified", monitoring_enabled=True)
        self.client.post(self.edit, self.payload)
        ip.refresh_from_db(); self.assertTrue(ip.monitoring_enabled)
        self.assertEqual(ip.provisioning_status, "verified")

    def test_delete_confirmation_warns_and_removes_assigned_records(self):
        ip = PublicIP.objects.create(address="8.8.8.8", device=self.device)
        response = self.client.get(self.delete)
        self.assertContains(response, "Saved router")
        self.assertEqual(response.context["assigned_ip_count"], 1)
        self.assertContains(response, "Permanent deletion:")
        self.assertContains(response, "Router cleanup will not be performed")
        response = self.client.post(self.delete, {"confirm": "yes"}, HTTP_ACCEPT="application/json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["deleted_public_ip_ids"], [ip.pk])
        self.assertFalse(Device.objects.filter(pk=self.device.pk).exists())
        self.assertFalse(PublicIP.objects.filter(pk=ip.pk).exists())
        audit = DeviceChange.objects.get()
        self.assertEqual(audit.assigned_ip_count, 1)
        self.assertFalse(audit.router_cleanup_performed)

    def test_delete_without_assignments_preserves_all_audit_history(self):
        ip = PublicIP.objects.create(address="8.8.8.8")
        audit = ProvisioningAttempt.objects.create(public_ip=ip, device=self.device, actor=self.admin, address_snapshot=ip.address, interface_snapshot="ether1")
        self.client.post(self.edit, self.payload)
        FirewallSample.objects.create(device=self.device, rows=[])
        with patch("routeros_api.RouterOsApiPool") as pool:
            response = self.client.post(self.delete, {"confirm": "yes"}, HTTP_ACCEPT="application/json")
        self.assertEqual(response.status_code, 200); pool.assert_not_called()
        self.assertFalse(Device.objects.filter(pk=self.device.pk).exists())
        self.assertTrue(Device.objects.filter(pk=self.other.pk).exists())
        self.assertTrue(PublicIP.objects.filter(pk=ip.pk).exists())
        self.assertFalse(FirewallSample.objects.filter(device_id=self.device.pk).exists())
        audit.refresh_from_db(); self.assertIsNone(audit.device_id)
        self.assertEqual(DeviceChange.objects.count(), 2)
        self.assertTrue(all(change.device_id is None for change in DeviceChange.objects.all()))
        self.assertEqual(DeviceChange.objects.get(action="delete").name_snapshot, "Updated router")

    def test_missing_confirmation_and_get_never_delete(self):
        self.client.get(self.delete)
        self.assertEqual(self.client.post(self.delete).status_code, 400)
        self.assertTrue(Device.objects.filter(pk=self.device.pk).exists())

    def test_permissions_and_csrf(self):
        client = Client(enforce_csrf_checks=True)
        for url in (self.edit, self.delete):
            self.assertEqual(client.get(url).status_code, 302)
        client.force_login(self.reader)
        for url in (self.edit, self.delete):
            self.assertEqual(client.get(url).status_code, 403)
        page = client.get(reverse("devices"))
        self.assertNotContains(page, self.edit); self.assertNotContains(page, self.delete)
        client.force_login(self.admin); client.get(reverse("devices"))
        token = client.cookies["csrftoken"].value
        for url, payload in ((self.edit, self.payload), (self.delete, {"confirm": "yes"})):
            self.assertEqual(client.post(url, payload).status_code, 403)
            self.assertEqual(client.put(url, payload, HTTP_X_CSRFTOKEN=token).status_code, 405)
        self.assertEqual(client.post(self.edit, self.payload, HTTP_X_CSRFTOKEN=token).status_code, 302)
        self.assertEqual(client.post(self.delete, {"confirm": "yes"}, HTTP_X_CSRFTOKEN=token).status_code, 302)

    def test_transaction_and_audit_failure_roll_back_device_changes(self):
        with patch("devices.services.management.DeviceChange.objects.create", side_effect=DatabaseError(self.password)):
            response = self.client.post(self.edit, self.payload, HTTP_ACCEPT="application/json")
            deletion = self.client.post(self.delete, {"confirm": "yes"}, HTTP_ACCEPT="application/json")
        self.assertEqual(response.status_code, 503); self.assertEqual(deletion.status_code, 503)
        self.assert_safe(response); self.assert_safe(deletion)
        self.device.refresh_from_db(); self.assertEqual(self.device.name, "Saved router")

    def test_busy_device_changes_refused_safely(self):
        with patch("devices.services.management.router_lock", side_effect=RouterBusy):
            self.assertEqual(self.client.post(self.edit, self.payload, HTTP_ACCEPT="application/json").status_code, 409)
            self.assertEqual(self.client.post(self.delete, {"confirm": "yes"}, HTTP_ACCEPT="application/json").status_code, 409)
        self.assertFalse(DeviceChange.objects.exists())

    def test_unknown_ids_are_404(self):
        for name in ("device_edit", "device_delete"):
            self.assertEqual(self.client.get(reverse(name, args=[999999])).status_code, 404)

    def test_late_connection_result_cannot_restore_old_profile_information(self):
        def changed(device):
            Device.objects.filter(pk=device.pk).update(updated_at=timezone.now(), management_ip="172.26.241.18")
            return ProbeResult(True, {"model": "Stale model"})
        with patch("devices.views.probe_device", side_effect=changed):
            response = self.client.post(reverse("device_test_connection", args=[self.device.pk]))
        self.assertEqual(response.status_code, 409)
        self.device.refresh_from_db()
        self.assertNotEqual(self.device.model, "Stale model")
        self.assertIsNone(self.device.last_connection_test)

    def test_extra_fields_cannot_overwrite_password_ciphertext_type_or_telemetry(self):
        original = self.device.encrypted_password
        self.client.post(self.edit, {**self.payload, "device_type": "cisco", "encrypted_password": "plaintext", "cpu_usage": "99", "enabled": "false"})
        self.device.refresh_from_db()
        self.assertEqual(self.device.encrypted_password, original)
        self.assertEqual(self.device.device_type, "mikrotik")
        self.assertTrue(self.device.enabled)
        self.assertIsNone(self.device.cpu_usage)
