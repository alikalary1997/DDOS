import os
import secrets
from unittest.mock import patch
from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.db import DatabaseError
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone
from devices.models import Device
from devices.services.router_lock import RouterBusy
from public_ips.models import FirewallSample, ProvisioningAttempt, PublicIP


class PublicIPEditDeleteTests(TestCase):
    def setUp(self):
        self.admin = get_user_model().objects.create_user(username="edit-admin", is_staff=True)
        self.reader = get_user_model().objects.create_user(username="edit-reader")
        self.client.force_login(self.admin)
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start(); self.addCleanup(env.stop)
        self.secret = secrets.token_urlsafe(32)
        self.device = self.make_device("First", "172.26.241.16")
        self.other_device = self.make_device("Second", "172.26.241.17")
        self.ip = PublicIP.objects.create(address="8.8.8.8", device=self.device, description="Original description")
        self.other_ip = PublicIP.objects.create(address="1.1.1.1", device=self.device)
        self.edit = reverse("public_ip_edit", args=[self.ip.pk])
        self.delete = reverse("public_ip_delete", args=[self.ip.pk])
        self.payload = {"edit-address": self.ip.address, "edit-device": str(self.device.pk), "edit-description": "Updated"}

    def make_device(self, name, address):
        device = Device(name=name, management_ip=address, username="hidden-api-user", incoming_monitoring_interface="ether1")
        device.set_password(self.secret); device.save(); return device

    def active(self):
        PublicIP.objects.filter(pk=self.ip.pk).update(provisioning_status="verified", provisioning_verified_at=timezone.now(), monitoring_enabled=True)
        self.ip.refresh_from_db()
        FirewallSample.objects.create(device=self.device, rows=[{"id": self.ip.pk}, {"id": self.other_ip.pk}])
        return ProvisioningAttempt.objects.create(public_ip=self.ip, actor=self.admin, device=self.device,
            address_snapshot=self.ip.address, interface_snapshot="ether1", status="verified", finished_at=timezone.now())

    def test_edit_is_prefilled_and_keeps_other_features(self):
        response = self.client.get(self.edit)
        self.assertContains(response, 'value="8.8.8.8"')
        self.assertContains(response, "Original description")
        for text in ("ipSearch", "ipDeviceFilter", "ipStatusFilter", "Add Public IP", "Retry provisioning", "Start Monitoring", "Stop Monitoring", "Delete"):
            self.assertContains(response, text)
        for secret in (self.secret, self.device.encrypted_password, self.device.username, os.environ["NETSHIELD_DEVICE_ENCRYPTION_KEY"]):
            self.assertNotIn(secret, response.content.decode())

    def test_description_edit_requires_review_and_preserves_other_record(self):
        self.active()
        response = self.client.post(self.edit, self.payload, follow=True)
        self.assertContains(response, "Public IP updated successfully.")
        self.ip.refresh_from_db(); self.other_ip.refresh_from_db()
        self.assertEqual(self.ip.description, "Updated")
        self.assertFalse(self.ip.monitoring_enabled)
        self.assertEqual(self.ip.provisioning_status, "review_required")
        self.assertIsNone(self.ip.provisioning_verified_at)
        self.assertEqual(self.other_ip.address, "1.1.1.1")

    def test_changed_address_or_device_stops_polling_and_invalidates_only_target(self):
        audit = self.active()
        with patch("routeros_api.RouterOsApiPool") as pool, patch("public_ips.services.provisioning.provision_public_ip") as provision:
            response = self.client.post(self.edit, {**self.payload, "edit-address": "8.8.4.4", "edit-device": str(self.other_device.pk)})
        self.assertEqual(response.status_code, 302)
        pool.assert_not_called(); provision.assert_not_called()
        self.ip.refresh_from_db()
        self.assertEqual(self.ip.device_id, self.other_device.pk)
        self.assertEqual(self.ip.address, "8.8.4.4")
        self.assertFalse(self.ip.monitoring_enabled)
        self.assertIsNone(self.ip.provisioning_verified_at)
        self.assertEqual(self.ip.provisioning_status, "review_required")
        self.assertEqual(FirewallSample.objects.get(device=self.device).rows, [{"id": self.other_ip.pk}])
        audit.refresh_from_db(); self.assertEqual(audit.address_snapshot, "8.8.8.8")

    def test_duplicate_invalid_ip_device_and_long_description_rejected(self):
        for changes in ({"edit-address": "1.1.1.1"}, {"edit-address": "192.168.1.1"}, {"edit-address": "::1"}, {"edit-device": "999999"}, {"edit-device": "invalid"}, {"edit-description": "x"*1001}):
            response = self.client.post(self.edit, {**self.payload, **changes})
            self.assertEqual(response.status_code, 400)
            self.ip.refresh_from_db(); self.assertEqual(self.ip.address, "8.8.8.8")
            self.assertEqual(self.ip.description, "Original description")
        self.assertEqual(PublicIP.objects.count(), 2)

    def test_extra_fields_cannot_grant_monitoring_or_modify_device(self):
        self.client.post(self.edit, {**self.payload, "monitoring_enabled": "true", "provisioning_status": "verified", "username": "override"})
        self.ip.refresh_from_db(); self.device.refresh_from_db()
        self.assertFalse(self.ip.monitoring_enabled)
        self.assertEqual(self.device.username, "hidden-api-user")

    def test_delete_confirmation_get_and_missing_confirmation_leave_record(self):
        self.assertContains(self.client.get(self.delete), "Delete Public IP")
        self.assertTrue(PublicIP.objects.filter(pk=self.ip.pk).exists())
        self.client.post(self.delete)
        self.assertTrue(PublicIP.objects.filter(pk=self.ip.pk).exists())

    def test_active_deletion_retains_audit_other_ip_device_and_router_rules(self):
        audit = self.active()
        with patch("routeros_api.RouterOsApiPool") as pool:
            response = self.client.post(self.delete, {"confirm": "yes"}, follow=True)
        self.assertContains(response, "Public IP deleted successfully.")
        pool.assert_not_called()
        self.assertFalse(PublicIP.objects.filter(pk=self.ip.pk).exists())
        audit.refresh_from_db(); self.assertIsNone(audit.public_ip_id)
        self.assertEqual(audit.address_snapshot, "8.8.8.8")
        self.assertTrue(PublicIP.objects.filter(pk=self.other_ip.pk).exists())
        self.assertEqual(Device.objects.count(), 2)
        self.assertEqual(FirewallSample.objects.get(device=self.device).rows, [{"id": self.other_ip.pk}])
        dashboard = self.client.get(reverse("monitoring_data")).json()
        self.assertEqual([row["address"] for row in dashboard["rules"]], ["1.1.1.1"])

    def test_permissions_post_only_mutations_and_csrf(self):
        client = Client(enforce_csrf_checks=True)
        for url in (self.edit, self.delete):
            self.assertEqual(client.get(url).status_code, 302)
        client.force_login(self.reader)
        for url in (self.edit, self.delete):
            self.assertEqual(client.get(url).status_code, 403)
        client.force_login(self.admin); client.get(reverse("public_ips"))
        token = client.cookies["csrftoken"].value
        for url, payload in ((self.edit, self.payload), (self.delete, {"confirm": "yes"})):
            self.assertEqual(client.post(url, payload).status_code, 403)
            self.assertEqual(client.put(url, payload, HTTP_X_CSRFTOKEN=token).status_code, 405)
        self.assertEqual(client.post(self.edit, self.payload, HTTP_X_CSRFTOKEN=token).status_code, 302)
        self.assertEqual(client.post(self.delete, {"confirm": "yes"}, HTTP_X_CSRFTOKEN=token).status_code, 302)

    def test_busy_device_and_pending_provisioning_retain_assignment(self):
        with patch("public_ips.services.assignments.router_lock", side_effect=RouterBusy):
            self.assertEqual(self.client.post(self.edit, self.payload).status_code, 400)
            self.assertEqual(self.client.post(self.delete, {"confirm": "yes"}).status_code, 302)
        PublicIP.objects.filter(pk=self.ip.pk).update(provisioning_status="pending")
        self.client.post(self.delete, {"confirm": "yes"})
        self.assertTrue(PublicIP.objects.filter(pk=self.ip.pk).exists())

    def test_database_failure_rolls_back_cleanup_and_sanitizes_messages(self):
        self.active()
        with patch("public_ips.services.assignments.PublicIP.delete", side_effect=DatabaseError(self.secret)):
            response = self.client.post(self.delete, {"confirm": "yes"}, follow=True)
        self.assertContains(response, "could not be deleted")
        self.assertNotContains(response, self.secret)
        self.ip.refresh_from_db(); self.assertTrue(self.ip.monitoring_enabled)
        self.assertEqual(len(FirewallSample.objects.get(device=self.device).rows), 2)

    def test_unknown_ids_are_404(self):
        for name in ("public_ip_edit", "public_ip_delete"):
            url = reverse(name, args=[999999])
            self.assertEqual(self.client.get(url).status_code, 404)
            self.assertEqual(self.client.post(url, {"confirm": "yes"}).status_code, 404)
