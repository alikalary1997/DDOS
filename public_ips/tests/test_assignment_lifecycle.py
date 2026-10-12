import os
import secrets
from unittest.mock import patch
from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.db import DatabaseError
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from devices.models import Device
from public_ips.forms import AddPublicIPForm, EditPublicIPForm
from public_ips.models import AssignmentReview, FirewallSample, ProvisioningAttempt, PublicIP
from public_ips.services.provisioning import provision_public_ip


class AssignmentLifecycleTests(TestCase):
    def setUp(self):
        self.admin = get_user_model().objects.create_user(username="lifecycle-admin", is_staff=True)
        self.reader = get_user_model().objects.create_user(username="lifecycle-reader")
        self.client.force_login(self.admin)
        self.secret = secrets.token_urlsafe(32)
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start(); self.addCleanup(env.stop)
        self.a = self.device("Router A", "172.26.241.16")
        self.b = self.device("Router B", "172.26.241.17")
        self.ip = PublicIP.objects.create(address="8.8.8.8", device=self.a, description="Customer")
        self.other = PublicIP.objects.create(address="1.1.1.1", device=self.a)
        self.edit = reverse("public_ip_edit", args=[self.ip.pk])
        self.unassign = reverse("public_ip_unassign", args=[self.ip.pk])
        self.delete = reverse("public_ip_delete", args=[self.ip.pk])

    def device(self, name, address):
        device = Device(name=name, management_ip=address, username="private-account", incoming_monitoring_interface="ether1")
        device.set_password(self.secret); device.save(); return device

    def payload(self, **changes):
        values = {"edit-address": self.ip.address, "edit-device": str(self.a.pk), "edit-description": self.ip.description}
        values.update(changes); return values

    def seed_verified_sample(self):
        PublicIP.objects.filter(pk=self.ip.pk).update(provisioning_status="verified", provisioning_verified_at=timezone.now(), monitoring_enabled=True)
        self.ip.refresh_from_db()
        self.audit = ProvisioningAttempt.objects.create(public_ip=self.ip, actor=self.admin, device=self.a,
            address_snapshot=self.ip.address, interface_snapshot="ether1", status="verified", finished_at=timezone.now(),
            requested_rule_comments=["MONITOR-"+self.ip.address], created_rule_ids=["*1"], verified_rule_ids=["*1", "*2", "*3"])
        row = dict(id=self.ip.pk, address=self.ip.address, device_id=self.a.pk, status="Monitoring", packets=1000, bytes=8000,
                   pps=100, mbps=1.2, last_update=timezone.now().isoformat(), attempted_at=timezone.now().isoformat(),
                   profile_version=[self.ip.updated_at.isoformat(), self.ip.provisioning_verified_at.isoformat()], protocol_rules=[])
        FirewallSample.objects.create(device=self.a, rows=[row, {"id": self.other.pk}])
        return row

    def test_unassign_retains_record_clears_samples_and_devices_dashboard_membership(self):
        self.seed_verified_sample()
        with patch("routeros_api.RouterOsApiPool") as pool, patch("public_ips.services.provisioning.provision_public_ip") as provision:
            response = self.client.post(self.unassign, follow=True)
        self.assertContains(response, "Public IP unassigned.")
        self.assertContains(response, "Unassigned")
        self.assertContains(response, "router cleanup has not been performed")
        pool.assert_not_called(); provision.assert_not_called()
        self.ip.refresh_from_db()
        self.assertIsNone(self.ip.device_id)
        self.assertFalse(self.ip.monitoring_enabled)
        self.assertEqual(self.ip.provisioning_status, "review_required")
        self.assertIsNone(self.ip.provisioning_verified_at)
        self.assertEqual(PublicIP.objects.count(), 2)
        self.assertEqual(FirewallSample.objects.get(device=self.a).rows, [{"id": self.other.pk}])
        dashboard = self.client.get(reverse("monitoring_data")).json()
        self.assertEqual([row["id"] for row in dashboard["rules"]], [self.other.pk])
        devices = self.client.get(reverse("devices")).context["device_rows"]
        self.assertNotIn(self.ip.address, next(row for row in devices if row["id"] == self.a.pk)["assigned_public_ips"])
        review = AssignmentReview.objects.get()
        self.assertEqual(review.action, "unassign")
        self.assertEqual(review.previous_device_id_snapshot, self.a.pk)
        self.assertIsNone(review.new_device_id_snapshot)
        self.assertTrue(review.cleanup_required)
        self.assertEqual(review.rule_references[0]["verified_rule_ids"], ["*1", "*2", "*3"])
        self.audit.refresh_from_db(); self.assertEqual(self.audit.public_ip_id, self.ip.pk)

    @override_settings(NETSHIELD_RAW_POLLING_ENABLED=True)
    def test_reassignment_does_not_reuse_old_monitoring_or_rule_ids(self):
        old = self.seed_verified_sample()
        with patch("public_ips.services.monitoring.POLLING_RELEASED", True):
            self.assertTrue(self.client.get(reverse("monitoring_data")).json()["monitoring"])
            with patch("routeros_api.RouterOsApiPool") as pool:
                self.assertEqual(self.client.post(self.edit, self.payload(**{"edit-device": str(self.b.pk)})).status_code, 302)
            pool.assert_not_called()
            # Even a late old cache write is not accepted as current.
            FirewallSample.objects.filter(device=self.a).update(rows=[old])
            data = self.client.get(reverse("monitoring_data")).json()
        row = next(row for row in data["rules"] if row["id"] == self.ip.pk)
        self.assertEqual(row["device_name"], "Router B")
        self.assertEqual(row["provisioning_status"], "review_required")
        self.assertIsNone(row["pps"]); self.assertIsNone(row["last_update"])
        self.assertEqual(AssignmentReview.objects.get().rule_references[0]["device_id"], self.a.pk)
        devices = self.client.get(reverse("devices")).context["device_rows"]
        self.assertIn(self.ip.address, next(row for row in devices if row["id"] == self.b.pk)["assigned_public_ips"])

    def test_unassigned_record_can_be_edited_and_reassigned(self):
        self.client.post(self.unassign)
        self.assertContains(self.client.get(self.edit), "Unassigned — keep the IP without a device")
        self.client.post(self.edit, self.payload(**{"edit-device": "", "edit-description": "Unassigned customer"}))
        self.ip.refresh_from_db(); self.assertIsNone(self.ip.device_id)
        self.assertEqual(self.ip.description, "Unassigned customer")
        self.client.post(self.edit, self.payload(**{"edit-device": str(self.b.pk)}))
        self.ip.refresh_from_db(); self.assertEqual(self.ip.device_id, self.b.pk)
        self.assertFalse(self.ip.monitoring_enabled)
        self.assertEqual(self.ip.provisioning_status, "review_required")

    def test_edit_empty_device_also_unassigns_and_is_duplicate_safe(self):
        response = self.client.post(self.edit, self.payload(**{"edit-device": ""}))
        self.assertEqual(response.status_code, 302)
        self.ip.refresh_from_db(); self.assertIsNone(self.ip.device_id)
        response = self.client.post(self.edit, self.payload(**{"edit-address": self.other.address, "edit-device": ""}))
        self.assertEqual(response.status_code, 400)
        self.ip.refresh_from_db(); self.assertEqual(self.ip.address, "8.8.8.8")

    def test_delete_retains_rule_cleanup_history_even_after_device_deletion(self):
        self.seed_verified_sample()
        with patch("routeros_api.RouterOsApiPool") as pool:
            self.client.post(self.delete, {"confirm": "yes"})
        pool.assert_not_called()
        review = AssignmentReview.objects.get()
        self.assertIsNone(review.public_ip_id)
        self.assertEqual(review.action, "delete")
        self.assertEqual(review.status, "pending")
        self.assertTrue(review.cleanup_required)
        self.other.delete(); self.a.delete()
        review.refresh_from_db()
        self.assertEqual(review.previous_device_name, "Router A")
        self.assertEqual(review.previous_management_ip, "172.26.241.16")
        self.assertEqual(review.rule_references[0]["created_rule_ids"], ["*1"])
        self.audit.refresh_from_db(); self.assertIsNone(self.audit.public_ip_id)
        self.assertIsNone(self.audit.device_id)

    def test_unassign_is_idempotent_and_preserves_description(self):
        self.client.post(self.unassign); count = AssignmentReview.objects.count()
        self.client.post(self.unassign)
        self.ip.refresh_from_db(); self.assertEqual(self.ip.description, "Customer")
        self.assertEqual(AssignmentReview.objects.count(), count)

    def test_unassign_auth_admin_csrf_and_post(self):
        client = Client(enforce_csrf_checks=True)
        self.assertEqual(client.post(self.unassign).status_code, 403)  # CSRF runs before authentication.
        self.assertEqual(client.get(self.unassign).status_code, 302)
        client.force_login(self.admin); client.get(reverse("public_ips"))
        token = client.cookies["csrftoken"].value
        client.force_login(self.reader)
        self.assertEqual(client.post(self.unassign, HTTP_X_CSRFTOKEN=token).status_code, 403)
        client.force_login(self.admin)
        self.assertEqual(client.get(self.unassign).status_code, 405)
        self.assertEqual(client.post(self.unassign).status_code, 403)
        self.assertEqual(client.post(self.unassign, HTTP_X_CSRFTOKEN=token).status_code, 302)

    def test_transaction_rolls_back_when_review_record_cannot_be_saved(self):
        self.seed_verified_sample()
        with patch("public_ips.services.assignments.AssignmentReview.objects.create", side_effect=DatabaseError(self.secret)):
            response = self.client.post(self.unassign, follow=True)
        self.assertNotContains(response, self.secret)
        self.assertContains(response, "could not be unassigned")
        self.ip.refresh_from_db(); self.assertEqual(self.ip.device_id, self.a.pk)
        self.assertTrue(self.ip.monitoring_enabled)
        self.assertEqual(len(FirewallSample.objects.get(device=self.a).rows), 2)
        self.assertFalse(AssignmentReview.objects.exists())

    def test_device_expanded_actions_are_admin_only_and_credential_free(self):
        response = self.client.get(reverse("devices"))
        for url in (self.edit, self.delete, self.unassign):
            self.assertContains(response, url)
        self.client.force_login(self.reader)
        response = self.client.get(reverse("devices"))
        for url in (self.edit, self.delete, self.unassign):
            self.assertNotContains(response, url)
        self.assertNotContains(response, self.secret)
        self.assertNotContains(response, self.a.encrypted_password)

    @override_settings(NETSHIELD_RAW_PROVISIONING_ENABLED=True, NETSHIELD_RAW_POLLING_ENABLED=True)
    def test_unassigned_ip_cannot_provision_or_start_polling_even_if_gates_are_patched(self):
        self.client.post(self.unassign)
        with patch("public_ips.services.provisioning.ROUTER_WRITES_RELEASED", True), patch("public_ips.services.monitoring.POLLING_RELEASED", True), patch("routeros_api.RouterOsApiPool") as pool:
            response = self.client.post(reverse("public_ip_provision", args=[self.ip.pk]), follow=True)
            self.assertContains(response, "Assign this public IP")
            self.assertEqual(provision_public_ip(self.ip.pk, self.admin).code, "unassigned")
            self.client.post(reverse("public_ip_monitoring_control", args=["ip", self.ip.pk, "start"]))
        pool.assert_not_called()
        self.ip.refresh_from_db(); self.assertFalse(self.ip.monitoring_enabled)
        self.assertFalse(ProvisioningAttempt.objects.exists())

    def test_add_still_requires_device_but_model_and_edit_allow_unassigned(self):
        self.assertFalse(AddPublicIPForm({"address": "9.9.9.9", "device": "", "description": ""}).is_valid())
        self.assertTrue(EditPublicIPForm({"address": "9.9.9.9", "device": "", "description": ""}).is_valid())
        saved = PublicIP.objects.create(address="9.9.9.9")
        self.assertIsNone(saved.device_id)

    def test_no_router_rule_cleanup_is_claimed_without_evidence(self):
        self.client.post(self.unassign)
        review = AssignmentReview.objects.get()
        self.assertFalse(review.cleanup_required)
        self.assertEqual(review.rule_references, [])
        self.ip.refresh_from_db()
        self.assertEqual(self.ip.provisioning_status, "review_required")
        self.assertIn("cleanup has not been performed", self.ip.provisioning_message)
