import os
from contextlib import contextmanager
from copy import deepcopy
from unittest.mock import MagicMock, patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from devices.models import Device
from devices.services.management import remove_device
from public_ips.forms import AddPublicIPForm, EditPublicIPForm
from public_ips.models import AssignmentReview, ProvisioningAttempt, PublicIP
from public_ips.services.assignments import delete_assignment
from public_ips.services.cleanup import cleanup_review
from public_ips.services.provisioning import provision_public_ip
from public_ips.services.rules import RuleConflict, expected_rules


@override_settings(NETSHIELD_RAW_PROVISIONING_ENABLED=True)
class RecordConfigurationTests(TestCase):
    def setUp(self):
        key = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        key.start(); self.addCleanup(key.stop)
        gate = patch("public_ips.services.provisioning.ROUTER_WRITES_RELEASED", True)
        gate.start(); self.addCleanup(gate.stop)
        self.admin = get_user_model().objects.create_user(username="record-admin", is_staff=True)
        self.reader = get_user_model().objects.create_user(username="record-reader")
        self.client.force_login(self.admin)
        self.device = Device(name="Router", management_ip="172.26.241.16", username="test-api", incoming_monitoring_interface="device-default")
        self.device.set_password("isolated-test-password"); self.device.save()
        self.ip = PublicIP.objects.create(address="8.8.8.8", device=self.device, incoming_monitoring_interface="record-uplink", provisioning_status="verified")
        self.unrelated = PublicIP.objects.create(address="1.1.1.1", device=self.device, incoming_monitoring_interface="other-uplink")
        self.rows = [dict(row, id="*"+str(i+1)) for i, row in enumerate(expected_rules(self.ip.address, self.ip.incoming_monitoring_interface))]
        self.rows.append({"id": "*F", "chain": "prerouting", "action": "drop", "comment": "Unrelated policy"})
        self.audit = ProvisioningAttempt.objects.create(public_ip=self.ip, actor=self.admin, device=self.device,
            address_snapshot=self.ip.address, interface_snapshot="record-uplink", status="verified", verified_rule_ids=["*1", "*2", "*3"])
        self.raw = MagicMock()
        self.raw.get.side_effect = lambda: deepcopy(self.rows)
        self.raw.remove.side_effect = lambda **kwargs: self.rows.__setitem__(slice(None), [row for row in self.rows if row["id"] != kwargs["id"]])
        self.raw.add.side_effect = self.add_rule
        self.interfaces = MagicMock()
        self.interfaces.get.return_value = [{"name": "record-uplink"}, {"name": "new-uplink"}]
        self.api = MagicMock()
        self.api.get_resource.side_effect = lambda name: {"/ip/firewall/raw": self.raw, "/interface": self.interfaces}[name]
        @contextmanager
        def session(device):
            self.assertEqual(device.pk, self.device.pk)
            yield self.api
        self.provision_session = patch("public_ips.services.provisioning.router_session", side_effect=session).start()
        self.cleanup_session = patch("public_ips.services.cleanup.router_session", side_effect=session).start()
        self.addCleanup(patch.stopall)

    def add_rule(self, **arguments):
        row = dict(arguments); anchor = row.pop("place-before", None)
        row["id"] = "*"+format(32+len(self.rows), "X")
        index = next((i for i, item in enumerate(self.rows) if item["id"] == anchor), len(self.rows))
        self.rows.insert(index, row)

    def delete_review(self):
        return delete_assignment(self.ip, self.admin)

    def test_record_interface_overrides_device_and_existing_set_is_reused(self):
        result = provision_public_ip(self.ip.pk, self.admin)
        self.assertTrue(result.success)
        self.raw.add.assert_not_called()
        self.assertEqual(ProvisioningAttempt.objects.first().interface_snapshot, "record-uplink")

    def test_form_saves_explicit_interface_and_validates_missing_values(self):
        data = {"address": "9.9.9.9", "device": self.device.pk, "incoming_monitoring_interface": "customer-ethernet"}
        form = AddPublicIPForm(data)
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.save().incoming_monitoring_interface, "device-default")
        self.assertNotIn("incoming_monitoring_interface", form.fields)
        form = EditPublicIPForm({**data, "address": "8.8.4.4", "incoming_monitoring_interface": "bad\ninterface"})
        self.assertFalse(form.is_valid())
        Device.objects.filter(pk=self.device.pk).update(incoming_monitoring_interface="")
        form = AddPublicIPForm({"address": "8.8.4.4", "device": self.device.pk})
        self.assertFalse(form.is_valid())
        self.assertIn("__all__", form.errors)

    def test_missing_or_invalid_configuration_never_generates_rules(self):
        for address, interface in (("8.8.8.8", ""), ("192.168.1.1", "ether1"), ("invalid", "ether1"), ("8.8.8.8", "bad\nname")):
            with self.assertRaises(RuleConflict):
                expected_rules(address, interface)

    def test_delete_removes_only_audited_exact_rules_and_preserves_history(self):
        review = self.delete_review()
        self.assertTrue(cleanup_review(review.pk, self.admin).success)
        self.assertEqual([row["id"] for row in self.rows], ["*F"])
        self.assertTrue(PublicIP.objects.filter(pk=self.unrelated.pk).exists())
        self.audit.refresh_from_db(); self.assertIsNone(self.audit.public_ip_id)
        review.refresh_from_db()
        self.assertFalse(review.cleanup_required)
        self.assertEqual(review.removed_rule_ids, ["*1", "*2", "*3"])
        self.assertEqual(review.requested_removal_ids, ["*1", "*2", "*3"])
        self.raw.set.assert_not_called()
        self.assertTrue(cleanup_review(review.pk, self.admin).success)
        self.assertEqual(self.raw.remove.call_count, 3)

    def test_pending_approval_delete_retains_audit_without_router_access(self):
        device_ip_id = self.ip.pk
        with patch("public_ips.services.provisioning.ROUTER_WRITES_RELEASED", False):
            response = self.client.post(reverse("public_ip_delete", args=[self.ip.pk]), {"confirm": "yes"})
            self.assertEqual(response.status_code, 302)
            review = AssignmentReview.objects.get()
            self.assertEqual(cleanup_review(review.pk, self.admin).code, "approval_required")
        self.cleanup_session.assert_not_called()
        self.raw.remove.assert_not_called()
        self.assertFalse(PublicIP.objects.filter(pk=device_ip_id).exists())

    def test_approved_public_ip_delete_view_cleans_rules_and_preserves_unrelated_ip(self):
        ip_id = self.ip.pk
        response = self.client.post(reverse("public_ip_delete", args=[ip_id]), {"confirm": "yes"}, follow=True)
        self.assertContains(response, "Associated monitoring rule cleanup verified.")
        self.assertFalse(PublicIP.objects.filter(pk=ip_id).exists())
        self.assertTrue(PublicIP.objects.filter(pk=self.unrelated.pk).exists())
        self.assertEqual([row["id"] for row in self.rows], ["*F"])

    def test_missing_record_interface_is_not_replaced_by_device_default_during_provisioning(self):
        PublicIP.objects.filter(pk=self.ip.pk).update(incoming_monitoring_interface="missing-uplink")
        result = provision_public_ip(self.ip.pk, self.admin)
        self.assertFalse(result.success)
        self.assertIn("does not exist", result.message)
        self.raw.add.assert_not_called(); self.raw.remove.assert_not_called()

    def test_conflicting_rule_or_unverified_ownership_blocks_all_removals(self):
        review = self.delete_review()
        self.rows[2]["action"] = "drop"
        self.assertFalse(cleanup_review(review.pk, self.admin).success)
        self.raw.remove.assert_not_called()
        self.rows[2]["action"] = "passthrough"
        review.refresh_from_db(); review.rule_references = []; review.save()
        self.assertFalse(cleanup_review(review.pk, self.admin).success)
        self.raw.remove.assert_not_called()

    def test_recreated_record_protects_shared_rule_set(self):
        address = self.ip.address
        review = self.delete_review()
        PublicIP.objects.create(address=address, device=self.device, incoming_monitoring_interface="record-uplink")
        self.assertFalse(cleanup_review(review.pk, self.admin).success)
        self.cleanup_session.assert_not_called()

    def test_partial_uncertain_removal_retries_without_touching_unrelated_rules(self):
        review = self.delete_review()
        original = self.raw.remove.side_effect
        def uncertain(**kwargs):
            original(**kwargs)
            raise TimeoutError("private transport details")
        self.raw.remove.side_effect = uncertain
        self.assertFalse(cleanup_review(review.pk, self.admin).success)
        review.refresh_from_db(); self.assertEqual(review.requested_removal_ids, ["*1"])
        self.raw.remove.side_effect = original
        self.assertTrue(cleanup_review(review.pk, self.admin).success)
        self.assertEqual([row["id"] for row in self.rows], ["*F"])

    def test_interface_edit_snapshots_old_profile_and_retry_reconciles_without_duplicates(self):
        response = self.client.post(reverse("public_ip_edit", args=[self.ip.pk]), {"edit-address": "8.8.8.8", "edit-device": self.device.pk,
            "edit-incoming_monitoring_interface": "new-uplink", "edit-description": "Updated"})
        self.assertEqual(response.status_code, 302)
        self.cleanup_session.assert_not_called()
        review = AssignmentReview.objects.get()
        self.assertEqual(review.previous_interface, "record-uplink")
        self.ip.refresh_from_db(); self.assertEqual(self.ip.incoming_monitoring_interface, "new-uplink")
        self.assertTrue(provision_public_ip(self.ip.pk, self.admin).success)
        self.assertEqual(self.raw.remove.call_count, 3)
        self.assertEqual(self.raw.add.call_count, 3)
        self.assertEqual(len({row["comment"] for row in self.rows}), 4)
        total = next(row for row in self.rows if row["comment"] == "MONITOR-8.8.8.8")
        self.assertEqual(total["in-interface"], "new-uplink")
        self.assertTrue(provision_public_ip(self.ip.pk, self.admin).success)
        self.assertEqual(self.raw.add.call_count, 3)

    def test_address_edit_reconciles_old_comments_and_destination(self):
        response = self.client.post(reverse("public_ip_edit", args=[self.ip.pk]), {"edit-address": "8.8.4.4", "edit-device": self.device.pk,
            "edit-incoming_monitoring_interface": "record-uplink", "edit-description": ""})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(provision_public_ip(self.ip.pk, self.admin).success)
        self.assertFalse(any(row.get("dst-address") == "8.8.8.8" for row in self.rows))
        self.assertEqual(sum(row.get("dst-address") == "8.8.4.4" for row in self.rows), 3)

    def test_device_deletion_never_requests_router_cleanup_even_after_release(self):
        remove_device(self.device, self.admin)
        self.cleanup_session.assert_not_called(); self.provision_session.assert_not_called()
        review = AssignmentReview.objects.filter(previous_address="8.8.8.8").get()
        self.assertEqual(cleanup_review(review.pk, self.admin).code, "database_only")
        self.cleanup_session.assert_not_called()

    def test_cleanup_requires_admin_post_and_csrf(self):
        review = self.delete_review()
        url = reverse("public_ip_cleanup", args=[review.pk])
        self.client.force_login(self.reader)
        self.assertEqual(self.client.post(url).status_code, 403)
        self.client.force_login(self.admin)
        self.assertEqual(self.client.get(url).status_code, 405)
        client = Client(enforce_csrf_checks=True); client.force_login(self.admin)
        self.assertEqual(client.post(url).status_code, 403)
        self.cleanup_session.assert_not_called()
