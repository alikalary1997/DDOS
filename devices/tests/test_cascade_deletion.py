import os
import secrets
from unittest.mock import patch
from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.db import DatabaseError, connection
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone
from devices.models import Device, DeviceChange
from public_ips.models import AssignmentReview, FirewallSample, ProvisioningAttempt, PublicIP
from public_ips.services.assignments import delete_assignment


class DeviceCascadeDeletionTests(TestCase):
    def setUp(self):
        self.admin = get_user_model().objects.create_user(username="cascade-admin", is_staff=True)
        self.reader = get_user_model().objects.create_user(username="cascade-reader")
        self.client.force_login(self.admin)
        self.password = secrets.token_urlsafe(32)
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start(); self.addCleanup(env.stop)
        self.device = self.create_device("Deleted router", "172.26.241.16")
        self.other = self.create_device("Keep router", "172.26.241.17")
        self.unrelated = PublicIP.objects.create(address="1.1.1.1", device=self.other)
        self.unassigned = PublicIP.objects.create(address="9.9.9.9")
        self.delete = reverse("device_delete", args=[self.device.pk])

    def create_device(self, name, address):
        device = Device(name=name, management_ip=address, username="private-api-account", incoming_monitoring_interface="ether1")
        device.set_password(self.password); device.save(); return device

    def assignment(self, address):
        return PublicIP.objects.create(address=address, device=self.device,
            provisioning_status="verified", provisioning_verified_at=timezone.now(), monitoring_enabled=True)

    def delete_device(self):
        return self.client.post(self.delete, {"confirm": "yes"}, HTTP_ACCEPT="application/json")

    def test_zero_one_and_multiple_assignments(self):
        addresses = ["8.8.8.8", "8.8.4.4", "1.0.0.1"]
        for count in (0, 1, 3):
            with self.subTest(count=count):
                device = self.create_device("Matrix router", "172.26.241."+str(20+count))
                ips = [PublicIP.objects.create(address=address, device=device) for address in addresses[:count]]
                response = self.client.post(reverse("device_delete", args=[device.pk]), {"confirm": "yes"}, HTTP_ACCEPT="application/json")
                self.assertEqual(response.status_code, 200)
                self.assertCountEqual(response.json()["deleted_public_ip_ids"], [ip.pk for ip in ips])
                self.assertFalse(Device.objects.filter(pk=device.pk).exists())
                self.assertFalse(PublicIP.objects.filter(pk__in=[ip.pk for ip in ips]).exists())
                history = DeviceChange.objects.get(device_id_snapshot=device.pk, action="delete")
                self.assertEqual(history.assigned_ip_count, count)
                self.assertFalse(history.router_cleanup_performed)
                self.assertIsNone(history.device_id)
        self.assertTrue(Device.objects.filter(pk=self.other.pk).exists())
        self.assertTrue(PublicIP.objects.filter(pk=self.unrelated.pk).exists())
        self.assertTrue(PublicIP.objects.filter(pk=self.unassigned.pk).exists())

    def test_active_monitoring_and_audit_history_are_cleaned_safely(self):
        ips = [self.assignment(address) for address in ("8.8.8.8", "8.8.4.4")]
        audits = [ProvisioningAttempt.objects.create(public_ip=ip, device=self.device, actor=self.admin,
            address_snapshot=ip.address, interface_snapshot="ether1", status="verified", verified_rule_ids=["*1", "*2", "*3"],
            requested_rule_comments=["MONITOR-"+ip.address]) for ip in ips]
        FirewallSample.objects.create(device=self.device, rows=[{"id": ip.pk, "pps": 100} for ip in ips])
        other_cache = FirewallSample.objects.create(device=self.other, rows=[{"id": self.unrelated.pk, "pps": 20}])
        with patch("routeros_api.RouterOsApiPool") as pool, patch("devices.views.probe_device") as probe:
            response = self.delete_device()
        self.assertEqual(response.status_code, 200)
        pool.assert_not_called(); probe.assert_not_called()
        self.assertFalse(response.json()["router_cleanup_performed"])
        self.assertIn("cleanup was not performed", response.json()["message"])
        self.assertFalse(PublicIP.objects.filter(device_id=self.device.pk).exists())
        self.assertFalse(FirewallSample.objects.filter(device_id=self.device.pk).exists())
        self.assertFalse(PublicIP.objects.filter(pk__in=[ip.pk for ip in ips], monitoring_enabled=True).exists())
        other_cache.refresh_from_db(); self.assertEqual(other_cache.rows, [{"id": self.unrelated.pk, "pps": 20}])
        for audit in audits:
            audit.refresh_from_db(); self.assertIsNone(audit.public_ip_id); self.assertIsNone(audit.device_id)
            self.assertEqual(audit.verified_rule_ids, ["*1", "*2", "*3"])
        reviews = AssignmentReview.objects.filter(previous_device_id_snapshot=self.device.pk)
        self.assertEqual(reviews.count(), 2)
        for review in reviews:
            self.assertIsNone(review.public_ip_id)
            self.assertEqual(review.status, "pending")
            self.assertTrue(review.cleanup_required)
            self.assertEqual(review.previous_device_name, "Deleted router")
            self.assertEqual(review.rule_references[0]["verified_rule_ids"], ["*1", "*2", "*3"])
        data = self.client.get(reverse("monitoring_data")).json()
        self.assertEqual([device["id"] for device in data["devices"]], [self.other.pk])
        self.assertEqual([row["id"] for row in data["rules"]], [self.unrelated.pk])
        inventory = self.client.get(reverse("public_ips"))
        self.assertCountEqual([row["id"] for row in inventory.context["public_ip_rows"]], [self.unrelated.pk, self.unassigned.pk])
        devices = self.client.get(reverse("devices"))
        self.assertEqual([row["id"] for row in devices.context["device_rows"]], [self.other.pk])
        with connection.cursor() as cursor:
            cursor.execute("PRAGMA foreign_key_check")
            self.assertEqual(cursor.fetchall(), [])

    def test_partial_ip_failure_rolls_back_all_assignments_and_audits(self):
        ips = [self.assignment(address) for address in ("8.8.8.8", "8.8.4.4")]
        FirewallSample.objects.create(device=self.device, rows=[{"id": ip.pk, "pps": 100} for ip in ips])
        calls = []
        def fail_second(ip, actor, **kwargs):
            calls.append(ip.pk)
            if len(calls) == 2:
                raise DatabaseError(self.password)
            return delete_assignment(ip, actor, **kwargs)
        with patch("devices.services.management.delete_assignment", side_effect=fail_second):
            response = self.delete_device()
        self.assertEqual(response.status_code, 503)
        self.assertNotIn(self.password, response.content.decode())
        self.assertTrue(Device.objects.filter(pk=self.device.pk).exists())
        self.assertEqual(PublicIP.objects.filter(pk__in=[ip.pk for ip in ips], monitoring_enabled=True).count(), 2)
        self.assertEqual(len(FirewallSample.objects.get(device=self.device).rows), 2)
        self.assertFalse(DeviceChange.objects.exists())
        self.assertFalse(AssignmentReview.objects.exists())

    def test_device_delete_failure_rolls_back_already_deleted_ips(self):
        ip = self.assignment("8.8.8.8")
        FirewallSample.objects.create(device=self.device, rows=[{"id": ip.pk}])
        with patch("devices.services.management.Device.delete", side_effect=DatabaseError(self.password)):
            response = self.delete_device()
        self.assertEqual(response.status_code, 503)
        ip.refresh_from_db(); self.assertTrue(ip.monitoring_enabled)
        self.assertEqual(FirewallSample.objects.get(device=self.device).rows, [{"id": ip.pk}])
        self.assertFalse(AssignmentReview.objects.exists())
        self.assertFalse(DeviceChange.objects.exists())

    def test_confirmation_missing_or_reader_csrf_cannot_cascade(self):
        ip = self.assignment("8.8.8.8")
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.admin); client.get(reverse("devices"))
        token = client.cookies["csrftoken"].value
        self.assertEqual(client.post(self.delete, {"confirm": "yes"}).status_code, 403)
        self.assertEqual(client.post(self.delete, HTTP_X_CSRFTOKEN=token).status_code, 400)
        client.force_login(self.reader)
        self.assertEqual(client.post(self.delete, {"confirm": "yes"}, HTTP_X_CSRFTOKEN=token).status_code, 403)
        self.assertTrue(Device.objects.filter(pk=self.device.pk).exists())
        self.assertTrue(PublicIP.objects.filter(pk=ip.pk).exists())

    def test_confirmation_is_informational_even_with_multiple_assignments(self):
        self.assignment("8.8.8.8"); self.assignment("8.8.4.4")
        response = self.client.get(self.delete)
        self.assertEqual(response.context["assigned_ip_count"], 2)
        self.assertContains(response, "permanently deleted from NetShield")
        self.assertContains(response, "Router cleanup will not be performed")
        self.assertNotContains(response, "Deletion is blocked")
        self.assertTrue(Device.objects.filter(pk=self.device.pk).exists())
        self.assertEqual(PublicIP.objects.filter(device=self.device).count(), 2)

    def test_stale_counter_references_are_removed_without_deleting_other_rows(self):
        ip = self.assignment("8.8.8.8")
        sample = FirewallSample.objects.create(device=self.other, rows=[
            {"id": ip.pk, "device_id": self.device.pk, "pps": 99},
            {"id": self.unrelated.pk, "device_id": self.other.pk, "pps": 10},
        ])
        response = self.delete_device()
        self.assertEqual(response.status_code, 200)
        sample.refresh_from_db()
        self.assertEqual(sample.rows, [{"id": self.unrelated.pk, "device_id": self.other.pk, "pps": 10}])
        self.assertTrue(Device.objects.filter(pk=self.other.pk).exists())
        self.assertTrue(PublicIP.objects.filter(pk=self.unrelated.pk).exists())

    def test_confirmation_loads_text_decoder_without_unescaping_html(self):
        self.device.name = "Router <script>alert(1)</script>"
        self.device.save()
        response = self.client.get(self.delete)
        self.assertContains(response, "confirmation_text.js")
        self.assertContains(response, "Router &lt;script&gt;alert(1)&lt;/script&gt;")
        self.assertNotContains(response, "Router <script>")
        self.assertContains(response, "permanently deleted from NetShield")
        self.assertTrue(Device.objects.filter(pk=self.device.pk).exists())
