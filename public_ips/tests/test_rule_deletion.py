"""Removing a public IP deletes exactly its three MONITOR RAW rules, matched by comment."""
import os
import secrets
from unittest.mock import MagicMock, patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from devices.models import Device
from public_ips.services.device_approval import device_fingerprint
from public_ips.models import PublicIP
from public_ips.services.rule_deletion import delete_monitor_rules

KEEP = "185.166.26.115"
REMOVE = "185.166.25.75"


def rule(identifier, comment, address):
    return {"id": identifier, "chain": "prerouting", "action": "passthrough",
            "comment": comment, "dst-address": address,
            "in-interface": "ether1", "disabled": "false", "dynamic": "false"}


class RuleDeletionTests(TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start(); self.addCleanup(env.stop)
        self.admin = get_user_model().objects.create_user(username="cleanup-admin", is_staff=True)
        self.client.force_login(self.admin)
        self.device = Device(name="Edge", management_ip="172.26.241.16", username="private-account",
                             incoming_monitoring_interface="ether1")
        self.device.set_password(secrets.token_urlsafe(24)); self.device.save()
        # Authorize router writes so cleanup is permitted (same gate as provisioning).
        Device.objects.filter(pk=self.device.pk).update(
            raw_provisioning_enabled=True, raw_provisioning_authorized_at=timezone.now(),
            raw_provisioning_authorized_by=self.admin)
        self.device.refresh_from_db()
        Device.objects.filter(pk=self.device.pk).update(raw_provisioning_fingerprint=device_fingerprint(self.device))
        # Two public IPs on the same device; each has its own three rules.
        self.target = PublicIP.objects.create(address=REMOVE, device=self.device, incoming_monitoring_interface="ether1",
                                              provisioning_status="verified", provisioning_verified_at=timezone.now())
        self.other = PublicIP.objects.create(address=KEEP, device=self.device, incoming_monitoring_interface="ether1",
                                             provisioning_status="verified", provisioning_verified_at=timezone.now())
        self.rows = [
            rule("*1", f"MONITOR-{REMOVE}", REMOVE), rule("*2", f"MONITOR-SYN-{REMOVE}", REMOVE),
            rule("*3", f"MONITOR-UDP-{REMOVE}", REMOVE),
            rule("*4", f"MONITOR-{KEEP}", KEEP), rule("*5", f"MONITOR-SYN-{KEEP}", KEEP),
            rule("*6", f"MONITOR-UDP-{KEEP}", KEEP),
            rule("*7", "SOME-OTHER-RULE", KEEP),  # unrelated rule must never be touched
        ]

    def fake_api(self):
        raw = MagicMock()
        raw.get.side_effect = lambda: [dict(row) for row in self.rows]
        def remove(id):
            self.rows[:] = [row for row in self.rows if row["id"] != id]
        raw.remove.side_effect = remove
        api = MagicMock()
        api.get_resource.return_value = raw
        return api, raw

    def run_cleanup(self, address=REMOVE):
        api, raw = self.fake_api()
        with patch("public_ips.services.rule_deletion.writes_enabled", return_value=True), \
                patch("public_ips.services.rule_deletion.router_session") as session:
            session.return_value.__enter__.return_value = api
            result = delete_monitor_rules(self.device, address, "ether1", self.admin)
        return result, raw

    def test_deletes_exactly_the_three_rules_for_this_ip(self):
        result, raw = self.run_cleanup()
        self.assertTrue(result.success, result.message)
        self.assertCountEqual(result.removed, [f"MONITOR-{REMOVE}", f"MONITOR-SYN-{REMOVE}", f"MONITOR-UDP-{REMOVE}"])
        removed_ids = {call.kwargs["id"] for call in raw.remove.call_args_list}
        self.assertEqual(removed_ids, {"*1", "*2", "*3"})
        # The other IP's rules and the unrelated rule are untouched.
        remaining = {row["comment"] for row in self.rows}
        self.assertEqual(remaining, {f"MONITOR-{KEEP}", f"MONITOR-SYN-{KEEP}", f"MONITOR-UDP-{KEEP}", "SOME-OTHER-RULE"})

    def test_missing_rules_are_skipped_not_failed(self):
        # Pretend the router was already cleaned manually: nothing to remove.
        self.rows[:] = [row for row in self.rows if REMOVE not in row["comment"]]
        result, raw = self.run_cleanup()
        self.assertTrue(result.success, result.message)
        self.assertEqual(result.removed, [])
        self.assertEqual(len(result.missing), 3)
        raw.remove.assert_not_called()

    def test_partial_rules_only_remove_what_exists(self):
        self.rows[:] = [row for row in self.rows if row["id"] != "*2"]  # SYN rule already gone
        result, raw = self.run_cleanup()
        self.assertTrue(result.success, result.message)
        self.assertCountEqual(result.removed, [f"MONITOR-{REMOVE}", f"MONITOR-UDP-{REMOVE}"])
        self.assertEqual(result.missing, [f"MONITOR-SYN-{REMOVE}"])
        self.assertEqual({call.kwargs["id"] for call in raw.remove.call_args_list}, {"*1", "*3"})

    def test_api_failure_reports_failure(self):
        with patch("public_ips.services.rule_deletion.writes_enabled", return_value=True), \
                patch("public_ips.services.rule_deletion.router_session", side_effect=OSError("boom")):
            result = delete_monitor_rules(self.device, REMOVE, "ether1", self.admin)
        self.assertFalse(result.success)
        self.assertIn("could not be reached", result.message)

    def test_disabled_gate_never_connects(self):
        with patch("public_ips.services.rule_deletion.writes_enabled", return_value=False), \
                patch("public_ips.services.rule_deletion.router_session") as session:
            result = delete_monitor_rules(self.device, REMOVE, "ether1", self.admin)
        self.assertEqual(result.code, "approval_required")
        session.assert_not_called()

    def test_deleting_public_ip_cleans_rules_first(self):
        url = reverse("public_ip_delete", args=[self.target.pk])
        api, raw = self.fake_api()
        with patch("public_ips.services.rule_deletion.writes_enabled", return_value=True), \
                patch("public_ips.services.rule_deletion.router_session") as session:
            session.return_value.__enter__.return_value = api
            response = self.client.post(url, {"confirm": "yes"}, follow=True)
        self.assertContains(response, "RAW monitoring rules removed")
        self.assertEqual({call.kwargs["id"] for call in raw.remove.call_args_list}, {"*1", "*2", "*3"})
        self.assertFalse(PublicIP.objects.filter(pk=self.target.pk).exists())
        self.assertTrue(PublicIP.objects.filter(pk=self.other.pk).exists())

    def test_removal_is_blocked_when_router_is_unreachable(self):
        url = reverse("public_ip_delete", args=[self.target.pk])
        with patch("public_ips.services.rule_deletion.writes_enabled", return_value=True), \
                patch("public_ips.services.rule_deletion.router_session", side_effect=OSError("unreachable")):
            response = self.client.post(url, {"confirm": "yes"}, follow=True)
        self.assertContains(response, "was not removed")
        # The public IP must still exist: no silent divergence from the router.
        self.assertTrue(PublicIP.objects.filter(pk=self.target.pk).exists())

    def test_no_router_connection_when_device_not_authorized(self):
        url = reverse("public_ip_delete", args=[self.target.pk])
        Device.objects.filter(pk=self.device.pk).update(raw_provisioning_authorized_at=None,
                                                       raw_provisioning_authorized_by=None,
                                                       raw_provisioning_fingerprint="")
        with patch("public_ips.services.rule_deletion.writes_enabled", return_value=False), \
                patch("routeros_api.RouterOsApiPool") as pool:
            response = self.client.post(url, {"confirm": "yes"}, follow=True)
        pool.assert_not_called()
        self.assertFalse(PublicIP.objects.filter(pk=self.target.pk).exists())
        self.assertContains(response, "No RAW monitoring rules needed removal")
