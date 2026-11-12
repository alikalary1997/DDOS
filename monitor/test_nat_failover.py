"""Automatic NAT failover: one SOS Public for the device, only matching comments touched."""
import os
from unittest.mock import MagicMock, patch

from cryptography.fernet import Fernet
from django.test import TestCase
from django.utils import timezone

from devices.models import Device
from monitor.models import (DetectionState, DeviceDDoSProtection, DeviceDDoSProtectionRule, NatFailoverLog)
from monitor.services.nat_failover import evaluate_device_failover
from public_ips.models import PublicIP

PRIMARY = "185.166.27.16"
SOS = "185.166.27.99"
ATTACK_IP = "185.166.26.115"


class NatFailoverTests(TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start(); self.addCleanup(env.stop)
        self.device = Device(name="Edge", management_ip="172.26.241.16", username="u", incoming_monitoring_interface="ether1")
        self.device.set_password("p"); self.device.save()
        self.ip = PublicIP.objects.create(address=ATTACK_IP, device=self.device, incoming_monitoring_interface="ether1",
                                          provisioning_status="verified", provisioning_verified_at=timezone.now(),
                                          monitoring_enabled=True)
        # ONE SOS Public + ONE Protection toggle for the whole device.
        self.protection = DeviceDDoSProtection.objects.create(device=self.device, sos_public=SOS, enabled=True)
        self.rule = DeviceDDoSProtectionRule.objects.create(protection=self.protection, position=0, name="iQ-25-01")
        self.other = DeviceDDoSProtectionRule.objects.create(protection=self.protection, position=1, name="iQ-25-02")
        self.rows = [
            self.nat("*1", "iQ-25-01", PRIMARY),
            self.nat("*2", "iQ-25-02", "185.166.27.20"),
            {"id": "*3", "chain": "srcnat", "action": "masquerade", "comment": "defconf masquerade"},
            {"id": "*4", "chain": "dstnat", "action": "dst-nat", "comment": "APP-Cards", "to-addresses": "10.0.0.5"},
        ]

    @staticmethod
    def nat(identifier, comment, address):
        return {"id": identifier, "chain": "srcnat", "action": "src-nat", "comment": comment, "to-addresses": address}

    def fake_api(self):
        nat = MagicMock()
        nat.get.side_effect = lambda: [dict(row) for row in self.rows]
        def set_(**kwargs):
            for row in self.rows:
                if row["id"] == kwargs["id"]:
                    row["to-addresses"] = kwargs["to-addresses"]
        nat.set.side_effect = set_
        api = MagicMock(); api.get_resource.return_value = nat
        return api, nat

    @staticmethod
    def session_for(api):
        session = MagicMock()
        session.return_value.__enter__.return_value = api
        session.return_value.__exit__.return_value = False
        return session

    def set_state(self, status):
        DetectionState.objects.update_or_create(public_ip=self.ip, defaults={"profile_key": "p", "confirmed_status": status})

    def run_failover(self):
        api, nat = self.fake_api()
        with patch("monitor.services.nat_failover.router_session", return_value=self.session_for(api).return_value):
            logs = evaluate_device_failover(self.device.pk)
        return nat, logs

    def to_address(self, comment):
        return next(row.get("to-addresses") for row in self.rows if row.get("comment") == comment)

    def test_switches_every_listed_entry_to_the_single_sos(self):
        self.set_state("Under Attack")
        nat, logs = self.run_failover()
        self.assertCountEqual([c.kwargs["id"] for c in nat.set.call_args_list], ["*1", "*2"])
        self.assertTrue(all(c.kwargs["to-addresses"] == SOS for c in nat.set.call_args_list))
        self.assertEqual({log.result for log in logs}, {"switched"})
        # Non-listed rules untouched.
        self.assertNotIn("to-addresses", self.rows[2])
        self.assertEqual(self.to_address("APP-Cards"), "10.0.0.5")

    def test_only_matching_comments_are_modified(self):
        self.protection.rules.exclude(name="iQ-25-01").delete()
        self.set_state("Under Attack")
        nat, _ = self.run_failover()
        self.assertEqual([c.kwargs["id"] for c in nat.set.call_args_list], ["*1"])
        self.assertEqual(self.to_address("iQ-25-02"), "185.166.27.20")   # other entry kept
        self.assertNotIn("to-addresses", self.rows[2])

    def test_single_unconfirmed_sample_does_not_switch(self):
        for status in ("Warning", "Unknown", "Normal"):
            with self.subTest(status=status):
                self.rows[0]["to-addresses"] = PRIMARY
                DeviceDDoSProtectionRule.objects.update(switched_at=None, switched_from="")
                self.set_state(status)
                nat, logs = self.run_failover()
                nat.set.assert_not_called()
                self.assertEqual(logs, [])

    def test_protection_off_never_touches_any_rule(self):
        self.protection.enabled = False; self.protection.save()
        self.set_state("Under Attack")
        nat, logs = self.run_failover()
        nat.set.assert_not_called()
        self.assertEqual(logs, [])

    def test_does_not_reswitch_an_already_switched_entry(self):
        self.set_state("Under Attack")
        nat, _ = self.run_failover()
        self.assertEqual(len(nat.set.call_args_list), 2)
        nat.set.reset_mock()
        nat2, logs2 = self.run_failover()
        nat2.set.assert_not_called()
        self.assertEqual(logs2, [])

    def test_no_switch_back_after_recovery(self):
        self.set_state("Under Attack")
        self.run_failover()
        self.rows[0]["to-addresses"] = PRIMARY   # would be re-applied if it reverted
        self.set_state("Normal")
        nat, logs = self.run_failover()
        nat.set.assert_not_called()
        self.assertEqual(logs, [])

    def test_already_on_sos_is_not_rewritten(self):
        self.rows[0]["to-addresses"] = SOS
        self.protection.rules.exclude(name="iQ-25-01").delete()
        self.set_state("Under Attack")
        nat, _ = self.run_failover()
        nat.set.assert_not_called()

    def test_missing_rule_is_logged_as_skipped(self):
        DeviceDDoSProtectionRule.objects.update(name="does-not-exist")
        self.set_state("Under Attack")
        nat, logs = self.run_failover()
        nat.set.assert_not_called()
        self.assertEqual([log.result for log in logs], ["skipped", "skipped"])

    def test_api_failure_is_logged_and_not_marked_switched(self):
        self.protection.rules.exclude(name="iQ-25-01").delete()
        self.set_state("Under Attack")
        api, nat = self.fake_api()
        nat.set.side_effect = RuntimeError("api exploded")
        with patch("monitor.services.nat_failover.router_session", return_value=self.session_for(api).return_value):
            logs = evaluate_device_failover(self.device.pk)
        self.assertEqual([log.result for log in logs], ["failed"])
        self.rule.refresh_from_db(); self.assertIsNone(self.rule.switched_at)
        self.assertIn("could not be updated", logs[0].message)

    def test_unreachable_device_is_logged_as_failure(self):
        from devices.services.router_session import RouterAccessError
        self.set_state("Under Attack")
        with patch("monitor.services.nat_failover.router_session",
                   side_effect=RouterAccessError("api_failed", "The RouterOS API operation failed.")):
            logs = evaluate_device_failover(self.device.pk)
        self.assertEqual([log.result for log in logs], ["failed"])
        self.rule.refresh_from_db(); self.assertIsNone(self.rule.switched_at)

    def test_no_sos_public_configured_changes_nothing(self):
        self.protection.sos_public = ""; self.protection.save()
        self.set_state("Under Attack")
        nat, logs = self.run_failover()
        nat.set.assert_not_called()
        self.assertEqual(logs, [])

    def test_switches_while_the_polling_cycle_holds_the_router_lock(self):
        """Regression: the signal fires inside the poller's router_lock.

        Re-acquiring the lock there raised RouterBusy, so a real attack never switched.
        """
        from devices.services.router_lock import router_lock
        from monitor.signals import POLL_LOCK_HELD
        from public_ips.models import FirewallSample

        self.set_state("Under Attack")
        self.protection.rules.exclude(name="iQ-25-01").delete()
        api, nat = self.fake_api()
        sample = FirewallSample.objects.create(device=self.device, status="not_monitored", rows=[])
        with patch("monitor.services.nat_failover.router_session", return_value=self.session_for(api).return_value):
            with router_lock(self.device.pk):            # simulate the polling worker
                token = POLL_LOCK_HELD.set(True)          # and its signal to the failover check
                try:
                    sample.status = "sampled"
                    sample.save()                         # fires detection + failover
                finally:
                    POLL_LOCK_HELD.reset(token)
        self.assertEqual(len(nat.set.call_args_list), 1)
        self.assertEqual(nat.set.call_args_list[0].kwargs["id"], "*1")
        self.assertEqual(self.to_address("iQ-25-01"), SOS)
        self.assertEqual(NatFailoverLog.objects.filter(result="switched").count(), 1)

    def test_log_records_old_and_new_addresses(self):
        self.protection.rules.exclude(name="iQ-25-01").delete()
        self.set_state("Under Attack")
        self.run_failover()
        log = NatFailoverLog.objects.get()
        self.assertEqual((log.old_address, log.new_address), (PRIMARY, SOS))
        self.assertEqual(log.nat_comment, "iQ-25-01")
        self.assertEqual(log.trigger_address, ATTACK_IP)
        self.assertEqual(log.device_name, "Edge")
