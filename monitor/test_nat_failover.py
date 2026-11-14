"""DDoS Protection failover: scoped NAT switching + an always-on Null-IP route."""
import os
from contextlib import contextmanager
from unittest.mock import Mock, patch

from cryptography.fernet import Fernet
from django.test import TestCase
from django.utils import timezone

from devices.models import Device
from monitor.models import (DeviceDDoSProtection, DeviceDDoSProtectionRule, DetectionState, NatFailoverLog)
from monitor.services.nat_failover import evaluate_device_failover
from public_ips.models import PublicIP

PRIMARY = "185.166.27.16"
SECOND = "185.166.27.20"
SOS = "185.166.27.99"
NULL_IP = "192.0.2.1"
ATTACK_IP = "185.166.26.115"


# RouterOS resources are mocked with callable objects, not lambdas: Mock treats a plain
# function assigned to side_effect as a *spec* and calls it with the mock's attributes.
class _NatRows:
    def __init__(self, case):
        self.case = case

    def __call__(self):
        # Plain dicts (not copies): a test's edit must be what the service reads back.
        return list(self.case.rows)


class _NatSet:
    def __init__(self, case):
        self.case = case

    def __call__(self, **kwargs):
        for row in self.case.rows:
            if isinstance(row, dict) and row["id"] == kwargs["id"]:
                row["to-addresses"] = kwargs["to-addresses"]


class _RouteRows:
    def __init__(self, case):
        self.case = case

    def __call__(self):
        return list(self.case.route_rows)


class _RouteAdd:
    def __init__(self, case):
        self.case = case

    def __call__(self, **kwargs):
        self.case.route_add_calls.append(kwargs)
        self.case.route_rows.append(dict(kwargs, id=f"*r{len(self.case.route_rows)}"))
        return None


class _Resources:
    def __init__(self, nat, routes):
        self.mapping = {"/ip/firewall/nat": nat, "/ip/route": routes}

    def __call__(self, name):
        return self.mapping[name]


class NatFailoverTests(TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start(); self.addCleanup(env.stop)
        self.device = Device(name="Edge", management_ip="172.26.241.16", username="u", incoming_monitoring_interface="ether1")
        self.device.set_password("p"); self.device.save()
        self.ip = PublicIP.objects.create(address=ATTACK_IP, device=self.device, incoming_monitoring_interface="ether1",
                                          provisioning_status="verified", provisioning_verified_at=timezone.now(),
                                          monitoring_enabled=True)
        self.other_ip = PublicIP.objects.create(address=SECOND, device=self.device, incoming_monitoring_interface="ether1",
                                                provisioning_status="verified", provisioning_verified_at=timezone.now(),
                                                monitoring_enabled=True)
        # ONE SOS Public + ONE Null IP + ONE Protection toggle for the whole device.
        self.protection = DeviceDDoSProtection.objects.create(device=self.device, sos_public=SOS, null_ip="", enabled=True)
        self.rule = DeviceDDoSProtectionRule.objects.create(protection=self.protection, position=0, name="iQ-25-01")
        self.other = DeviceDDoSProtectionRule.objects.create(protection=self.protection, position=1, name="iQ-25-02")
        self.rows = [
            self.nat("*1", "iQ-25-01", PRIMARY),
            self.nat("*2", "iQ-25-02", SECOND),
            {"id": "*3", "chain": "srcnat", "action": "masquerade", "comment": "defconf masquerade"},
            {"id": "*4", "chain": "dstnat", "action": "dst-nat", "comment": "APP-Cards", "to-addresses": "10.0.0.5"},
        ]
        self.route_rows = []
        self.route_add_calls = []

    # --- mock RouterOS API -------------------------------------------------
    @staticmethod
    def nat(identifier, comment, address):
        return {"id": identifier, "chain": "srcnat", "action": "src-nat", "comment": comment, "to-addresses": address}

    def fake_api(self):
        """A RouterOS API whose NAT and route resources read/write the plain dict rows above."""
        case = self
        nat = Mock()
        nat.get.side_effect = _NatRows(case)
        nat.set.side_effect = _NatSet(case)
        routes = Mock()
        routes.get.side_effect = _RouteRows(case)
        routes.add.side_effect = _RouteAdd(case)
        api = Mock()
        api.get_resource.side_effect = _Resources(nat, routes)
        return api, nat, routes

    @staticmethod
    def session_for(api):
        @contextmanager
        def session(_device):
            yield api

        return session

    # --- helpers -----------------------------------------------------------
    def set_state(self, status, public_ip=None):
        DetectionState.objects.update_or_create(public_ip=public_ip or self.ip,
                                                defaults={"profile_key": "p", "confirmed_status": status})

    def set_null_ip(self, value):
        self.protection.null_ip = value; self.protection.save()

    def run_failover(self):
        api, nat, routes = self.fake_api()
        with patch("monitor.services.nat_failover.router_session", new=self.session_for(api)):
            logs = evaluate_device_failover(self.device.pk)
        return nat, routes, logs

    def to_address(self, comment):
        return next(row.get("to-addresses") for row in self.rows
                    if isinstance(row, dict) and row.get("comment") == comment)

    def set_ids(self, nat):
        return [call.kwargs["id"] for call in nat.set.call_args_list]

    # --- (a) only the rule serving the attacked IP changes -----------------
    def test_only_the_rule_serving_the_attacked_ip_is_switched(self):
        self.rows[0]["to-addresses"] = ATTACK_IP
        self.set_state("Under Attack")
        nat, _routes, logs = self.run_failover()
        self.assertEqual(self.set_ids(nat), ["*1"])
        self.assertEqual(self.to_address("iQ-25-01"), SOS)
        self.assertEqual(self.to_address("iQ-25-02"), SECOND)     # untouched
        self.assertNotIn("to-addresses", self.rows[2])            # masquerade untouched
        self.assertEqual(self.to_address("APP-Cards"), "10.0.0.5")
        self.assertEqual([log.result for log in logs], ["switched"])

    def test_non_listed_rule_serving_the_attacked_ip_is_never_touched(self):
        """Matching is by to-addresses AND the device's entry names - a stray rule is left alone."""
        self.rows.append(self.nat("*5", "some-other-rule", ATTACK_IP))
        self.rows[0]["to-addresses"] = ATTACK_IP
        self.set_state("Under Attack")
        nat, _routes, _logs = self.run_failover()
        self.assertEqual(self.set_ids(nat), ["*1"])
        self.assertEqual(self.to_address("some-other-rule"), ATTACK_IP)

    # --- (b) no matching rule -> no NAT rule changes -----------------------
    def test_no_matching_rule_changes_nothing(self):
        self.rows[0]["to-addresses"] = PRIMARY
        self.set_state("Under Attack")
        nat, _routes, logs = self.run_failover()
        nat.set.assert_not_called()
        self.assertEqual([log.result for log in logs], ["skipped"])
        self.assertIn("No NAT rule matching", logs[0].message)

    # --- (c) the Null-IP route is unconditional ---------------------------
    def test_null_route_added_when_a_nat_rule_matches(self):
        self.set_null_ip(NULL_IP)
        self.rows[0]["to-addresses"] = ATTACK_IP
        self.set_state("Under Attack")
        nat, routes, logs = self.run_failover()
        self.assertEqual(self.set_ids(nat), ["*1"])
        self.assertEqual(self.route_add_calls, [{
            "disabled": "no", "dst-address": f"{ATTACK_IP}/32", "gateway": NULL_IP, "routing-table": "main"}])
        self.assertEqual({log.result for log in logs}, {"switched"})

    def test_null_route_added_when_no_nat_rule_matches(self):
        self.set_null_ip(NULL_IP)
        self.rows[0]["to-addresses"] = PRIMARY
        self.set_state("Under Attack")
        nat, routes, logs = self.run_failover()
        nat.set.assert_not_called()
        self.assertEqual(len(self.route_add_calls), 1)
        self.assertEqual(self.route_add_calls[0]["dst-address"], f"{ATTACK_IP}/32")
        self.assertEqual([log.result for log in logs], ["skipped", "switched"])

    def test_route_is_not_added_twice_and_never_reverted(self):
        self.set_null_ip(NULL_IP)
        self.rows[0]["to-addresses"] = ATTACK_IP
        self.set_state("Under Attack")
        self.run_failover()
        self.run_failover()               # second run sees the existing route
        self.assertEqual(len(self.route_rows), 1)
        self.assertEqual(self.route_rows[0]["dst-address"], f"{ATTACK_IP}/32")
        self.assertEqual(self.to_address("iQ-25-01"), SOS)

    # --- (d) Null IP unset -> route skipped, NAT step still runs ----------
    def test_null_ip_unset_skips_route_but_still_switches_nat(self):
        self.rows[0]["to-addresses"] = ATTACK_IP
        self.set_state("Under Attack")
        nat, _routes, _logs = self.run_failover()
        self.assertEqual(self.route_add_calls, [])
        self.assertEqual(self.set_ids(nat), ["*1"])
        self.assertEqual(self.to_address("iQ-25-01"), SOS)

    def test_null_ip_unset_without_nat_match_logs_why_no_route_was_added(self):
        self.rows[0]["to-addresses"] = PRIMARY
        self.set_state("Under Attack")
        _nat, _routes, logs = self.run_failover()
        self.assertEqual(self.route_add_calls, [])
        self.assertEqual([log.result for log in logs], ["skipped"])

    def test_route_step_failure_does_not_break_the_nat_step(self):
        self.set_null_ip(NULL_IP)
        self.rows[0]["to-addresses"] = ATTACK_IP
        self.set_state("Under Attack")
        api, nat, routes = self.fake_api()
        routes.add.side_effect = RuntimeError("route api exploded")
        with patch("monitor.services.nat_failover.router_session", new=self.session_for(api)):
            logs = evaluate_device_failover(self.device.pk)
        self.assertEqual(self.set_ids(nat), ["*1"])          # NAT step still ran
        self.assertEqual(sorted(log.result for log in logs), ["failed", "switched"])
        self.assertTrue(any("could not be added" in log.message for log in logs))

    # --- (e) neither action reverts after the attack clears ---------------
    def test_no_switch_back_after_recovery(self):
        self.set_null_ip(NULL_IP)
        self.rows[0]["to-addresses"] = ATTACK_IP
        self.set_state("Under Attack")
        self.run_failover()
        switched_to = self.to_address("iQ-25-01")
        self.rows[0]["to-addresses"] = ATTACK_IP   # would be re-applied if anything reverted
        self.set_state("Normal")
        nat, routes, logs = self.run_failover()
        nat.set.assert_not_called()
        routes.add.assert_not_called()
        self.assertEqual(logs, [])
        self.assertEqual(switched_to, SOS)
        self.assertEqual(self.to_address("iQ-25-01"), ATTACK_IP)   # left exactly as found

    # --- confirmed state only ---------------------------------------------
    def test_single_unconfirmed_sample_does_not_switch(self):
        for status in ("Warning", "Unknown", "Normal"):
            with self.subTest(status=status):
                self.rows[0]["to-addresses"] = ATTACK_IP
                self.set_state(status)
                nat, routes, logs = self.run_failover()
                nat.set.assert_not_called()
                routes.add.assert_not_called()
                self.assertEqual(logs, [])

    def test_protection_off_never_touches_anything(self):
        self.set_null_ip(NULL_IP)
        self.rows[0]["to-addresses"] = ATTACK_IP
        self.protection.enabled = False; self.protection.save()
        self.set_state("Under Attack")
        nat, routes, logs = self.run_failover()
        nat.set.assert_not_called()
        routes.add.assert_not_called()
        self.assertEqual(logs, [])

    def test_already_on_sos_is_not_rewritten(self):
        # Already switched: a second cycle must neither rewrite nor log again.
        self.rows[0]["to-addresses"] = ATTACK_IP
        self.set_state("Under Attack")
        nat, _routes, logs = self.run_failover()
        self.assertEqual(self.set_ids(nat), ["*1"])
        self.assertEqual([log.result for log in logs], ["switched"])
        nat.set.reset_mock()
        nat2, _routes, logs2 = self.run_failover()
        nat2.set.assert_not_called()
        self.assertEqual(logs2, [])

    def test_each_attacked_ip_is_handled_independently(self):
        self.rows[0]["to-addresses"] = ATTACK_IP
        self.set_state("Under Attack")
        self.set_state("Under Attack", public_ip=self.other_ip)
        self.set_null_ip(NULL_IP)
        nat, _routes, _logs = self.run_failover()
        self.assertEqual(sorted(self.set_ids(nat)), ["*1", "*2"])
        self.assertEqual(len(self.route_add_calls), 2)

    def test_api_failure_is_logged_and_leaves_the_rule_alone(self):
        self.rows[0]["to-addresses"] = ATTACK_IP
        self.set_state("Under Attack")
        api, nat, _routes = self.fake_api()
        nat.set.side_effect = RuntimeError("api exploded")
        with patch("monitor.services.nat_failover.router_session", new=self.session_for(api)):
            logs = evaluate_device_failover(self.device.pk)
        self.assertEqual([log.result for log in logs], ["failed"])
        self.assertIn("could not be updated", logs[0].message)
        self.assertEqual(self.to_address("iQ-25-01"), ATTACK_IP)

    def test_unreachable_device_is_logged_as_failure(self):
        from devices.services.router_session import RouterAccessError
        self.set_state("Under Attack")
        with patch("monitor.services.nat_failover.router_session",
                   side_effect=RouterAccessError("api_failed", "The RouterOS API operation failed.")):
            logs = evaluate_device_failover(self.device.pk)
        self.assertEqual([log.result for log in logs], ["failed"])

    def test_no_sos_and_no_null_ip_changes_nothing(self):
        self.protection.sos_public = ""; self.protection.null_ip = ""; self.protection.save()
        self.set_state("Under Attack")
        api, _nat, _routes = self.fake_api()
        with patch("monitor.services.nat_failover.router_session", new=self.session_for(api)):
            logs = evaluate_device_failover(self.device.pk)
        api.get_resource.assert_not_called()
        self.assertEqual(logs, [])

    def test_switches_while_the_polling_cycle_holds_the_router_lock(self):
        """Regression: the signal fires inside the poller's router_lock.

        Re-acquiring the lock there raised RouterBusy, so a real attack never switched.
        """
        from devices.services.router_lock import router_lock
        from monitor.signals import POLL_LOCK_HELD
        from public_ips.models import FirewallSample

        self.rows[0]["to-addresses"] = ATTACK_IP
        self.set_state("Under Attack")
        api, nat, _routes = self.fake_api()
        sample = FirewallSample.objects.create(device=self.device, status="not_monitored", rows=[])
        with patch("monitor.services.nat_failover.router_session", new=self.session_for(api)):
            with router_lock(self.device.pk):            # simulate the polling worker
                token = POLL_LOCK_HELD.set(True)          # and its signal to the failover check
                try:
                    sample.status = "sampled"
                    sample.save()                         # fires detection + failover
                finally:
                    POLL_LOCK_HELD.reset(token)
        self.assertEqual(self.set_ids(nat), ["*1"])
        self.assertEqual(self.to_address("iQ-25-01"), SOS)
        self.assertEqual(NatFailoverLog.objects.filter(result="switched").count(), 1)

    def test_log_records_old_and_new_addresses(self):
        self.rows[0]["to-addresses"] = ATTACK_IP
        self.set_state("Under Attack")
        self.run_failover()
        log = NatFailoverLog.objects.get()
        self.assertEqual((log.old_address, log.new_address), (ATTACK_IP, SOS))
        self.assertEqual(log.nat_comment, "iQ-25-01")
        self.assertEqual(log.trigger_address, ATTACK_IP)
        self.assertEqual(log.device_name, "Edge")
