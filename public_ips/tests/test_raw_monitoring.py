import os
import secrets
import tempfile
from copy import deepcopy
from unittest.mock import MagicMock, patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from devices.models import Device
from public_ips.models import FirewallSample, PublicIP
from public_ips.services.monitoring import RateCalculator, cached_rows, poll_device
from public_ips.services.rules import expected_rules


class RateTests(TestCase):
    def test_supported_intervals_use_actual_elapsed_time_including_sixty_seconds(self):
        from monitor.models import POLLING_INTERVALS
        for interval in POLLING_INTERVALS:
            calculator = RateCalculator()
            calculator.rates(1, "*1", {"packets": 10, "bytes": 100}, 100, ())
            elapsed = interval + .25
            sample = calculator.rates(1, "*1", {"packets": 110, "bytes": 1100}, 100 + elapsed, ())
            self.assertAlmostEqual(sample[2], 100 / elapsed)
            self.assertAlmostEqual(sample[3] / 1000000, 8000 / elapsed / 1000000)

    def test_elapsed_rates_and_zero_traffic(self):
        calculator = RateCalculator()
        first = calculator.rates(1, "*1", {"packets": "100", "bytes": "1000"}, 10, ())
        self.assertEqual(first, (100, 1000, None, None))
        second = calculator.rates(1, "*1", {"packets": "110", "bytes": "2000"}, 12.5, ())
        self.assertEqual(second, (110, 2000, 4.0, 3200.0))
        self.assertEqual(calculator.rates(1, "*1", {"packets": "110", "bytes": "2000"}, 14.5, ())[2:], (0.0, 0.0))

    def test_reset_rollover_missing_and_changed_rules_rebaseline(self):
        for current in ({"packets": "1", "bytes": "1"}, {"packets": None, "bytes": "1000"},
                        {"packets": "1000", "bytes": "-1"}):
            calculator = RateCalculator()
            calculator.rates(1, "*1", {"packets": str(2**64-1), "bytes": str(2**64-1)}, 10, ())
            self.assertEqual(calculator.rates(1, "*1", current, 12, ())[2:], (None, None))
        calculator = RateCalculator()
        calculator.rates(1, "*1", {"packets": "100", "bytes": "1000"}, 10, ("old",))
        self.assertEqual(calculator.rates(1, "*1", {"packets": "110", "bytes": "1100"}, 12, ("new",))[2:], (None, None))
        self.assertEqual(calculator.rates(1, "*2", {"packets": "110", "bytes": "1100"}, 12, ("new",))[2:], (None, None))

    def test_long_gaps_and_invalid_time_do_not_invent_rates(self):
        calculator = RateCalculator()
        calculator.rates(1, "*1", {"packets": 0, "bytes": 0}, 10, ())
        self.assertEqual(calculator.rates(1, "*1", {"packets": 100, "bytes": 1000}, 310, ())[2:], (None, None))
        self.assertEqual(calculator.rates(1, "*1", {"packets": 200, "bytes": 2000}, float("nan"), ())[2:], (None, None))


class RAWMonitoringTests(TestCase):
    def test_interval_change_while_monitoring_preserves_counter_baseline_and_reads_only(self):
        from monitor.models import RAWMonitoringSettings
        with patch("public_ips.services.monitoring.time.monotonic", side_effect=[10, 70]):
            poll_device(self.device.pk, self.calculator)
            RAWMonitoringSettings.objects.update_or_create(pk=1, defaults={"polling_interval": 60})
            for row in self.rows:
                row.update(packets="220", bytes="61000")
            sample = poll_device(self.device.pk, self.calculator)[0]
        self.assertEqual(sample["status"], "Monitoring")
        self.assertEqual(sample["pps"], 2)
        self.assertEqual(sample["mbps"], .008)
        self.assertEqual(sample["polling_interval"], 60)
        self.assertTrue(all(call[0] == "get" for call in self.raw.mock_calls))
        self.assertEqual(self.rows[0]["packets"], "220")

    def test_wait_shortens_and_extends_without_restart_or_api_calls(self):
        from monitor.models import RAWMonitoringSettings
        from public_ips.management.commands.poll_raw_firewall import wait_for_next_cycle
        for initial, changed in ((60, 2), (2, 15)):
            RAWMonitoringSettings.objects.update_or_create(pk=1, defaults={"polling_interval": initial})
            clock = [0]
            def sleep(seconds):
                clock[0] += seconds
                if clock[0] == 1:
                    RAWMonitoringSettings.objects.filter(pk=1).update(polling_interval=changed)
            with patch("public_ips.management.commands.poll_raw_firewall.time.monotonic", side_effect=lambda: clock[0]), \
                 patch("public_ips.management.commands.poll_raw_firewall.time.sleep", side_effect=sleep):
                wait_for_next_cycle(0)
            self.assertEqual(clock[0], changed)
        self.pool.assert_not_called()

    def test_active_worker_finishes_current_cycle_and_uses_changed_interval_without_overlap(self):
        from django.core.management import call_command
        from monitor.models import RAWMonitoringSettings
        clock, starts, running = [0], [], [False]
        def sample(device_id, calculator, *, scope):
            self.assertFalse(running[0])
            running[0] = True
            starts.append(clock[0])
            if len(starts) == 3:
                raise KeyboardInterrupt
            if len(starts) == 1:
                RAWMonitoringSettings.objects.update_or_create(pk=1, defaults={"polling_interval": 10})
            else:
                RAWMonitoringSettings.objects.filter(pk=1).update(polling_interval=2)
            clock[0] += 3  # API cycle takes longer than the second interval.
            running[0] = False
        def sleep(seconds):
            self.assertFalse(running[0])
            clock[0] += seconds
        with patch("public_ips.management.commands.poll_raw_firewall.poll_device", side_effect=sample), \
             patch("public_ips.management.commands.poll_raw_firewall.time.monotonic", side_effect=lambda: clock[0]), \
             patch("public_ips.management.commands.poll_raw_firewall.time.sleep", side_effect=sleep):
            call_command("poll_raw_firewall", device_id=self.device.pk, assignment_id=self.ip.pk, public_ip=self.ip.address)
        self.assertEqual(starts, [0, 10, 13])
        self.pool.assert_not_called()

    def test_second_worker_cannot_overlap(self):
        from django.core.management import call_command
        from django.core.management.base import CommandError
        from devices.services.router_lock import router_lock
        with router_lock(0):
            with self.assertRaisesMessage(CommandError, "already running"):
                call_command("poll_raw_firewall", device_id=self.device.pk, assignment_id=self.ip.pk, public_ip=self.ip.address)
        self.pool.assert_not_called()

    @classmethod
    def setUpTestData(cls):
        cls.admin = get_user_model().objects.create_user(username="raw-admin", is_staff=True)
        cls.reader = get_user_model().objects.create_user(username="raw-reader")

    def setUp(self):
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start()
        self.addCleanup(env.stop)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        settings = override_settings(
            NETSHIELD_RAW_POLLING_ENABLED=True,
            DEVICE_CONNECTION_ALLOWED_NETWORKS=("172.26.241.0/24",),
            NETSHIELD_ROUTER_LOCK_DIRECTORY=directory.name,
        )
        settings.enable()
        self.addCleanup(settings.disable)
        gate = patch("public_ips.services.monitoring.POLLING_RELEASED", True)
        gate.start()
        self.addCleanup(gate.stop)
        self.device = Device(name="Router", management_ip="172.26.241.16",
                             username=secrets.token_urlsafe(16), incoming_monitoring_interface="uplink")
        self.device.set_password(secrets.token_urlsafe(32))
        self.device.save()
        self.ip = PublicIP.objects.create(address="8.8.8.8", device=self.device,
                                          provisioning_status="verified", monitoring_enabled=True)
        self.rows = [dict(row, id="*" + str(i+1), packets="100", bytes="1000")
                     for i, row in enumerate(expected_rules(self.ip.address, "uplink"))]
        factory = patch("devices.services.router_session.routeros_api.RouterOsApiPool")
        self.pool = factory.start()
        self.addCleanup(factory.stop)
        self.raw = self.pool.return_value.get_api.return_value.get_resource.return_value
        self.raw.get.side_effect = lambda: deepcopy(self.rows)
        self.calculator = RateCalculator()

    def test_one_read_per_device_covers_multiple_ips_without_double_counting(self):
        other = PublicIP.objects.create(address="1.1.1.1", device=self.device,
                                         provisioning_status="verified", monitoring_enabled=True)
        self.rows += [dict(row, id="*" + str(i+4), packets="100", bytes="1000")
                      for i, row in enumerate(expected_rules(other.address, "uplink"))]
        with patch("public_ips.services.monitoring.time.monotonic", side_effect=[10, 12]):
            first = poll_device(self.device.pk, self.calculator)
            self.assertEqual(len(first), 2)
            self.assertTrue(all(row["status"] == "Not monitored" for row in first))
            for row in self.rows:
                row.update(packets="120", bytes="2000")
            second = poll_device(self.device.pk, self.calculator)
        self.assertTrue(all(row["status"] == "Monitoring" for row in second))
        self.assertEqual(second[0]["pps"], 10)
        self.assertEqual(second[0]["mbps"], 0.004)
        self.assertEqual(len(second[0]["protocol_rules"]), 2)
        self.assertEqual(self.raw.get.call_count, 2)
        self.assertTrue(all(call[0] == "get" for call in self.raw.mock_calls))
        self.assertEqual([call.args[0] for call in self.pool.return_value.get_api.return_value.get_resource.call_args_list],
                         ["/ip/firewall/raw", "/ip/firewall/raw"])

    def test_scoped_worker_excludes_new_ips_and_other_devices_between_cycles(self):
        from django.core.management import call_command
        import io
        waits = []
        def next_cycle(started):
            waits.append(started)
            if len(waits) == 2:
                raise KeyboardInterrupt
            PublicIP.objects.create(address="1.1.1.1", device=self.device,
                                    provisioning_status="verified", monitoring_enabled=True)
            other = Device(name="Excluded", management_ip="172.26.241.17", username=self.device.username,
                           encrypted_password=self.device.encrypted_password,
                           incoming_monitoring_interface="uplink")
            other.save()
            PublicIP.objects.create(address="9.9.9.9", device=other,
                                    provisioning_status="verified", monitoring_enabled=True)
        with patch("public_ips.management.commands.poll_raw_firewall.wait_for_next_cycle", side_effect=next_cycle):
            call_command("poll_raw_firewall", device_id=self.device.pk, assignment_id=self.ip.pk,
                         public_ip=self.ip.address, stdout=io.StringIO())
        self.assertEqual(self.pool.call_count, 2)
        self.assertTrue(all(call.args[0] == self.device.management_ip for call in self.pool.call_args_list))
        self.assertEqual(FirewallSample.objects.count(), 1)
        self.assertEqual([row["id"] for row in FirewallSample.objects.get().rows], [self.ip.pk])
        self.assertEqual({call[0] for call in self.raw.method_calls}, {"get"})

    def test_scoped_service_rejects_mismatched_identity_before_api(self):
        from public_ips.services.monitoring_scope import MonitoringScope, MonitoringScopeError
        for device_id, assignment_id, address in ((self.device.pk + 1, self.ip.pk, self.ip.address),
                                                 (self.device.pk, self.ip.pk + 1, self.ip.address),
                                                 (self.device.pk, self.ip.pk, "1.1.1.1")):
            scope = MonitoringScope(device_id, assignment_id, address)
            with self.assertRaises(MonitoringScopeError):
                poll_device(self.device.pk, self.calculator, scope=scope)
        self.pool.assert_not_called()

    def test_scoped_service_stops_for_changed_deleted_or_disabled_assignment(self):
        from public_ips.services.monitoring_scope import MonitoringScope, MonitoringScopeError
        for changes in ({"address": "1.1.1.1"}, {"device_id": None},
                        {"monitoring_enabled": False}, {"provisioning_status": "failed"},
                        {"incoming_monitoring_interface": "another-interface"}):
            scope = MonitoringScope(self.device.pk, self.ip.pk, self.ip.address)
            scope.validate()
            PublicIP.objects.filter(pk=self.ip.pk).update(**changes)
            with self.assertRaises(MonitoringScopeError):
                poll_device(self.device.pk, self.calculator, scope=scope)
            PublicIP.objects.filter(pk=self.ip.pk).update(address=self.ip.address, device_id=self.device.pk,
                monitoring_enabled=True, provisioning_status="verified", incoming_monitoring_interface="uplink")
        scope = MonitoringScope(self.device.pk, self.ip.pk, self.ip.address)
        scope.validate()
        self.ip.delete()
        with self.assertRaises(MonitoringScopeError):
            poll_device(self.device.pk, self.calculator, scope=scope)
        self.pool.assert_not_called()

    def test_scoped_worker_exits_if_target_changes_after_first_cycle(self):
        from django.core.management import call_command, CommandError
        import io
        def change_target(started):
            PublicIP.objects.filter(pk=self.ip.pk).update(address="1.1.1.1")
        with patch("public_ips.management.commands.poll_raw_firewall.wait_for_next_cycle", side_effect=change_target):
            with self.assertRaisesMessage(CommandError, "scoped assignment"):
                call_command("poll_raw_firewall", device_id=self.device.pk, assignment_id=self.ip.pk,
                             public_ip=self.ip.address, stdout=io.StringIO())
        self.pool.assert_called_once()

    def test_scoped_worker_ctrl_c_disconnects_and_releases_locks(self):
        from django.core.management import call_command
        from devices.services.router_lock import router_lock
        import io
        self.raw.get.side_effect = KeyboardInterrupt
        output = io.StringIO()
        call_command("poll_raw_firewall", device_id=self.device.pk, assignment_id=self.ip.pk,
                     public_ip=self.ip.address, stdout=output)
        self.assertIn("RAW polling stopped", output.getvalue())
        self.pool.return_value.disconnect.assert_called_once()
        with router_lock(0), router_lock(self.device.pk):
            pass

    def test_scoped_worker_requires_explicit_parameters(self):
        from django.core.management import call_command, CommandError
        with self.assertRaises(CommandError):
            call_command("poll_raw_firewall")
        self.pool.assert_not_called()

    def test_scoped_worker_duration_exits_without_another_poll(self):
        from django.core.management import call_command
        import io
        clock = [0]
        def wait(started, deadline):
            self.assertEqual(deadline, 120)
            clock[0] = 120
        output = io.StringIO()
        with patch("public_ips.management.commands.poll_raw_firewall.time.monotonic", side_effect=lambda: clock[0]), \
             patch("public_ips.management.commands.poll_raw_firewall.wait_for_next_cycle", side_effect=wait), \
             patch("public_ips.management.commands.poll_raw_firewall.poll_device") as poll:
            call_command("poll_raw_firewall", device_id=self.device.pk, assignment_id=self.ip.pk,
                         public_ip=self.ip.address, duration_seconds=120, stdout=output)
        poll.assert_called_once()
        self.assertIn("duration limit reached", output.getvalue())
        from devices.services.router_lock import router_lock
        with router_lock(0):
            pass

    def test_scoped_service_stops_when_device_endpoint_changes(self):
        from public_ips.services.monitoring_scope import MonitoringScope, MonitoringScopeError
        scope = MonitoringScope(self.device.pk, self.ip.pk, self.ip.address)
        scope.validate()
        Device.objects.filter(pk=self.device.pk).update(management_ip="172.26.241.17")
        with self.assertRaises(MonitoringScopeError):
            poll_device(self.device.pk, self.calculator, scope=scope)
        self.pool.assert_not_called()

    def test_scoped_read_discards_sample_when_assignment_changes_during_api(self):
        from public_ips.services.monitoring_scope import MonitoringScope, MonitoringScopeError
        scope = MonitoringScope(self.device.pk, self.ip.pk, self.ip.address)
        def changed_rows():
            PublicIP.objects.filter(pk=self.ip.pk).update(address="1.1.1.1")
            return deepcopy(self.rows)
        self.raw.get.side_effect = changed_rows
        with self.assertRaises(MonitoringScopeError):
            poll_device(self.device.pk, self.calculator, scope=scope)
        self.assertFalse(FirewallSample.objects.exists())
        self.pool.return_value.disconnect.assert_called_once()

    def test_multiple_devices_have_independent_baselines(self):
        other = Device(name="Other", management_ip="172.26.241.17", username=self.device.username,
                       incoming_monitoring_interface="uplink")
        other.set_password(secrets.token_urlsafe(32))
        other.save()
        PublicIP.objects.create(address="1.1.1.1", device=other, provisioning_status="verified", monitoring_enabled=True)
        with patch("public_ips.services.monitoring.time.monotonic", return_value=10):
            poll_device(self.device.pk, self.calculator)
            self.rows = [dict(row, id="*" + str(i+1), packets="100", bytes="1000")
                         for i, row in enumerate(expected_rules("1.1.1.1", "uplink"))]
            result = poll_device(other.pk, self.calculator)
        self.assertEqual(result[0]["status"], "Not monitored")
        self.assertTrue(any(key[0] == self.device.pk for key in self.calculator.previous))
        self.assertTrue(any(key[0] == other.pk for key in self.calculator.previous))

    def test_missing_rule_and_unrelated_destination_not_monitored(self):
        self.rows[0]["dst-address"] = "1.1.1.1"
        result = poll_device(self.device.pk, self.calculator)
        self.assertEqual(result[0]["status"], "No matching RAW rule")
        self.assertIsNone(result[0]["pps"])

    def test_timeout_clears_baselines_and_reports_connection_error(self):
        import socket
        poll_device(self.device.pk, self.calculator)
        self.raw.get.side_effect = socket.timeout("safe test timeout")
        result = poll_device(self.device.pk, self.calculator)
        self.assertEqual(result[0]["status"], "Connection error")
        self.assertEqual(self.calculator.previous, {})
        self.pool.return_value.disconnect.assert_called()

    def test_cache_is_authenticated_and_never_calls_router(self):
        url = reverse("public_ip_monitoring_data")
        self.assertEqual(self.client.get(url).status_code, 302)
        self.client.force_login(self.reader)
        self.assertEqual(self.client.get(url).status_code, 200)
        self.pool.assert_not_called()

    def save_display_sample(self, **changes):
        from django.utils import timezone
        from public_ips.services.monitoring import empty_row
        sample = empty_row(self.ip, "Monitoring", updated_at=timezone.now().isoformat())
        sample.update(packets=100, bytes=2800, pps=10, mbps=0.00224,
                      protocol_rules=[{"name": "MONITOR-UDP-8.8.8.8", "pps": 9.75},
                                      {"name": "MONITOR-SYN-8.8.8.8", "pps": 0}])
        sample.update(changes)
        FirewallSample.objects.update_or_create(device=self.device, defaults={
            "sampled_at": timezone.now(), "status": "sampled", "rows": [sample]})
        return sample

    def test_api_and_initial_cards_use_real_cache_protocol_rates(self):
        sample = self.save_display_sample()
        self.client.force_login(self.reader)
        response = self.client.get(reverse("public_ip_monitoring_data")).json()["rows"][0]
        for key, value in {"pps": 10, "mbps": 0.00224, "syn_pps": 0, "udp_pps": 9.75,
                           "last_update": sample["last_update"], "status": "Monitoring"}.items():
            self.assertEqual(response[key], value)
        from public_ips.views import inventory_context
        from django.test import RequestFactory
        request = RequestFactory().get("/public-ips/")
        request.user = self.reader
        row = inventory_context(request)["public_ip_rows"][0]
        self.assertEqual(row["udp_pps"], response["udp_pps"])
        self.assertEqual(row["syn_pps"], 0)
        self.pool.assert_not_called()

    def test_cache_zero_missing_and_duplicate_protocols_do_not_invent_rates(self):
        self.client.force_login(self.reader)
        for protocols, expected in (([{"name": "MONITOR-UDP-8.8.8.8", "pps": 0}], 0),
                                    ([], None),
                                    ([{"name": "MONITOR-UDP-1.1.1.1", "pps": 20}], None),
                                    ([{"name": "MONITOR-UDP-8.8.8.8", "pps": -1}], None),
                                    ([{"name": "MONITOR-UDP-8.8.8.8", "pps": 5}] * 2, None)):
            self.save_display_sample(pps=0, mbps=0, protocol_rules=protocols)
            row = self.client.get(reverse("public_ip_monitoring_data")).json()["rows"][0]
            self.assertEqual(row["pps"], 0)
            self.assertEqual(row["mbps"], 0)
            self.assertEqual(row["udp_pps"], expected)
            self.assertIsNone(row["syn_pps"])
        self.pool.assert_not_called()

    def test_api_suppresses_stale_disconnected_missing_and_disabled_samples(self):
        from datetime import timedelta
        from django.utils import timezone
        self.client.force_login(self.reader)
        for changes in ({"attempted_at": (timezone.now() - timedelta(minutes=5)).isoformat()},
                        {"status": "Connection error", "message": "RAW counters could not be retrieved."},
                        {"status": "No matching RAW rule", "message": "Missing RAW rule."},
                        {"status": "Not monitored"}):
            self.save_display_sample(**changes)
            row = self.client.get(reverse("public_ip_monitoring_data")).json()["rows"][0]
            self.assertNotEqual(row["status"], "Monitoring")
            if "attempted_at" in changes:
                self.assertTrue(row["retained"])
                self.assertEqual(row["pps"], 10)
            else:
                for key in ("pps", "mbps", "syn_pps", "udp_pps", "last_update"):
                    self.assertIsNone(row[key])
        self.save_display_sample()
        with patch("public_ips.services.monitoring.POLLING_RELEASED", False):
            row = self.client.get(reverse("public_ip_monitoring_data")).json()["rows"][0]
            self.assertEqual(row["udp_pps"], 9.75)
            self.assertTrue(row["retained"])
        self.pool.assert_not_called()

    def test_app_start_is_scoped_idempotent_and_stop_retains_profile(self):
        from public_ips.services.monitoring_runtime import start, stop
        from public_ips.models import MonitoringRun
        from django.core.exceptions import ValidationError
        version = self.ip.updated_at
        with patch("public_ips.services.monitoring_runtime.launch") as launch:
            run = start(self.ip.pk)
            self.assertEqual(start(self.ip.pk).token, run.token)
            other = PublicIP.objects.create(address="1.1.1.1", device=self.device,
                                             provisioning_status="verified", monitoring_enabled=True)
            with self.assertRaises(ValidationError):
                start(other.pk)
            launch.assert_called_once()
        stop([self.ip.pk])
        self.ip.refresh_from_db()
        self.assertFalse(self.ip.monitoring_enabled)
        self.assertEqual(self.ip.updated_at, version)
        self.assertFalse(MonitoringRun.objects.get().active)
        self.pool.assert_not_called()

    def test_app_post_start_launches_worker_and_reader_cannot_start(self):
        from public_ips.models import MonitoringRun
        url = reverse("public_ip_monitoring_control", args=["ip", self.ip.pk, "start"])
        with patch("public_ips.services.monitoring_runtime.launch") as launch:
            self.client.force_login(self.reader)
            self.assertEqual(self.client.post(url).status_code, 403)
            launch.assert_not_called()
            self.client.force_login(self.admin)
            self.assertEqual(self.client.get(url).status_code, 405)
            with patch("public_ips.services.monitoring.POLLING_RELEASED", False):
                self.assertEqual(self.client.post(url).status_code, 302)
            launch.assert_called_once()
            self.assertEqual(MonitoringRun.objects.get().assignment_id_snapshot, self.ip.pk)
        self.pool.assert_not_called()

    def test_managed_worker_uses_app_stop_and_keeps_real_samples(self):
        from public_ips.services.monitoring_runtime import start, stop
        from public_ips.models import MonitoringRun
        from django.core.management import call_command
        from devices.services.router_lock import router_lock
        import io
        with patch("public_ips.services.monitoring_runtime.launch"):
            run = start(self.ip.pk)
        cycles = []
        def wait(started, deadline, managed_token):
            cycles.append(started)
            if len(cycles) == 1:
                for row in self.rows:
                    row.update(packets="200", bytes="2000")
            else:
                stop([self.ip.pk])
        with patch("public_ips.management.commands.poll_raw_firewall.wait_for_next_cycle", side_effect=wait), \
             patch("public_ips.services.monitoring.POLLING_RELEASED", False):
            call_command("poll_raw_firewall", device_id=self.device.pk, assignment_id=self.ip.pk,
                         public_ip=self.ip.address, managed_token=str(run.token), stdout=io.StringIO())
        self.assertEqual(self.pool.call_count, 2)
        self.assertFalse(MonitoringRun.objects.get().active)
        self.assertEqual(cached_rows()[self.ip.pk]["packets"], 200)
        self.assertTrue(cached_rows()[self.ip.pk]["retained"])
        with router_lock(0), router_lock(self.device.pk):
            pass

    def test_last_traffic_survives_zero_and_connection_error(self):
        with patch("public_ips.services.monitoring.time.monotonic", side_effect=[10, 20, 30]):
            poll_device(self.device.pk, self.calculator)
            for row in self.rows:
                row.update(packets="200", bytes="2000")
            poll_device(self.device.pk, self.calculator)
            poll_device(self.device.pk, self.calculator)
        row = cached_rows()[self.ip.pk]
        self.assertEqual(row["pps"], 0)
        self.assertEqual(row["last_traffic"]["pps"], 10)
        import socket
        self.raw.get.side_effect = socket.timeout()
        poll_device(self.device.pk, self.calculator)
        row = cached_rows()[self.ip.pk]
        self.assertTrue(row["retained"])
        self.assertEqual(row["pps"], 0)
        self.assertEqual(row["last_traffic"]["pps"], 10)

    def test_launch_failure_and_stale_heartbeat_never_show_running(self):
        from public_ips.services.monitoring_runtime import start, live_run
        from public_ips.models import MonitoringRun
        from django.core.exceptions import ValidationError
        from django.utils import timezone
        from datetime import timedelta
        with patch("public_ips.services.monitoring_runtime.launch", side_effect=OSError("test")):
            with self.assertRaises(ValidationError):
                start(self.ip.pk)
        self.assertFalse(MonitoringRun.objects.get().active)
        self.assertIsNone(live_run())
        MonitoringRun.objects.update(active=True, started_at=timezone.now()-timedelta(minutes=5))
        self.assertIsNone(live_run())

    def test_disabled_release_gate_blocks_poller_connections(self):
        with patch("public_ips.services.monitoring.POLLING_RELEASED", False):
            self.assertEqual(poll_device(self.device.pk, self.calculator), [])
        self.pool.assert_not_called()

    def test_stale_or_stopped_cache_never_reports_monitoring(self):
        from datetime import timedelta
        from django.utils import timezone
        FirewallSample.objects.create(device=self.device, sampled_at=timezone.now()-timedelta(seconds=20),
                                      status="sampled", rows=[{"id": self.ip.pk, "device_id": self.device.pk, "address": self.ip.address, "status": "Monitoring", "pps": 100}])
        self.assertEqual(cached_rows()[self.ip.pk]["status"], "Not monitored")
        self.assertIsNone(cached_rows()[self.ip.pk]["pps"])

    def test_controls_are_admin_post_csrf_and_only_change_netshield(self):
        url = reverse("public_ip_monitoring_control", args=["ip", self.ip.pk, "stop"])
        self.client.force_login(self.reader)
        self.assertEqual(self.client.post(url).status_code, 403)
        self.client.force_login(self.admin)
        self.assertEqual(self.client.get(url).status_code, 405)
        self.assertEqual(self.client.post(url).status_code, 302)
        self.ip.refresh_from_db()
        self.assertFalse(self.ip.monitoring_enabled)
        self.pool.assert_not_called()

    def test_worker_command_fails_closed_before_loop(self):
        from django.core.management import call_command
        from django.core.management.base import CommandError
        with patch("public_ips.services.monitoring.POLLING_RELEASED", False):
            with self.assertRaises(CommandError):
                call_command("poll_raw_firewall", device_id=self.device.pk, assignment_id=self.ip.pk, public_ip=self.ip.address)
        self.pool.assert_not_called()

    def test_stop_and_restart_rebaseline_even_with_short_pause(self):
        from django.utils import timezone
        with patch("public_ips.services.monitoring.time.monotonic", side_effect=[10, 12]):
            poll_device(self.device.pk, self.calculator)
            PublicIP.objects.filter(pk=self.ip.pk).update(updated_at=timezone.now())
            for row in self.rows:
                row.update(packets="120", bytes="2000")
            result = poll_device(self.device.pk, self.calculator)
        self.assertIsNone(result[0]["pps"])
        self.assertEqual(result[0]["status"], "Not monitored")

    def test_cached_status_invalidates_immediately_after_preference_change(self):
        from django.utils import timezone
        with patch("public_ips.services.monitoring.time.monotonic", side_effect=[10, 12]):
            poll_device(self.device.pk, self.calculator)
            for row in self.rows:
                row.update(packets="120", bytes="2000")
            poll_device(self.device.pk, self.calculator)
        self.assertEqual(cached_rows()[self.ip.pk]["status"], "Monitoring")
        PublicIP.objects.filter(pk=self.ip.pk).update(updated_at=timezone.now())
        self.assertEqual(cached_rows()[self.ip.pk]["status"], "Not monitored")
        self.assertIsNone(cached_rows()[self.ip.pk]["pps"])

    def test_deleted_device_between_selection_and_lock_never_polls_or_recreates_cache(self):
        from contextlib import contextmanager
        from devices.services.management import remove_device
        device_id = self.device.pk
        self.calculator.previous[(device_id, "*1")] = object()
        @contextmanager
        def delete_before_acquiring_lock(identifier):
            self.assertEqual(identifier, device_id)
            remove_device(self.device, self.admin)
            yield
        with patch("public_ips.services.monitoring.router_lock", side_effect=delete_before_acquiring_lock):
            self.assertEqual(poll_device(device_id, self.calculator), [])
        self.pool.assert_not_called()
        self.assertFalse(FirewallSample.objects.filter(device_id=device_id).exists())
        self.assertFalse(any(key[0] == device_id for key in self.calculator.previous))

    def test_error_sample_is_written_before_releasing_device_lock(self):
        from contextlib import contextmanager
        from devices.services.router_session import RouterAccessError
        locked = []
        @contextmanager
        def track_lock(identifier):
            locked.append(identifier)
            try:
                yield
            finally:
                locked.pop()
        original = FirewallSample.objects.update_or_create
        def persist(*args, **kwargs):
            self.assertEqual(locked, [self.device.pk])
            return original(*args, **kwargs)
        with patch("public_ips.services.monitoring.router_lock", side_effect=track_lock), \
             patch("public_ips.services.monitoring.router_session", side_effect=RouterAccessError("connection_error", "unavailable")), \
             patch("public_ips.services.monitoring.FirewallSample.objects.update_or_create", side_effect=persist):
            result = poll_device(self.device.pk, self.calculator)
        self.assertEqual(result[0]["status"], "Connection error")
        self.assertEqual(locked, [])
