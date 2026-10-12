import io
import json
import os
from copy import deepcopy
from unittest.mock import patch
from cryptography.fernet import Fernet

from django.core.management import call_command, CommandError
from django.test import TestCase

from devices.models import Device
from public_ips.models import FirewallSample, PublicIP
from public_ips.services.rules import expected_rules
from devices.services.router_session import RouterAccessError


MODULE = "public_ips.management.commands.sample_raw_readonly"


class ReadOnlyCollectorTests(TestCase):
    def setUp(self):
        patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()}).start()
        self.addCleanup(patch.stopall)
        self.device = Device(name="Diagnostic", management_ip="10.3.15.122", username="test-user",
                             incoming_monitoring_interface="ether1")
        self.device.set_password("test-only-password")
        self.device.save()
        self.ip = PublicIP.objects.create(address="185.166.25.75", device=self.device,
                                          incoming_monitoring_interface="ether1")
        self.rows = [dict(spec, id=f"*{index + 1}", packets="100", bytes="2800")
                     for index, spec in enumerate(expected_rules(self.ip.address, "ether1"))]
        self.session = patch(MODULE + ".router_session").start()
        self.api = self.session.return_value.__enter__.return_value
        self.raw = self.api.get_resource.return_value
        self.raw.get.return_value = self.rows
        patch(MODULE + ".polling_interval", return_value=10).start()

    def run_collector(self, count=1):
        output = io.StringIO()
        call_command("sample_raw_readonly", self.ip.address, samples=count, stdout=output)
        return [json.loads(line) for line in output.getvalue().splitlines()]

    def test_three_samples_one_connection_actual_rates_and_no_database_changes(self):
        before_device = list(Device.objects.values())
        before_ip = list(PublicIP.objects.values())
        later = [dict(row, packets="200", bytes="5600") for row in self.rows]
        self.raw.get.side_effect = [self.rows, later, later]
        with patch(MODULE + ".time.monotonic", side_effect=[10, 20, 20.25, 31, 31]):
            result = self.run_collector(3)
        samples = [item for item in result if item["event"] == "sample"]
        self.assertEqual(samples[0]["rules"][0]["status"], "baseline")
        self.assertAlmostEqual(samples[1]["rules"][0]["pps"], 100 / 10.25)
        self.assertAlmostEqual(samples[1]["rules"][0]["mbps"], 2800 * 8 / 10.25 / 1000000)
        self.assertEqual(samples[2]["rules"][2]["pps"], 0)
        self.session.assert_called_once()
        self.assertEqual({call[0] for call in self.raw.method_calls}, {"get"})
        self.assertEqual(before_device, list(Device.objects.values()))
        self.assertEqual(before_ip, list(PublicIP.objects.values()))
        self.assertFalse(FirewallSample.objects.exists())

    def test_missing_duplicate_and_unsafe_order_stop_without_writes(self):
        for rows in (self.rows[:2], self.rows + [dict(self.rows[0], id="*9")],
                     [dict(id="*9", chain="prerouting", action="drop")] + self.rows):
            self.raw.get.return_value = rows
            with self.assertRaises(CommandError):
                self.run_collector()
        self.assertEqual({call[0] for call in self.raw.method_calls}, {"get"})

    def test_stats_fallback_and_invalid_counters(self):
        self.raw.get.return_value = [{k: v for k, v in row.items() if k not in ("packets", "bytes")}
                                     for row in self.rows]
        stats = deepcopy(self.rows)
        stats[0]["packets"] = "invalid"
        self.raw.call.return_value = stats
        result = self.run_collector()
        self.raw.call.assert_called_once_with("print", {"stats": ""})
        self.assertEqual(result[1]["rules"][0]["status"], "invalid_or_rebaseline")
        self.assertIsNone(result[1]["rules"][0]["pps"])

    def test_api_failure_stops_and_unassigned_ip_never_connects(self):
        self.raw.get.side_effect = RouterAccessError("timeout", "API timed out.")
        with self.assertRaises(CommandError):
            self.run_collector()
        self.session.reset_mock()
        with self.assertRaises(CommandError):
            call_command("sample_raw_readonly", "8.8.8.8", stdout=io.StringIO())
        self.session.assert_not_called()
