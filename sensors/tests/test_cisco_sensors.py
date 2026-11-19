"""SNMP sensors on a Cisco switch: bandwidth (port picker), uptime, ping and neighbours.

A Cisco switch has no RouterOS API, so everything here is plain SNMPv2c. The values come from
standard MIBs (ifTable/ifXTable, sysUpTime) plus the LLDP/CDP neighbour tables, and the tests
pin the parts that are easy to get wrong: which column is walked, zero versus no-reading, and
that a Cisco device is accepted at all.
"""
import os
import secrets
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from devices.models import Device
from devices.services.credentials import encrypt_password
from sensors.models import Sensor, SensorRuntime, SNMPProfile
from sensors.polling import Poller
from sensors import snmp
from sensors.snmp import CDP_NEIGHBOR_COLUMN, Client, LLDP_NEIGHBOR_COLUMN, SNMPError


def rows(column, indexes):
    """Bindings for one walked column: <column root>.<row index>."""
    root = tuple(map(int, column.split(".")))
    return [(root + (index,), 0) for index in indexes]


class FakeWalk:
    """Stands in for Client.bulk_walk: one batch per requested column, then the edge.

    Patching bulk_walk (not the PySNMP command) keeps the test on this code's own contract and
    avoids introspecting PySNMP ObjectType objects, which raise SmiError once constructed.
    """

    def __init__(self, batches):
        self.batches = list(batches)
        self.roots = []

    def __call__(self, prefix, **kwargs):
        self.roots.append(prefix)
        batch = self.batches.pop(0) if self.batches else []

        async def stream():
            return batch
        return stream()


class NeighborCountTests(TestCase):
    def count(self, batches):
        import asyncio
        walk = FakeWalk(batches)

        async def go():
            client = Client("127.0.0.1", "community", 161)
            await client.open()
            try:
                return await client.neighbors()
            finally:
                if client.engine:
                    client.engine.close_dispatcher()
        with patch.object(Client, "bulk_walk", new=walk):
            return asyncio.run(go()), walk

    def test_each_neighbour_is_counted_once(self):
        total, _ = self.count([rows(LLDP_NEIGHBOR_COLUMN, [1, 2, 3])])
        self.assertEqual(total, 3)

    def test_a_single_column_is_walked_not_the_whole_table(self):
        # Walking the table root returns every column for every row: a real switch produced
        # 387 bindings for 43 neighbours. Only one per-row column may be read.
        _, walk = self.count([rows(LLDP_NEIGHBOR_COLUMN, [1])])
        self.assertEqual(walk.roots[0], LLDP_NEIGHBOR_COLUMN)
        self.assertTrue(LLDP_NEIGHBOR_COLUMN.count(".") > snmp.LLDP_NEIGHBOR_COLUMN.count(".") - 1)

    def test_lldp_wins_and_cdp_is_not_double_counted(self):
        # A switch may advertise the same links over both protocols.
        total, walk = self.count([rows(LLDP_NEIGHBOR_COLUMN, [1, 2]),
                                  rows(CDP_NEIGHBOR_COLUMN, [1, 2, 3])])
        self.assertEqual(total, 2, "LLDP describes the links; CDP is ignored")
        self.assertEqual(walk.roots, [LLDP_NEIGHBOR_COLUMN], "CDP is never walked once LLDP answers")

    def test_cdp_is_used_when_a_switch_has_no_lldp(self):
        total, walk = self.count([[], rows(CDP_NEIGHBOR_COLUMN, [5, 6])])
        self.assertEqual(total, 2)
        self.assertEqual(walk.roots, [LLDP_NEIGHBOR_COLUMN, CDP_NEIGHBOR_COLUMN])

    def test_an_empty_table_is_a_real_zero_not_missing_data(self):
        total, _ = self.count([[], []])
        self.assertEqual(total, 0)


class CiscoSensorTests(TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start(); self.addCleanup(env.stop)
        worker = patch("sensors.runtime.ensure_worker")
        worker.start(); self.addCleanup(worker.stop)
        self.admin = get_user_model().objects.create_user(username="cisco-snmp", is_staff=True)
        self.client.force_login(self.admin)
        self.device = Device.objects.create(name="SW-1", management_ip="10.10.10.15",
                                            device_type=Device.DeviceType.CISCO)
        SNMPProfile.objects.create(device=self.device, community=encrypt_password("public"),
                                   validated_ip=self.device.management_ip, tested_at=timezone.now())
        SensorRuntime.objects.create(pk=1, polling_authorized=True)

    def sensor(self, kind, **kwargs):
        return Sensor.objects.create(device=self.device, kind=kind, name=kind, enabled=True,
                                     interval=10, **kwargs)

    def test_a_cisco_device_is_accepted_by_the_snmp_adapter(self):
        # The device-type guard is what used to reject every switch; prove `cisco` passes it.
        device = SimpleNamespace(pk=1, enabled=True, device_type="cisco", management_ip="10.10.10.15", api_port=161)
        with patch("sensors.snmp.Client") as cls, patch("sensors.snmp.validate_target"):
            instance = cls.return_value
            instance.open = AsyncMock()
            instance.uptime = AsyncMock(return_value=12.0)
            instance.engine = None
            self.assertEqual(snmp.read(device, "public", 161, "test"), 12.0)
            instance.uptime.assert_awaited()

    def test_an_unsupported_device_type_is_still_refused(self):
        device = SimpleNamespace(pk=1, enabled=True, device_type="other", management_ip="10.10.10.15", api_port=161)
        with self.assertRaises(SNMPError):
            snmp.read(device, "public", 161, "test")

    def test_neighbours_are_stored_as_a_reading(self):
        sensor = self.sensor("neighbors")
        with patch("sensors.snmp.read", return_value={"uptime_seconds": 100, "neighbor_count": 43}):
            Poller().poll(sensor)
        row = sensor.samples.order_by("-pk").first()
        self.assertTrue(row.valid)
        self.assertEqual(row.neighbor_count, 43)

    def test_zero_neighbours_is_a_valid_zero(self):
        sensor = self.sensor("neighbors")
        with patch("sensors.snmp.read", return_value={"uptime_seconds": 100, "neighbor_count": 0}):
            Poller().poll(sensor)
        row = sensor.samples.order_by("-pk").first()
        self.assertTrue(row.valid)
        self.assertEqual(row.neighbor_count, 0)

    def test_a_failed_neighbour_read_is_not_zero(self):
        sensor = self.sensor("neighbors")
        with patch("sensors.snmp.read", side_effect=SNMPError("SNMP read timed out.")):
            Poller().poll(sensor)
        row = sensor.samples.order_by("-pk").first()
        self.assertFalse(row.valid)
        self.assertIsNone(row.neighbor_count)
        self.assertIn("timed out", row.error)

    def test_neighbours_detect_button_reports_the_count(self):
        response = self.client.post(reverse("sensor_detect", args=[self.device.pk]), {"kind": "neighbors"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"neighbour(s)", response.content)

    def test_bandwidth_detection_lists_real_ports(self):
        ports = [{"index": 10101, "name": "GigabitEthernet0/1", "status": "Up"},
                 {"index": 10106, "name": "GigabitEthernet0/6", "status": "Down"}]
        with patch("sensors.snmp.read", return_value=ports):
            response = self.client.post(reverse("sensor_discover", args=[self.device.pk]), {"kind": "traffic"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "GigabitEthernet0/1")
        self.assertContains(response, "GigabitEthernet0/6")

    def test_a_selected_port_becomes_a_bandwidth_sensor(self):
        import django.core.signing as signing
        ports = [{"index": 10101, "name": "GigabitEthernet0/1", "status": "Up"}]
        token = signing.dumps({"device": self.device.pk, "ip": self.device.management_ip,
                               "revision": SNMPProfile.objects.get(device=self.device).revision,
                               "user": self.admin.pk, "interfaces": ports},
                              salt="snmp-discovery", compress=True)
        response = self.client.post(reverse("sensor_add", args=[self.device.pk]),
                                    {"kind": "traffic", "interval": "10", "discovery": token,
                                     "interfaces": ["10101"]})
        self.assertEqual(response.status_code, 302)
        sensor = Sensor.objects.get(device=self.device, kind="traffic")
        self.assertEqual(sensor.interface_index, 10101)
        self.assertEqual(sensor.interface_name, "GigabitEthernet0/1")

    def test_ping_works_without_snmp_credentials(self):
        with patch("sensors.ping.probe", return_value={"ping_ms": 3.5, "packet_loss": 0.0}):
            response = self.client.post(reverse("sensor_detect", args=[self.device.pk]), {"kind": "ping"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"3.5 ms", response.content)

    def test_the_sensor_page_offers_bandwidth_uptime_ping_and_neighbours(self):
        html = self.client.get(reverse("device_sensors", args=[self.device.pk])).content.decode()
        for kind in ("traffic", "uptime", "ping", "neighbors"):
            self.assertIn(f'value="{kind}"', html)
        # MikroTik-only readings are not offered for a switch.
        cpu = html.split('value="cpu"')[1][:200]
        self.assertIn("disabled", cpu, "CPU readings need the MikroTik HOST-RESOURCES MIB")
