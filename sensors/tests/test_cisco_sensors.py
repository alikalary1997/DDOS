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


class SwitchPortNeighborTests(TestCase):
    """The switch panel's per-port neighbours: LLDP and CDP both have to reach the port.

    A real switch advertised the neighbour on GigabitEthernet0/21 (a LiteBeam radio) only over
    CDP, while LLDP described the same port with an empty chassis name and the port "eth0" -
    so the panel showed "Unknown device / eth0". These tests pin the two things that fixes:
    CDP's ifIndex-based index being joined to a port name, and CDP replacing a blank LLDP row.
    """
    LLDP_BASE = LLDP_NEIGHBOR_COLUMN.rsplit(".", 1)[0]
    CDP_BASE = snmp.CDP_TABLE_ROOT

    def neighbours(self, batches):
        """Run neighbors_by_port against a fixed set of walks.

        `batches` maps a walked OID prefix to [(oid tuple, value), ...]; anything not listed is
        an empty table, so a test states only the columns it cares about.
        """
        import asyncio

        async def fake_walk(self_, prefix, **kwargs):
            return list(batches.get(prefix, []))

        async def go():
            client = Client("127.0.0.1", "community", 161)
            await client.open()
            try:
                return await client.neighbors_by_port()
            finally:
                if client.engine:
                    client.engine.close_dispatcher()
        with patch.object(Client, "bulk_walk", new=fake_walk):
            return asyncio.run(go())

    @staticmethod
    def octets(text):
        return snmp.OctetString(text.encode())

    def test_a_cdp_only_neighbour_reaches_its_port(self):
        # ifDescr gives the port name keyed by ifIndex; the CDP cache is indexed by the same
        # ifIndex, so port 10121 is GigabitEthernet0/21 without any LLDP data at all.
        descr = tuple(map(int, snmp.DESCR.split(".")))
        cdp = tuple(map(int, self.CDP_BASE.split(".")))
        batches = {
            snmp.DESCR: [(descr + (10121,), self.octets("GigabitEthernet0/21"))],
            f"{self.CDP_BASE}.6": [(cdp + (10121, 55), self.octets("OnlineCompany-SL24"))],
            f"{self.CDP_BASE}.7": [(cdp + (10121, 55), self.octets("br0"))],
            f"{self.CDP_BASE}.8": [(cdp + (10121, 55), self.octets("LiteBeam 5AC"))],
        }
        result = self.neighbours(batches)
        entries = result.get("GigabitEthernet0/21", [])
        self.assertEqual(len(entries), 1, result)
        self.assertEqual(entries[0]["name"], "OnlineCompany-SL24")
        self.assertEqual(entries[0]["port"], "br0")
        self.assertEqual(entries[0]["platform"], "LiteBeam 5AC")
        self.assertEqual(entries[0]["protocol"], "CDP")

    def test_cdp_replaces_a_blank_lldp_entry_for_the_same_port(self):
        # LLDP knew the port but not who is on it; CDP is what names the device.
        local = tuple(map(int, snmp.LLDP_LOCAL_PORT_ID.split(".")))
        lldp = tuple(map(int, self.LLDP_BASE.split(".")))
        descr = tuple(map(int, snmp.DESCR.split(".")))
        cdp = tuple(map(int, self.CDP_BASE.split(".")))
        batches = {
            snmp.LLDP_LOCAL_PORT_ID: [(local + (21,), self.octets("Gi0/21"))],
            f"{self.LLDP_BASE}.9": [(lldp + (0, 21, 4), self.octets(""))],
            f"{self.LLDP_BASE}.7": [(lldp + (0, 21, 4), self.octets("eth0"))],
            snmp.DESCR: [(descr + (10121,), self.octets("GigabitEthernet0/21"))],
            f"{self.CDP_BASE}.6": [(cdp + (10121, 55), self.octets("OnlineCompany-SL24"))],
            f"{self.CDP_BASE}.7": [(cdp + (10121, 55), self.octets("br0"))],
            f"{self.CDP_BASE}.8": [(cdp + (10121, 55), self.octets("LiteBeam 5AC"))],
        }
        entries = self.neighbours(batches).get("GigabitEthernet0/21", [])
        self.assertEqual(len(entries), 1, entries)
        self.assertEqual(entries[0]["name"], "OnlineCompany-SL24", "CDP replaced the blank LLDP row")

    def test_cdp_names_the_link_and_lldp_does_not_duplicate_it(self):
        """The reference switch named its neighbour only over CDP.

        `show cdp neighbors Gi0/21` listed a LiteBeam while LLDP on the same port was idle, and
        the app showed "Unknown device / eth0". CDP must therefore win, and the nameless LLDP
        row must not be listed beside it. The two tables also key the port differently
        (Gi0/21 vs GigabitEthernet0/21), which is what made the old merge miss entirely.
        """
        local = tuple(map(int, snmp.LLDP_LOCAL_PORT_ID.split(".")))
        lldp = tuple(map(int, self.LLDP_BASE.split(".")))
        descr = tuple(map(int, snmp.DESCR.split(".")))
        cdp = tuple(map(int, self.CDP_BASE.split(".")))
        batches = {
            snmp.LLDP_LOCAL_PORT_ID: [(local + (21,), self.octets("Gi0/21"))],
            f"{self.LLDP_BASE}.9": [(lldp + (0, 21, 4), self.octets(""))],
            f"{self.LLDP_BASE}.7": [(lldp + (0, 21, 4), self.octets("eth0"))],
            snmp.DESCR: [(descr + (10121,), self.octets("GigabitEthernet0/21"))],
            f"{self.CDP_BASE}.6": [(cdp + (6, 10121, 55), self.octets("OnlineCompany-SL24"))],
            f"{self.CDP_BASE}.7": [(cdp + (7, 10121, 55), self.octets("br0"))],
            f"{self.CDP_BASE}.8": [(cdp + (8, 10121, 55), self.octets("LiteBeam 5AC"))],
        }
        entries = self.neighbours(batches).get("GigabitEthernet0/21", [])
        self.assertEqual(len(entries), 1, entries)
        self.assertEqual(entries[0]["name"], "OnlineCompany-SL24")
        self.assertEqual(entries[0]["protocol"], "CDP")

    def test_several_neighbours_on_one_port_are_all_kept(self):
        """A port can hold more than one CDP neighbour; keying by ifIndex alone loses them.

        ifIndex 10121 carried three (device indexes 55, 89, 90); keeping one row per interface
        dropped the LiteBeam on .55 - the neighbour the user was looking for.
        """
        descr = tuple(map(int, snmp.DESCR.split(".")))
        cdp = tuple(map(int, self.CDP_BASE.split(".")))
        batches = {
            snmp.DESCR: [(descr + (10121,), self.octets("GigabitEthernet0/21"))],
            f"{self.CDP_BASE}.6": [(cdp + (6, 10121, 55), self.octets("LiteBeam-A")),
                                   (cdp + (6, 10121, 89), self.octets("Nexus-B"))],
            f"{self.CDP_BASE}.7": [(cdp + (7, 10121, 55), self.octets("br0")),
                                   (cdp + (7, 10121, 89), self.octets("Eth1/30"))],
            f"{self.CDP_BASE}.8": [(cdp + (8, 10121, 55), self.octets("LiteBeam 5AC")),
                                   (cdp + (8, 10121, 89), self.octets("N3K"))],
        }
        entries = self.neighbours(batches).get("GigabitEthernet0/21", [])
        self.assertEqual({e["name"] for e in entries}, {"LiteBeam-A", "Nexus-B"})

    def test_cdp_is_read_under_the_cisco_enterprise_oid(self):
        """This switch serves the CDP cache only under .1.3.6.1.4.1.9.9.23, not .1.3.6.1.9.9.23.

        Walking the textbook form returns "no more variables left in this MIB view" for every
        column while `show cdp neighbors` lists the neighbours, so the wrong base silently
        reported an empty table.
        """
        self.assertTrue(CDP_NEIGHBOR_COLUMN.startswith("1.3.6.1.4.1.9.9.23"), CDP_NEIGHBOR_COLUMN)
        self.assertEqual(snmp.CDP_TABLE_ROOT, "1.3.6.1.4.1.9.9.23.1.2.1.1")

    def test_a_walk_that_dies_part_way_falls_back_instead_of_reporting_empty(self):
        """A bulk walk that stops mid-table must not be reported as an empty table.

        This is what made every CDP neighbour disappear: the switch dropped the GETBULK part-way
        through, and the code returned the (empty) partial result as though nothing were there.
        The GETNEXT fallback is what keeps the table readable on a loaded switch.
        """
        import asyncio

        root = tuple(map(int, (self.CDP_BASE + ".6").split(".")))
        answers = [(root + (10121, 55), snmp.OctetString(b"OnlineCompany-SL24"))]
        requested = []

        async def fake_query(self_, oids, walk=False):
            requested.append(oids[0])
            if answers:
                return [answers.pop(0)]
            return [(root, snmp.EndOfMibView(b""))]

        async def stop_responding(*args, **kwargs):
            # An error (not a status) is how PySNMP reports a stall: the device stopped
            # answering, it did not refuse the read.
            yield ("No SNMP response received before timeout", snmp.Integer32(0), snmp.Integer32(0), ())

        async def go():
            client = Client("127.0.0.1", "community", 161)
            await client.open()
            try:
                with patch.object(Client, "query", new=fake_query), \
                        patch.object(snmp, "bulk_walk_cmd", new=stop_responding):
                    return await client.bulk_walk(self.CDP_BASE + ".6", limit=100)
            finally:
                if client.engine:
                    client.engine.close_dispatcher()

        out = asyncio.run(go())
        self.assertTrue(requested, "the fallback asked the device row by row")
        self.assertEqual(len(out), 1, out)
        self.assertEqual(out[0][1].prettyPrint(), "OnlineCompany-SL24")


class VlanTests(TestCase):
    """Per-port VLAN membership, read from CISCO-VLAN-MEMBERSHIP-MIB.

    The reference switch was the reason these exist: `show vlan` listed Gi0/1 as an access port
    in VLAN 51, while the VTP tables (CISCO-VTP-MIB) reported every port as a trunk allowing all
    VLANs. Membership only comes from the membership table, indexed by ifIndex.
    """
    PORTS = [{"index": 10101, "name": "GigabitEthernet0/1"},
             {"index": 10303, "name": "GigabitEthernet1/3"}]

    def vlans(self, batches):
        import asyncio

        async def fake_walk(self_, prefix, **kwargs):
            return list(batches.get(prefix, []))

        async def go():
            client = Client("127.0.0.1", "community", 161)
            await client.open()
            try:
                return await client.vlans_by_port(self.PORTS)
            finally:
                if client.engine:
                    client.engine.close_dispatcher()
        with patch.object(Client, "bulk_walk", new=fake_walk):
            return asyncio.run(go())

    @staticmethod
    def vs(prefix, index, value):
        root = tuple(map(int, prefix.split(".")))
        return (root + (index,), value)

    def test_an_access_port_reports_the_vlan_the_switch_shows(self):
        # Gi0/1 is an access port in VLAN 51 on the real switch.
        batches = {
            snmp.VLAN_MEMBERSHIP_VLAN: [self.vs(snmp.VLAN_MEMBERSHIP_VLAN, 10101, snmp.Integer32(51))],
            snmp.VLAN_MEMBERSHIP_STATUS: [self.vs(snmp.VLAN_MEMBERSHIP_STATUS, 10101, snmp.Integer32(2))],
            snmp.VTP_VLAN_NAME: [self.vs(snmp.VTP_VLAN_NAME, 51, snmp.OctetString(b"VLAN0051"))],
        }
        entry = self.vlans(batches)["GigabitEthernet0/1"]
        self.assertEqual(entry["mode"], "access")
        self.assertEqual(entry["access"], 51)
        self.assertEqual(entry["access_name"], "VLAN0051")

    def test_membership_is_indexed_by_ifindex_not_port_number(self):
        # Membership lives at ifIndex 10101; the port number 1 belongs to a different table.
        # Reading the wrong index is what made every port look like VLAN 1.
        batches = {
            snmp.VLAN_MEMBERSHIP_VLAN: [self.vs(snmp.VLAN_MEMBERSHIP_VLAN, 10101, snmp.Integer32(51))],
            snmp.VLAN_MEMBERSHIP_STATUS: [self.vs(snmp.VLAN_MEMBERSHIP_STATUS, 10101, snmp.Integer32(2))],
        }
        self.assertEqual(self.vlans(batches)["GigabitEthernet0/1"]["access"], 51)

    def test_a_trunk_is_reported_as_a_trunk(self):
        batches = {
            snmp.VLAN_MEMBERSHIP_VLAN: [self.vs(snmp.VLAN_MEMBERSHIP_VLAN, 10303, snmp.Integer32(4))],
            snmp.VLAN_MEMBERSHIP_STATUS: [self.vs(snmp.VLAN_MEMBERSHIP_STATUS, 10303, snmp.Integer32(1))],
        }
        entry = self.vlans(batches)["GigabitEthernet1/3"]
        self.assertEqual(entry["mode"], "trunk")
        self.assertEqual(entry["native"], 4)

    def test_a_vlan_the_switch_never_defined_is_flagged(self):
        batches = {
            snmp.VLAN_MEMBERSHIP_VLAN: [self.vs(snmp.VLAN_MEMBERSHIP_VLAN, 10101, snmp.Integer32(4))],
            snmp.VLAN_MEMBERSHIP_STATUS: [self.vs(snmp.VLAN_MEMBERSHIP_STATUS, 10101, snmp.Integer32(2))],
            snmp.VTP_VLAN_NAME: [self.vs(snmp.VTP_VLAN_NAME, 51, snmp.OctetString(b"VLAN0051"))],
        }
        self.assertIn("undefined", self.vlans(batches)["GigabitEthernet0/1"]["access_name"])

    def test_a_port_absent_from_the_table_has_no_membership(self):
        # An uplink or routed port is simply not in the table; it must not be guessed.
        batches = {
            snmp.VLAN_MEMBERSHIP_VLAN: [self.vs(snmp.VLAN_MEMBERSHIP_VLAN, 10101, snmp.Integer32(51))],
            snmp.VLAN_MEMBERSHIP_STATUS: [self.vs(snmp.VLAN_MEMBERSHIP_STATUS, 10101, snmp.Integer32(2))],
        }
        self.assertNotIn("GigabitEthernet1/3", self.vlans(batches))

    def test_a_switch_without_vlan_support_reports_nothing(self):
        self.assertEqual(self.vlans({}), {})


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


class OpticalPowerTests(TestCase):
    """Optical levels for fiber ports, read from CISCO-ENTITY-SENSOR-MIB.

    Verified against a real Catalyst 3560X: the transceivers publish sensors named after their
    port ("Te1/1 Receive Power Sensor"), entSensorValue is a scaled signed integer, and a copper
    port publishes no optical sensors at all - which is how a port is recognised as fiber.
    """
    PORTS = [{"index": 10401, "name": "TenGigabitEthernet1/1"},
             {"index": 10303, "name": "GigabitEthernet1/3"},
             {"index": 10121, "name": "GigabitEthernet0/21"}]

    def optical(self, batches):
        import asyncio

        async def fake_walk(self_, prefix, **kwargs):
            return list(batches.get(prefix, []))

        async def go():
            client = Client("127.0.0.1", "community", 161)
            await client.open()
            try:
                return await client.optical_by_port(self.PORTS)
            finally:
                if client.engine:
                    client.engine.close_dispatcher()
        with patch.object(Client, "bulk_walk", new=fake_walk):
            return asyncio.run(go())

    @staticmethod
    def name(index, text):
        root = tuple(map(int, snmp.ENTITY_PHYSICAL_NAME.split(".")))
        return (root + (index,), snmp.OctetString(text.encode()))

    @staticmethod
    def sensor(prefix, index, value):
        root = tuple(map(int, prefix.split(".")))
        return (root + (index,), snmp.Integer32(value))

    def test_only_ports_with_a_transceiver_are_fiber(self):
        batches = {
            snmp.ENTITY_PHYSICAL_NAME: [self.name(1071, "Te1/1 Transmit Power Sensor"),
                                        self.name(1072, "Te1/1 Receive Power Sensor"),
                                        self.name(1068, "Te1/1 Module Temperature Sensor")],
            snmp.ENTITY_SENSOR_VALUE: [self.sensor(snmp.ENTITY_SENSOR_VALUE, 1072, -73)],
            snmp.ENTITY_SENSOR_SCALE: [self.sensor(snmp.ENTITY_SENSOR_SCALE, 1072, 9)],
            snmp.ENTITY_SENSOR_PRECISION: [self.sensor(snmp.ENTITY_SENSOR_PRECISION, 1072, 1)],
        }
        result = self.optical(batches)
        self.assertEqual(set(result), {"TenGigabitEthernet1/1"}, "copper ports have no transceiver")
        self.assertNotIn("GigabitEthernet0/21", result)

    def test_the_value_is_scaled_to_dbm(self):
        # -73 at entSensorScale 9 (nano) with precision 1 is -7.3 dBm, exactly what the switch
        # reports for this port; get the scaling wrong and it shows -73 or -0.000000073.
        batches = {
            snmp.ENTITY_PHYSICAL_NAME: [self.name(1072, "Te1/1 Receive Power Sensor"),
                                        self.name(1071, "Te1/1 Transmit Power Sensor")],
            snmp.ENTITY_SENSOR_VALUE: [self.sensor(snmp.ENTITY_SENSOR_VALUE, 1072, -73),
                                       self.sensor(snmp.ENTITY_SENSOR_VALUE, 1071, -34)],
            snmp.ENTITY_SENSOR_SCALE: [self.sensor(snmp.ENTITY_SENSOR_SCALE, 1072, 9),
                                       self.sensor(snmp.ENTITY_SENSOR_SCALE, 1071, 9)],
            snmp.ENTITY_SENSOR_PRECISION: [self.sensor(snmp.ENTITY_SENSOR_PRECISION, 1072, 1),
                                           self.sensor(snmp.ENTITY_SENSOR_PRECISION, 1071, 1)],
        }
        entry = self.optical(batches)["TenGigabitEthernet1/1"]
        self.assertEqual(entry["rx"], -7.3)
        self.assertEqual(entry["tx"], -3.4)

    def test_a_receive_level_sets_the_link_judgement(self):
        for rx, expected in ((-7.3, "good"), (-15.0, "ok"), (-25.0, "low"), (-40.0, "none")):
            batches = {
                snmp.ENTITY_PHYSICAL_NAME: [self.name(1072, "Te1/1 Receive Power Sensor")],
                snmp.ENTITY_SENSOR_VALUE: [self.sensor(snmp.ENTITY_SENSOR_VALUE, 1072, int(rx * 10))],
                snmp.ENTITY_SENSOR_SCALE: [self.sensor(snmp.ENTITY_SENSOR_SCALE, 1072, 9)],
                snmp.ENTITY_SENSOR_PRECISION: [self.sensor(snmp.ENTITY_SENSOR_PRECISION, 1072, 1)],
            }
            self.assertEqual(self.optical(batches)["TenGigabitEthernet1/1"]["state"], expected, rx)

    def test_an_impossible_positive_transmit_is_dropped_not_shown(self):
        # This IOS build reported -34 dBm as +34; a laser cannot transmit a positive dBm, so the
        # bogus value is withheld rather than presented as a real reading.
        batches = {
            snmp.ENTITY_PHYSICAL_NAME: [self.name(1071, "Te1/1 Transmit Power Sensor"),
                                        self.name(1072, "Te1/1 Receive Power Sensor")],
            snmp.ENTITY_SENSOR_VALUE: [self.sensor(snmp.ENTITY_SENSOR_VALUE, 1071, 34),
                                       self.sensor(snmp.ENTITY_SENSOR_VALUE, 1072, -73)],
            snmp.ENTITY_SENSOR_SCALE: [self.sensor(snmp.ENTITY_SENSOR_SCALE, 1071, 9),
                                       self.sensor(snmp.ENTITY_SENSOR_SCALE, 1072, 9)],
            snmp.ENTITY_SENSOR_PRECISION: [self.sensor(snmp.ENTITY_SENSOR_PRECISION, 1071, 1),
                                           self.sensor(snmp.ENTITY_SENSOR_PRECISION, 1072, 1)],
        }
        entry = self.optical(batches)["TenGigabitEthernet1/1"]
        self.assertIsNone(entry["tx"])
        self.assertEqual(entry["rx"], -7.3)

    def test_an_all_copper_switch_reports_no_optics(self):
        self.assertEqual(self.optical({}), {})
