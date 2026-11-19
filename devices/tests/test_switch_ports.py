"""Switch port panel on the topology map: live SNMP port states for a Cisco switch.

The map draws a port grid (green = link up, red = not connected, hatched = shut). Those states
must come from the device, never from a guess, so these tests pin the endpoint's behaviour and
the fact that it degrades honestly when SNMP is unavailable.
"""
import os
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from devices.models import Device
from devices.services.credentials import encrypt_password
from sensors import snmp
from sensors.models import SNMPProfile


PORTS = [
    {"index": 1, "name": "Vlan1", "oper": "up", "admin": "up", "speed_mbps": 0, "alias": ""},
    {"index": 10101, "name": "GigabitEthernet0/1", "oper": "up", "admin": "up", "speed_mbps": 1000, "alias": "uplink"},
    {"index": 10102, "name": "GigabitEthernet0/2", "oper": "down", "admin": "up", "speed_mbps": 0, "alias": ""},
    {"index": 10103, "name": "GigabitEthernet0/3", "oper": "down", "admin": "down", "speed_mbps": 0, "alias": "shut"},
]


class SwitchPortTests(TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start(); self.addCleanup(env.stop)
        self.admin = get_user_model().objects.create_user(username="ports-admin", is_staff=True)
        self.client.force_login(self.admin)
        self.device = Device.objects.create(name="Sarchl", management_ip="10.10.10.15",
                                            device_type=Device.DeviceType.CISCO)
        SNMPProfile.objects.create(device=self.device, community=encrypt_password("public"),
                                   validated_ip=self.device.management_ip, tested_at=timezone.now())
        self.url = reverse("device_switch_ports", args=[self.device.pk])

    def test_port_states_come_from_snmp(self):
        with patch("sensors.snmp.read", return_value=PORTS):
            response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["name"], "Sarchl")
        states = {port["name"]: port for port in data["ports"]}
        self.assertEqual(states["GigabitEthernet0/1"]["oper"], "up")
        self.assertEqual(states["GigabitEthernet0/2"]["oper"], "down")
        self.assertEqual(states["GigabitEthernet0/3"]["admin"], "down")

    def test_counts_match_the_port_list(self):
        with patch("sensors.snmp.read", return_value=PORTS):
            data = self.client.get(self.url).json()
        # Vlan1 is a pseudo-interface, not a port a cable plugs into.
        self.assertNotIn("Vlan1", [port["name"] for port in data["ports"]])
        self.assertEqual(data["total"], 3)
        self.assertEqual(data["connected"], 1)
        self.assertEqual(data["disabled"], 1)

    def test_missing_snmp_credentials_are_reported_not_guessed(self):
        SNMPProfile.objects.filter(device=self.device).delete()
        data = self.client.get(self.url).json()
        self.assertFalse(data["ok"])
        self.assertNotIn("ports", data)
        self.assertIn("SNMP credentials", data["error"])

    def test_a_failed_snmp_read_is_reported_not_guessed(self):
        with patch("sensors.snmp.read", side_effect=snmp.SNMPError("SNMP read timed out.")):
            data = self.client.get(self.url).json()
        self.assertFalse(data["ok"])
        self.assertIn("timed out", data["error"])
        self.assertNotIn("ports", data)

    def test_credentials_validated_for_an_old_address_are_refused(self):
        SNMPProfile.objects.filter(device=self.device).update(validated_ip="10.10.10.99")
        data = self.client.get(self.url).json()
        self.assertFalse(data["ok"], "a profile for a different address must not be used")

    def test_the_endpoint_requires_a_signed_in_user(self):
        self.client.logout()
        self.assertEqual(self.client.get(self.url).status_code, 302)

    def test_the_map_page_marks_the_switch_so_the_panel_can_open(self):
        Device.objects.create(name="RB-1", management_ip="10.20.30.40", username="u",
                              encrypted_password=encrypt_password("p"))
        html = self.client.get(reverse("device_topology_map")).content.decode()
        self.assertIn('data-device-type="cisco"', html)
        self.assertIn('id="tmapSwitch"', html)
        # The panel builds its URL from this template, so it must point at the real route.
        self.assertIn("/devices/topology/map/switch/0/ports/", html)
