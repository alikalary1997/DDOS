"""Topology map: 4-column layout built from the real device chain, no fabricated stats."""
import os
import secrets
from datetime import timedelta
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from devices.models import Device
from devices.services.credentials import encrypt_password
from devices.services.topology_map import build_map
from sensors.models import Sensor, SensorSample


class MapTests(TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start(); self.addCleanup(env.stop)
        self.admin = get_user_model().objects.create_user(username="map-admin", is_staff=True)
        self.client.force_login(self.admin)
        self.counter = 0

    def device(self, name, parent=None, tested=True):
        self.counter += 1
        device = Device(name=name, management_ip=f"10.40.0.{self.counter}", username="api-user",
                        last_connection_test=timezone.now(), last_connection_test_succeeded=tested,
                        encrypted_password=encrypt_password(secrets.token_urlsafe(12)))
        device.save()
        if parent is not None:
            device.set_topology_parent(parent)
            device.save()
        return device

    def sensor(self, device, kind="pppoe", value=7, fresh=True, enabled=True):
        sensor = Sensor.objects.create(device=device, kind=kind, name=kind, enabled=enabled, interval=10)
        SensorSample.objects.create(
            sensor=sensor, timestamp=timezone.now() - (timedelta(seconds=0) if fresh else timedelta(hours=2)),
            valid=True, pppoe_users=value if kind == "pppoe" else None,
            in_mbps=1.5 if kind == "traffic" else None, out_mbps=0.5 if kind == "traffic" else None,
            uptime_seconds=100)
        return sensor

    def columns(self, data=None):
        data = data or build_map()
        return {column["key"]: [card["name"] for card in column["cards"]] for column in data["columns"]}

    def card(self, name, data=None):
        data = data or build_map()
        for column in data["columns"]:
            for card in column["cards"]:
                if card["name"] == name:
                    return card
        raise AssertionError(f"{name} is not on the map")

    def test_full_depth_branch_puts_each_device_in_its_column(self):
        core = self.device("NCS")
        limit = self.device("Limit-1", core)
        server = self.device("Kalar", limit)
        # A PPPoE server is identified by its own PPPoE sensor, not by depth alone.
        self.sensor(server, kind="pppoe", value=4)
        self.device("Tower-A", server)
        columns = self.columns()
        self.assertEqual(columns["core"], ["NCS"])
        self.assertEqual(columns["limit"], ["Limit-1"])
        self.assertEqual(columns["pppoe"], ["Kalar"])
        self.assertEqual(columns["tower"], ["Tower-A"])

    def test_branch_skipping_pppoe_still_puts_tower_in_towers_column(self):
        # Limit-6 has no PPPoE server: its tower hangs straight off the limit.
        core = self.device("NCS")
        limit = self.device("Limit-6", core)
        self.device("Tower-B", limit)
        data = build_map()
        columns = self.columns(data)
        self.assertEqual(columns["pppoe"], [], "no placeholder card is inserted for the gap")
        self.assertEqual(columns["tower"], ["Tower-B"])
        link = [item for item in data["links"] if item["from_column"] == 1][0]
        self.assertEqual(link["to_column"], 3, "the connector spans the empty PPPoE column")

    def test_any_number_of_devices_per_level(self):
        core = self.device("Core")
        limits = [self.device(f"Limit-{n}", core) for n in range(1, 5)]
        for limit in limits:
            server = self.device(f"Server-{limit.name}", limit)
            self.sensor(server, kind="pppoe", value=3)
        columns = self.columns()
        self.assertEqual(len(columns["core"]), 1)
        self.assertEqual(len(columns["limit"]), 4)
        self.assertEqual(len(columns["pppoe"]), 4)
        heights = {card["row"] for column in build_map()["columns"] for card in column["cards"]}
        self.assertTrue(heights, "rows are assigned per column")

    def test_status_colour_reflects_the_device_state(self):
        self.device("Online-Dev", tested=True)
        self.device("Offline-Dev", tested=False)
        untouched = Device(name="Untested", management_ip="10.40.9.9", username="u",
                           encrypted_password=encrypt_password("x"))
        untouched.save()
        self.assertEqual(self.card("Online-Dev")["state"], "online")
        self.assertEqual(self.card("Offline-Dev")["state"], "offline")
        self.assertEqual(self.card("Untested")["state"], "not-tested")

    def test_device_without_sensors_reports_no_data_not_a_fabricated_stat(self):
        core = self.device("NCS")
        limit = self.device("Limit-1", core)
        self.device("Bare-Tower", limit)
        card = self.card("Bare-Tower")
        self.assertIsNone(card["value"])
        self.assertEqual(card["note"], "No data")
        html = self.client.get(reverse("device_topology_map")).content.decode()
        self.assertIn("No data", html)

    def test_stale_pppoe_sensor_is_not_reported_as_a_reading(self):
        tower = self.device("Stale-Tower")
        self.sensor(tower, kind="pppoe", value=42, fresh=False)
        self.assertIsNone(self.card("Stale-Tower")["value"])

    def test_fresh_pppoe_and_traffic_readings_are_used(self):
        core = self.device("NCS")
        limit = self.device("Limit-1", core)
        server = self.device("Kalar", limit)
        tower = self.device("Tower-A", server)
        self.sensor(server, kind="pppoe", value=12)
        self.sensor(tower, kind="traffic")
        # The PPPoE server rolls up user counts from itself and everything below it.
        self.assertEqual(self.card("Kalar")["note"], "1 tower · 12 users")
        self.assertEqual(self.card("Tower-A")["value"], 2.0, "tower shows its own traffic")
        self.assertEqual(self.card("Tower-A")["note"], "2.00 Mbps")

    def test_stale_sensor_is_not_counted_in_a_roll_up(self):
        core = self.device("NCS")
        limit = self.device("Limit-1", core)
        server = self.device("Kalar", limit)
        self.device("Tower-A", server)
        self.device("Tower-B", server)
        self.sensor(server, kind="pppoe", value=9)
        self.sensor(server, kind="traffic", value=None, fresh=False)
        self.assertEqual(self.card("Kalar")["note"], "2 towers · 9 users")
        self.assertEqual(self.card("Kalar")["value"], 2, "the prominent figure is the tower count")

    def test_aggregate_counts_roll_up_through_the_branch(self):
        core = self.device("NCS")
        limit = self.device("Limit-1", core)
        server = self.device("Kalar", limit)
        self.sensor(server, kind="pppoe", value=5)
        self.device("Tower-A", server)
        self.device("Tower-B", server)
        self.assertEqual(self.card("NCS")["note"], "1 limits below")
        self.assertEqual(self.card("Limit-1")["value"], 1, "one PPPoE server below the limit")
        self.assertEqual(self.card("Kalar")["value"], 2, "two towers below the PPPoE server")

    def test_map_page_renders_four_fixed_columns_in_order(self):
        self.device("NCS")
        response = self.client.get(reverse("device_topology_map"))
        self.assertEqual(response.status_code, 200)
        labels = [column["label"] for column in response.context["topology_map"]["columns"]]
        self.assertEqual(labels, ["Core", "Limit Servers", "PPPoE Servers", "Towers"])

    def test_a_zero_count_is_always_labelled_never_a_bare_number(self):
        core = self.device("NCS")
        # A limit with no PPPoE servers used to render a lone "0" on its own line.
        self.device("Limit-6", core)
        html = self.client.get(reverse("device_topology_map")).content.decode()
        self.assertIn("0</b> <span class=\"topo-unit\">PPPoE servers</span>", html)
        self.assertNotIn(">0</b>\n", html)
        for card in [c for col in build_map()["columns"] for c in col["cards"]]:
            if card["value"] is not None:
                self.assertTrue(card["unit"], f"{card['name']} shows a number with no unit")

    def test_map_requires_login(self):
        self.client.logout()
        response = self.client.get(reverse("device_topology_map"))
        self.assertEqual(response.status_code, 302)

    def test_sidebar_has_a_topology_nav_item_pointing_at_the_map(self):
        self.device("NCS")
        html = self.client.get(reverse("device_topology_map")).content.decode()
        self.assertIn(f'href="{reverse("device_topology_map")}"', html)
        self.assertIn(">Topology</a>", html)
        # The nav highlights on the map page and not on the device list.
        self.assertIn('aria-current="page"', html)
        devices_html = self.client.get(reverse("devices")).content.decode()
        self.assertIn(f'href="{reverse("device_topology_map")}"', devices_html,
                      "the entry is reachable from every page")
