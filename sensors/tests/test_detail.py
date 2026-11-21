"""Sensor detail page: tabs, range-scoped history and the per-sensor Settings tab."""
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
from monitor.models import DDoSDetectionSettings, DeviceDDoSProtection, DeviceDDoSThreshold
from sensors.models import Sensor, SensorRuntime, SNMPProfile, SensorSample


class SensorDetailTests(TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start(); self.addCleanup(env.stop)
        worker = patch("sensors.runtime.ensure_worker")
        worker.start(); self.addCleanup(worker.stop)
        self.admin = get_user_model().objects.create_user(username="detail-admin", is_staff=True)
        self.reader = get_user_model().objects.create_user(username="detail-reader")
        self.client.force_login(self.admin)
        self.device = Device.objects.create(
            name="Detail router", management_ip="10.20.30.40", username="api-user",
            encrypted_password=encrypt_password(secrets.token_urlsafe(16)))
        SensorRuntime.objects.create(pk=1, polling_authorized=True)
        self.cpu = Sensor.objects.create(device=self.device, kind="cpu", name="CPU Sensor",
                                         interface_index=0, interval=10, enabled=True)
        self.other = Sensor.objects.create(device=self.device, kind="ping", name="Ping Sensor",
                                           interface_index=0, interval=30, enabled=True)

    # --- helpers ---------------------------------------------------------
    def urls(self, sensor):
        return (reverse("sensor_detail", args=[self.device.pk, sensor.pk]),
                reverse("sensor_history", args=[self.device.pk, sensor.pk]),
                reverse("sensor_settings", args=[self.device.pk, sensor.pk]))

    def sample(self, sensor, age, **values):
        defaults = dict(valid=True)
        defaults.update(values)
        return SensorSample.objects.create(sensor=sensor, timestamp=timezone.now() - age, **defaults)

    def latest(self, sensor, **values):
        """A fresh reading so the sensor reads as Active, without widening the ranges."""
        Sensor.objects.filter(pk=sensor.pk).update(last_success=timezone.now())
        return self.sample(sensor, timedelta(seconds=1), **values)

    def seed_ranges(self, sensor):
        """One reading inside each range, so every range returns a distinct count."""
        self.sample(sensor, timedelta(minutes=5), cpu=10)      # 30m, 2h, 24h, 7d, 30d
        self.sample(sensor, timedelta(hours=2, minutes=10), cpu=20)   # 24h, 7d, 30d
        self.sample(sensor, timedelta(days=2), cpu=30)         # 7d, 30d
        self.sample(sensor, timedelta(days=20), cpu=40)        # 30d only

    # --- page ------------------------------------------------------------
    def test_detail_page_renders_all_four_tabs_and_real_metadata(self):
        self.seed_ranges(self.cpu)
        self.latest(self.cpu, cpu=15)
        url, _history, _settings = self.urls(self.cpu)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        page = response.content.decode()
        for tab in ("Overview", "Graphs", "Historic Data", "Settings"):
            self.assertIn(tab, page)
        # Real stored values, not invented ones.
        self.assertIn("Every 10 seconds", page)
        self.assertIn("CPU Sensor", page)
        self.assertEqual(response.context["sensor"], self.cpu)
        self.assertEqual(response.context["status"], "Active")
        self.assertIn("sensorHistorySeed", page)

    def test_detail_page_never_mentions_device_level_ddos_settings(self):
        """DDoS Settings / Protection stay on the device page and are not referenced here."""
        url, _history, _settings = self.urls(self.cpu)
        page = self.client.get(url).content.decode()
        self.assertNotIn("DDoS Settings", page)
        self.assertNotIn("DDoS Protection", page)
        self.assertNotIn("SOS Public", page)
        self.assertNotIn("Null IP", page)

    def test_card_links_to_the_detail_view(self):
        page = self.client.get(reverse("device_sensors", args=[self.device.pk])).content.decode()
        url, _history, _settings = self.urls(self.cpu)
        self.assertIn(f'href="{url}"', page)

    def test_settings_area_switches_between_sensors_and_device_settings(self):
        base = reverse("device_sensors", args=[self.device.pk])
        sensors_view = self.client.get(base).content.decode()
        settings_view = self.client.get(base, {"view": "settings"}).content.decode()
        # Both views carry the two pills; the active one is marked for styling.
        for page in (sensors_view, settings_view):
            self.assertIn("settings-switcher", page)
            self.assertIn("Sensors<", page)
            self.assertIn("Device Settings<", page)
        sensors_pill = sensors_view.split('aria-label="Device settings sections"', 1)[1].split("</div>", 1)[0]
        self.assertIn(f'href="{base}" aria-current="page">Sensors<', sensors_pill)
        settings_pill = settings_view.split('aria-label="Device settings sections"', 1)[1].split("</div>", 1)[0]
        self.assertIn('aria-current="page">Device Settings<', settings_pill)
        # The sensor list belongs to the Sensors view only...
        self.assertIn("sensor-grid", sensors_view)
        self.assertNotIn("sensor-grid", settings_view)
        # ...and the device-wide panels to the Device Settings view only.
        self.assertNotIn("deviceDDoSSettings", sensors_view)
        self.assertIn("deviceDDoSSettings", settings_view)
        self.assertIn("deviceDDoSProtection", settings_view)
        self.assertIn("DEVICE / SETTINGS", settings_view)
        self.assertIn("Device-wide configuration. Not tied to any single sensor.", settings_view)
        for label in ("Total PPS", "CPU (%)", "Save thresholds", "Save protection settings",
                      "SOS Public", "Null IP"):
            self.assertIn(label, settings_view)

    def test_sensor_detail_uses_the_reference_layout(self):
        detail_url = reverse("sensor_detail", args=[self.device.pk, self.cpu.pk])
        page = self.client.get(detail_url).content.decode()
        self.assertIn("sensor-crumbs", page)            # Device / SNMP Sensors / <sensor>
        self.assertIn("sensor-live-pill", page)         # status pill beside the heading
        self.assertIn("Live Graph", page)               # graph panel title
        self.assertIn("data-range-slot", page)          # range buttons land here
        self.assertIn("gauge-ring", page)               # donut gauges
        self.assertNotIn("DDoS Settings", page)
        self.assertNotIn("DDoS Protection", page)

    def test_the_devices_page_still_reaches_the_sensor_pages(self):
        """The device page no longer renders an inspector; its rows link to device settings.

        The sensor list itself lives on the device's Sensors page, which must stay reachable.
        """
        page = self.client.get(reverse("devices")).content.decode()
        self.assertNotIn("Device Management Fleet", page, "the retired fleet page is gone")
        # Row settings lead to the device's own page, where its sensors are listed.
        sensors_page = self.client.get(reverse("device_sensors", args=[self.device.pk]))
        self.assertEqual(sensors_page.status_code, 200)
        url, _history, _settings = self.urls(self.cpu)
        self.assertIn(url, sensors_page.content.decode())

    # --- range switching -------------------------------------------------
    def test_switching_range_returns_different_stored_samples(self):
        self.seed_ranges(self.cpu)
        self.latest(self.cpu, cpu=15)
        _url, history, _settings = self.urls(self.cpu)
        counts = {}
        for key in ("30m", "2h", "24h", "7d", "30d"):
            response = self.client.get(history, {"range": key})
            self.assertEqual(response.status_code, 200)
            payload = response.json()
            self.assertEqual(payload["range"], key)
            counts[key] = payload["count"]
            # Every returned point is a stored sample inside that range.
            self.assertEqual({"t", "valid", "cpu"} <= set(payload["points"][0]), True)
        self.assertEqual(counts, {"30m": 2, "2h": 2, "24h": 3, "7d": 4, "30d": 5})
        # Values come from storage, in order, and are not recalculated.
        points = self.client.get(history, {"range": "30d"}).json()["points"]
        self.assertEqual(sorted(point["cpu"] for point in points), [10, 15, 20, 30, 40])
        self.assertEqual([point["t"] for point in points], sorted(point["t"] for point in points))

    def test_unknown_range_falls_back_to_the_default(self):
        self.seed_ranges(self.cpu)
        _url, history, _settings = self.urls(self.cpu)
        payload = self.client.get(history, {"range": "everything"}).json()
        self.assertEqual(payload["range"], "30m")

    def test_history_is_scoped_to_this_sensor_only(self):
        self.sample(self.cpu, timedelta(minutes=1), cpu=10)
        self.sample(self.other, timedelta(minutes=1), ping_ms=5, packet_loss=0)
        _url, history, _settings = self.urls(self.cpu)
        payload = self.client.get(history, {"range": "24h"}).json()
        self.assertEqual(payload["count"], 1)
        self.assertEqual([point["cpu"] for point in payload["points"]], [10])
        self.assertTrue(all(point["ping_ms"] is None for point in payload["points"]))

    # --- settings tab ----------------------------------------------------
    def test_settings_tab_saves_only_this_sensor(self):
        global_settings, _ = DDoSDetectionSettings.objects.get_or_create(pk=1)
        global_cpu_warning = global_settings.cpu_warning
        device_override = DeviceDDoSThreshold.objects.create(device=self.device, cpu_warning=55)
        protection = DeviceDDoSProtection.objects.create(device=self.device, sos_public="185.166.80.90", enabled=True)
        self.other.name, self.other.interval = "Ping Sensor", 30
        self.other.save()

        _url, _history, settings = self.urls(self.cpu)
        response = self.client.post(settings, {"name": "Core CPU", "interval": "30", "enabled": "1"})
        self.assertEqual(response.status_code, 302)

        self.cpu.refresh_from_db()
        self.assertEqual((self.cpu.name, self.cpu.interval), ("Core CPU", 30))
        # The other sensor is untouched.
        self.other.refresh_from_db()
        self.assertEqual((self.other.name, self.other.interval), ("Ping Sensor", 30))
        # Device-level DDoS settings are untouched by a sensor edit.
        device_override.refresh_from_db()
        self.assertEqual(float(device_override.cpu_warning), 55)
        global_settings.refresh_from_db()
        self.assertEqual(global_settings.cpu_warning, global_cpu_warning)
        protection.refresh_from_db()
        self.assertEqual((protection.sos_public, protection.enabled), ("185.166.80.90", True))

    def test_settings_tab_validates_and_rejects_bad_input(self):
        _url, _history, settings = self.urls(self.cpu)
        response = self.client.post(settings, {"name": "", "interval": "7", "enabled": "1"})
        self.assertEqual(response.status_code, 400)
        self.cpu.refresh_from_db()
        self.assertEqual((self.cpu.name, self.cpu.interval), ("CPU Sensor", 10))

    def test_settings_tab_can_stop_and_start_this_sensor(self):
        _url, _history, settings = self.urls(self.cpu)
        with patch("sensors.views.start_sensors") as start:
            response = self.client.post(settings, {"name": "CPU Sensor", "interval": "10", "enabled": "0"})
        self.assertEqual(response.status_code, 302)
        self.cpu.refresh_from_db()
        self.assertFalse(self.cpu.enabled)
        start.assert_not_called()                       # stopping never polls

        # Starting reuses the existing Start path, which needs saved SNMP credentials.
        SNMPProfile.objects.create(device=self.device, community=encrypt_password("c"),
                                   validated_ip=self.device.management_ip, tested_at=timezone.now())
        with patch("sensors.views.start_sensors") as start:
            self.client.post(settings, {"name": "CPU Sensor", "interval": "10", "enabled": "1"})
        start.assert_called_once_with([self.cpu.pk])

    def test_reader_cannot_open_settings_or_save(self):
        detail_url = reverse("sensor_detail", args=[self.device.pk, self.cpu.pk])
        _url, _history, settings = self.urls(self.cpu)
        self.client.force_login(self.reader)
        self.assertEqual(self.client.post(settings, {"name": "x", "interval": "10"}).status_code, 403)
        self.assertContains(self.client.get(detail_url), "Administrator access is required")

    def test_other_devices_sensor_is_not_reachable(self):
        other_device = Device.objects.create(name="Other", management_ip="10.20.30.50", username="u",
                                             encrypted_password=encrypt_password("p"))
        foreign = Sensor.objects.create(device=other_device, kind="cpu", name="Foreign", interface_index=0)
        self.assertEqual(self.client.get(
            reverse("sensor_detail", args=[self.device.pk, foreign.pk])).status_code, 404)
