"""A PPPoE sensor on a busy server must not report "Waiting for data" while it is polling.

Two things caused it: the sensor was created with a 2-second interval although each reading
walks the whole session table, and a reading older than 30 seconds was called stale even
though the worker legitimately needs longer on a loaded device.
"""
import os
import secrets
from datetime import timedelta
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from devices.models import Device
from devices.services.credentials import encrypt_password
from sensors.forms import AddSensorForm
from sensors.models import Sensor, SensorSample
from sensors.polling import STALE_FLOOR_SECONDS, staleness_window


class IntervalGuardTests(TestCase):
    def test_a_pppoe_sensor_needs_at_least_thirty_seconds(self):
        form = AddSensorForm({"kind": "pppoe", "interval": "2"})
        self.assertFalse(form.is_valid())
        self.assertIn("at least 30 seconds", str(form.errors["__all__"]))

    def test_a_pppoe_sensor_accepts_thirty_seconds(self):
        self.assertTrue(AddSensorForm({"kind": "pppoe", "interval": "30"}).is_valid())

    def test_other_sensor_kinds_keep_the_short_intervals(self):
        for kind in ("cpu", "uptime", "ping", "traffic"):
            with self.subTest(kind=kind):
                self.assertTrue(AddSensorForm({"kind": kind, "interval": "2"}).is_valid())


class StalenessTests(TestCase):
    def test_the_window_has_a_floor_well_above_one_poll_cycle(self):
        # Sensors share one serialized connection per device; a table walk can take seconds.
        self.assertGreaterEqual(STALE_FLOOR_SECONDS, 90)
        self.assertEqual(staleness_window(2), STALE_FLOOR_SECONDS)
        self.assertEqual(staleness_window(60), 180)

    def test_a_recent_reading_is_not_called_stale(self):
        self.assertGreater(staleness_window(2), 60)


class SensorPageStatusTests(TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start(); self.addCleanup(env.stop)
        self.admin = get_user_model().objects.create_user(username="pppoe-status", is_staff=True)
        self.client.force_login(self.admin)
        self.device = Device.objects.create(
            name="PPPoE server", management_ip="10.20.30.90", username="api",
            encrypted_password=encrypt_password(secrets.token_urlsafe(12)))
        self.sensor = Sensor.objects.create(device=self.device, kind="pppoe", name="PPPoE Active Users",
                                            enabled=True, interval=30)

    def status(self):
        with patch("sensors.views.authorized", return_value=True), \
             patch("sensors.views.worker_running", return_value=True):
            payload = self.client.get(f"/devices/{self.device.pk}/sensors/data/").json()
        return next(row for row in payload["sensors"] if row["kind"] == "pppoe")

    def test_no_reading_yet_is_waiting_for_data(self):
        self.assertEqual(self.status()["status"], "Waiting for data")

    def test_a_reading_from_a_slow_worker_still_counts_as_active(self):
        # 90 s between polls is normal on a busy server; that must not read as stale.
        SensorSample.objects.create(sensor=self.sensor, timestamp=timezone.now() - timedelta(seconds=90),
                                    valid=True, pppoe_users=968, uptime_seconds=100)
        row = self.status()
        self.assertEqual(row["status"], "Active")
        self.assertEqual(row["pppoe_users"], 968)

    def test_a_genuinely_old_reading_is_stale(self):
        SensorSample.objects.create(sensor=self.sensor, timestamp=timezone.now() - timedelta(minutes=30),
                                    valid=True, pppoe_users=900, uptime_seconds=100)
        self.assertEqual(self.status()["status"], "Stale")
