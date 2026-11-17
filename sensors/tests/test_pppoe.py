"""PPPoE Active Users sensor: counted from the MikroTik PPP SNMP table, never faked."""
import os
import secrets
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from devices.models import Device
from devices.services.credentials import encrypt_password
from sensors.models import Sensor, SensorRuntime, SNMPProfile
from sensors.polling import Poller
from sensors.snmp import Client, PPP_COLUMN, SNMPError
from sensors import snmp

# The counter walks column 1 only, which enumerates every session once.
ROOT = tuple(map(int, PPP_COLUMN.split(".")))


def binding(column, index, value=0):
    """One binding in the walked column: <root>.<session index>;
    `column` is kept in the signature so call sites read the same as before."""
    return (ROOT + (index,), value)


class FakeWalk:
    """Stands in for Client.bulk_walk_cmd's async generator."""

    def __init__(self, bindings, error=None, reject_above=None):
        self.bindings = bindings
        self.error = error
        self.reject_above = reject_above
        self.repetitions = []
        self.started_at = None

    def __call__(self, *args, **kwargs):
        bindings, error = self.bindings, self.error
        # maxRepetitions is the 6th positional argument; the target OID is the 7th.
        repetitions = args[5]
        self.repetitions.append(repetitions)
        if self.started_at is None and len(args) > 6:
            try:
                self.started_at = str(args[6][0])
            except Exception:
                self.started_at = None
        rejected = self.reject_above is not None and repetitions > self.reject_above

        async def stream():
            if rejected:
                yield 0, 1, 0, []       # status set: the device refused the batch size
                return
            if error:
                yield error, 0, 0, []
                return
            yield 0, 0, 0, bindings
        return stream()


class PppoeCountTests(TestCase):
    def count(self):
        """Run the real counter with the table walk replaced by `bulk_walk_cmd`."""
        import asyncio

        async def go():
            client = Client("127.0.0.1", "community", 161)
            await client.open()               # real transport setup; the walk is patched
            try:
                return await client.pppoe_users()
            finally:
                if client.engine:
                    client.engine.close_dispatcher()
        return asyncio.run(go())

    def test_count_is_the_number_of_distinct_sessions(self):
        # Column 1 lists each session once, so 3 rows means 3 users.
        rows = [binding(1, idx) for idx in (1, 2, 3)]
        with patch("sensors.snmp.bulk_walk_cmd", new=FakeWalk(rows)):
            self.assertEqual(self.count(), 3)

    def test_only_column_one_is_walked(self):
        # Walking the whole table repeats every session across all columns: a real device
        # produced 111,869 bindings (109 s) for 1,617 sessions, versus 1.3 s for column 1.
        # Detect PPPoE appeared to hang because of that. Pin the narrowed walk.
        self.assertTrue(snmp.PPP_COLUMN.endswith(".1"))
        walk = FakeWalk([binding(1, 1), binding(1, 2)])
        with patch("sensors.snmp.bulk_walk_cmd", new=walk):
            self.assertEqual(self.count(), 2)
        # The walk must be rooted at the column, not the table: assert on the code's constant.
        import inspect
        body = inspect.getsource(Client.pppoe_users)
        self.assertIn("PPP_COLUMN", body)
        self.assertNotIn("PPP_TABLE", body, "the whole table is no longer walked")

    def test_an_empty_table_is_a_real_zero(self):
        with patch("sensors.snmp.bulk_walk_cmd", new=FakeWalk([])):
            self.assertEqual(self.count(), 0)

    def test_a_failed_walk_raises_instead_of_reporting_zero(self):
        for error in ("timeout", "genError"):
            with self.subTest(error=error), patch("sensors.snmp.bulk_walk_cmd", new=FakeWalk([], error=error)):
                with self.assertRaises(SNMPError):
                    self.count()

    def test_a_rejected_batch_size_retries_smaller_instead_of_failing(self):
        # Some RouterOS builds refuse large GETBULK batches. That is not a sensor failure:
        # fall back to the conservative size and still return the real count.
        rows = [binding(1, idx) for idx in (1, 2)]
        walk = FakeWalk(rows, reject_above=snmp.PPP_BULK_REPETITIONS_FALLBACK)
        with patch("sensors.snmp.bulk_walk_cmd", new=walk):
            self.assertEqual(self.count(), 2)
        self.assertEqual(walk.repetitions[0], snmp.PPP_BULK_REPETITIONS)
        self.assertEqual(walk.repetitions[1], snmp.PPP_BULK_REPETITIONS_FALLBACK)


class PppoeSensorTests(TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start(); self.addCleanup(env.stop)
        worker = patch("sensors.runtime.ensure_worker")
        worker.start(); self.addCleanup(worker.stop)
        self.admin = get_user_model().objects.create_user(username="pppoe-admin", is_staff=True)
        self.client.force_login(self.admin)
        self.device = Device.objects.create(
            name="PPPoE server", management_ip="10.20.30.40", username="api-user",
            encrypted_password=encrypt_password(secrets.token_urlsafe(16)))
        SNMPProfile.objects.create(device=self.device, community=encrypt_password("private-community"),
                                   validated_ip=self.device.management_ip, tested_at=timezone.now())
        self.sensor = Sensor.objects.create(device=self.device, kind="pppoe", name="PPPoE Active Users",
                                            interface_index=0, interval=10, enabled=True)
        self.other = Sensor.objects.create(device=self.device, kind="cpu", name="CPU Sensor",
                                           interface_index=0, interval=10, enabled=True)
        SensorRuntime.objects.create(pk=1, polling_authorized=True)

    def sample(self, **values):
        values.setdefault("uptime_seconds", 100)
        with patch("sensors.snmp.read", return_value=values), \
                patch("sensors.polling.time.monotonic", return_value=1.0):
            Poller().poll(self.sensor)
        return self.sensor.samples.order_by("-timestamp", "-pk").first()

    # --- polling / storage -----------------------------------------------
    def test_poll_stores_the_count(self):
        row = self.sample(pppoe_users=25)
        self.assertTrue(row.valid)
        self.assertEqual(row.pppoe_users, 25)

    def test_zero_sessions_is_stored_as_a_valid_zero(self):
        row = self.sample(pppoe_users=0)
        self.assertTrue(row.valid)
        self.assertEqual(row.pppoe_users, 0)      # a real reading, not None
        self.assertEqual(row.error, "")

    def test_snmp_failure_is_stored_as_no_reading_not_zero(self):
        with patch("sensors.snmp.read", side_effect=SNMPError("SNMP read timed out.")):
            Poller().poll(self.sensor)
        row = self.sensor.samples.order_by("-pk").first()
        self.assertFalse(row.valid)
        self.assertIsNone(row.pppoe_users)        # never a fabricated 0
        self.assertIn("timed out", row.error)

    def test_polling_this_sensor_does_not_touch_other_sensors(self):
        before = self.other.samples.count()
        self.sample(pppoe_users=7)
        self.assertEqual(self.other.samples.count(), before)
        self.other.refresh_from_db()
        self.assertTrue(self.other.enabled)

    # --- list endpoint + detail page --------------------------------------
    def test_card_data_reports_the_count(self):
        self.sample(pppoe_users=25)
        rows = self.client.get(reverse("sensor_data", args=[self.device.pk])).json()["sensors"]
        row = next(item for item in rows if item["id"] == self.sensor.pk)
        self.assertEqual(row["pppoe_users"], 25)
        self.assertEqual(row["status"], "Active")

    def test_detail_page_shows_the_count_plainly(self):
        self.sample(pppoe_users=25)
        page = self.client.get(reverse("sensor_detail", args=[self.device.pk, self.sensor.pk])).content.decode()
        self.assertIn("Active PPPoE users", page)
        self.assertIn("gauge-plain", page)         # no arbitrary ring scale
        self.assertEqual(self.client.get(reverse("sensor_detail", args=[self.device.pk, self.sensor.pk])
                                        ).context["gauges"][0]["value"], 25)

    def test_range_switching_returns_correct_stored_counts(self):
        # One reading per range window, with distinct counts.
        for age, count in ((timedelta(minutes=5), 25), (timedelta(hours=6), 20),
                           (timedelta(days=3), 12), (timedelta(days=20), 5)):
            self.sensor.samples.create(timestamp=timezone.now() - age, valid=True,
                                       uptime_seconds=100, pppoe_users=count)
        url = reverse("sensor_history", args=[self.device.pk, self.sensor.pk])
        expected = {"30m": 1, "2h": 1, "24h": 2, "7d": 3, "30d": 4}
        for key, count in expected.items():
            payload = self.client.get(url, {"range": key}).json()
            self.assertEqual(payload["count"], count, key)
            self.assertTrue(all(point["pppoe_users"] is not None for point in payload["points"]))
        self.assertEqual([p["pppoe_users"] for p in self.client.get(url, {"range": "30d"}).json()["points"]],
                         sorted([25, 20, 12, 5]))

    # --- start / stop isolation -------------------------------------------
    def test_starting_and_stopping_this_sensor_leaves_others_alone(self):
        with patch("sensors.views.start_sensors") as start:
            self.client.post(reverse("sensor_control", args=[self.device.pk, self.sensor.pk, "stop"]))
        self.sensor.refresh_from_db(); self.other.refresh_from_db()
        self.assertFalse(self.sensor.enabled)
        self.assertTrue(self.other.enabled)
        self.assertEqual(self.other.revision, 1)        # untouched
        start.assert_not_called()

        with patch("sensors.views.start_sensors") as start:
            self.client.post(reverse("sensor_control", args=[self.device.pk, self.sensor.pk, "start"]))
        start.assert_called_once_with([self.sensor.pk])
        self.other.refresh_from_db()
        self.assertTrue(self.other.enabled)
        self.assertEqual(self.other.revision, 1)

    # --- creation ---------------------------------------------------------
    def test_pppoe_is_offered_in_the_add_sensor_picker(self):
        page = self.client.get(reverse("device_sensors", args=[self.device.pk])).content.decode()
        self.assertIn('value="pppoe"', page)
        self.assertIn("Detect PPPoE", page)

    def test_detection_reports_the_live_count(self):
        with patch("sensors.snmp.read", return_value={"uptime_seconds": 1, "pppoe_users": 42}):
            response = self.client.post(reverse("sensor_detect", args=[self.device.pk]), {"kind": "pppoe"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("42 active PPPoE user(s)", response.content.decode())

    def test_adding_the_sensor_uses_the_existing_snmp_profile(self):
        # A device that does not have this sensor yet.
        fresh = Device.objects.create(name="Second PPPoE server", management_ip="10.20.30.41",
                                      username="api-user", encrypted_password=encrypt_password("p"))
        SNMPProfile.objects.create(device=fresh, community=encrypt_password("private-community"),
                                   validated_ip=fresh.management_ip, tested_at=timezone.now())
        url = reverse("sensor_add", args=[fresh.pk])
        with patch("sensors.views.start_sensors") as start:
            response = self.client.post(url, {"kind": "pppoe", "interval": "10"})
        self.assertEqual(response.status_code, 302)
        created = Sensor.objects.get(device=fresh, kind="pppoe")
        self.assertEqual(created.name, "PPPoE Active Users")
        start.assert_called_once_with([created.pk])
