"""Device ONLINE / NO DATA on the dashboard is decided by the ping sensor."""
from datetime import timedelta
import os
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.test import TestCase
from django.utils import timezone

from devices.models import Device
from devices.services.credentials import encrypt_password
from monitor.services.dashboard_data import dashboard_data
from sensors.models import Sensor, SensorSample


class PingDrivenDeviceStatusTests(TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start(); self.addCleanup(env.stop)
        self.device = Device.objects.create(name="Ping router", management_ip="10.20.30.60", username="u",
                                            encrypted_password=encrypt_password("p"))
        self.now = timezone.now()
        self.clock = patch("django.utils.timezone.now", side_effect=lambda: self.now)
        self.clock.start(); self.addCleanup(self.clock.stop)

    def ping_sensor(self, ping_ms=12.0, packet_loss=0.0, age_seconds=0, valid=True):
        sensor, _ = Sensor.objects.get_or_create(device=self.device, kind="ping", interface_index=0,
                                                 defaults={"name": "Ping", "interval": 10, "enabled": True})
        SensorSample.objects.filter(sensor=sensor).update(valid=False)
        SensorSample.objects.create(sensor=sensor, timestamp=self.now - timedelta(seconds=age_seconds),
                                    valid=valid, ping_ms=ping_ms, packet_loss=packet_loss)
        return sensor

    def status(self):
        return [d for d in dashboard_data()["devices"] if d["id"] == self.device.pk][0]

    def test_reply_marks_device_online(self):
        self.ping_sensor(ping_ms=12.0, packet_loss=0.0)
        device = self.status()
        self.assertEqual(device["ping_state"], "reachable")
        self.assertEqual(device["status3"], "online")

    def test_total_loss_marks_device_no_data(self):
        # 100% packet loss means no reply: the device is not ONLINE.
        self.ping_sensor(ping_ms=None, packet_loss=100.0)
        device = self.status()
        self.assertEqual(device["ping_state"], "unreachable")
        self.assertEqual(device["status3"], "no_data")

    def test_stale_ping_is_unknown_not_offline(self):
        self.ping_sensor(ping_ms=12.0, age_seconds=120)  # older than interval * 3
        self.assertEqual(self.status()["ping_state"], "unknown")

    def test_no_ping_sensor_leaves_status_unknown(self):
        self.assertEqual(self.status()["ping_state"], "unknown")
        self.assertEqual(self.status()["status3"], "no_data")

    def test_invalid_ping_sample_is_unknown(self):
        self.ping_sensor(valid=False)
        self.assertEqual(self.status()["ping_state"], "unknown")

    def test_attack_still_wins_over_ping(self):
        from public_ips.models import PublicIP
        from monitor.services import dashboard_data as module
        self.ping_sensor()
        ip = PublicIP.objects.create(address="8.8.8.8", device=self.device, monitoring_enabled=True)
        rows = [{"id": ip.pk, "address": ip.address, "device_id": self.device.pk, "device_name": "Ping router",
                 "monitoring_health": "Active", "ddos_status": "Under Attack"}]
        with patch.object(module, "cached_rows", return_value={}):
            device = [d for d in dashboard_data()["devices"] if d["id"] == self.device.pk][0]
        self.assertEqual(device["status3"], "online")

    def test_ping_drives_status_without_public_ips(self):
        # No public IPs at all: reachability must still come from ping.
        self.assertEqual(self.device.public_ips.count(), 0)
        self.ping_sensor(ping_ms=3.0)
        self.assertEqual(self.status()["status3"], "online")
