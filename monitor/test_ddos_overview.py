import os
import tempfile
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from devices.models import Device
from datetime import timedelta
from sensors.models import Sensor, SensorSample
from monitor.models import DetectionEvent, DetectionState
from public_ips.models import MonitoringRun, PublicIP


class DDoSOverviewTests(TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start()
        self.addCleanup(env.stop)
        self.device = Device(name="Edge 1", management_ip="192.0.2.10", username="test")
        self.device.set_password("test-only")
        self.device.save()
        self.ip = PublicIP.objects.create(address="8.8.8.8", device=self.device, incoming_monitoring_interface="ether1",
                                          provisioning_status="verified", provisioning_verified_at=timezone.now())
        lock_dir = tempfile.TemporaryDirectory()
        self.addCleanup(lock_dir.cleanup)
        override = override_settings(NETSHIELD_ROUTER_LOCK_DIRECTORY=lock_dir.name)
        override.enable(); self.addCleanup(override.disable)
        self.user = get_user_model().objects.create_superuser("admin", "a@example.com", "pw-for-tests-1")
        self.client.force_login(self.user)

    def devices(self):
        return self.client.get("/ddos-detection/data/").json()["devices"]

    def test_page_drops_history_and_unknown_metrics_are_not_zero(self):
        page = self.client.get("/ddos-detection/")
        self.assertContains(page, "Start or stop attack monitoring per MikroTik device")
        for removed in ("Detection history", "PASSIVE DETECTION", "Detection thresholds and recovery settings"):
            self.assertNotContains(page, removed)
        device = self.devices()[0]
        for kind in ("cpu", "uptime", "traffic"):
            self.assertEqual(device["metrics"][kind], {"state": "no_sensor", "value": None, "mode": None, "age_seconds": None})
        self.assertFalse(device["monitored"]); self.assertFalse(device["attacked"])

    def test_unmonitored_device_keeps_open_attack(self):
        event = DetectionEvent.objects.create(
            public_ip=self.ip, device=self.device, assignment_id_snapshot=self.ip.pk, device_id_snapshot=self.device.pk,
            address=self.ip.address, device_name="Edge 1", management_ip="192.0.2.10", profile_key="p",
            started_at=timezone.now(), last_observed_at=timezone.now(), highest_severity="Under Attack")
        DetectionState.objects.create(public_ip=self.ip, profile_key="p", confirmed_status="Under Attack", event=event)
        device = self.devices()[0]
        self.assertTrue(device["attacked"]); self.assertFalse(device["monitored"])
        self.assertTrue(device["ips"][0]["attacked"])

    def test_live_warning_is_reported_as_warning_not_attack(self):
        rows = [{"id": self.ip.pk, "address": self.ip.address, "device_id": self.device.pk, "device_name": "Edge 1",
                 "monitoring_health": "Active", "ddos_status": "Warning"}]
        from monitor.services import ddos_overview
        with patch.object(ddos_overview, "dashboard_data", return_value={"rules": rows}), \
                patch.object(ddos_overview, "fleet_snapshot", return_value={}):
            device = [d for d in ddos_overview.overview()["devices"] if d["id"] == self.device.pk][0]
        self.assertFalse(device["attacked"]); self.assertTrue(device["warning"])
        self.assertEqual(device["ips"][0]["status"], "Warning")
        self.assertFalse(device["ips"][0]["attacked"]); self.assertTrue(device["ips"][0]["warning"])

    def test_unmonitored_device_keeps_open_warning(self):
        event = DetectionEvent.objects.create(
            public_ip=self.ip, device=self.device, assignment_id_snapshot=self.ip.pk, device_id_snapshot=self.device.pk,
            address=self.ip.address, device_name="Edge 1", management_ip="192.0.2.10", profile_key="p",
            started_at=timezone.now(), last_observed_at=timezone.now(), highest_severity="Warning")
        DetectionState.objects.create(public_ip=self.ip, profile_key="p", confirmed_status="Warning", event=event)
        device = self.devices()[0]
        self.assertFalse(device["attacked"]); self.assertTrue(device["warning"])
        self.assertEqual(device["ips"][0]["status"], "Warning")

    def test_cpu_thresholds_are_exposed_per_device(self):
        from monitor.models import DDoSDetectionSettings, DeviceDDoSThreshold
        settings = DDoSDetectionSettings.objects.get(pk=1)
        settings.cpu_warning = 5; settings.cpu_attack = 45; settings.save()
        device = self.devices()[0]
        self.assertEqual((device["cpu_warning"], device["cpu_attack"]), (5.0, 45.0))
        # A per-device override wins over the global default, exactly like the dashboard.
        DeviceDDoSThreshold.objects.create(device=self.device, cpu_warning=4, cpu_attack=8)
        device = self.devices()[0]
        self.assertEqual((device["cpu_warning"], device["cpu_attack"]), (4.0, 8.0))

    def test_control_requires_post_csrf_session_and_admin(self):
        self.assertEqual(self.client.get(f"/ddos-detection/devices/{self.device.pk}/start/").status_code, 405)
        self.client.logout()
        self.assertEqual(self.client.post(f"/ddos-detection/devices/{self.device.pk}/stop/").status_code, 302)

    def test_start_uses_runtime_and_stop_keeps_incidents(self):
        with patch("public_ips.services.monitoring_runtime.launch") as launch:
            response = self.client.post(f"/ddos-detection/devices/{self.device.pk}/start/")
        self.assertEqual(response.status_code, 200, response.content); launch.assert_called_once()
        self.ip.refresh_from_db(); self.assertTrue(self.ip.monitoring_enabled)
        self.assertTrue(response.json()["data"]["devices"][0]["monitored"])
        event = DetectionEvent.objects.create(
            public_ip=self.ip, device=self.device, assignment_id_snapshot=self.ip.pk, device_id_snapshot=self.device.pk,
            address=self.ip.address, device_name="Edge 1", management_ip="192.0.2.10", profile_key="p",
            started_at=timezone.now(), last_observed_at=timezone.now(), highest_severity="Under Attack")
        self.assertEqual(self.client.post("/ddos-detection/all/stop/").status_code, 200)
        self.ip.refresh_from_db(); event.refresh_from_db()
        self.assertFalse(self.ip.monitoring_enabled); self.assertIsNone(event.ended_at)
        self.assertFalse(MonitoringRun.objects.get(pk=1).active)

    def test_start_monitors_every_verified_ip_of_the_device(self):
        second = PublicIP.objects.create(address="1.1.1.1", device=self.device, incoming_monitoring_interface="ether1",
                                         provisioning_status="verified", provisioning_verified_at=timezone.now())
        unverified = PublicIP.objects.create(address="9.9.9.9", device=self.device, provisioning_status="pending")
        with patch("public_ips.services.monitoring_runtime.launch") as launch:
            response = self.client.post(f"/ddos-detection/devices/{self.device.pk}/start/")
        self.assertEqual(response.status_code, 200, response.content); launch.assert_called_once()
        run = MonitoringRun.objects.get(pk=1)
        self.assertEqual(sorted(run.assignment_ids), sorted([self.ip.pk, second.pk]))
        for ip in (self.ip, second, unverified):
            ip.refresh_from_db()
        self.assertTrue(self.ip.monitoring_enabled and second.monitoring_enabled)
        self.assertFalse(unverified.monitoring_enabled)
        self.assertIn("2 public IPs", response.json()["message"])

    def test_start_on_another_device_while_one_runs_is_refused(self):
        other = Device(name="Edge 2", management_ip="192.0.2.11", username="u"); other.set_password("p"); other.save()
        PublicIP.objects.create(address="1.1.1.1", device=other, incoming_monitoring_interface="ether1",
                                provisioning_status="verified", provisioning_verified_at=timezone.now())
        with patch("public_ips.services.monitoring_runtime.launch"):
            self.assertEqual(self.client.post(f"/ddos-detection/devices/{self.device.pk}/start/").status_code, 200)
            self.assertEqual(self.client.post(f"/ddos-detection/devices/{other.pk}/start/").status_code, 409)

    def sensor(self, kind, enabled=True, age=5, valid=True, **sample):
        sensor = Sensor.objects.create(device=self.device, kind=kind, name=kind, interface_index=len(Sensor.objects.all()) + 1,
                                       interface_name="ether1" if kind == "traffic" else "", enabled=enabled)
        if age is not None:
            SensorSample.objects.create(sensor=sensor, timestamp=timezone.now() - timedelta(seconds=age), valid=valid, **sample)
        return sensor

    def test_saved_readings_of_paused_sensors_keep_values_but_are_not_live(self):
        # Same shape as RB-3011: enabled sensors, SNMP worker not running, samples an hour old.
        self.sensor("cpu", age=3600, cpu=18.5)
        self.sensor("uptime", age=3600, uptime_seconds=460853)
        self.sensor("traffic", age=3600, in_mbps=18.781, out_mbps=12.582)
        metrics = self.devices()[0]["metrics"]
        self.assertEqual((metrics["cpu"]["state"], metrics["cpu"]["mode"], metrics["cpu"]["value"]), ("ok", "paused", 18.5))
        self.assertEqual((metrics["uptime"]["mode"], metrics["uptime"]["value"]), ("paused", 460853))
        traffic = metrics["traffic"]
        self.assertEqual(traffic["mode"], "paused")
        self.assertAlmostEqual(traffic["in_mbps"], 18.781); self.assertAlmostEqual(traffic["out_mbps"], 12.582)
        self.assertEqual(traffic["interfaces"][0]["interface"], "ether1")
        self.assertGreaterEqual(metrics["cpu"]["age_seconds"], 3600)

    def test_stopped_sensor_with_saved_reading_is_paused_and_without_one_is_stopped(self):
        self.sensor("cpu", enabled=False, cpu=95)
        self.sensor("uptime", enabled=False, age=None)
        metrics = self.devices()[0]["metrics"]
        self.assertEqual((metrics["cpu"]["mode"], metrics["cpu"]["value"]), ("paused", 95))
        self.assertEqual(metrics["uptime"], {"state": "stopped", "value": None, "mode": None, "age_seconds": None})
        self.assertEqual(metrics["traffic"]["state"], "no_sensor")

    def test_invalid_or_unsampled_sensor_is_unknown(self):
        self.sensor("cpu", valid=False, cpu=None)
        self.sensor("uptime", age=None)
        metrics = self.devices()[0]["metrics"]
        self.assertEqual(metrics["cpu"]["state"], "unknown"); self.assertEqual(metrics["uptime"]["state"], "unknown")

    def test_running_sensors_are_live_or_stale(self):
        with patch("sensors.presentation.authorized", return_value=True), patch("sensors.presentation.worker_running", return_value=True):
            self.sensor("cpu", cpu=82)
            self.sensor("uptime", age=3600, uptime_seconds=100)
            self.sensor("traffic", in_mbps=10, out_mbps=5)
            self.sensor("traffic", in_mbps=1, out_mbps=2)
            metrics = self.devices()[0]["metrics"]
        self.assertEqual((metrics["cpu"]["mode"], metrics["cpu"]["value"]), ("live", 82))
        self.assertEqual((metrics["uptime"]["mode"], metrics["uptime"]["value"]), ("stale", 100))
        traffic = metrics["traffic"]
        self.assertEqual((traffic["mode"], traffic["value"], traffic["in_mbps"], traffic["out_mbps"]), ("live", 18, 11, 7))
        self.assertEqual(len(traffic["interfaces"]), 2)
