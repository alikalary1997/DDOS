"""CPU as the fifth DDoS detection metric, read from the device's CPU sensor."""
from datetime import timedelta
import os
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from devices.models import Device
from devices.services.credentials import encrypt_password
from monitor.models import (CPU_METRIC, DDoSDetectionSettings, DetectionEvent, DetectionPolicy, DetectionState,
                            DeviceDDoSThreshold, THRESHOLD_METRICS)
from monitor.services.detection import process_sample
from monitor.services.detection_presentation import DetectionPresentation
from public_ips.models import FirewallSample, PublicIP
from sensors.models import Sensor, SensorSample


class CpuThresholdDetectionTests(TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start(); self.addCleanup(env.stop)
        self.device = Device(name="CPU router", management_ip="192.0.2.30", username="test")
        self.device.set_password("test-only"); self.device.save()
        self.ip = PublicIP.objects.create(address="8.8.8.8", device=self.device, incoming_monitoring_interface="ether1",
                                         monitoring_enabled=True, provisioning_status="verified",
                                         provisioning_verified_at=timezone.now())
        self.policy = DetectionPolicy.objects.get(pk=1); self.policy.enabled = True; self.policy.save()
        self.now = timezone.now()
        self.clock = patch("django.utils.timezone.now", side_effect=lambda: self.now)
        self.clock.start(); self.addCleanup(self.clock.stop)

    # RAW traffic stays at zero so only CPU can drive the result.
    def sample(self, step=10):
        self.now += timedelta(seconds=step)
        row = {"id": self.ip.pk, "device_id": self.ip.device_id, "address": self.ip.address, "status": "Monitoring",
               "attempted_at": self.now.isoformat(), "last_update": self.now.isoformat(), "polling_interval": 10,
               "profile_version": [self.ip.updated_at.isoformat(), self.ip.provisioning_verified_at.isoformat()],
               "pps": 0, "mbps": 0, "packets": 100, "bytes": 1000,
               "protocol_rules": [{"name": "MONITOR-SYN-" + self.ip.address, "pps": 0},
                                  {"name": "MONITOR-UDP-" + self.ip.address, "pps": 0}]}
        cache, _ = FirewallSample.objects.update_or_create(device_id=self.ip.device_id,
                                                          defaults={"status": "sampled", "sampled_at": self.now, "rows": [row]})
        process_sample(cache)
        return DetectionState.objects.filter(public_ip=self.ip).first()

    def cpu_sensor(self, value, age_seconds=0, enabled=True, valid=True):
        sensor, _ = Sensor.objects.get_or_create(device=self.device, kind="cpu", interface_index=0,
                                                 defaults={"name": "CPU", "interval": 10})
        Sensor.objects.filter(pk=sensor.pk).update(enabled=enabled)
        SensorSample.objects.filter(sensor=sensor).update(valid=False)
        SensorSample.objects.create(sensor=sensor, timestamp=self.now - timedelta(seconds=age_seconds),
                                    valid=valid, cpu=value)
        return sensor

    def repeat(self, count=3):
        state = None
        for _ in range(count):
            state = self.sample()
        return state

    def projection(self):
        with patch("monitor.services.detection_presentation.polling_enabled", return_value=True):
            last = FirewallSample.objects.get().rows[0]
            return DetectionPresentation().fields(self.ip.pk, last)

    def test_cpu_warning_and_attack_from_cpu_sensor(self):
        sensor = self.cpu_sensor(75)  # global default: warning 70, attack 90
        self.assertEqual(self.repeat(2).confirmed_status, "Unknown")
        self.assertEqual(self.sample().confirmed_status, "Warning")
        self.cpu_sensor(95)
        self.assertEqual(self.sample().confirmed_status, "Warning")
        self.assertEqual(self.sample().confirmed_status, "Warning")
        self.assertEqual(self.sample().confirmed_status, "Under Attack")
        event = DetectionEvent.objects.get()
        self.assertEqual(event.highest_severity, "Under Attack")
        self.assertIn(CPU_METRIC[0], [item["metric"] for item in event.triggering_metrics])
        self.assertEqual(event.peak_cpu, 95)
        self.assertEqual(DetectionState.objects.get(public_ip=self.ip).confirmed_status, "Under Attack")
        self.sensor_pk = sensor.pk

    def test_cpu_unknown_without_sensor_or_with_stale_reading(self):
        # No CPU sensor at all: CPU must not be guessed as 0% or Normal.
        state = self.repeat(3)
        self.assertEqual(state.confirmed_status, "Normal")
        self.assertNotIn(CPU_METRIC[0], [item["metric"] for item in state.triggering_metrics])
        # A stale CPU reading (older than interval * 3) is also Unknown, not a fresh crossing.
        self.cpu_sensor(99, age_seconds=120)
        self.assertEqual(self.sample().confirmed_status, "Normal")
        self.assertNotIn(CPU_METRIC[0], [item["metric"] for item in DetectionState.objects.get(public_ip=self.ip).triggering_metrics])
        # A disabled CPU sensor is ignored even when it has a fresh high reading.
        self.cpu_sensor(99, enabled=False)
        self.assertEqual(self.sample().confirmed_status, "Normal")

    def test_device_override_applies_to_cpu_thresholds(self):
        DeviceDDoSThreshold.objects.create(device=self.device, cpu_warning=95, cpu_attack=99)
        self.cpu_sensor(75)  # above global warning (70) but below this device's override (95)
        self.assertEqual(self.repeat(3).confirmed_status, "Normal")

    def test_invalid_cpu_thresholds_are_rejected(self):
        settings = DDoSDetectionSettings.objects.get(pk=1)
        settings.cpu_warning = 90; settings.cpu_attack = 90
        with self.assertRaises(Exception):
            settings.full_clean()
        settings.cpu_attack = 101
        with self.assertRaises(Exception):
            settings.full_clean()


class CpuThresholdFormTests(TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start(); self.addCleanup(env.stop)
        self.admin = get_user_model().objects.create_user(username="cpu-admin", is_staff=True)
        self.client.force_login(self.admin)
        self.device = Device.objects.create(name="CPU UI router", management_ip="10.20.30.50", username="private-user",
                                            encrypted_password=encrypt_password("private-api-password"))
        self.values = {metric + "_" + level: "10" if level == "warning" else "50"
                       for metric, _ in THRESHOLD_METRICS for level in ("warning", "attack")}
        self.values.update(cpu_warning="70", cpu_attack="90")
        self.save_url = reverse("device_ddos_settings", args=[self.device.pk])

    def test_cpu_row_renders_and_saves_on_device_page(self):
        page = self.client.get(reverse("device_sensors", args=[self.device.pk]))
        self.assertContains(page, "CPU (%)")
        self.assertEqual(len(page.context["ddos_form"].fields), 10)
        self.assertEqual(page.context["ddos_form"]["cpu_warning"].field.widget.attrs.get("max"), "100")
        self.assertRedirects(self.client.post(self.save_url, {**self.values, "action": "save"}),
                             reverse("device_sensors", args=[self.device.pk]))
        override = DeviceDDoSThreshold.objects.get(device=self.device)
        self.assertEqual((override.cpu_warning, override.cpu_attack), (70, 90))

    def test_cpu_row_saves_on_global_settings_page(self):
        response = self.client.post(reverse("settings"), {"settings_section": "ddos", **self.values})
        self.assertRedirects(response, reverse("settings") + "#detectionSettings")
        settings = DDoSDetectionSettings.objects.get(pk=1)
        self.assertEqual((settings.cpu_warning, settings.cpu_attack), (70, 90))

    def test_cpu_attack_must_exceed_warning_and_stay_within_100(self):
        response = self.client.post(self.save_url, {**self.values, "cpu_attack": "70", "action": "save"})
        self.assertEqual(response.status_code, 400)
        self.assertContains(response, "Attack must be greater than Warning", status_code=400)
        response = self.client.post(self.save_url, {**self.values, "cpu_attack": "101", "action": "save"})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(DeviceDDoSThreshold.objects.filter(device=self.device).exists())
