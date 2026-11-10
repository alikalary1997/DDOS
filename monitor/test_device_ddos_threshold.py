from datetime import timedelta
from decimal import Decimal
import os
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from devices.models import Device
from devices.services.credentials import encrypt_password
from public_ips.models import FirewallSample, PublicIP
from monitor.models import DetectionPolicy, DetectionState, DDoSDetectionSettings, DeviceDDoSThreshold, RAWMonitoringSettings


class DeviceDDoSThresholdDetectionTests(TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start(); self.addCleanup(env.stop)
        self.device = Device(name="Global router", management_ip="192.0.2.10", username="test")
        self.device.set_password("test-only"); self.device.save()
        self.override_device = Device(name="Override router", management_ip="192.0.2.11", username="test")
        self.override_device.set_password("test-only"); self.override_device.save()
        self.ip = PublicIP.objects.create(address="8.8.8.8", device=self.device, incoming_monitoring_interface="ether1",
                                         monitoring_enabled=True, provisioning_status="verified", provisioning_verified_at=timezone.now())
        self.override_ip = PublicIP.objects.create(address="8.8.4.4", device=self.override_device, incoming_monitoring_interface="ether1",
                                                  monitoring_enabled=True, provisioning_status="verified", provisioning_verified_at=timezone.now())
        self.policy = DetectionPolicy.objects.get(pk=1); self.policy.enabled = True; self.policy.save()
        RAWMonitoringSettings.objects.update_or_create(pk=1, defaults={"polling_interval": 10})
        self.now = timezone.now()
        self.clock = patch("django.utils.timezone.now", side_effect=lambda: self.now)
        self.clock.start(); self.addCleanup(self.clock.stop)

    def sample(self, ip, pps=0, mbps=0, syn=0, udp=0, step=10):
        self.now += timedelta(seconds=step)
        row = {"id": ip.pk, "device_id": ip.device_id, "address": ip.address, "status": "Monitoring",
               "attempted_at": self.now.isoformat(), "last_update": self.now.isoformat(), "polling_interval": 10,
               "profile_version": [ip.updated_at.isoformat(), ip.provisioning_verified_at.isoformat()],
               "pps": pps, "mbps": mbps, "packets": 100, "bytes": 1000,
               "protocol_rules": [{"name": "MONITOR-SYN-" + ip.address, "pps": syn}, {"name": "MONITOR-UDP-" + ip.address, "pps": udp}]}
        FirewallSample.objects.update_or_create(device_id=ip.device_id, defaults={"status": "sampled", "sampled_at": self.now, "rows": [row]})
        return DetectionState.objects.filter(public_ip=ip).first()

    def repeat(self, ip, count=3, **kwargs):
        state = None
        for _ in range(count):
            state = self.sample(ip, **kwargs)
        return state

    def test_no_override_uses_global_thresholds(self):
        # Global syn_pps_warning is 2000 by default; a device without an override crosses it.
        self.assertEqual(self.repeat(self.ip, syn=2500).confirmed_status, "Warning")

    def test_override_uses_its_own_thresholds(self):
        DeviceDDoSThreshold.objects.create(device=self.override_device, syn_pps_warning=5000, syn_pps_attack=10000)
        # 2500 is above the global warning (2000) but below this device's override (5000).
        self.assertEqual(self.repeat(self.override_ip, syn=2500).confirmed_status, "Normal")

    def test_engine_picks_correct_thresholds_per_device(self):
        DeviceDDoSThreshold.objects.create(device=self.override_device, syn_pps_warning=5000, syn_pps_attack=10000)
        self.repeat(self.ip, syn=3000)
        self.repeat(self.override_ip, syn=3000)
        self.assertEqual(DetectionState.objects.get(public_ip=self.ip).confirmed_status, "Warning")
        self.assertEqual(DetectionState.objects.get(public_ip=self.override_ip).confirmed_status, "Normal")

    def test_fallback_follows_global_change_not_a_copy(self):
        # Raise the global warning above the sample value; a no-override device must follow it.
        self.repeat(self.ip, syn=2500)
        DetectionState.objects.all().delete()
        settings = DDoSDetectionSettings.objects.get(pk=1)
        settings.syn_pps_warning = 3000; settings.save()
        self.assertEqual(self.repeat(self.ip, syn=2500).confirmed_status, "Normal")


class DeviceDDoSThresholdUITests(TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start(); self.addCleanup(env.stop)
        self.admin = get_user_model().objects.create_user(username="threshold-admin", is_staff=True)
        self.client.force_login(self.admin)
        self.device = Device.objects.create(name="UI router", management_ip="10.20.30.40", username="private-user",
                                            encrypted_password=encrypt_password("private-api-password"))
        self.url = reverse("device_sensors", args=[self.device.pk])
        self.save_url = reverse("device_ddos_settings", args=[self.device.pk])
        self.values = {"total_pps_warning": "9000", "total_pps_attack": "45000",
                       "bandwidth_mbps_warning": "95.125", "bandwidth_mbps_attack": "450.5",
                       "syn_pps_warning": "1500", "syn_pps_attack": "9000",
                       "udp_pps_warning": "4000", "udp_pps_attack": "19000",
                       "cpu_warning": "70", "cpu_attack": "90"}

    def test_section_renders_with_global_defaults(self):
        response = self.client.get(self.url)
        self.assertContains(response, "DDoS Settings")
        self.assertContains(response, "USING GLOBAL DEFAULTS")
        self.assertContains(response, "not validated production thresholds")
        for label in ("Total PPS", "Bandwidth (Mbps)", "TCP SYN PPS", "UDP PPS", "CPU (%)"):
            self.assertContains(response, label)
        self.assertEqual(len(response.context["ddos_form"].fields), 10)
        # The global default is pre-filled, but no override row exists yet.
        self.assertEqual(Decimal(response.context["ddos_form"]["syn_pps_warning"].value()), Decimal("2000"))
        self.assertFalse(DeviceDDoSThreshold.objects.filter(device=self.device).exists())

    def test_save_creates_override_and_shows_custom_indicator(self):
        response = self.client.post(self.save_url, {**self.values, "action": "save"})
        self.assertRedirects(response, self.url)
        override = DeviceDDoSThreshold.objects.get(device=self.device)
        self.assertEqual(override.syn_pps_warning, 1500)
        page = self.client.get(self.url)
        self.assertContains(page, "CUSTOM OVERRIDE")
        self.assertEqual(Decimal(page.context["ddos_form"]["syn_pps_warning"].value()), Decimal("1500"))

    def test_save_updates_existing_override_without_duplicating(self):
        DeviceDDoSThreshold.objects.create(device=self.device, **self.values)
        self.client.post(self.save_url, {**self.values, "syn_pps_warning": "1600", "action": "save"})
        self.assertEqual(DeviceDDoSThreshold.objects.filter(device=self.device).count(), 1)
        self.assertEqual(DeviceDDoSThreshold.objects.get(device=self.device).syn_pps_warning, 1600)

    def test_reset_removes_override_and_returns_to_global(self):
        DeviceDDoSThreshold.objects.create(device=self.device, **self.values)
        response = self.client.post(self.save_url, {"action": "reset"})
        self.assertRedirects(response, self.url)
        self.assertFalse(DeviceDDoSThreshold.objects.filter(device=self.device).exists())
        self.assertContains(self.client.get(self.url), "USING GLOBAL DEFAULTS")

    def test_validation_rejects_attack_below_warning(self):
        response = self.client.post(self.save_url, {**self.values, "syn_pps_attack": "100", "action": "save"})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(DeviceDDoSThreshold.objects.filter(device=self.device).exists())
