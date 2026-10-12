from datetime import timedelta
import os
from cryptography.fernet import Fernet
from io import StringIO
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command, CommandError
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from devices.models import Device
from public_ips.models import FirewallSample, PublicIP
from monitor.models import DetectionPolicy, DetectionState, DetectionEvent, DDoSDetectionSettings, RAWMonitoringSettings
from monitor.services.detection import process_sample
from monitor.services.detection_presentation import DetectionPresentation


class DetectionTests(TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start()
        self.addCleanup(env.stop)
        self.device = Device(name="Test router", management_ip="192.0.2.10", username="test")
        self.device.set_password("test-only")
        self.device.save()
        self.ip = PublicIP.objects.create(address="8.8.8.8", device=self.device, incoming_monitoring_interface="ether1",
                                         monitoring_enabled=True, provisioning_status="verified", provisioning_verified_at=timezone.now())
        self.policy = DetectionPolicy.objects.get(pk=1)
        self.policy.enabled = True
        self.policy.save()
        RAWMonitoringSettings.objects.update_or_create(pk=1, defaults={"polling_interval": 10})
        self.now = timezone.now()
        self.clock = patch("django.utils.timezone.now", side_effect=lambda: self.now)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.pool = patch("devices.services.router_session.routeros_api.RouterOsApiPool").start()
        self.addCleanup(patch.stopall)

    def tearDown(self):
        self.pool.assert_not_called()

    @staticmethod
    def target(ip):
        return {"device_id": ip.device_id, "assignment_id": ip.pk, "public_ip": ip.address}

    def sample(self, ip=None, pps=0, mbps=0, syn=0, udp=0, step=10, **overrides):
        ip = ip or self.ip
        self.now += timedelta(seconds=step)
        row = {"id": ip.pk, "device_id": ip.device_id, "address": ip.address, "status": "Monitoring",
               "attempted_at": self.now.isoformat(), "last_update": self.now.isoformat(), "polling_interval": 10,
               "profile_version": [ip.updated_at.isoformat(), ip.provisioning_verified_at.isoformat()],
               "pps": pps, "mbps": mbps, "packets": 100, "bytes": 1000,
               "protocol_rules": [{"name": "MONITOR-SYN-" + ip.address, "pps": syn}, {"name": "MONITOR-UDP-" + ip.address, "pps": udp}]}
        row.update(overrides)
        self.cache, _ = FirewallSample.objects.update_or_create(device_id=ip.device_id,
                                                              defaults={"status": "sampled", "sampled_at": self.now, "rows": [row]})
        self.row = row
        return DetectionState.objects.filter(public_ip=ip).first()

    def repeat(self, count=3, **kwargs):
        for _ in range(count):
            state = self.sample(**kwargs)
        return state

    def projection(self, row=None):
        with patch("monitor.services.detection_presentation.polling_enabled", return_value=True):
            return DetectionPresentation().fields(self.ip.pk, self.row if row is None else row)

    def test_global_disable_and_enable_does_not_start_worker(self):
        self.policy.enabled = False
        self.policy.save()
        self.assertIsNone(self.sample(pps=100000))
        with patch("subprocess.Popen") as launch:
            call_command("detection_control", enable=True, stdout=StringIO())
            self.assertEqual(self.repeat(pps=50000).confirmed_status, "Under Attack")
            call_command("detection_control", disable=True, stdout=StringIO())
            launch.assert_not_called()
        self.assertEqual(self.projection()["ddos_status"], "Unknown")

    def test_normal_and_actual_zero_traffic(self):
        self.assertEqual(self.sample().confirmed_status, "Normal")
        self.assertEqual(self.projection()["ddos_status"], "Normal")
        self.assertFalse(DetectionEvent.objects.exists())

    def test_default_enabled_and_per_ip_opt_out_does_not_change_monitoring_or_history(self):
        self.assertTrue(self.ip.detection_enabled)
        self.assertTrue(DetectionPolicy().enabled)
        self.repeat(pps=50000)
        before = PublicIP.objects.values().get(pk=self.ip.pk)
        admin = get_user_model().objects.create_user(username="toggle-admin", is_staff=True)
        self.client.force_login(admin)
        disable = reverse("public_ip_detection_control", args=[self.ip.pk, "disable"])
        with patch("subprocess.Popen") as launch:
            self.assertEqual(self.client.get(disable).status_code, 405)
            self.assertEqual(self.client.post(disable).status_code, 302)
            launch.assert_not_called()
        self.ip.refresh_from_db()
        self.assertFalse(self.ip.detection_enabled)
        after = PublicIP.objects.values().get(pk=self.ip.pk)
        self.assertEqual({k:v for k,v in before.items() if k != "detection_enabled"},
                         {k:v for k,v in after.items() if k != "detection_enabled"})
        self.assertEqual(self.projection()["ddos_status"], "Unknown")
        self.assertIsNone(DetectionEvent.objects.get().ended_at)
        self.assertEqual(self.client.post(reverse("public_ip_detection_control", args=[self.ip.pk, "enable"])).status_code, 302)
        self.ip.refresh_from_db()
        self.assertEqual(self.repeat().confirmed_status, "Normal")
        self.assertEqual(DetectionEvent.objects.count(), 1)
        self.assertIsNotNone(DetectionEvent.objects.get().ended_at)

    def test_detection_toggle_requires_admin_and_csrf(self):
        from django.test import Client
        user = get_user_model().objects.create_user(username="toggle-reader")
        url = reverse("public_ip_detection_control", args=[self.ip.pk, "disable"])
        self.assertEqual(self.client.post(url).status_code, 302)
        self.client.force_login(user)
        self.assertEqual(self.client.post(url).status_code, 403)
        user.is_staff = True
        user.save()
        client = Client(enforce_csrf_checks=True)
        client.force_login(user)
        self.assertEqual(client.post(url).status_code, 403)
        self.ip.refresh_from_db()
        self.assertTrue(self.ip.detection_enabled)

    def test_stopped_monitoring_and_disabled_device_never_evaluate(self):
        PublicIP.objects.filter(pk=self.ip.pk).update(monitoring_enabled=False)
        self.repeat(pps=100000)
        self.assertFalse(DetectionEvent.objects.exists())
        self.assertEqual(self.projection()["ddos_status"], "Unknown")
        self.device.enabled = False
        self.device.save()
        PublicIP.objects.filter(pk=self.ip.pk).update(monitoring_enabled=True)
        self.repeat(pps=100000)
        self.assertFalse(DetectionEvent.objects.exists())

    def test_three_warning_samples_and_peak_includes_first_sample(self):
        self.assertEqual(self.sample(pps=30000).confirmed_status, "Unknown")
        self.assertEqual(self.sample(pps=10000).confirmed_status, "Unknown")
        self.assertEqual(self.sample(pps=10000).confirmed_status, "Warning")
        event = DetectionEvent.objects.get()
        self.assertEqual(event.peak_total_pps, 30000)
        self.assertEqual(event.started_at, self.now - timedelta(seconds=20))
        self.assertEqual(event.triggering_metrics[0]["metric"], "total_pps")

    def test_independent_attack_thresholds_inclusive(self):
        for metric, payload in (("total_pps", {"pps": 50000}), ("bandwidth_mbps", {"mbps": 500}),
                                ("syn_pps", {"syn": 10000}), ("udp_pps", {"udp": 20000})):
            with self.subTest(metric=metric):
                DetectionState.objects.all().delete()
                DetectionEvent.objects.all().delete()
                self.assertEqual(self.repeat(**payload).confirmed_status, "Under Attack")
                self.assertEqual(DetectionEvent.objects.get().triggering_metrics[0]["metric"], metric)

    def test_warning_to_attack_escalation_requires_three_attack_samples(self):
        self.repeat(pps=10000)
        self.assertEqual(self.sample(syn=10000).confirmed_status, "Warning")
        self.assertEqual(self.sample(syn=10000).confirmed_status, "Warning")
        self.assertEqual(self.sample(syn=10000).confirmed_status, "Under Attack")
        self.assertEqual(DetectionEvent.objects.count(), 1)
        self.assertEqual(DetectionEvent.objects.get().highest_severity, "Under Attack")

    def test_multiple_triggers_and_no_duplicate_events_or_duplicate_sample_counts(self):
        self.sample(pps=50000, mbps=500, syn=10000, udp=20000)
        process_sample(self.cache)
        self.assertEqual(DetectionState.objects.get().attack_count, 1)
        self.repeat(5, pps=50000, mbps=500, syn=10000, udp=20000)
        self.assertEqual(DetectionEvent.objects.count(), 1)
        self.assertEqual(len(DetectionEvent.objects.get().triggering_metrics), 4)

    def test_hysteresis_recovery_and_new_incident(self):
        self.repeat(pps=50000)
        self.assertEqual(self.repeat(pps=45000).confirmed_status, "Under Attack")
        self.assertEqual(self.sample(pps=30000).confirmed_status, "Under Attack")
        self.assertEqual(self.repeat(2, pps=30000).confirmed_status, "Warning")
        self.assertEqual(self.repeat(pps=9000).confirmed_status, "Warning")
        self.assertEqual(self.sample(pps=7000).confirmed_status, "Warning")
        self.assertEqual(self.repeat(2, pps=7000).confirmed_status, "Normal")
        event = DetectionEvent.objects.get()
        self.assertEqual(event.ended_at, self.now)
        self.assertGreater(event.duration_seconds, 0)
        self.repeat(pps=50000)
        self.assertEqual(DetectionEvent.objects.count(), 2)

    def test_invalid_protocol_samples_and_gaps_reset_confirmation(self):
        self.repeat(2, udp=20000)
        self.sample(udp=None)
        self.assertIsNone(DetectionState.objects.get().last_valid_at)
        self.repeat(2, udp=20000)
        self.assertFalse(DetectionEvent.objects.exists())
        self.sample(udp=20000, step=30)
        self.assertEqual(DetectionState.objects.get().attack_count, 1)
        self.assertFalse(DetectionEvent.objects.exists())
        self.repeat(2, udp=20000)
        self.assertEqual(DetectionEvent.objects.count(), 1)

    def test_missing_stale_error_and_retained_samples_are_unknown_and_do_not_close_incident(self):
        self.repeat(pps=50000)
        self.now += timedelta(seconds=30)
        self.assertEqual(self.projection()["monitoring_health"], "Stale")
        self.assertEqual(self.projection()["ddos_status"], "Unknown")
        for changes in ({"status": "Connection error"}, {"retained": True}, {"pps": None}, {"protocol_rules": []},
                        {"attempted_at": "bad"}, {"status": "No matching RAW rule"}, {"pps": -1}):
            self.sample(**changes)
            self.assertEqual(self.projection()["ddos_status"], "Unknown")
            self.assertIsNone(DetectionEvent.objects.get().ended_at)
        self.assertEqual(self.projection({})["ddos_status"], "Unknown")
        self.sample(status="Connection error")
        self.assertEqual(self.projection()["monitoring_health"], "Connection Failed")
        with patch("monitor.services.detection_presentation.polling_enabled", return_value=False):
            self.assertEqual(DetectionPresentation().fields(self.ip.pk, self.row)["monitoring_health"], "Not Monitored")

    def test_threshold_changes_and_configurable_counts_apply_on_next_new_sample(self):
        self.repeat(2, syn=1600)
        settings = DDoSDetectionSettings.objects.get(pk=1)
        settings.syn_pps_warning = 1500
        settings.save()
        self.assertEqual(self.projection()["ddos_status"], "Unknown")
        self.repeat(2, syn=1600)
        self.assertFalse(DetectionEvent.objects.exists())
        self.assertEqual(self.sample(syn=1600).confirmed_status, "Warning")
        self.policy.recovery_samples = 1
        self.policy.hysteresis_percent = 10
        self.policy.save()
        self.assertEqual(self.sample().confirmed_status, "Normal")

    def test_different_devices_ips_and_unauthorized_assignment_isolation(self):
        other_device = Device(name="Other", management_ip="192.0.2.11", username="test")
        other_device.set_password("test-only")
        other_device.save()
        second = PublicIP.objects.create(address="8.8.4.4", device=other_device, monitoring_enabled=True,
                                         provisioning_status="verified", provisioning_verified_at=self.now)
        third = PublicIP.objects.create(address="9.9.9.9", device=self.device, monitoring_enabled=True, detection_enabled=False,
                                        provisioning_status="verified", provisioning_verified_at=self.now)
        self.assertIsNone(self.repeat(ip=third, pps=100000))
        for _ in range(3):
            self.sample(ip=self.ip, pps=50000, step=5)
            self.sample(ip=second, step=5)
        self.assertEqual(DetectionState.objects.get(public_ip=self.ip).confirmed_status, "Under Attack")
        self.assertEqual(DetectionState.objects.get(public_ip=second).confirmed_status, "Normal")
        self.assertEqual(DetectionEvent.objects.count(), 1)

    def test_profile_change_and_deletion_preserve_history(self):
        self.repeat(pps=50000)
        self.ip.incoming_monitoring_interface = "ether2"
        self.ip.save()
        self.assertEqual(self.projection()["ddos_status"], "Unknown")
        self.assertEqual(self.sample().confirmed_status, "Normal")
        self.assertIsNone(DetectionEvent.objects.get().ended_at)
        self.ip.delete()
        self.device.delete()
        event = DetectionEvent.objects.get()
        self.assertIsNone(event.public_ip_id)
        self.assertIsNone(event.device_id)
        self.assertEqual(event.address, "8.8.8.8")
        self.assertEqual(event.device_name, "Test router")

    def test_stale_and_wrong_identity_samples_do_not_count(self):
        self.sample(pps=50000, last_update=(self.now - timedelta(minutes=1)).isoformat())
        self.assertEqual(DetectionState.objects.get().attack_count, 0)
        self.sample(pps=50000, address="1.1.1.1")
        self.assertEqual(DetectionState.objects.get().attack_count, 0)

    def test_nonconsecutive_crossings_and_invalid_recovery_do_not_change_status(self):
        self.sample()
        for _ in range(3):
            self.repeat(2, pps=50000)
            self.assertEqual(self.sample().confirmed_status, "Normal")
        self.assertFalse(DetectionEvent.objects.exists())
        self.repeat(pps=50000)
        self.repeat(2)
        self.sample(status="Connection error")
        self.assertEqual(self.repeat(2).confirmed_status, "Under Attack")
        self.assertIsNone(DetectionEvent.objects.get().ended_at)
        self.assertEqual(self.sample().confirmed_status, "Normal")

    def test_configured_entry_count_and_recovery_boundary(self):
        self.policy.confirmation_samples = 1
        self.policy.recovery_samples = 1
        self.policy.save()
        self.assertEqual(self.sample(pps=50000).confirmed_status, "Under Attack")
        self.assertEqual(self.sample(pps=40000).confirmed_status, "Under Attack")
        self.assertEqual(self.sample(pps=39999).confirmed_status, "Warning")
        self.assertEqual(self.sample(pps=8000).confirmed_status, "Warning")
        self.assertEqual(self.sample(pps=7999).confirmed_status, "Normal")

    def test_detection_failure_retains_raw_sample_and_reports_unknown(self):
        self.sample()
        with patch("monitor.services.detection.process_sample", side_effect=RuntimeError("test failure")), self.assertLogs("monitor.signals", level="ERROR"):
            self.sample(pps=50000)
        self.assertEqual(FirewallSample.objects.get().rows[0]["pps"], 50000)
        self.assertEqual(self.projection()["ddos_status"], "Unknown")

    def test_repeated_retained_sibling_is_not_a_new_confirmation(self):
        sibling = PublicIP.objects.create(address="9.9.9.9", device=self.device, monitoring_enabled=True,
                                         provisioning_status="verified", provisioning_verified_at=self.now)
        self.sample(pps=50000)
        original = dict(self.row)
        for _ in range(3):
            self.sample(ip=sibling, step=1)
            self.cache.rows.append(original)
            self.cache.save()
        self.assertEqual(DetectionState.objects.get(public_ip=self.ip).attack_count, 1)
        self.assertFalse(DetectionEvent.objects.exists())

    def test_policy_form_admin_only_and_cannot_activate(self):
        user = get_user_model().objects.create_user(username="reader")
        self.client.force_login(user)
        payload = {"settings_section": "ddos_policy", "confirmation_samples": 4, "recovery_samples": 5,
                   "hysteresis_percent": 25, "enabled": "true"}
        self.assertEqual(self.client.post(reverse("settings"), payload).status_code, 403)
        user.is_staff = True
        user.save()
        self.policy.enabled = False
        self.policy.save()
        self.assertEqual(self.client.post(reverse("settings"), payload).status_code, 302)
        self.policy.refresh_from_db()
        self.assertFalse(self.policy.enabled)
        self.assertEqual(self.policy.confirmation_samples, 4)
        for key, value in (("confirmation_samples", 0), ("recovery_samples", 101), ("hysteresis_percent", 100)):
            self.assertEqual(self.client.post(reverse("settings"), {**payload, key: value}).status_code, 400)

    def test_api_dashboard_and_history_use_persisted_detection_status(self):
        self.repeat(syn=10000)
        user = get_user_model().objects.create_user(username="viewer")
        self.client.force_login(user)
        with patch("public_ips.services.monitoring.POLLING_RELEASED", True), self.settings(NETSHIELD_RAW_POLLING_ENABLED=True):
            data = self.client.get(reverse("public_ip_monitoring_data")).json()["rows"][0]
            self.assertEqual(data["ddos_status"], "Under Attack")
            self.assertEqual(data["monitoring_health"], "Active")
            dashboard = self.client.get(reverse("monitoring_data")).json()["rules"][0]
            self.assertEqual(dashboard["ddos_status"], "Under Attack")
            self.assertContains(self.client.get(reverse("public_ips")), "Under Attack")
        history = self.client.get(reverse("ddos_detection"))
        self.assertContains(history, "TCP SYN PPS")
        self.assertContains(history, "8.8.8.8")
        self.client.logout()
        self.assertEqual(self.client.get(reverse("ddos_detection")).status_code, 302)
