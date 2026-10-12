import os
from datetime import timedelta
from unittest.mock import patch
from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone
from devices.models import Device
from public_ips.models import PublicIP, FirewallSample
from monitor.models import DetectionEvent, RAWMonitoringSettings
from monitor.services.dashboard_data import dashboard_data


@override_settings(NETSHIELD_RAW_POLLING_ENABLED=True)
class DashboardOverviewTests(TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start()
        self.addCleanup(env.stop)
        gate = patch("public_ips.services.monitoring.POLLING_RELEASED", True)
        gate.start()
        self.addCleanup(gate.stop)
        self.router = Device(name="Saved router", management_ip="192.0.2.1", username="private-account")
        self.router.set_password("test-only")
        self.router.save()
        self.ip = PublicIP.objects.create(address="8.8.8.8", device=self.router, monitoring_enabled=True,
            incoming_monitoring_interface="ether1", provisioning_status="verified", provisioning_verified_at=timezone.now())
        RAWMonitoringSettings.objects.update_or_create(pk=1, defaults={"polling_interval": 10})
        self.now = timezone.now()
        clock = patch("django.utils.timezone.now", side_effect=lambda: self.now)
        clock.start()
        self.addCleanup(clock.stop)
        self.pool = patch("devices.services.router_session.routeros_api.RouterOsApiPool").start()
        self.addCleanup(patch.stopall)

    def tearDown(self):
        self.pool.assert_not_called()

    def sample(self, ips=None, pps=0, mbps=0):
        self.now += timedelta(seconds=2)
        rows = []
        for ip in ips or [self.ip]:
            rows.append({"id": ip.pk, "address": ip.address, "device_id": ip.device_id,
                "status": "Monitoring", "pps": pps, "mbps": mbps, "packets": 500, "bytes": 2000,
                "last_update": self.now.isoformat(), "attempted_at": self.now.isoformat(),
                "profile_version": [ip.updated_at.isoformat(), ip.provisioning_verified_at.isoformat()],
                "protocol_rules": [{"name": "MONITOR-SYN-" + ip.address, "pps": 5},
                                   {"name": "MONITOR-UDP-" + ip.address, "pps": 6}]})
        FirewallSample.objects.update_or_create(device=self.router, defaults={"status": "sampled", "sampled_at": self.now, "rows": rows})

    def test_missing_zero_and_aggregate_totals_do_not_double_count_protocols(self):
        initial = dashboard_data()
        self.assertIsNone(initial["overview"]["total_pps"])
        self.assertEqual(initial["overview"]["unknown_ips"], 1)
        self.sample()
        self.assertEqual(dashboard_data()["overview"]["total_pps"], 0)
        second = PublicIP.objects.create(address="9.9.9.9", device=self.router, monitoring_enabled=True,
            provisioning_status="verified", provisioning_verified_at=self.now)
        self.sample([self.ip, second], pps=100, mbps=.02)
        data = dashboard_data()
        self.assertEqual(data["overview"]["total_pps"], 200)
        self.assertEqual(data["overview"]["total_mbps"], .04)
        self.assertEqual(data["devices"][0]["monitored_ips"], 2)
        self.assertEqual(data["devices"][0]["monitoring_health"], "Receiving samples")

    def test_live_incident_then_stale_is_unresolved_history_not_an_active_attack(self):
        for _ in range(3):
            self.sample(pps=50000)
        data = dashboard_data()
        self.assertEqual(data["overview"]["attack_ips"], 1)
        self.assertEqual(data["incidents"][0]["started_at"], DetectionEvent.objects.get().started_at)
        self.assertEqual(data["recent_events"][0]["status"], "Ongoing")
        self.now += timedelta(seconds=30)
        data = dashboard_data()
        self.assertEqual(data["incidents"], [])
        self.assertEqual(data["overview"]["active_detections"], 0)
        self.assertEqual(data["recent_events"][0]["status"], "Unresolved")
        self.assertIsNone(data["overview"]["total_pps"])
        self.assertEqual(data["devices"][0]["monitoring_health"], "Stale")

    def test_recovered_and_deleted_assignment_events_keep_real_history(self):
        for _ in range(3):
            self.sample(pps=50000)
        for _ in range(3):
            self.sample()
        self.assertEqual(dashboard_data()["recent_events"][0]["status"], "Recovered")
        self.ip.delete()
        data = dashboard_data()
        self.assertEqual(data["rules"], [])
        self.assertEqual(data["recent_events"][0]["address"], "8.8.8.8")
        self.assertEqual(data["recent_events"][0]["peak_pps"], 50000)

    def test_page_read_only_links_theme_and_truthful_health(self):
        user = get_user_model().objects.create_user(username="overview-reader")
        self.client.force_login(user)
        with patch("subprocess.Popen") as launch:
            response = self.client.get("/")
            self.assertEqual(response.status_code, 200)
            for label in ("DDoS detection center", "MikroTik fleet", "Public IP traffic", "Recent detection events",
                          "System &amp; monitoring", "overview.css", "theme.js", "dashboardSearch"):
                self.assertContains(response, label)
            for label in ("Flush Flowspec", "Scrubbing Active", "Stop Monitoring", "SYN Flood", "RADIUS"):
                self.assertNotContains(response, label)
            data = self.client.get("/monitoring-data/").json()
            self.assertFalse(data["system"]["worker_running"])
            self.assertEqual(data["system"]["sampled_devices"], 0)
            self.assertEqual(data["devices"][0]["monitoring_health"], "Stale")
            self.assertIn("#ipAddress", data["rules"][0]["inspect_url"])
            self.assertIsNone(data["rules"][0]["retry_url"])
            launch.assert_not_called()
