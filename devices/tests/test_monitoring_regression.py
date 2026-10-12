import os
import secrets
from datetime import timedelta
from unittest.mock import patch
from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.utils import timezone
from devices.models import Device
from public_ips.models import FirewallSample, PublicIP


class MonitoringRegressionTests(TestCase):
    def setUp(self):
        self.admin = get_user_model().objects.create_user(username="dashboard-admin", is_staff=True)
        self.reader = get_user_model().objects.create_user(username="dashboard-reader")
        self.client.force_login(self.admin)
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start(); self.addCleanup(env.stop)
        self.secret = secrets.token_urlsafe(32)

    def device(self, name="Saved router", ip="172.26.241.16"):
        device = Device(name=name, management_ip=ip, username="private-api-account", incoming_monitoring_interface="ether1")
        device.set_password(self.secret); device.save(); return device

    def assignment(self, device=None, address="185.166.26.16"):
        return PublicIP.objects.create(device=device or self.device(), address=address)

    def sample(self, ip, **changes):
        PublicIP.objects.filter(pk=ip.pk).update(provisioning_status="verified", provisioning_verified_at=timezone.now(), monitoring_enabled=True)
        ip.refresh_from_db()
        row = dict(id=ip.pk, address=ip.address, device_id=ip.device_id, status="Monitoring", packets=200, bytes=1000, pps=50, mbps=0.004,
                   last_update=timezone.now().isoformat(), attempted_at=timezone.now().isoformat(),
                   profile_version=[ip.updated_at.isoformat(), ip.provisioning_verified_at.isoformat()],
                   protocol_rules=[dict(name="MONITOR-SYN-"+ip.address, pps=10), dict(name="MONITOR-UDP-"+ip.address, pps=20)])
        row.update(changes)
        FirewallSample.objects.update_or_create(device=ip.device, defaults={"rows": [row]})

    def test_empty_dashboard_and_no_legacy_router_connection(self):
        with patch("monitor.services.mikrotik_api.get_firewall_rules") as legacy, patch("devices.services.router_session.routeros_api.RouterOsApiPool") as pool:
            self.assertContains(self.client.get("/"), "No devices or public IPs configured yet.")
            data = self.client.get("/monitoring-data/").json()
            self.assertEqual(data["rules"], []); self.assertEqual(data["devices"], [])
            self.assertFalse(data["monitoring"]); legacy.assert_not_called(); pool.assert_not_called()

    def test_only_saved_devices_and_assignments_are_displayed(self):
        ip = self.assignment(); self.device("Second router", "172.26.241.17")
        FirewallSample.objects.create(device=ip.device, rows=[dict(id=999, address="8.8.8.8", device_id=ip.device_id)])
        data = self.client.get("/monitoring-data/").json()
        self.assertEqual(len(data["devices"]), 2)
        self.assertEqual([r["address"] for r in data["rules"]], [ip.address])
        self.assertEqual(data["rules"][0]["status"], "Not monitored")
        self.assertIsNone(data["rules"][0]["pps"])
        body = str(data)
        for secret in (self.secret, ip.device.username, ip.device.encrypted_password, os.environ["NETSHIELD_DEVICE_ENCRYPTION_KEY"]):
            self.assertNotIn(secret, body)
        self.assertContains(self.client.get("/"), ip.address)

    @override_settings(NETSHIELD_RAW_POLLING_ENABLED=True)
    def test_protocol_rates_remain_separate_without_double_counting(self):
        ip = self.assignment(); self.sample(ip)
        with patch("public_ips.services.monitoring.POLLING_RELEASED", True):
            data = self.client.get("/monitoring-data/").json()
        row = data["rules"][0]
        self.assertEqual((row["pps"], row["syn_pps"], row["udp_pps"], row["mbps"]), (50,10,20,0.004))
        self.assertTrue(data["monitoring"])

    @override_settings(NETSHIELD_RAW_POLLING_ENABLED=True)
    def test_stale_rates_including_protocols_are_unavailable(self):
        ip = self.assignment(); self.sample(ip, attempted_at=(timezone.now()-timedelta(seconds=20)).isoformat())
        with patch("public_ips.services.monitoring.POLLING_RELEASED", True):
            row = self.client.get("/monitoring-data/").json()["rules"][0]
        self.assertEqual(row["status"], "Not monitored")
        for key in ("pps", "syn_pps", "udp_pps", "mbps", "packets", "bytes"):
            self.assertIsNone(row[key])

    @override_settings(NETSHIELD_RAW_POLLING_ENABLED=True)
    def test_mismatched_assignment_cache_is_rejected(self):
        ip = self.assignment(); self.sample(ip, device_id=999, address="8.8.8.8")
        with patch("public_ips.services.monitoring.POLLING_RELEASED", True):
            row = self.client.get("/monitoring-data/").json()["rules"][0]
        self.assertIsNone(row["pps"]); self.assertEqual(row["address"], ip.address)

    def test_disabled_gate_suppresses_previous_samples(self):
        ip = self.assignment(); self.sample(ip)
        data = self.client.get("/monitoring-data/").json()
        self.assertFalse(data["monitoring"]); self.assertIsNone(data["rules"][0]["syn_pps"])
        self.assertEqual(self.client.post("/start-monitoring/").status_code, 409)

    def test_authentication_admin_permissions_post_and_csrf(self):
        client = Client(enforce_csrf_checks=True)
        for url in ("/", "/monitoring-data/", "/start-monitoring/", "/stop-monitoring/"):
            self.assertEqual(client.get(url).status_code, 302)
        client.force_login(self.admin); client.get("/")
        token = client.cookies["csrftoken"].value
        self.assertEqual(client.post("/stop-monitoring/").status_code, 403)
        self.assertEqual(client.get("/stop-monitoring/").status_code, 405)
        self.assertEqual(client.post("/stop-monitoring/", HTTP_X_CSRFTOKEN=token).status_code, 200)
        client.force_login(self.reader)
        self.assertEqual(client.get("/monitoring-data/").status_code, 200)
        self.assertEqual(client.post("/stop-monitoring/", HTTP_X_CSRFTOKEN=token).status_code, 403)

    @override_settings(NETSHIELD_RAW_POLLING_ENABLED=True)
    def test_controls_only_change_saved_polling_preferences(self):
        ip = self.assignment(); self.sample(ip)
        pending = self.assignment(ip.device, "185.166.26.252")
        with patch("public_ips.services.monitoring.POLLING_RELEASED", True), patch("devices.services.router_session.routeros_api.RouterOsApiPool") as pool:
            self.assertEqual(self.client.post("/stop-monitoring/").status_code, 200)
            ip.refresh_from_db(); self.assertFalse(ip.monitoring_enabled)
            self.assertEqual(self.client.post("/start-monitoring/").status_code, 200)
            ip.refresh_from_db(); pending.refresh_from_db()
            self.assertTrue(ip.monitoring_enabled); self.assertFalse(pending.monitoring_enabled)
            pool.assert_not_called()

    def test_existing_frontends_themes_and_refresh_preserved(self):
        for url in ("/", "/devices/", "/public-ips/", "/traffic-monitor/", "/ddos-detection/", "/alerts/", "/reports/", "/settings/"):
            self.assertEqual(self.client.get(url).status_code, 200)
        page = self.client.get("/")
        self.assertContains(page, "theme.js"); self.assertContains(page, "dashboard.js")
        self.assertContains(page, "Total packet rate"); self.assertContains(page, "SYN PPS"); self.assertContains(page, "UDP PPS")

    @override_settings(NETSHIELD_RAW_POLLING_ENABLED=True)
    def test_cache_container_must_match_assigned_device(self):
        ip = self.assignment(); self.sample(ip)
        other = self.device("Other", "172.26.241.18")
        FirewallSample.objects.filter(device=ip.device).update(device=other)
        with patch("public_ips.services.monitoring.POLLING_RELEASED", True):
            row = self.client.get("/monitoring-data/").json()["rules"][0]
        self.assertIsNone(row["pps"])
        self.assertEqual(row["status"], "Not monitored")
