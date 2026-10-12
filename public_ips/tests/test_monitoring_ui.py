from django.template.loader import render_to_string
from django.test import SimpleTestCase
from unittest.mock import patch

from monitor.templatetags.monitoring_ui import monitoring_label, provisioning_label


class MonitoringUITests(SimpleTestCase):
    def render(self, **changes):
        row = {
            "id": 101, "address": "5.5.5.55", "device_id": 8,
            "device__name": "Noc", "device__management_ip": "192.168.32.1",
            "incoming_monitoring_interface": "ether3", "provisioning_status": "verified",
            "monitoring_enabled": True, "monitoring_status": "Not monitored",
            "provisioning_message": "Rules verified", "provisioning_code": "verified",
            "packets": None, "pps": None, "bytes": None, "mbps": None,
            "syn_pps": None, "udp_pps": None, "last_update": None, "description": "",
        }
        row.update(changes)
        with patch("routeros_api.RouterOsApiPool") as transport:
            html = render_to_string("monitor/public_ips.html", {
                "public_ip_rows": [row], "total_public_ips": 1,
                "monitored_public_ips": 0, "unmonitored_public_ips": 1,
                "available_devices": [{"id": 8, "name": "Noc", "management_ip": "192.168.32.1"}],
                "can_add_public_ips": True,
            })
            transport.assert_not_called()
        return html

    def test_rows_show_separate_device_column_without_interface(self):
        html = self.render()
        for value in ("5.5.5.55", "Noc", "192.168.32.1", ">Public IP</span><span>Device name</span>", ">Provisioned</span>", ">No Data</span>"):
            self.assertIn(value, html)
        self.assertNotIn('class="ip-interface"', html)
        self.assertNotIn("ether3", html)
        self.assertNotIn('class="public-ips-table"', html)
        self.assertNotIn("Public IP details", html)
        for metric in ("packets", "pps", "bytes", "mbps", "syn_pps", "udp_pps", "last_update"):
            self.assertIn('data-raw="%s">—<' % metric, html)

    def test_no_stale_metrics_or_timestamp_when_sample_is_unavailable(self):
        html = self.render(packets=123456789, pps=12345.67, bytes=987654321,
                           mbps=123.45, last_update="2020-01-01T00:00:00Z")
        for value in ("123456789", "12345.67", "987654321", "123.45", "2020-01-01"):
            self.assertNotIn(value, html)

    def test_real_zero_samples_are_displayed(self):
        html = self.render(monitoring_status="Monitoring", packets=0, pps=0, bytes=0, mbps=0, syn_pps=0, udp_pps=0)
        self.assertIn(">Active</span>", html)
        for metric in ("packets", "pps", "bytes", "mbps", "syn_pps", "udp_pps"):
            self.assertIn('data-raw="%s">0<' % metric, html)

    def test_conflict_error_is_escaped_inside_collapsed_details(self):
        html = self.render(provisioning_status="failed", provisioning_code="rule_conflict",
                           provisioning_message="<script>bad()</script>" * 10)
        self.assertIn(">Conflict</span>", html)
        self.assertIn('<details class="ip-card-details">', html)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script>bad()", html)
        self.assertLess(html.index('<details class="ip-card-details">'), html.index("&lt;script&gt;"))

    def test_retained_values_use_one_metric_section(self):
        html = self.render(retained=True, monitoring_enabled=False, pps=5, mbps=0.001,
                           syn_pps=0, udp_pps=5, last_update="2026-10-11T12:00:00Z",
                           last_traffic={"pps": 10, "mbps": 0.00224, "syn_pps": 0, "udp_pps": 10,
                                         "last_update": "2026-10-11T11:59:50Z"})
        self.assertIn('>Saved Sample</span>', html)
        self.assertIn('data-raw="pps">5<', html)
        self.assertNotIn('data-history=', html)
        self.assertNotIn('Last traffic detected', html)
        self.assertEqual(html.count('data-raw="pps"'), 1)
        self.assertIn('these rates are historical, not live', html)
        self.assertIn('data-monitor-start>', html)

    def test_existing_actions_and_filters_are_preserved(self):
        html = self.render()
        for action in ("Retry provisioning", "Edit", "Delete", "Unassign", "Start Monitoring", "Stop Monitoring"):
            self.assertIn(action, html)
        for field in ("ipSearch", "ipDeviceFilter", "ipStatusFilter"):
            self.assertIn('id="%s"' % field, html)

    def test_status_mappings(self):
        for status, code, expected in (("verified", "verified", "Provisioned"),
                ("pending", "", "Pending"), ("awaiting_approval", "approval_required", "Pending"),
                ("failed", "timeout", "Failed"), ("failed", "rule_conflict", "Conflict")):
            self.assertEqual(provisioning_label({"provisioning_status": status, "provisioning_code": code}), expected)
        self.assertEqual(monitoring_label({"monitoring_enabled": False, "provisioning_status": "verified"}), "Not Monitored")
