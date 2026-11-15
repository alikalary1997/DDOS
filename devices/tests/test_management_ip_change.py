"""Editing only a device's management IP must re-target live polling by itself.

Covers both live paths, with no manual restart anywhere in the test:
  * SNMP sensors  - the next poll cycle reads the new address instead of refusing to poll.
  * RAW/API poll  - the next cycle dials the new address instead of reusing the old socket,
                    and the running monitoring worker keeps running (it used to stop).
"""
import os
import secrets
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from devices.models import Device
from devices.services.credentials import encrypt_password
from devices.services.router_session import _CONNECTIONS
from public_ips.models import PublicIP
from public_ips.services.monitoring_scope import DeviceMonitoringScope, MonitoringScope
from sensors.models import Sensor, SensorRuntime, SNMPProfile
from sensors.polling import Poller

OLD_IP = "10.20.30.40"
NEW_IP = "10.20.30.41"
PUBLIC = "185.166.26.115"


def field_key(name):
    return f"edit-{name}"


class ManagementIpChangePropagationTests(TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"NETSHIELD_DEVICE_ENCRYPTION_KEY": Fernet.generate_key().decode()})
        env.start(); self.addCleanup(env.stop)
        self.admin = get_user_model().objects.create_user(username="ip-change-admin", is_staff=True)
        self.client.force_login(self.admin)
        self.device = Device.objects.create(
            name="Edge router", management_ip=OLD_IP, username="api-account",
            incoming_monitoring_interface="ether1",
            encrypted_password=encrypt_password(secrets.token_urlsafe(16)))
        self.edit = reverse("device_edit", args=[self.device.pk])
        # Mirrors what the browser submits: every field as stored, only the IP differing.
        self.payload = {
            "edit-name": self.device.name, "edit-management_ip": NEW_IP,
            "edit-device_type": self.device.device_type, "edit-api_port": self.device.api_port,
            "edit-use_ssl": "true" if self.device.use_ssl else "false",
            "edit-username": self.device.username, "edit-password": "",
            "edit-incoming_monitoring_interface": self.device.incoming_monitoring_interface,
            "edit-description": self.device.description, "edit-group": "",
        }
        _CONNECTIONS.clear()
        self.addCleanup(_CONNECTIONS.clear)

    # --- shared fixture helpers -------------------------------------------
    def _working_snmp(self):
        SensorRuntime.objects.update_or_create(pk=1, defaults={"polling_authorized": True})
        SNMPProfile.objects.create(device=self.device, community=encrypt_password("private-community"),
                                   validated_ip=OLD_IP, tested_at=timezone.now())
        sensor = Sensor.objects.create(device=self.device, kind="traffic", name="uplink",
                                       interface_index=3, interval=10, enabled=True)
        return sensor

    def _working_raw(self):
        from public_ips.services.rules import expected_rules
        ip = PublicIP.objects.create(
            address=PUBLIC, device=self.device, incoming_monitoring_interface="ether1",
            provisioning_status="verified", provisioning_verified_at=timezone.now(),
            monitoring_enabled=True)
        # Exactly the rules NetShield provisions for this address - nothing invented.
        rows = [dict(rule, id=f"*{index}", packets="100", bytes="1000")
                for index, rule in enumerate(expected_rules(PUBLIC, "ether1"), start=1)]
        return ip, rows

    def edit_ip(self):
        """The only operator action: save the edit form with the new IP."""
        response = self.client.post(self.edit, self.payload, HTTP_ACCEPT="application/json")
        self.assertEqual(response.status_code, 200, response.content[:400])
        self.device.refresh_from_db()
        self.assertEqual(self.device.management_ip, NEW_IP)

    # --- SNMP -------------------------------------------------------------
    def test_sensors_poll_the_new_ip_on_the_next_cycle_with_no_restart(self):
        sensor = self._working_snmp()
        values = dict(in_octets=1000, out_octets=2000, uptime_seconds=100, discontinuity=0, interface_status="Up")
        with patch("sensors.snmp.read", return_value=values) as read:
            Poller().poll(sensor)                       # healthy before the change
            self.assertEqual(read.call_args.args[0].management_ip, OLD_IP)

            self.edit_ip()                              # <- the only operator step

            sensor.refresh_from_db()
            read.reset_mock()
            Poller().poll(sensor)                       # the very next normal cycle
        read.assert_called_once()
        self.assertEqual(read.call_args.args[0].management_ip, NEW_IP)
        self.assertTrue(sensor.samples.last().valid)
        self.assertEqual(sensor.error, "")
        self.assertEqual(SNMPProfile.objects.get(device=self.device).validated_ip, NEW_IP)

    def test_sensors_recover_from_a_stale_state_left_by_the_old_ip(self):
        """The sensor had already been failing on the dead IP before the fix."""
        sensor = self._working_snmp()
        # Simulate the stale error state already present on the old (dead) address.
        Sensor.objects.filter(pk=sensor.pk).update(error="Connection timed out", last_attempt=timezone.now())
        SNMPProfile.objects.filter(device=self.device).update(validated_ip=OLD_IP)
        self.edit_ip()
        sensor.refresh_from_db()
        values = dict(in_octets=10, out_octets=20, uptime_seconds=30, discontinuity=0, interface_status="Up")
        with patch("sensors.snmp.read", return_value=values) as read:
            Poller().poll(sensor)
        self.assertEqual(read.call_args.args[0].management_ip, NEW_IP)
        sensor.refresh_from_db()
        self.assertEqual(sensor.error, "")
        self.assertIsNotNone(sensor.last_success)
        self.assertTrue(sensor.samples.last().valid)

    # --- RAW / RouterOS API ----------------------------------------------
    def _raw_worker(self, change_ip=None, cycles=2):
        """Run the real poll_raw_firewall loop for a few cycles, editing the IP between them."""
        import io
        from django.core.management import call_command
        from django.test import override_settings
        import tempfile

        _ip, rows = self._working_raw()
        directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        waits = []

        def next_cycle(started):
            waits.append(started)
            if len(waits) >= cycles:
                raise KeyboardInterrupt          # normal end of the simulated run
            if change_ip and len(waits) == 1:
                change_ip()                      # the operator's IP edit, between cycles

        with override_settings(NETSHIELD_RAW_POLLING_ENABLED=True,
                               DEVICE_CONNECTION_ALLOWED_NETWORKS=("10.20.30.0/24",),
                               NETSHIELD_ROUTER_LOCK_DIRECTORY=directory.name), \
                patch("public_ips.services.monitoring.POLLING_RELEASED", True), \
                patch("devices.services.router_session.routeros_api.RouterOsApiPool") as pool, \
                patch("public_ips.management.commands.poll_raw_firewall.wait_for_next_cycle",
                      side_effect=next_cycle):
            api = pool.return_value.get_api.return_value
            api.get_resource.return_value.get.side_effect = lambda: [dict(row) for row in rows]
            call_command("poll_raw_firewall", device_id=self.device.pk, assignment_id=self.device.public_ips.get().pk,
                         public_ip=PUBLIC, stdout=io.StringIO())
        return pool

    def test_raw_worker_dials_the_new_ip_on_the_next_cycle(self):
        """No restart: the same live worker reconnects to the new address by itself."""
        pool = self._raw_worker(change_ip=self.edit_ip)
        # One login per cycle, and the second dial goes to the IP saved by the edit.
        self.assertEqual(pool.call_count, 2)
        self.assertEqual(pool.call_args_list[0].args[0], OLD_IP)
        self.assertEqual(pool.call_args_list[1].args[0], NEW_IP)

    def test_raw_worker_does_not_stop_on_an_ip_change(self):
        """The worker used to raise MonitoringScopeError and exit on any profile change."""
        from public_ips.models import FirewallSample
        pool = self._raw_worker(change_ip=self.edit_ip)
        # Both cycles produced a sample; the run was not abandoned.
        self.assertEqual(pool.call_count, 2)
        self.assertEqual(FirewallSample.objects.count(), 1)
        self.assertEqual([row["address"] for row in FirewallSample.objects.get().rows], [PUBLIC])

    def test_cached_router_session_is_dropped_so_the_next_poll_reconnects(self):
        _CONNECTIONS[self.device.pk] = {"pool": "stale-socket", "signature": ("old",)}
        self.edit_ip()
        self.assertNotIn(self.device.pk, _CONNECTIONS)

    def test_raw_monitoring_recovers_after_a_stale_cycle_on_the_old_ip(self):
        """A device already failing on the dead IP resumes once the IP is corrected."""
        from public_ips.models import FirewallSample
        self._raw_worker(change_ip=self.edit_ip, cycles=1)
        sample = FirewallSample.objects.get()
        self.assertEqual(sample.status, "sampled")
        self.assertEqual([row["address"] for row in sample.rows], [PUBLIC])
        self.assertTrue(all(row["message"] != "The monitoring rules are missing, conflicting or not safely placed."
                            for row in sample.rows))

    # --- scope ------------------------------------------------------------
    def test_scope_ignores_an_ip_change_but_still_stops_on_credentials(self):
        self._working_raw()
        scope = DeviceMonitoringScope(self.device.pk)
        scope.targets()
        Device.objects.filter(pk=self.device.pk).update(management_ip=NEW_IP)
        self.assertEqual(scope.targets()[0].address, PUBLIC)      # IP change: re-targeted

        from public_ips.services.monitoring_scope import MonitoringScopeError
        Device.objects.filter(pk=self.device.pk).update(username="someone-else")
        with self.assertRaises(MonitoringScopeError):             # credential change: still stops
            scope.targets()

    def test_single_assignment_scope_also_follows_an_ip_change(self):
        ip, _rows = self._working_raw()
        scope = MonitoringScope(self.device.pk, ip.pk, PUBLIC)
        scope.validate()
        Device.objects.filter(pk=self.device.pk).update(management_ip=NEW_IP)
        self.assertEqual(scope.validate().pk, ip.pk)

    # --- scope discipline: only the IP triggers this ----------------------
    def test_other_profile_changes_still_require_the_operator(self):
        """Port/SSL/username keep today's behaviour: no automatic SNMP re-validation."""
        self._working_snmp()
        profile_ip = SNMPProfile.objects.get(device=self.device).validated_ip
        for field, value in (("api_port", "8728"), ("use_ssl", "false"), ("username", "other-account")):
            with self.subTest(field=field):
                response = self.client.post(self.edit, {**self.payload, "edit-management_ip": OLD_IP, field_key(field): value},
                                            HTTP_ACCEPT="application/json")
                self.assertEqual(response.status_code, 200)
                # Only an IP change re-binds the SNMP profile; these fields must not.
                self.assertEqual(SNMPProfile.objects.get(device=self.device).validated_ip, profile_ip)
                Device.objects.filter(pk=self.device.pk).update(api_port=8729, use_ssl=True, username="api-account")
                profile_ip = SNMPProfile.objects.get(device=self.device).validated_ip
