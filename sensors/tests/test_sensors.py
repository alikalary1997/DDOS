import asyncio
import os
from types import SimpleNamespace
from unittest.mock import patch, AsyncMock
from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.core import signing
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, SimpleTestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta
from pysnmp.proto.rfc1902 import Counter64, Integer32, OctetString, TimeTicks
from devices.models import Device
from devices.services.credentials import encrypt_password, decrypt_password
from sensors.models import Sensor, SensorSample, SensorRuntime, SNMPProfile
from sensors.polling import Poller, format_uptime
from sensors.snmp import Client, SNMPError, number, read, CPU
from sensors.locking import worker_lock, WorkerBusy


class SensorTests(TestCase):
    def setUp(self):
        worker = patch('sensors.runtime.ensure_worker')
        self.worker = worker.start(); self.addCleanup(worker.stop)
        env = patch.dict(os.environ, {'NETSHIELD_DEVICE_ENCRYPTION_KEY': Fernet.generate_key().decode()})
        env.start(); self.addCleanup(env.stop)
        self.admin = get_user_model().objects.create_user(username='sensor-admin', is_staff=True)
        self.client.force_login(self.admin)
        self.device = Device.objects.create(name='Sensor router', management_ip='10.20.30.40', username='private-user',
                                             encrypted_password=encrypt_password('private-api-password'))
        self.profile = SNMPProfile.objects.create(device=self.device, community=encrypt_password('private-community'),
                                                 validated_ip=self.device.management_ip, tested_at=timezone.now())
        self.sensor = Sensor.objects.create(device=self.device, kind='traffic', name='uplink', interface_index=3, interface_name='ether3')

    def url(self, name, *args):
        return reverse(name, args=[self.device.pk, *args])

    def activate(self):
        SensorRuntime.objects.create(pk=1, polling_authorized=True)
        self.sensor.enabled = True; self.sensor.save()

    def test_inventory_and_data_do_not_contact_router_or_expose_credentials(self):
        with patch('sensors.snmp.read') as snmp, patch('routeros_api.RouterOsApiPool') as api:
            page = self.client.get(self.url('device_sensors'))
            data = self.client.get(self.url('sensor_data'))
        snmp.assert_not_called(); api.assert_not_called()
        for secret in ('private-user', 'private-api-password', 'private-community', self.profile.community):
            self.assertNotIn(secret, page.content.decode() + data.content.decode())
        self.assertEqual(data.json()['sensors'][0]['status'], 'Stopped')
        self.assertIsNone(data.json()['sensors'][0]['in_mbps'])

    def test_profile_test_encrypts_and_reuses_no_raw_api(self):
        with patch('sensors.snmp.read', return_value=123) as probe, patch('routeros_api.RouterOsApiPool') as api:
            response = self.client.post(self.url('sensor_profile'), {'community': 'new-private-community', 'port': 1161})
        self.assertEqual(response.status_code, 302); api.assert_not_called()
        self.profile.refresh_from_db()
        self.assertEqual(decrypt_password(self.profile.community), 'new-private-community')
        self.assertNotIn('new-private-community', self.profile.community)
        self.assertEqual(self.profile.port, 1161)
        self.assertEqual(probe.call_args.args[3], 'test')

    def test_bad_profile_leaves_existing_credential_and_does_not_echo_secret(self):
        previous = self.profile.community
        with patch('sensors.snmp.read', side_effect=SNMPError('No valid SNMP reply.')):
            response = self.client.post(self.url('sensor_profile'), {'community': 'new-secret', 'port': 161})
        self.assertEqual(response.status_code, 400)
        self.assertNotContains(response, 'new-secret', status_code=400)
        self.profile.refresh_from_db(); self.assertEqual(self.profile.community, previous)

    def test_invalid_port_and_empty_community_no_connection(self):
        with patch('sensors.snmp.read') as probe:
            response = self.client.post(self.url('sensor_profile'), {'community': '', 'port': 65536})
        self.assertEqual(response.status_code, 400); probe.assert_not_called()

    def test_setup_is_modal_with_three_detection_buttons(self):
        with patch('sensors.snmp.read') as probe:
            response = self.client.get(self.url('device_sensors'))
        probe.assert_not_called()
        for value in ('<dialog id="addSensor"', 'data-open-sensor', 'Detect CPU', 'Detect Uptime', 'Detect Bandwidth',
                      'Test connection &amp; save', 'data-wizard-form="profile"'):
            self.assertContains(response, value)

    def test_device_fleet_shows_sensor_values_without_snmp_requests(self):
        SensorSample.objects.create(sensor=self.sensor, timestamp=timezone.now(), in_mbps=1.5, out_mbps=0, uptime_seconds=90)
        with patch('sensors.snmp.read') as probe:
            page = self.client.get(reverse('devices'))
            response = self.client.get(reverse('device_sensor_data'))
        probe.assert_not_called()
        self.assertContains(page, 'data-device-add-sensor')
        self.assertContains(page, 'data-device-sensor="traffic"')
        item = response.json()['devices'][str(self.device.pk)][0]
        self.assertEqual(item['in_mbps'], 1.5)
        self.assertEqual(item['out_mbps'], 0)
        self.assertEqual(item['status'], 'Stopped')
        self.assertNotIn('private-community', response.content.decode())

    def test_fleet_health_distinguishes_active_stale_failed_and_stopped(self):
        from sensors.presentation import fleet_snapshot, summarize_sensors
        self.activate()
        cpu = Sensor.objects.create(device=self.device, kind='cpu', name='CPU', enabled=True)
        uptime = Sensor.objects.create(device=self.device, kind='uptime', name='Uptime')
        SensorSample.objects.create(sensor=self.sensor, timestamp=timezone.now(), in_mbps=0, out_mbps=0, interface_status='Up')
        SensorSample.objects.create(sensor=cpu, timestamp=timezone.now() - timedelta(minutes=5), cpu=22)
        SensorSample.objects.create(sensor=uptime, timestamp=timezone.now(), uptime_seconds=90061)
        with patch('sensors.presentation.worker_running', return_value=True), patch('sensors.snmp.read') as snmp:
            rows = fleet_snapshot()[self.device.pk]
        snmp.assert_not_called()
        self.assertEqual([row['status'] for row in rows], ['Active', 'Stale', 'Stopped'])
        self.assertEqual(summarize_sensors(rows), {'total': 3, 'enabled': 2, 'active': 1, 'attention': 1})
        self.assertTrue(rows[0]['is_live'])
        self.assertEqual(rows[0]['interface_status'], 'Up')
        self.assertEqual(rows[0]['in_mbps'], 0)
        self.assertFalse(rows[1]['is_live'])
        self.assertEqual(rows[1]['cpu'], 22)
        self.assertEqual(rows[2]['uptime'], '1d 01h 01m 01s')
        SensorSample.objects.create(sensor=cpu, timestamp=timezone.now(), valid=False, error='No reply')
        with patch('sensors.presentation.worker_running', return_value=True):
            failed = fleet_snapshot()[self.device.pk][1]
        self.assertEqual(failed['status'], 'Connection Failed')
        self.assertEqual(failed['status_tone'], 'attention')
        self.assertIsNone(failed['cpu'])

    def test_fleet_pending_baseline_and_paused_never_invent_traffic(self):
        from sensors.presentation import fleet_snapshot, summarize_sensors
        self.activate()
        with patch('sensors.presentation.worker_running', return_value=True):
            row = fleet_snapshot()[self.device.pk][0]
        self.assertEqual(row['status'], 'Waiting for data')
        self.assertIsNone(row['sample_at'])
        self.assertIsNone(row['in_mbps'])
        SensorSample.objects.create(sensor=self.sensor, timestamp=timezone.now(), in_octets='100', out_octets='200')
        with patch('sensors.presentation.worker_running', return_value=True):
            baseline = fleet_snapshot()[self.device.pk][0]
        self.assertEqual(baseline['status'], 'Active')
        self.assertIsNone(baseline['in_mbps'])
        self.assertIsNone(baseline['out_mbps'])
        with patch('sensors.presentation.worker_running', return_value=False):
            paused = fleet_snapshot()[self.device.pk]
        self.assertEqual(paused[0]['status'], 'Paused')
        self.assertFalse(paused[0]['is_live'])
        self.assertEqual(summarize_sensors(paused)['attention'], 1)

    def test_fleet_data_keeps_device_groups_isolated_and_has_no_credentials(self):
        other = Device.objects.create(name='Other router', management_ip='10.20.30.41', username='other-private-user',
                                      encrypted_password=encrypt_password('other-password'))
        other_sensor = Sensor.objects.create(device=other, kind='cpu', name='CPU')
        SensorSample.objects.create(sensor=other_sensor, timestamp=timezone.now(), cpu=55)
        with patch('sensors.snmp.read') as snmp, patch('routeros_api.RouterOsApiPool') as api:
            response = self.client.get(reverse('device_sensor_data'))
        snmp.assert_not_called(); api.assert_not_called()
        groups = response.json()['devices']
        self.assertEqual([row['id'] for row in groups[str(self.device.pk)]], [self.sensor.pk])
        self.assertEqual(groups[str(other.pk)][0]['cpu'], 55)
        for secret in ('community', 'encrypted_password', 'username', 'private-user', 'other-password'):
            self.assertNotIn(secret, response.content.decode())

    def test_integrated_stop_returns_to_devices(self):
        response = self.client.post(self.url('sensor_control', self.sensor.pk, 'stop'), {'next': 'devices'})
        self.assertRedirects(response, reverse('devices'))

    def test_detect_cpu_uptime_are_one_off_without_starting_sensors(self):
        for kind, value in [('cpu', '25.0%'), ('uptime', '1d 01h 01m 01s')]:
            with patch('sensors.snmp.read', return_value={'cpu': 25, 'uptime_seconds': 90061}) as probe:
                response = self.client.post(self.url('sensor_detect'), {'kind': kind})
            self.assertEqual(response.status_code, 200)
            self.assertContains(response, value)
            self.assertContains(response, 'data-reopen="true"')
            self.assertEqual(probe.call_count, 1)
            self.assertEqual(probe.call_args.args[4].kind, kind)
        self.assertEqual(SensorSample.objects.count(), 0)
        self.assertFalse(Sensor.objects.filter(enabled=True).exists())
        self.assertFalse(SensorRuntime.objects.filter(polling_authorized=True).exists())

    def test_detect_errors_stay_in_modal_and_require_admin(self):
        with patch('sensors.snmp.read', side_effect=SNMPError('CPU unavailable.')):
            response = self.client.post(self.url('sensor_detect'), {'kind': 'cpu'})
        self.assertContains(response, 'CPU unavailable.', status_code=400)
        self.assertContains(response, 'data-reopen="true"', status_code=400)
        self.assertEqual(self.client.post(self.url('sensor_detect'), {'kind': 'other'}).status_code, 400)
        self.client.force_login(get_user_model().objects.create_user(username='sensor-reader'))
        with patch('sensors.snmp.read') as probe:
            self.assertEqual(self.client.post(self.url('sensor_detect'), {'kind': 'cpu'}).status_code, 403)
        probe.assert_not_called()

    def discovery(self):
        interfaces = [{'index': 3, 'name': 'ether3', 'status': 'Up'}, {'index': 4, 'name': '<uplink>', 'status': 'Down'}]
        with patch('sensors.snmp.read', return_value=interfaces) as probe:
            response = self.client.post(self.url('sensor_discover'))
        self.assertEqual(probe.call_args.args[1], 'private-community')
        self.assertContains(response, '&lt;uplink&gt;')
        return response.context['sensor_form'].initial['discovery']

    def test_multiselect_starts_only_new_sensors_and_deduplicates(self):
        token = self.discovery()
        for _ in range(2):
            response = self.client.post(self.url('sensor_add'), {'kind': 'traffic', 'interval': 5, 'interfaces': ['3', '4'], 'discovery': token})
            self.assertEqual(response.status_code, 302)
        self.assertEqual(Sensor.objects.count(), 2)
        self.assertEqual(Sensor.objects.filter(enabled=True).count(), 1)
        self.sensor.refresh_from_db(); self.assertFalse(self.sensor.enabled)
        self.worker.assert_called_once()

    def test_forged_or_stale_interface_selection_rejected(self):
        token = self.discovery()
        for token, selected in [(token, '999'), (token + 'tampered', '4')]:
            response = self.client.post(self.url('sensor_add'), {'kind': 'traffic', 'interval': 10, 'interfaces': [selected], 'discovery': token})
            self.assertEqual(response.status_code, 400)
        self.assertEqual(Sensor.objects.count(), 1)

    def test_profile_change_invalidates_discovery(self):
        token = self.discovery()
        SNMPProfile.objects.filter(pk=self.profile.pk).update(revision=2)
        response = self.client.post(self.url('sensor_add'), {'kind': 'traffic', 'interval': 10, 'interfaces': ['4'], 'discovery': token})
        self.assertEqual(response.status_code, 400)

    def test_cpu_uptime_creation_and_interval_validation(self):
        for kind in ('cpu', 'uptime'):
            self.assertEqual(self.client.post(self.url('sensor_add'), {'kind': kind, 'interval': 15}).status_code, 302)
        response = self.client.post(self.url('sensor_add'), {'kind': 'cpu', 'interval': 3})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(Sensor.objects.count(), 3)

    def test_worker_refuses_before_explicit_add_or_start_then_start_authorizes(self):
        with patch('sensors.snmp.read') as probe:
            self.assertFalse(Poller().cycle())
            with self.assertRaises(CommandError): call_command('poll_sensors')
        probe.assert_not_called()
        self.client.post(self.url('sensor_control', self.sensor.pk, 'start'))
        self.sensor.refresh_from_db(); self.assertTrue(self.sensor.enabled)
        self.assertTrue(SensorRuntime.objects.get(pk=1).polling_authorized)
        self.worker.assert_called_once()

    def test_worker_launch_failure_keeps_saved_sensor_with_visible_error(self):
        from sensors.runtime import StartupError
        self.worker.side_effect = StartupError('Worker startup failed.')
        response = self.client.post(self.url('sensor_add'), {'kind': 'cpu', 'interval': 10})
        self.assertEqual(response.status_code, 302)
        sensor = Sensor.objects.get(kind='cpu')
        self.assertFalse(sensor.enabled)
        self.assertEqual(sensor.error, 'Worker startup failed.')

    def test_new_sensor_auto_start_does_not_enable_unrelated_sensor(self):
        self.client.post(self.url('sensor_add'), {'kind': 'cpu', 'interval': 10})
        self.assertTrue(Sensor.objects.get(kind='cpu').enabled)
        self.sensor.refresh_from_db(); self.assertFalse(self.sensor.enabled)
        self.worker.assert_called_once()

    def test_only_admin_and_csrf_protected(self):
        reader = get_user_model().objects.create_user(username='reader')
        self.client.force_login(reader)
        for name, args in [('sensor_profile', []), ('sensor_discover', []), ('sensor_add', []), ('sensor_control', [self.sensor.pk, 'start'])]:
            self.assertEqual(self.client.post(self.url(name, *args)).status_code, 403)
        from django.test import Client as WebClient
        secure = WebClient(enforce_csrf_checks=True); secure.force_login(self.admin)
        self.assertEqual(secure.post(self.url('sensor_discover')).status_code, 403)

    def test_edit_interval_stop_delete_preserve_other_sensors(self):
        self.activate()
        other = Sensor.objects.create(device=self.device, kind='cpu', name='CPU')
        response = self.client.post(self.url('sensor_edit', self.sensor.pk), {'name': 'New name', 'interval': 30})
        self.assertEqual(response.status_code, 302)
        self.sensor.refresh_from_db(); self.assertEqual(self.sensor.interval, 30); self.assertTrue(self.sensor.enabled)
        sample = SensorSample.objects.create(sensor=self.sensor, timestamp=timezone.now(), uptime_seconds=50)
        self.client.post(self.url('sensor_control', self.sensor.pk, 'stop'))
        self.sensor.refresh_from_db(); self.assertFalse(self.sensor.enabled)
        self.assertTrue(SensorSample.objects.filter(pk=sample.pk).exists())
        self.client.post(self.url('sensor_control', self.sensor.pk, 'delete'))
        self.assertFalse(Sensor.objects.filter(pk=self.sensor.pk).exists())
        self.assertTrue(Sensor.objects.filter(pk=other.pk).exists())

    @staticmethod
    def values(incoming=1000, outgoing=2000, uptime=100, discontinuity=0):
        return dict(in_octets=incoming, out_octets=outgoing, uptime_seconds=uptime, discontinuity=discontinuity, interface_status='Up')

    def test_counter64_elapsed_rates_and_zero(self):
        self.activate(); poller = Poller()
        start = 2**63 + 100
        with patch('sensors.snmp.read', side_effect=[self.values(start, start), self.values(start+2_500_000, start+5_000_000, 120), self.values(start+2_500_000, start+5_000_000, 140)]), patch('sensors.polling.time.monotonic', side_effect=[1., 21., 41.]):
            for _ in range(3): poller.poll(self.sensor)
        samples = list(self.sensor.samples.all())
        self.assertIsNone(samples[0].in_mbps)
        self.assertEqual(int(samples[0].in_octets), start)
        self.assertEqual(samples[1].in_mbps, 1)
        self.assertEqual(samples[1].out_mbps, 2)
        self.assertEqual(samples[2].in_mbps, 0)

    def test_failure_resets_baseline_and_records_error(self):
        self.activate(); poller = Poller()
        with patch('sensors.snmp.read', side_effect=[self.values(), SNMPError('No reply.'), self.values(5000, 8000)]):
            for _ in range(3): poller.poll(self.sensor)
        samples = list(self.sensor.samples.all())
        self.assertFalse(samples[1].valid); self.assertEqual(samples[1].error, 'No reply.')
        self.assertIsNone(samples[2].in_mbps)

    def test_restart_and_discontinuity_reset_rates(self):
        self.activate(); poller = Poller()
        with patch('sensors.snmp.read', side_effect=[self.values(), self.values(50, 60, 1), self.values(100, 200, 10, 4)]):
            for _ in range(3): poller.poll(self.sensor)
        samples = list(self.sensor.samples.all())
        self.assertTrue(samples[1].restart_detected); self.assertTrue(samples[1].counter_reset)
        self.assertTrue(samples[2].counter_reset); self.assertIsNone(samples[2].in_mbps)

    def test_stop_during_read_discards_inflight_sample(self):
        self.activate()
        def reply(*args):
            Sensor.objects.filter(pk=self.sensor.pk).update(enabled=False)
            return self.values()
        with patch('sensors.snmp.read', side_effect=reply): Poller().poll(self.sensor)
        self.assertEqual(SensorSample.objects.count(), 0)

    def test_device_change_does_not_poll_old_profile(self):
        self.activate()
        self.device.management_ip = '10.20.30.41'; self.device.save()
        self.sensor.refresh_from_db()
        with patch('sensors.snmp.read') as probe: Poller().poll(self.sensor)
        probe.assert_not_called()
        self.assertFalse(self.sensor.samples.last().valid)

    def test_history_stale_and_failed_are_not_live(self):
        self.activate()
        SensorSample.objects.create(sensor=self.sensor, timestamp=timezone.now()-timedelta(minutes=10), in_mbps=3)
        with patch('sensors.views.worker_running', return_value=True):
            row = self.client.get(self.url('sensor_data')).json()['sensors'][0]
        self.assertEqual(row['status'], 'Stale'); self.assertEqual(row['in_mbps'], 3)
        SensorSample.objects.create(sensor=self.sensor, timestamp=timezone.now(), valid=False, error='No reply')
        with patch('sensors.views.worker_running', return_value=True):
            row = self.client.get(self.url('sensor_data')).json()['sensors'][0]
        self.assertEqual(row['status'], 'Connection Failed'); self.assertIsNone(row['in_mbps'])

    def test_disabled_sensors_never_polled_and_interval_changes_apply(self):
        self.activate(); poller = Poller()
        Sensor.objects.create(device=self.device, kind='cpu', name='Stopped CPU')
        with patch('sensors.snmp.read', return_value=self.values()) as probe:
            poller.cycle(); poller.cycle()
            self.assertEqual(probe.call_count, 1)
            Sensor.objects.filter(pk=self.sensor.pk).update(interval=30, revision=2)
            poller.cycle(); self.assertEqual(probe.call_count, 2)

    def test_gate_disable_stops_all_without_router_calls(self):
        self.activate()
        with patch('sensors.snmp.read') as probe: call_command('sensor_polling_gate', '--disable')
        probe.assert_not_called()
        self.assertFalse(Sensor.objects.filter(enabled=True).exists())
        self.assertFalse(SensorRuntime.objects.get(pk=1).polling_authorized)

    def test_deletion_is_database_only(self):
        with patch('sensors.snmp.read') as probe, patch('routeros_api.RouterOsApiPool') as api: self.device.delete()
        probe.assert_not_called(); api.assert_not_called()
        self.assertEqual(Sensor.objects.count(), 0)


class AdapterTests(SimpleTestCase):
    def test_running_worker_is_reused_without_spawning(self):
        from sensors.runtime import ensure_worker
        with patch('sensors.runtime.worker_running', return_value=True), patch('sensors.runtime.subprocess.Popen') as spawn:
            ensure_worker()
        spawn.assert_not_called()

    def test_worker_spawn_failure_is_reported(self):
        from sensors.runtime import ensure_worker, StartupError
        with patch('sensors.runtime.worker_running', return_value=False), patch('sensors.runtime.subprocess.Popen', side_effect=OSError):
            with self.assertRaises(StartupError): ensure_worker()

    def test_worker_launch_uses_hidden_process_and_checks_lock(self):
        from sensors.runtime import ensure_worker
        with patch('sensors.runtime.worker_running', side_effect=[False, True]), patch('sensors.runtime.subprocess.Popen') as spawn:
            ensure_worker()
        self.assertEqual(spawn.call_count, 1)
        self.assertIn('poll_sensors', spawn.call_args.args[0])
        self.assertIn('creationflags', spawn.call_args.kwargs)

    def test_counter_types_and_range(self):
        self.assertEqual(number(Counter64(2**64-1), Counter64), 2**64-1)
        with self.assertRaises(SNMPError): number(OctetString('12'), Integer32)
        with self.assertRaises(SNMPError): number(Integer32(101), Integer32, maximum=100)

    def test_walk_rejects_non_increasing_oids(self):
        client = Client('10.1.1.1', 'secret', 161)
        client.query = AsyncMock(return_value=[(tuple(map(int, CPU.split('.'))), Integer32(1))])
        with self.assertRaises(SNMPError): asyncio.run(client.walk(CPU))

    def test_cpu_averages_all_cores(self):
        client = Client('10.1.1.1', 'secret', 161)
        client.uptime = AsyncMock(return_value=123)
        client.walk = AsyncMock(return_value=[(1, Integer32(20)), (2, Integer32(40))])
        self.assertEqual(asyncio.run(client.sample(SimpleNamespace(kind='cpu')))['cpu'], 30)

    def test_interface_identity_change_rejected(self):
        client = Client('10.1.1.1', 'secret', 161)
        client.uptime = AsyncMock(return_value=123)
        client.get = AsyncMock(return_value=[OctetString('renamed'), Integer32(1), Counter64(5), Counter64(6), TimeTicks(0)])
        with self.assertRaises(SNMPError): asyncio.run(client.sample(SimpleNamespace(kind='traffic', interface_index=3, interface_name='ether3')))

    @override_settings(DEVICE_CONNECTION_ALLOWED_NETWORKS=['10.0.0.0/8'])
    def test_library_errors_redacted_and_transport_closed(self):
        device = SimpleNamespace(pk=1, enabled=True, device_type='mikrotik', management_ip='10.1.1.1')
        with patch('sensors.snmp.Client') as cls:
            instance = cls.return_value
            instance.open = AsyncMock(side_effect=ValueError('private-community'))
            with self.assertRaises(SNMPError) as exc: read(device, 'private-community', 161, 'test')
            self.assertNotIn('private-community', str(exc.exception))
            instance.engine.close_dispatcher.assert_called_once()

    def test_single_worker_lock(self):
        with worker_lock():
            with self.assertRaises(WorkerBusy):
                with worker_lock(): pass

    def test_uptime_format(self):
        self.assertEqual(format_uptime(90061), '1d 01h 01m 01s')
