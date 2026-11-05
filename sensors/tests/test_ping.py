import os
import subprocess
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase, SimpleTestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from devices.models import Device
from devices.services.credentials import encrypt_password
from sensors import ping
from sensors.models import Sensor, SensorSample, SensorRuntime, SNMPProfile
from sensors.polling import Poller

ALLOW = override_settings(DEVICE_CONNECTION_ALLOWED_NETWORKS=('10.20.30.0/24',))
WIN_REPLY = 'Reply from 10.20.30.40: bytes=32 time={}ms TTL=64'
UNREACHABLE = 'Reply from 10.20.30.1: Destination host unreachable.'


def fake_process(output, timeout=False):
    process = MagicMock()
    process.poll.return_value = 0
    if timeout:
        process.communicate.side_effect = [subprocess.TimeoutExpired('ping', 1), ('', None)]
    else:
        process.communicate.return_value = (output, None)
    return process


class PingAdapterTests(SimpleTestCase):
    device = SimpleNamespace(pk=1, enabled=True, device_type='mikrotik', management_ip='10.20.30.40', api_port=8729)

    def test_reply_parsing(self):
        self.assertEqual(ping.reply_ms(WIN_REPLY.format(12), '10.20.30.40'), 12.0)
        self.assertEqual(ping.reply_ms('Reply from 10.20.30.40: bytes=32 time<1ms TTL=64', '10.20.30.40'), 0.5)
        self.assertEqual(ping.reply_ms('64 bytes from 10.20.30.40: icmp_seq=1 ttl=64 time=0.123 ms', '10.20.30.40'), 0.123)

    def test_non_replies_count_as_lost(self):
        for output in (UNREACHABLE, 'Request timed out.', '', 'garbage', WIN_REPLY.format(5).replace('10.20.30.40', '10.20.30.99'),
                       WIN_REPLY.format(5).replace('10.20.30.40', '110.20.30.40')):
            self.assertIsNone(ping.reply_ms(output, '10.20.30.40'), output)

    def test_summary_never_invents_zero(self):
        self.assertEqual(ping.summarize([None, None, None]), {'ping_ms': None, 'packet_loss': 100.0})
        mixed = ping.summarize([10.0, None, 20.0])
        self.assertEqual(mixed['ping_ms'], 15.0); self.assertAlmostEqual(mixed['packet_loss'], 100 / 3)
        self.assertEqual(ping.summarize([0.5, 0.5, 0.5]), {'ping_ms': 0.5, 'packet_loss': 0.0})

    @ALLOW
    def test_probe_runs_parallel_argv_without_shell(self):
        outputs = [WIN_REPLY.format(10), UNREACHABLE, WIN_REPLY.format(20)]
        with patch('sensors.ping.subprocess.Popen', side_effect=[fake_process(o) for o in outputs]) as popen:
            result = ping.probe(self.device)
        self.assertEqual(popen.call_count, 3)
        self.assertEqual(result['ping_ms'], 15.0)
        self.assertAlmostEqual(result['packet_loss'], 100 / 3)
        argv = popen.call_args.args[0]
        self.assertIsInstance(argv, list); self.assertEqual(argv[-1], '10.20.30.40')
        self.assertNotIn('shell', popen.call_args.kwargs)
        if os.name == 'nt':
            self.assertTrue(argv[0].upper().endswith('PING.EXE')); self.assertTrue(os.path.isabs(argv[0]))

    @ALLOW
    def test_timeout_is_killed_and_counted_lost(self):
        processes = [fake_process('', timeout=True) for _ in range(3)]
        with patch('sensors.ping.subprocess.Popen', side_effect=processes):
            result = ping.probe(self.device)
        self.assertEqual(result, {'ping_ms': None, 'packet_loss': 100.0})
        processes[0].kill.assert_called()

    @ALLOW
    def test_missing_ping_utility_is_redacted(self):
        with patch('sensors.ping.subprocess.Popen', side_effect=FileNotFoundError('C:\\secret\\PING.EXE')):
            with self.assertRaises(ping.PingError) as raised:
                ping.probe(self.device)
        self.assertNotIn('secret', str(raised.exception))

    def test_allowlist_denies_before_any_process(self):
        cases = [('10.20.30.40', ()),                  # empty allowlist denies all
                 ('127.0.0.1', ('127.0.0.0/8',)),       # loopback never permitted
                 ('192.0.2.9', ('10.20.30.0/24',))]     # outside the allowlist
        for address, networks in cases:
            device = SimpleNamespace(**{**vars(self.device), 'management_ip': address})
            with override_settings(DEVICE_CONNECTION_ALLOWED_NETWORKS=networks),                     patch('sensors.ping.subprocess.Popen') as popen, self.assertRaises(ping.PingError):
                ping.probe(device)
            popen.assert_not_called()

    @ALLOW
    def test_disabled_or_wrong_type_device_rejected(self):
        for extra in (dict(enabled=False), dict(device_type='cisco')):
            with patch('sensors.ping.subprocess.Popen') as popen, self.assertRaises(ping.PingError):
                ping.probe(SimpleNamespace(**{**vars(self.device), **extra}))
            popen.assert_not_called()


class PingSensorTests(TestCase):
    def setUp(self):
        worker = patch('sensors.runtime.ensure_worker')
        self.worker = worker.start(); self.addCleanup(worker.stop)
        env = patch.dict(os.environ, {'NETSHIELD_DEVICE_ENCRYPTION_KEY': Fernet.generate_key().decode()})
        env.start(); self.addCleanup(env.stop)
        self.admin = get_user_model().objects.create_user(username='ping-admin', is_staff=True)
        self.client.force_login(self.admin)
        # Deliberately no SNMPProfile: Ping must not need SNMP credentials.
        self.device = Device.objects.create(name='Ping router', management_ip='10.20.30.40', username='u',
                                             encrypted_password=encrypt_password('p'))

    def url(self, name, *args):
        return reverse(name, args=[self.device.pk, *args])

    def make(self, enabled=True):
        SensorRuntime.objects.update_or_create(pk=1, defaults={'polling_authorized': True})
        return Sensor.objects.create(device=self.device, kind='ping', name='Ping', enabled=enabled)

    # --- poller ---
    def test_poll_stores_valid_sample_without_snmp_profile(self):
        sensor = self.make()
        with patch('sensors.snmp.read') as snmp, patch('sensors.ping.probe', return_value={'ping_ms': 12.5, 'packet_loss': 0.0}):
            Poller().poll(sensor)
        snmp.assert_not_called()
        sample = sensor.samples.get()
        self.assertTrue(sample.valid); self.assertEqual((sample.ping_ms, sample.packet_loss), (12.5, 0.0))
        sensor.refresh_from_db(); self.assertIsNotNone(sensor.last_success); self.assertEqual(sensor.error, '')

    def test_total_loss_is_invalid_with_null_latency_not_zero(self):
        sensor = self.make()
        with patch('sensors.ping.probe', return_value={'ping_ms': None, 'packet_loss': 100.0}):
            Poller().poll(sensor)
        sample = sensor.samples.get()
        self.assertFalse(sample.valid); self.assertIsNone(sample.ping_ms); self.assertEqual(sample.packet_loss, 100.0)
        self.assertIn('100% packet loss', sample.error)
        sensor.refresh_from_db(); self.assertIsNone(sensor.last_success); self.assertTrue(sensor.error)

    def test_partial_loss_is_valid_with_real_values(self):
        sensor = self.make()
        with patch('sensors.ping.probe', return_value={'ping_ms': 15.0, 'packet_loss': 100 / 3}):
            Poller().poll(sensor)
        sample = sensor.samples.get(); self.assertTrue(sample.valid); self.assertAlmostEqual(sample.packet_loss, 33.33, 1)

    def test_ping_error_records_failed_sample(self):
        sensor = self.make()
        with patch('sensors.ping.probe', side_effect=ping.PingError('outside the configured device allowlist')):
            Poller().poll(sensor)
        sample = sensor.samples.get()
        self.assertFalse(sample.valid); self.assertIsNone(sample.ping_ms); self.assertIsNone(sample.packet_loss)
        self.assertIn('allowlist', sample.error)

    @override_settings(DEVICE_CONNECTION_ALLOWED_NETWORKS=())
    def test_allowlist_blocks_poll_before_any_ping_process(self):
        sensor = self.make()
        with patch('sensors.ping.subprocess.Popen') as popen:
            Poller().poll(sensor)
        popen.assert_not_called()
        self.assertFalse(sensor.samples.get().valid)

    def test_stop_during_probe_discards_sample(self):
        sensor = self.make()
        def reply(device):
            Sensor.objects.filter(pk=sensor.pk).update(enabled=False)
            return {'ping_ms': 5.0, 'packet_loss': 0.0}
        with patch('sensors.ping.probe', side_effect=reply): Poller().poll(sensor)
        self.assertEqual(SensorSample.objects.count(), 0)

    def test_device_ip_change_discards_in_flight_sample(self):
        sensor = self.make()
        def reply(device):
            Device.objects.filter(pk=self.device.pk).update(management_ip='10.20.30.41')
            return {'ping_ms': 5.0, 'packet_loss': 0.0}
        with patch('sensors.ping.probe', side_effect=reply): Poller().poll(sensor)
        self.assertEqual(SensorSample.objects.count(), 0)

    def test_disabled_sensor_gate_off_and_disabled_device_never_probe(self):
        stopped = self.make(enabled=False)
        with patch('sensors.ping.probe') as probe:
            Poller().poll(stopped); Poller().cycle()
            probe.assert_not_called()
            stopped.enabled = True; stopped.save()
            SensorRuntime.objects.filter(pk=1).update(polling_authorized=False)
            self.assertFalse(Poller().cycle())
            SensorRuntime.objects.filter(pk=1).update(polling_authorized=True)
            Device.objects.filter(pk=self.device.pk).update(enabled=False)
            Poller().cycle()
            probe.assert_not_called()

    def test_interval_applies_between_cycles(self):
        sensor = self.make(); poller = Poller()
        with patch('sensors.ping.probe', return_value={'ping_ms': 1.0, 'packet_loss': 0.0}) as probe:
            poller.cycle(); poller.cycle(); self.assertEqual(probe.call_count, 1)
            Sensor.objects.filter(pk=sensor.pk).update(interval=30, revision=2)
            poller.cycle(); self.assertEqual(probe.call_count, 2)

    # --- views ---
    def test_dialog_offers_ping_without_snmp_profile(self):
        page = self.client.get(self.url('device_sensors'))
        for value in ('Detect Ping', 'Latency and packet loss', 'name="kind" value="ping"'):
            self.assertContains(page, value)
        html = page.content.decode()
        button = html[html.index('value="ping" class="sensor-type"'):][:80]
        self.assertNotIn('disabled', button)
        cpu = html[html.index('value="cpu" class="sensor-type"'):][:80]
        self.assertIn('disabled', cpu)

    @ALLOW
    def test_detect_ping_is_one_off_without_profile_and_starts_nothing(self):
        with patch('sensors.ping.probe', return_value={'ping_ms': 12.34, 'packet_loss': 0.0}):
            response = self.client.post(self.url('sensor_detect'), {'kind': 'ping'})
        self.assertContains(response, 'Ping Sensor detected: 12.3 ms, 0% loss')
        self.assertFalse(Sensor.objects.exists()); self.worker.assert_not_called()

    @ALLOW
    def test_detect_ping_total_loss_is_an_error(self):
        with patch('sensors.ping.probe', return_value={'ping_ms': None, 'packet_loss': 100.0}):
            response = self.client.post(self.url('sensor_detect'), {'kind': 'ping'})
        self.assertEqual(response.status_code, 400); self.assertContains(response, '100% packet loss', status_code=400)

    @ALLOW
    def test_add_ping_without_profile_auto_starts_once_and_deduplicates(self):
        data = {'kind': 'ping', 'interval': 10}
        response = self.client.post(self.url('sensor_add'), data)
        self.assertEqual(response.status_code, 302)
        sensor = Sensor.objects.get(); self.assertEqual((sensor.kind, sensor.name, sensor.enabled), ('ping', 'Ping Sensor', True))
        self.assertTrue(SensorRuntime.objects.get(pk=1).polling_authorized); self.worker.assert_called_once()
        self.client.post(self.url('sensor_add'), data)
        self.assertEqual(Sensor.objects.count(), 1)

    @override_settings(DEVICE_CONNECTION_ALLOWED_NETWORKS=('192.0.2.0/24',))
    def test_add_ping_outside_allowlist_creates_nothing(self):
        with patch('sensors.ping.subprocess.Popen') as popen:
            response = self.client.post(self.url('sensor_add'), {'kind': 'ping', 'interval': 10})
        self.assertEqual(response.status_code, 400); self.assertContains(response, 'allowlist', status_code=400)
        self.assertFalse(Sensor.objects.exists()); popen.assert_not_called()

    def test_start_stop_edit_delete_without_profile(self):
        sensor = self.make(enabled=False)
        self.client.post(reverse('sensor_control', args=[self.device.pk, sensor.pk, 'start']))
        sensor.refresh_from_db(); self.assertTrue(sensor.enabled)
        self.client.post(reverse('sensor_control', args=[self.device.pk, sensor.pk, 'stop']))
        sensor.refresh_from_db(); self.assertFalse(sensor.enabled)
        self.client.post(reverse('sensor_edit', args=[self.device.pk, sensor.pk]), {'name': 'Gateway ping', 'interval': 30})
        sensor.refresh_from_db(); self.assertEqual((sensor.name, sensor.interval), ('Gateway ping', 30))
        self.client.post(reverse('sensor_control', args=[self.device.pk, sensor.pk, 'delete']))
        self.assertFalse(Sensor.objects.exists())

    def test_replacing_snmp_credentials_stops_snmp_but_not_ping(self):
        SNMPProfile.objects.create(device=self.device, community=encrypt_password('c'), validated_ip=self.device.management_ip, tested_at=timezone.now())
        ping_sensor = self.make()
        cpu = Sensor.objects.create(device=self.device, kind='cpu', name='CPU', enabled=True)
        with patch('sensors.snmp.read', return_value=1):
            self.client.post(self.url('sensor_profile'), {'community': 'new', 'port': 161})
        ping_sensor.refresh_from_db(); cpu.refresh_from_db()
        self.assertTrue(ping_sensor.enabled); self.assertFalse(cpu.enabled)

    def test_non_admin_cannot_add_or_detect_ping(self):
        self.client.force_login(get_user_model().objects.create_user(username='viewer'))
        self.assertEqual(self.client.post(self.url('sensor_add'), {'kind': 'ping', 'interval': 10}).status_code, 403)
        self.assertEqual(self.client.post(self.url('sensor_detect'), {'kind': 'ping'}).status_code, 403)

    def test_data_and_fleet_expose_ping_only_for_valid_samples(self):
        sensor = self.make()
        SensorSample.objects.create(sensor=sensor, timestamp=timezone.now(), ping_ms=12.5, packet_loss=0.0)
        with patch('sensors.views.worker_running', return_value=True), patch('sensors.presentation.worker_running', return_value=True):
            row = self.client.get(self.url('sensor_data')).json()['sensors'][0]
            fleet = self.client.get(reverse('device_sensor_data')).json()['devices'][str(self.device.pk)][0]
        self.assertEqual((row['status'], row['ping_ms'], row['packet_loss']), ('Active', 12.5, 0.0))
        self.assertEqual((fleet['ping_ms'], fleet['packet_loss']), (12.5, 0.0))
        SensorSample.objects.create(sensor=sensor, timestamp=timezone.now(), valid=False, error='No reply', ping_ms=None, packet_loss=100.0)
        with patch('sensors.views.worker_running', return_value=True), patch('sensors.presentation.worker_running', return_value=True):
            row = self.client.get(self.url('sensor_data')).json()['sensors'][0]
            fleet = self.client.get(reverse('device_sensor_data')).json()['devices'][str(self.device.pk)][0]
        self.assertEqual(row['status'], 'Connection Failed'); self.assertIsNone(row['ping_ms']); self.assertIsNone(row['packet_loss'])
        self.assertIsNone(fleet['ping_ms'])
        self.assertEqual(row['history'][-1]['ping_ms'], None)

    def test_fleet_table_has_ping_column(self):
        sensor = self.make()
        SensorSample.objects.create(sensor=sensor, timestamp=timezone.now(), ping_ms=12.5, packet_loss=0.0)
        with patch('sensors.presentation.worker_running', return_value=True):
            page = self.client.get(reverse('devices'))
        for value in ('<th scope="col">Ping</th>', 'data-device-sensor="ping"', '12.5 ms', 'Live ping'):
            self.assertContains(page, value)
