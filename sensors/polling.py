"""Single-threaded sensor sampling, independent from browser refresh and RAW."""
import time
from django.core.exceptions import ImproperlyConfigured
from django.db import transaction
from django.utils import timezone
from devices.services.credentials import decrypt_password, CredentialError
from . import snmp
from .models import Sensor, SensorSample, SensorRuntime, SNMPProfile


def authorized():
    return SensorRuntime.objects.filter(pk=1, polling_authorized=True).exists()


class Poller:
    def __init__(self):
        self.baselines = {}
        self.due = {}

    def cycle(self):
        if not authorized():
            return False
        active = set(Sensor.objects.filter(enabled=True, device__enabled=True).values_list('id', flat=True))
        for mapping in (self.baselines, self.due):
            for key in set(mapping) - active:
                mapping.pop(key, None)
        for pk in sorted(active):
            if not authorized():
                return False
            sensor = Sensor.objects.filter(pk=pk, enabled=True).select_related('device').first()
            if not sensor:
                continue
            previous = self.due.get(pk)
            if previous and previous[1] == sensor.revision and time.monotonic() - previous[0] < sensor.interval:
                continue
            SensorRuntime.objects.filter(pk=1).update(heartbeat=timezone.now())
            self.poll(sensor)
            self.due[pk] = (time.monotonic(), sensor.revision)
        SensorRuntime.objects.filter(pk=1).update(heartbeat=timezone.now())
        return True

    def poll(self, sensor):
        if not authorized() or not sensor.enabled:
            return
        profile = SNMPProfile.objects.filter(device_id=sensor.device_id).first()
        signature = (sensor.revision, sensor.device.management_ip, profile.revision if profile else None)
        values, error = {}, ''
        try:
            if not profile or profile.validated_ip != sensor.device.management_ip:
                raise snmp.SNMPError('Test and save SNMP credentials for the current management IP first.')
            values = snmp.read(sensor.device, decrypt_password(profile.community), profile.port, 'sample', sensor)
        except snmp.SNMPError as exc:
            error = str(exc)
        except (CredentialError, ImproperlyConfigured):
            error = 'SNMP credentials could not be decrypted. Check the server encryption key.'
        now, stamp = time.monotonic(), timezone.now()
        baseline = self.baselines.get(sensor.pk)
        stored = dict(values)
        stored.pop('discontinuity', None)
        if error:
            self.baselines.pop(sensor.pk, None)
        else:
            if baseline and baseline['signature'] == signature:
                elapsed = now - baseline['time']
                old = baseline['values']
                wrap = (2**32)/100
                wrapped = old['uptime_seconds'] > wrap - elapsed * 2 and values['uptime_seconds'] < elapsed * 2
                restarted = values['uptime_seconds'] < old['uptime_seconds'] and not wrapped
                stored['restart_detected'] = restarted
                if sensor.kind == 'traffic':
                    reset = (restarted or values['in_octets'] < old['in_octets'] or values['out_octets'] < old['out_octets']
                             or values.get('discontinuity') != old.get('discontinuity'))
                    stored['counter_reset'] = reset
                    if not reset and 0 < elapsed <= max(60, sensor.interval * 3):
                        stored['in_mbps'] = (values['in_octets'] - old['in_octets']) * 8 / elapsed / 1_000_000
                        stored['out_mbps'] = (values['out_octets'] - old['out_octets']) * 8 / elapsed / 1_000_000
            self.baselines[sensor.pk] = {'time': now, 'values': values, 'signature': signature}
        # Discard in-flight results after stop/edit/delete/profile changes.
        with transaction.atomic():
            current = Sensor.objects.select_for_update().filter(pk=sensor.pk, enabled=True, revision=sensor.revision,
                device__enabled=True, device__management_ip=sensor.device.management_ip).first()
            same_profile = profile and SNMPProfile.objects.filter(pk=profile.pk, revision=profile.revision).exists()
            if not current or not authorized() or (profile and not same_profile):
                self.baselines.pop(sensor.pk, None)
                return
            SensorSample.objects.create(sensor=current, timestamp=stamp, valid=not error, error=error, **stored)
            updates = {'last_attempt': stamp, 'error': error}
            if not error:
                updates['last_success'] = stamp
            Sensor.objects.filter(pk=current.pk).update(**updates)


def format_uptime(seconds):
    if seconds is None:
        return None
    days, rest = divmod(int(seconds), 86400)
    hours, rest = divmod(rest, 3600)
    minutes, seconds = divmod(rest, 60)
    return f'{days}d {hours:02}h {minutes:02}m {seconds:02}s'
