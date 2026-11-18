"""Single-threaded sensor sampling, independent from browser refresh and RAW."""
import time
from django.core.exceptions import ImproperlyConfigured
from django.db import transaction
from django.utils import timezone
from devices.services.credentials import decrypt_password, CredentialError
from devices.services.management import MANAGEMENT_IP_FIELD
from . import ping, snmp
from .models import Sensor, SensorSample, SensorRuntime, SNMPProfile


def authorized():
    return SensorRuntime.objects.filter(pk=1, polling_authorized=True).exists()


def profile_matches(profile, device):
    """True when the saved SNMP credentials were validated for this device's current address."""
    return bool(profile) and profile.validated_ip == device.management_ip


def carry_forward_on_ip_change(device):
    """Follow a management-IP change with the already-validated SNMP profile.

    Only an IP change does this: the credentials were validated against this device and
    SNMP is read-only, so re-binding the validated address keeps sensors polling at the
    new IP without a manual re-test. Any other profile change still requires the operator
    to test and save the credentials, exactly as before.
    """
    from devices.models import DeviceChange
    if not DeviceChange.objects.filter(device_id=device.pk, action="edit",
                                       changed_fields__icontains=MANAGEMENT_IP_FIELD).exists():
        return False
    profile = SNMPProfile.objects.filter(device_id=device.pk).first()
    if not profile or profile.validated_ip == device.management_ip:
        return False
    SNMPProfile.objects.filter(pk=profile.pk).update(validated_ip=device.management_ip)
    return True


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
        if sensor.kind == 'ping':
            return self.poll_ping(sensor)
        profile = SNMPProfile.objects.filter(device_id=sensor.device_id).first()
        if profile is not None and not profile_matches(profile, sensor.device):
            # A management-IP edit only: follow it with the same validated credentials.
            if carry_forward_on_ip_change(sensor.device):
                profile = SNMPProfile.objects.filter(pk=profile.pk).first()
        signature = (sensor.revision, sensor.device.management_ip, profile.revision if profile else None)
        values, error = {}, ''
        try:
            if not profile or not profile_matches(profile, sensor.device):
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


    def poll_ping(self, sensor):
        # ICMP echo needs no SNMP profile; it is still gated by the device allowlist.
        values, error = {}, ''
        try:
            result = ping.probe(sensor.device)
            if result['ping_ms'] is None:
                # Keep the real 100% loss figure; latency stays None rather than 0.
                values = {'packet_loss': result['packet_loss']}
                raise ping.PingError(f"No reply to any probe ({result['packet_loss']:.0f}% packet loss).")
            # Refuse to persist an "Active" sample that carries no measurement.
            if result.get('packet_loss') is None:
                raise ping.PingError('The ping probe returned no packet-loss figure.')
            values = result
        except ping.PingError as exc:
            error = str(exc)
        stamp = timezone.now()
        with transaction.atomic():
            # Discard in-flight results after stop/edit/delete or a management-IP change.
            current = Sensor.objects.select_for_update().filter(pk=sensor.pk, enabled=True, revision=sensor.revision,
                device__enabled=True, device__management_ip=sensor.device.management_ip).first()
            if not current or not authorized():
                return
            SensorSample.objects.create(sensor=current, timestamp=stamp, valid=not error, error=error, **values)
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


# Sensors on one device are polled over a single serialized connection, and a table walk (PPPoE)
# can take seconds. A reading is therefore allowed to be older than three intervals without
# being called stale: on a busy server that margin was being exceeded constantly, so healthy
# sensors reported "Waiting for data".
STALE_FLOOR_SECONDS = 120


def staleness_window(interval):
    """How old a reading may be before it is reported as stale."""
    return max(STALE_FLOOR_SECONDS, (interval or 0) * 3)
