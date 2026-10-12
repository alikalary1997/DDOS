"""Database-only sensor summaries for the device fleet."""
from datetime import timedelta
from django.db.models import F, Window
from django.db.models.functions import RowNumber
from django.utils import timezone
from .models import Sensor, SensorSample
from .polling import authorized, format_uptime
from .locking import worker_running


ATTENTION_STATUSES = {'Paused', 'Stale', 'Connection Failed'}


def summarize_sensors(sensors):
    """Summarize saved sensor health without conflating enablement with data."""
    return {
        'total': len(sensors),
        'enabled': sum(bool(sensor['enabled']) for sensor in sensors),
        'active': sum(sensor['status'] == 'Active' for sensor in sensors),
        'attention': sum(sensor['status'] in ATTENTION_STATUSES for sensor in sensors),
    }


def fleet_snapshot():
    sensors = list(Sensor.objects.values('id', 'device_id', 'device__enabled', 'kind', 'name', 'interface_name',
                                        'enabled', 'interval', 'last_success', 'error'))
    samples = {s.sensor_id: s for s in SensorSample.objects.filter(sensor_id__in=[s['id'] for s in sensors]).annotate(
        position=Window(expression=RowNumber(), partition_by=[F('sensor_id')], order_by=[F('timestamp').desc(), F('pk').desc()])).filter(position=1)}
    gate, running, now = authorized(), worker_running(), timezone.now()
    groups = {}
    for sensor in sensors:
        sample = samples.get(sensor['id'])
        status = 'Stopped'
        if sensor['enabled']:
            if not gate or not running or not sensor['device__enabled']:
                status = 'Paused'
            elif not sample:
                status = 'Waiting for data'
            elif sample.timestamp < now - timedelta(seconds=max(30, sensor['interval'] * 3)):
                status = 'Stale'
            else:
                status = 'Active' if sample.valid else 'Connection Failed'
        sensor.update(
            status=status,
            status_tone='active' if status == 'Active' else 'attention' if status in ATTENTION_STATUSES else 'idle',
            is_live=status == 'Active', has_reading=bool(sample and sample.valid), sample_at=sample.timestamp if sample else None,
            cpu=None, uptime=None, in_mbps=None, out_mbps=None,
            interface_status=None, restart_detected=False,
        )
        if sample and sample.valid:
            sensor.update(cpu=sample.cpu, uptime=format_uptime(sample.uptime_seconds),
                          in_mbps=sample.in_mbps, out_mbps=sample.out_mbps,
                          interface_status=sample.interface_status or None, restart_detected=sample.restart_detected)
        groups.setdefault(sensor['device_id'], []).append(sensor)
    return groups
