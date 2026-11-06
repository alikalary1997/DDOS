"""Read-only dashboard projections of stored SNMP sensor samples. Never contacts a router."""
import time
from datetime import timedelta
from django.utils import timezone
from sensors.models import Sensor, SensorSample

RANGE = timedelta(hours=24)
BUCKET_SECONDS = 300
_CACHE = {"at": 0.0, "value": None}
_CACHE_SECONDS = 20


def _empty():
    return {"available": False, "range_hours": 24, "bucket_seconds": BUCKET_SECONDS, "points": [],
            "current_in": None, "current_out": None, "average_in": None, "average_out": None,
            "peak_in": None, "peak_out": None, "sensors": 0}


def traffic_history(use_cache=True):
    """Sum of in/out Mbps across enabled traffic sensors, averaged into 5-minute buckets over 24h."""
    now_mono = time.monotonic()
    if use_cache and _CACHE["value"] is not None and now_mono - _CACHE["at"] < _CACHE_SECONDS:
        return _CACHE["value"]
    result = _empty()
    sensor_ids = list(Sensor.objects.filter(kind="traffic", enabled=True).values_list("pk", flat=True))
    result["sensors"] = len(sensor_ids)
    if sensor_ids:
        since = timezone.now() - RANGE
        rows = SensorSample.objects.filter(sensor_id__in=sensor_ids, timestamp__gte=since, valid=True,
                                           counter_reset=False, in_mbps__isnull=False, out_mbps__isnull=False
                                           ).values_list("timestamp", "sensor_id", "in_mbps", "out_mbps")
        buckets = {}  # bucket -> sensor -> [sum_in, sum_out, n]
        for stamp, sensor_id, inbound, outbound in rows.iterator():
            key = int(stamp.timestamp()) // BUCKET_SECONDS * BUCKET_SECONDS
            cell = buckets.setdefault(key, {}).setdefault(sensor_id, [0.0, 0.0, 0])
            cell[0] += inbound; cell[1] += outbound; cell[2] += 1
        points = []
        for key in sorted(buckets):
            per_sensor = buckets[key].values()
            points.append({"t": key, "in": round(sum(c[0] / c[2] for c in per_sensor), 6),
                           "out": round(sum(c[1] / c[2] for c in per_sensor), 6)})
        if points:
            ins, outs = [p["in"] for p in points], [p["out"] for p in points]
            result.update(available=True, points=points, current_in=ins[-1], current_out=outs[-1],
                          average_in=sum(ins) / len(ins), average_out=sum(outs) / len(outs),
                          peak_in=max(ins), peak_out=max(outs))
    _CACHE.update(at=now_mono, value=result)
    return result


def device_cpu():
    """Latest fresh CPU percentage per device from enabled CPU sensors (device_id -> float)."""
    now = timezone.now()
    cpu = {}
    for sensor in Sensor.objects.filter(kind="cpu", enabled=True):
        sample = SensorSample.objects.filter(sensor=sensor, valid=True, cpu__isnull=False).order_by("-timestamp").first()
        if sample and now - sample.timestamp <= timedelta(seconds=max(60, sensor.interval * 3)):
            cpu[sensor.device_id] = sample.cpu
    return cpu
