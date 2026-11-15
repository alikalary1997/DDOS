"""Read-only presentation helpers for a single sensor's detail page.

Nothing here polls, writes or changes how samples are stored: it only queries the
already-stored SensorSample rows for one time range and derives display values.
"""
from datetime import timedelta

from django.db.models import Avg, Max, Min
from django.utils import timezone

from .models import SensorSample

# Order matters: the first entry is the default.
RANGES = [
    ("30m", "30 minutes", timedelta(minutes=30)),
    ("2h", "2 hours", timedelta(hours=2)),
    ("24h", "24 hours", timedelta(hours=24)),
    ("7d", "7 days", timedelta(days=7)),
    ("30d", "30 days", timedelta(days=30)),
]
DEFAULT_RANGE = RANGES[0][0]
# Keeps a 30-day range readable in one response without changing what is stored.
MAX_POINTS = 720

# The metric columns each sensor kind graphs, in display order.
METRICS = {
    "traffic": ["in_mbps", "out_mbps"],
    "cpu": ["cpu"],
    "uptime": ["uptime_seconds"],
    "ping": ["ping_ms", "packet_loss"],
}


def range_keys():
    return [key for key, _label, _delta in RANGES]


def resolve_range(key):
    """Return (key, label, delta) for a requested range, falling back to the default."""
    for candidate, label, delta in RANGES:
        if candidate == key:
            return candidate, label, delta
    return RANGES[0]


def samples_for(sensor, key=DEFAULT_RANGE):
    """Stored samples for this sensor inside the requested range, oldest first."""
    key, _label, delta = resolve_range(key)
    since = timezone.now() - delta
    return SensorSample.objects.filter(sensor=sensor, timestamp__gte=since).order_by("timestamp", "pk")


def history_payload(sensor, key=DEFAULT_RANGE):
    """JSON-ready history for one sensor and range. Never invents values."""
    key, label, delta = resolve_range(key)
    rows = list(samples_for(sensor, key))
    total = len(rows)
    step = max(1, -(-total // MAX_POINTS))          # ceiling division: thin dense ranges
    if step > 1:
        # Always keep the most recent reading so the gauge and graph agree.
        rows = rows[::step] + ([] if (total - 1) % step == 0 else [rows[-1]])
        rows.sort(key=lambda sample: (sample.timestamp, sample.pk))
    return {
        "range": key,
        "range_label": label,
        "since": (timezone.now() - delta).isoformat(),
        "count": total,
        "points": [
            {
                "t": sample.timestamp.isoformat(),
                "valid": sample.valid,
                "cpu": sample.cpu,
                "uptime_seconds": sample.uptime_seconds,
                "in_mbps": sample.in_mbps,
                "out_mbps": sample.out_mbps,
                "ping_ms": sample.ping_ms if sample.valid else None,
                "packet_loss": sample.packet_loss if sample.valid else None,
                "restart_detected": sample.restart_detected,
                "counter_reset": sample.counter_reset,
            }
            for sample in rows
        ],
        "metrics": METRICS.get(sensor.kind, []),
    }


def uptime_percent(sensor, key="24h"):
    """Share of stored samples in the range that came back valid (None when there are none)."""
    rows = samples_for(sensor, key)
    total = rows.count()
    if not total:
        return None
    return round(rows.filter(valid=True).count() * 100 / total, 1)


def stats_for(sensor, key="24h"):
    """Simple per-metric aggregates for the range, from stored samples only."""
    rows = samples_for(sensor, key)
    aggregates = {}
    for metric in METRICS.get(sensor.kind, []):
        values = rows.aggregate(low=Min(metric), high=Max(metric), mean=Avg(metric))
        aggregates[metric] = {
            "min": _number(values["low"]),
            "max": _number(values["high"]),
            "avg": _number(values["mean"]),
        }
    return {
        "total": rows.count(),
        "valid": rows.filter(valid=True).count(),
        "uptime_percent": uptime_percent(sensor, key),
        "metrics": aggregates,
    }


def _number(value):
    return None if value is None else round(float(value), 3)


def cpu_thresholds(device_id):
    """The CPU warning/attack cutoffs detection uses for this device (override, else global)."""
    from monitor.models import DDoSDetectionSettings, DeviceDDoSThreshold

    override = DeviceDDoSThreshold.objects.filter(device_id=device_id).first()
    settings = override or DDoSDetectionSettings.objects.filter(pk=1).first()
    if settings is None:
        return None
    return {"warning": float(settings.cpu_warning), "attack": float(settings.cpu_attack)}


def tune_for(value, thresholds):
    """Green/amber/red tone for a reading, using the same cutoffs as detection."""
    if value is None or thresholds is None:
        return "neutral"
    if value >= thresholds["attack"]:
        return "attack"
    if value >= thresholds["warning"]:
        return "warning"
    return "normal"
