"""Uncached configuration reads let the existing worker apply changes in place."""
from monitor.models import DEFAULT_POLLING_INTERVAL, POLLING_INTERVALS, RAWMonitoringSettings


def polling_interval():
    value = RAWMonitoringSettings.objects.filter(pk=1).values_list("polling_interval", flat=True).first()
    return value if value in POLLING_INTERVALS else DEFAULT_POLLING_INTERVAL


def sample_freshness_seconds(sample_interval=None):
    current = polling_interval()
    previous = sample_interval if sample_interval in POLLING_INTERVALS else current
    # Allow the previous cycle to stay visible during a configuration transition.
    return max(current, previous) + 3
