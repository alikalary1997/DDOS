"""Read-only RAW sampling. No CPU/RAM/interface telemetry or configuration writes."""
import math
import time
from dataclasses import dataclass

from django.conf import settings
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from devices.models import Device
from devices.services.router_lock import RouterBusy, router_lock
from devices.services.router_session import RouterAccessError, router_session
from public_ips.models import FirewallSample, PublicIP
from .rules import RuleConflict, expected_rules, rule_id, validate_rules
from .monitoring_history import retain
from monitor.models import POLLING_INTERVALS
from monitor.services.raw_settings import polling_interval, sample_freshness_seconds

POLLING_RELEASED = False


def polling_enabled():
    from .monitoring_runtime import live_run
    return (POLLING_RELEASED is True and settings.NETSHIELD_RAW_POLLING_ENABLED is True) or live_run() is not None


def counter(value):
    if isinstance(value, bool):
        return None
    text = str(value)
    if not text.isascii() or not text.isdecimal():
        return None
    result = int(text)
    return result if result <= 2**64 - 1 else None


@dataclass
class Baseline:
    packets: int
    bytes: int
    at: float
    signature: tuple


class RateCalculator:
    def __init__(self):
        self.previous = {}

    def clear_device(self, device_id):
        self.previous = {key: value for key, value in self.previous.items() if key[0] != device_id}

    def rates(self, device_id, identifier, row, at, signature):
        key = (device_id, identifier)
        packets, byte_count = counter(row.get("packets")), counter(row.get("bytes"))
        if packets is None or byte_count is None or not math.isfinite(at):
            self.previous.pop(key, None)
            return packets, byte_count, None, None
        previous = self.previous.get(key)
        self.previous[key] = Baseline(packets, byte_count, at, signature)
        if previous is None or signature != previous.signature:
            return packets, byte_count, None, None
        elapsed = at - previous.at
        if elapsed <= 0 or elapsed > max(POLLING_INTERVALS) * 3 or packets < previous.packets or byte_count < previous.bytes:
            # Counter resets/restarts/rollover: rebaseline; never manufacture wrap deltas.
            return packets, byte_count, None, None
        return packets, byte_count, (packets - previous.packets) / elapsed, (byte_count - previous.bytes) * 8 / elapsed


def empty_row(ip, status, message="", updated_at=None):
    return {
        "id": ip.pk, "address": ip.address, "device_id": ip.device_id,
        "status": status, "message": message, "packets": None, "bytes": None,
        "pps": None, "bps": None, "mbps": None, "last_update": updated_at,
        "protocol_rules": [], "attempted_at": timezone.now().isoformat(),
        "profile_version": [ip.updated_at.isoformat(), ip.provisioning_verified_at.isoformat() if ip.provisioning_verified_at else ""],
    }


def poll_device(device_id, calculator, *, scope=None):
    if not polling_enabled():
        return []
    from .monitoring_runtime import live_run
    run = live_run()
    if run and (scope is None or (device_id, scope.assignment_id, scope.address) !=
                (run.device_id_snapshot, run.assignment_id_snapshot, run.address)):
        return []
    try:
        # Read assignments and persist success/error samples under the same lock
        # as deletion. A stale worker ID must never reconnect or recreate a cache.
        with router_lock(device_id):
            return _poll_locked_device(device_id, calculator, scope=scope)
    except RouterBusy:
        return []


def _poll_locked_device(device_id, calculator, *, scope=None):
    if not polling_enabled():
        return []  # Release gate also blocks reads/background connections.
    if scope is not None:
        from .monitoring_scope import MonitoringScopeError
        if device_id != scope.device_id:
            raise MonitoringScopeError("Device does not match the monitoring scope.")
        target = scope.validate()
        device = target.device
    else:
        device = Device.objects.filter(pk=device_id).first()
    if device is None:
        calculator.clear_device(device_id)
        return []
    ips = [target] if scope is not None else list(PublicIP.objects.filter(
        device_id=device_id, monitoring_enabled=True, provisioning_status="verified"))
    if not ips:
        calculator.clear_device(device_id)
        return []
    try:
        with router_session(device) as api:
            raw = api.get_resource("/ip/firewall/raw")
            rules = raw.get()
            if any("packets" not in row or "bytes" not in row for row in rules):
                # Some RouterOS versions expose counters only through print stats.
                statistics = raw.call("print", {"stats": ""})
                by_id = {}
                for row in statistics:
                    identifier = rule_id(row)
                    if identifier in by_id:
                        raise RuleConflict("Duplicate RAW counter identifiers.")
                    by_id[identifier] = row
                rules = [dict(row, **{key: by_id.get(rule_id(row), {}).get(key) for key in ("packets", "bytes")}) for row in rules]
            now = time.monotonic()
            updated_at = timezone.now().isoformat()
            interval = polling_interval()
            result = []
            present_ids = set()
            for ip in ips:
                item = empty_row(ip, "No matching RAW rule", updated_at=updated_at)
                item["polling_interval"] = interval
                try:
                    specifications = expected_rules(ip.address, ip.incoming_monitoring_interface)
                    found = validate_rules(rules, specifications)
                    if len(found) != 3:
                        raise RuleConflict("The verified monitoring rule set is missing.")
                    by_id = {rule_id(row): row for row in rules}
                    for specification in specifications:
                        identifier = found[specification["comment"]]
                        present_ids.add((device_id, identifier))
                        packets, byte_count, pps, bps = calculator.rates(
                            device_id, identifier, by_id[identifier], now, (tuple(sorted(specification.items())), ip.updated_at.isoformat(),
                                  ip.provisioning_verified_at.isoformat() if ip.provisioning_verified_at else "")
                        )
                        sample = {"name": specification["comment"], "packets": packets, "bytes": byte_count,
                                  "pps": pps, "bps": bps, "mbps": bps / 1000000 if bps is not None else None}
                        if specification == specifications[0]:
                            item.update({key: sample[key] for key in ("packets", "bytes", "pps", "bps", "mbps")})
                        else:
                            item["protocol_rules"].append(sample)
                    item["status"] = "Monitoring" if item["pps"] is not None and item["bps"] is not None else "Not monitored"
                    if item["status"] == "Not monitored":
                        item["message"] = "Waiting for two valid counter samples."
                except RuleConflict:
                    item["message"] = "The monitoring rules are missing, conflicting or not safely placed."
                    calculator.clear_device(device_id)
                result.append(item)
            calculator.previous = {key: value for key, value in calculator.previous.items()
                                   if key[0] != device_id or key in present_ids}
            if scope is not None:
                scope.validate()  # Discard results if an out-of-band edit happened during the read.
            FirewallSample.objects.update_or_create(device_id=device_id, defaults={
                "sampled_at": timezone.now(), "status": "sampled", "rows": retain(device_id, result),
            })
            return result
    except RouterBusy:
        return []  # A provisioning operation owns the device; don't create a parallel session.
    except (RouterAccessError, RuleConflict):
        if scope is not None:
            scope.validate()
        calculator.clear_device(device_id)
        result = [empty_row(ip, "Connection error", "RAW counters could not be retrieved.") for ip in ips]
        FirewallSample.objects.update_or_create(device_id=device_id, defaults={"status": "error", "rows": retain(device_id, result)})
        return result


def cached_rows():
    # No browser read invokes RouterOS. Version checks invalidate stop/restart caches.
    rows = {}
    now = timezone.now()
    freshness = sample_freshness_seconds()
    from .monitoring_runtime import live_run
    run = live_run()
    enabled = polling_enabled()
    profiles = {ip["id"]: ip for ip in PublicIP.objects.values(
        "id", "address", "device_id", "updated_at", "provisioning_verified_at", "monitoring_enabled", "provisioning_status"
    )}
    for sample in FirewallSample.objects.all():
        for item in sample.rows:
            if not isinstance(item, dict) or item.get("id") not in profiles:
                continue
            profile = profiles[item["id"]]
            if sample.device_id != profile["device_id"] or item.get("device_id") != profile["device_id"] or item.get("address") != profile["address"]:
                continue
            version = [profile["updated_at"].isoformat(),
                       profile["provisioning_verified_at"].isoformat() if profile["provisioning_verified_at"] else ""]
            attempted = parse_datetime(item.get("attempted_at", "")) if isinstance(item.get("attempted_at"), str) else None
            sample_interval = item.get("polling_interval")
            max_age = max(freshness, sample_interval + 3) if sample_interval in POLLING_INTERVALS else freshness
            fresh = (
                enabled and profile["monitoring_enabled"] and profile["provisioning_status"] == "verified"
                and (run is None or run.assignment_id_snapshot == item["id"])
                and version == item.get("profile_version") and attempted and timezone.is_aware(attempted)
                and 0 <= (now - attempted).total_seconds() <= max_age
            )
            if fresh:
                rows[item["id"]] = dict(item, retained=False)
            else:
                rows[item["id"]] = dict(item, status="Not monitored", message="Polling is stopped or the sample is stale.",
                                       packets=None, bytes=None, pps=None, bps=None, mbps=None, protocol_rules=[])
            current = rows[item["id"]]
            if version != item.get("profile_version"):
                current.pop("last_traffic", None)
                continue
            if current.get("status") != "Monitoring":
                previous = item.get("last_successful") or (item if item.get("status") == "Monitoring" else None)
                if previous and previous.get("profile_version") == version:
                    for key in ("packets", "bytes", "pps", "bps", "mbps", "protocol_rules", "last_update"):
                        current[key] = previous.get(key)
                    current["retained"] = True
                    current["message"] = (current.get("message", "") + " Showing the last successful sample; these are not live rates.").strip()
    return rows
