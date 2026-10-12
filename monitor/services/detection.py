"""Database-only incident evaluation. No router access and no worker activation."""
import hashlib
import json
from datetime import datetime
from decimal import Decimal

from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from monitor.models import DETECTION_METRICS, DDoSDetectionSettings, DetectionPolicy, DetectionState, DetectionEvent
from monitor.services.raw_settings import sample_freshness_seconds
from public_ips.models import PublicIP
from public_ips.services.monitoring_presentation import traffic_fields

COUNTS = ("warning_count", "attack_count", "warning_recovery_count", "attack_recovery_count")
RANK = {"Unknown": -1, "Normal": 0, "Warning": 1, "Under Attack": 2}


def timestamp(value):
    try:
        parsed = value if isinstance(value, datetime) else parse_datetime(value) if isinstance(value, str) else None
        return parsed if parsed and timezone.is_aware(parsed) else None
    except (ValueError, TypeError):
        return None


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def profile_key(ip):
    return digest([ip.device_id, ip.address, ip.incoming_monitoring_interface, ip.updated_at,
                   ip.provisioning_verified_at])


def authorized(policy, ip):
    return bool(policy and policy.enabled and ip.detection_enabled and ip.device_id
                and ip.device.enabled and ip.device.device_type == "mikrotik")


def values_for(row, address):
    values = traffic_fields(row, address)
    result = {"total_pps": values["pps"], "bandwidth_mbps": values["mbps"],
              "syn_pps": values["syn_pps"], "udp_pps": values["udp_pps"]}
    return result if all(value is not None for value in result.values()) else None


def reset_counts(state):
    for name in COUNTS:
        setattr(state, name, 0)
    state.pending_since = None
    state.pending_peaks = {}


def configuration_key(thresholds, policy):
    return digest([thresholds.updated_at, policy.updated_at])


@transaction.atomic
def process_sample(sample):
    # Serializes writers on databases supporting row locks; the existing worker
    # lock and SQLite write transaction also prevent concurrent polling writers.
    policy = DetectionPolicy.objects.select_for_update().filter(pk=1, enabled=True).first()
    if not policy:
        return
    thresholds = DDoSDetectionSettings.objects.filter(pk=1).first()
    if not thresholds or not isinstance(sample.rows, list):
        return
    now = timezone.now()
    config = configuration_key(thresholds, policy)
    for row in sample.rows:
        if not isinstance(row, dict):
            continue
        ip = PublicIP.objects.select_related("device").defer("device__username", "device__encrypted_password").filter(pk=row.get("id"), device_id=sample.device_id).first()
        if not ip or not authorized(policy, ip):
            continue
        at = timestamp(row.get("attempted_at"))
        if not at:
            # Invalid attempts break confirmation, even when their timestamp is unusable.
            state = DetectionState.objects.filter(public_ip=ip).first()
            if state:
                reset_counts(state)
                state.last_valid_at = None
                state.save()
            continue
        state, _ = DetectionState.objects.select_for_update().get_or_create(public_ip=ip, defaults={"profile_key": profile_key(ip)})
        # Retained siblings and repeated saves must never count as new samples.
        if state.last_sample_at and at <= state.last_sample_at:
            continue
        key = profile_key(ip)
        if state.profile_key != key:
            reset_counts(state)
            state.profile_key, state.confirmed_status, state.event = key, "Unknown", None
            state.last_valid_at, state.triggering_metrics = None, []
        max_age = sample_freshness_seconds(row.get("polling_interval"))
        if (state.configuration_key != config or not state.last_valid_at or
                (at - state.last_valid_at).total_seconds() > max_age):
            reset_counts(state)
        state.configuration_key, state.last_sample_at = config, at
        expected_version = [ip.updated_at.isoformat(), ip.provisioning_verified_at.isoformat() if ip.provisioning_verified_at else ""]
        valid = (sample.status == "sampled" and row.get("status") == "Monitoring" and not row.get("retained")
                 and ip.monitoring_enabled and ip.provisioning_status == "verified"
                 and row.get("device_id") == ip.device_id and row.get("address") == ip.address
                 and row.get("profile_version") == expected_version
                 and 0 <= (now - at).total_seconds() <= max_age
                 and timestamp(row.get("last_update")) is not None
                 and abs((at - timestamp(row["last_update"])).total_seconds()) <= max_age)
        values = values_for(row, ip.address) if valid else None
        if values is None:
            reset_counts(state)
            state.last_valid_at = None
            state.save()
            continue
        state.last_valid_at = at
        warning = [name for name, _ in DETECTION_METRICS if Decimal(str(values[name])) >= getattr(thresholds, name + "_warning")]
        attack = [name for name, _ in DETECTION_METRICS if Decimal(str(values[name])) >= getattr(thresholds, name + "_attack")]
        factor = Decimal(100 - policy.hysteresis_percent) / 100
        def below(level):
            return all(Decimal(str(values[name])) < getattr(thresholds, name + "_" + level) * factor
                       for name, _ in DETECTION_METRICS)
        for name, condition in zip(COUNTS, (bool(warning), bool(attack), below("warning"), below("attack"))):
            setattr(state, name, min(getattr(state, name) + 1, 100) if condition else 0)
        if warning:
            state.pending_since = state.pending_since or at
            state.pending_peaks = {name: max(state.pending_peaks.get(name, 0), value) for name, value in values.items()}
        else:
            state.pending_since, state.pending_peaks = None, {}
        status = state.confirmed_status
        if state.attack_count >= policy.confirmation_samples:
            status = "Under Attack"
        elif status == "Under Attack":
            if state.attack_recovery_count >= policy.recovery_samples:
                status = "Normal" if state.warning_recovery_count >= policy.recovery_samples else "Warning"
        elif status == "Warning":
            if state.warning_recovery_count >= policy.recovery_samples:
                status = "Normal"
        elif state.warning_count >= policy.confirmation_samples:
            status = "Warning"
        elif not warning:
            status = "Normal"
        triggers = [{"metric": name, "label": label, "severity": "Under Attack" if name in attack else "Warning"}
                    for name, label in DETECTION_METRICS if name in warning]
        if status in ("Warning", "Under Attack") and not state.event_id:
            state.event, _ = DetectionEvent.objects.get_or_create(
                assignment_id_snapshot=ip.pk, profile_key=key, ended_at__isnull=True,
                defaults={"public_ip": ip, "device": ip.device, "device_id_snapshot": ip.device_id,
                          "address": ip.address, "device_name": ip.device.name, "management_ip": ip.device.management_ip,
                          "started_at": state.pending_since or at, "last_observed_at": at, "highest_severity": status})
        if state.event_id:
            event = state.event
            event.last_observed_at = at
            for name, value in values.items():
                field = "peak_" + name
                setattr(event, field, max(getattr(event, field), value, state.pending_peaks.get(name, 0)))
            # Keep the highest observed trigger for each metric throughout the incident.
            combined = {item["metric"]: item for item in event.triggering_metrics}
            for item in triggers:
                previous = combined.get(item["metric"])
                if not previous or RANK[item["severity"]] > RANK[previous["severity"]]:
                    combined[item["metric"]] = item
            event.triggering_metrics = list(combined.values())
            if RANK[status] > RANK[event.highest_severity]:
                event.highest_severity = status
            if status == "Normal":
                event.ended_at = at
            event.save()
            if event.ended_at:
                state.event = None
        state.confirmed_status = status
        state.triggering_metrics = triggers if triggers else (state.triggering_metrics if status in ("Warning", "Under Attack") else [])
        state.save()
