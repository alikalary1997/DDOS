"""Dashboard projections from saved assignments only; never contacts a router."""
from django.urls import reverse
from django.utils import timezone
from devices.models import Device
from public_ips.models import PublicIP
from public_ips.services.monitoring import cached_rows, polling_enabled
from public_ips.services.monitoring_presentation import traffic_fields
from public_ips.services.monitoring_runtime import live_run
from monitor.models import DetectionEvent
from .raw_settings import polling_interval

EMPTY_MESSAGE = "No devices or public IPs configured yet."


def dashboard_data(can_control=False):
    devices = list(Device.objects.filter(device_type="mikrotik").values(
        "id", "name", "management_ip", "enabled", "last_connection_test", "last_connection_test_succeeded"))
    by_id = {device["id"]: device for device in devices}
    cache = cached_rows()
    from .detection_presentation import DetectionPresentation
    detection = DetectionPresentation()
    rows = []
    requested = False
    for ip in PublicIP.objects.filter(device_id__in=by_id).values(
        "id", "address", "device_id", "provisioning_status", "monitoring_enabled"):
        device = by_id[ip["device_id"]]
        requested = requested or ip["monitoring_enabled"]
        row = dict(ip, device_name=device["name"], management_ip=device["management_ip"],
                   status="Not monitored", packets=None, bytes=None, pps=None, syn_pps=None,
                   udp_pps=None, mbps=None, last_update=None)
        sample = cache.get(ip["id"], {})
        if sample.get("device_id") == ip["device_id"] and sample.get("address") == ip["address"]:
            row["status"] = sample.get("status")
            if row["status"] == "Monitoring" and not sample.get("retained"):
                fields = traffic_fields(sample, ip["address"])
                for key in ("packets", "bytes", "pps", "mbps", "syn_pps", "udp_pps", "last_update"):
                    row[key] = fields[key]
        row["retry_url"] = reverse("public_ip_provision", args=[ip["id"]]) if can_control else None
        row.update(detection.fields(ip["id"], sample))
        if row["monitoring_health"] != "Active":
            for key in ("packets", "bytes", "pps", "mbps", "syn_pps", "udp_pps", "last_update"):
                row[key] = None
        row["inspect_url"] = reverse("public_ips") + f"#ipAddress{ip['id']}"
        rows.append(row)
    active = [row for row in rows if row["monitoring_health"] == "Active"]
    def total(items, key):
        values = [item[key] for item in items if item[key] is not None]
        return sum(values) if values else None

    incidents = [dict(row) for row in rows if row["ddos_status"] in ("Warning", "Under Attack")]
    incidents.sort(key=lambda row: (row["ddos_status"] != "Under Attack", row["address"]))
    event_ids = [state.event_id for state in detection.states.values() if state.event_id]
    open_events = {event.pk: event for event in DetectionEvent.objects.filter(pk__in=event_ids, ended_at__isnull=True)}
    for row in incidents:
        state = detection.states.get(row["id"])
        event = open_events.get(state.event_id) if state else None
        row["started_at"] = event.started_at if event else None
        row["duration_seconds"] = event.duration_seconds if event else None

    current = {row["id"]: row for row in rows}
    recent = []
    for event in DetectionEvent.objects.all()[:8]:
        row = current.get(event.public_ip_id, {})
        state = detection.states.get(event.public_ip_id)
        live = bool(state and state.event_id == event.pk and row.get("ddos_status") in ("Warning", "Under Attack"))
        recent.append({"id": event.pk, "address": event.address, "device_name": event.device_name,
                       "severity": event.highest_severity, "metrics": event.triggering_metrics,
                       "started_at": event.started_at, "ended_at": event.ended_at,
                       "last_observed_at": event.last_observed_at, "duration_seconds": event.duration_seconds,
                       "peak_pps": event.peak_total_pps, "peak_mbps": event.peak_bandwidth_mbps,
                       "status": "Recovered" if event.ended_at else "Ongoing" if live else "Unresolved",
                       "history_url": reverse("ddos_detection")})
    for device in devices:
        assigned = [row for row in rows if row["device_id"] == device["id"]]
        live = [row for row in assigned if row["monitoring_health"] == "Active"]
        healths = {row["monitoring_health"] for row in assigned}
        device.update(assigned_ips=len(assigned), monitored_ips=len(live), pps=total(live, "pps"), mbps=total(live, "mbps"),
                      monitoring_health="Disabled" if not device["enabled"] else "Receiving samples" if live else
                      "Connection Failed" if "Connection Failed" in healths else "Stale" if "Stale" in healths else "Not Monitored")
    run = live_run()
    return {"monitoring": bool(active), "polling_requested": requested,
            "polling_interval": polling_interval(),
            "polling_available": polling_enabled(), "can_control": can_control,
            "rules": rows, "devices": devices, "empty_message": EMPTY_MESSAGE,
            "incidents": incidents, "recent_events": recent,
            "overview": {"total_pps": total(active, "pps"), "total_mbps": total(active, "mbps"),
                         "active_detections": len(incidents), "monitored_ips": len(active),
                         "attack_ips": sum(row["ddos_status"] == "Under Attack" for row in rows),
                         "warning_ips": sum(row["ddos_status"] == "Warning" for row in rows),
                         "unknown_ips": sum(row["ddos_status"] == "Unknown" for row in rows)},
            "system": {"worker_running": run is not None, "worker_assignment_id": run.assignment_id_snapshot if run else None,
                       "detection_enabled": bool(detection.policy and detection.policy.enabled),
                       "sampled_devices": len({row["device_id"] for row in active}), "checked_at": timezone.now()},
            "summary": {"devices": len(devices), "monitored_devices": len({row["device_id"] for row in active}), "public_ips": len(rows)},
            "last_update": max((row["last_update"] for row in active if row["last_update"]), default=None)}
