"""Dashboard projections from saved assignments only; never contacts a router."""
from django.urls import reverse
from django.utils import timezone
from devices.models import Device
from public_ips.models import PublicIP
from public_ips.services.monitoring import cached_rows, polling_enabled
from public_ips.services.monitoring_presentation import traffic_fields
from public_ips.services.monitoring_runtime import live_run
from monitor.models import DDoSDetectionSettings, DetectionEvent, DeviceDDoSThreshold
from sensors.models import Sensor, SensorSample
from .raw_settings import polling_interval
from .sensor_history import device_cpu, device_telemetry, devices_with_cpu_sensor, traffic_history

EMPTY_MESSAGE = "No devices or public IPs configured yet."


def _ping_state_by_device(now):
    """Device uptime per its ping sensor: 'reachable' / 'unreachable' / None when unknown.
    Only a fresh, valid sample counts; a missing or stale ping is unknown, never offline."""
    state = {}
    for sensor in Sensor.objects.filter(kind="ping", enabled=True):
        sample = SensorSample.objects.filter(sensor=sensor, valid=True).order_by("-timestamp", "-pk").first()
        if not sample or (now - sample.timestamp).total_seconds() > max(60, sensor.interval * 3):
            continue
        # 100% loss means no reply at all: the device is unreachable.
        state[sensor.device_id] = "unreachable" if (sample.packet_loss or 0) >= 100 else "reachable"
    return state


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
    cpu_by_device = device_cpu()
    cpu_sensors = devices_with_cpu_sensor()
    # CPU colours follow the saved detection thresholds (per-device override, else global).
    global_thresholds = DDoSDetectionSettings.objects.filter(pk=1).first()
    cpu_thresholds = {device_id: (cpu_warning, cpu_attack)
                      for device_id, cpu_warning, cpu_attack
                      in DeviceDDoSThreshold.objects.values_list("device_id", "cpu_warning", "cpu_attack")}
    for device in devices:
        device["cpu"] = cpu_by_device.get(device["id"])
        warning, attack = cpu_thresholds.get(device["id"], (
            global_thresholds.cpu_warning if global_thresholds else None,
            global_thresholds.cpu_attack if global_thresholds else None))
        device["cpu_warning_threshold"] = float(warning) if warning is not None else None
        device["cpu_attack_threshold"] = float(attack) if attack is not None else None
        device["cpu_state"] = "ok" if device["cpu"] is not None else "stale" if device["id"] in cpu_sensors else "no_sensor"
        assigned =[row for row in rows if row["device_id"] == device["id"]]
        live = [row for row in assigned if row["monitoring_health"] == "Active"]
        healths = {row["monitoring_health"] for row in assigned}
        device.update(assigned_ips=len(assigned), monitored_ips=len(live), pps=total(live, "pps"), mbps=total(live, "mbps"),
                      monitoring_health="Disabled" if not device["enabled"] else "Receiving samples" if live else
                      "Connection Failed" if "Connection Failed" in healths else "Stale" if "Stale" in healths else "Not Monitored")
    telemetry = device_telemetry()
    ping_state = _ping_state_by_device(timezone.now())
    for device in devices:
        info = telemetry.get(device["id"], {})
        device["interfaces"] = info.get("interfaces", [])
        device["uptime_seconds"] = info.get("uptime_seconds")
        device["uptime_text"] = info.get("uptime_text")
        assigned = [row for row in rows if row["device_id"] == device["id"]]
        cpu_level = None
        if device["cpu"] is not None:
            if device["cpu_attack_threshold"] is not None and device["cpu"] >= device["cpu_attack_threshold"]:
                cpu_level = "attack"
            elif device["cpu_warning_threshold"] is not None and device["cpu"] >= device["cpu_warning_threshold"]:
                cpu_level = "warning"
        if any(row["ddos_status"] == "Under Attack" for row in assigned) or cpu_level == "attack":
            device["status3"] = "attack"
        elif (any(row["ddos_status"] == "Warning" for row in assigned) or cpu_level == "warning"
              or device["monitoring_health"] in ("Stale", "Connection Failed")
              or device["last_connection_test_succeeded"] is False):
            device["status3"] = "warning"
        else:
            # Reachability comes from the device's own ping sensor when one is reporting.
            reachable = ping_state.get(device["id"], "unknown")
            device["ping_state"] = reachable
            if reachable == "reachable":
                device["status3"] = "online"
            elif reachable == "unreachable":
                device["status3"] = "no_data"
            elif device["monitoring_health"] == "Receiving samples":
                device["status3"] = "online"
            else:
                device["status3"] = "no_data"
    status_counts = {key: sum(d["status3"] == key for d in devices) for key in ("online", "warning", "attack", "no_data")}
    attack_types = sorted({m["label"] for row in incidents if row["ddos_status"] == "Under Attack" for m in row["ddos_metrics"] if m.get("label")})
    if status_counts["attack"]:
        network = ("ATTACK", f"{status_counts['attack']} device(s) under attack")
    elif status_counts["warning"]:
        network = ("DEGRADED", f"{status_counts['warning']} device(s) need attention")
    elif not devices or status_counts["online"] == 0:
        network = ("UNKNOWN", "No fresh monitoring data")
    else:
        network = ("HEALTHY", "No attacks or device faults detected")
    run = live_run()
    return {"monitoring": bool(active), "polling_requested": requested,
            "polling_interval": polling_interval(),
            "polling_available": polling_enabled(), "can_control": can_control,
            "rules": rows, "devices": devices, "empty_message": EMPTY_MESSAGE,
            "incidents": incidents, "recent_events": recent,
            "traffic_history": traffic_history(),
            "overview": {"devices_total": len(devices), "devices_online": status_counts["online"], "device_status_counts": status_counts,
                         "normal_ips": sum(row["ddos_status"] == "Normal" for row in rows), "attack_types": attack_types,
                         "network_status": network[0], "network_reason": network[1],
                         "total_pps": total(active, "pps"), "total_gbps": (total(active, "mbps") / 1000) if total(active, "mbps") is not None else None, "total_syn_pps": total(active, "syn_pps"), "total_udp_pps": total(active, "udp_pps"), "total_mbps": total(active, "mbps"),
                         "active_detections": len(incidents), "monitored_ips": len(active),
                         "attack_ips": sum(row["ddos_status"] == "Under Attack" for row in rows),
                         "warning_ips": sum(row["ddos_status"] == "Warning" for row in rows),
                         "unknown_ips": sum(row["ddos_status"] == "Unknown" for row in rows)},
            "system": {"worker_running": run is not None, "worker_assignment_id": run.assignment_id_snapshot if run else None,
                       "detection_enabled": bool(detection.policy and detection.policy.enabled),
                       "sampled_devices": len({row["device_id"] for row in active}), "checked_at": timezone.now()},
            "summary": {"devices": len(devices), "monitored_devices": len({row["device_id"] for row in active}), "public_ips": len(rows)},
            "last_update": max((row["last_update"] for row in active if row["last_update"]), default=None)}
