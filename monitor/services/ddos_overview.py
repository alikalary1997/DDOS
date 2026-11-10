"""Saved-data projection and start/stop control for the DDoS Detection page.

Reads only the database (devices, assignments, detection states, SNMP samples).
It never contacts a router and never changes router configuration.
"""
from datetime import timedelta

from django.core.exceptions import ValidationError
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.utils import timezone

from devices.models import Device
from public_ips.models import PublicIP
from sensors.presentation import fleet_snapshot
from monitor.models import DDoSDetectionSettings, DetectionState, DeviceDDoSThreshold
from .dashboard_data import dashboard_data

HIGH_CPU = 80
WARN_CPU = 65


def _mode(sensor):
    """How the reading should be presented, taken from fleet_snapshot()'s own status (same as the Devices page)."""
    if sensor["status"] == "Active":
        return "live"
    return "stale" if sensor["status"] == "Stale" else "paused"


def _device_metrics(sensors, now):
    """Latest saved valid readings from fleet_snapshot(), each labelled live / paused / stale.

    Only mode "live" (running and fresh) may drive warnings; saved readings are never shown as live.
    """
    result = {}
    for kind in ("cpu", "uptime", "traffic"):
        items = [s for s in sensors if s["kind"] == kind]
        entry = {"state": "ok", "value": None, "mode": None, "age_seconds": None}
        if kind == "traffic":
            have = [s for s in items if s["has_reading"] and (s["in_mbps"] is not None or s["out_mbps"] is not None)]
        else:
            have = [s for s in items if s["has_reading"] and s["cpu" if kind == "cpu" else "uptime_seconds"] is not None]
        if not items:
            entry["state"] = "no_sensor"
        elif not have:
            if not any(s["enabled"] for s in items):
                entry["state"] = "stopped"
            else:
                entry["state"] = "stale" if any(s["status"] == "Stale" for s in items) else "unknown"
        else:
            modes = {_mode(s) for s in have}
            entry["mode"] = "stale" if "stale" in modes else "paused" if "paused" in modes else "live"
            entry["age_seconds"] = max(0, int((now - min(s["sample_at"] for s in have)).total_seconds()))
            if kind == "cpu":
                entry["value"] = have[0]["cpu"]
            elif kind == "uptime":
                entry["value"] = have[0]["uptime_seconds"]
            else:
                entry.update(value=sum((s["in_mbps"] or 0) + (s["out_mbps"] or 0) for s in have),
                             in_mbps=sum(s["in_mbps"] or 0 for s in have), out_mbps=sum(s["out_mbps"] or 0 for s in have),
                             interfaces=[{"interface": s["interface_name"] or s["name"], "in_mbps": s["in_mbps"],
                                          "out_mbps": s["out_mbps"]} for s in have], skipped=len(items) - len(have))
        result[kind] = entry
    return result


def overview(can_control=False):
    now = timezone.now()
    data = dashboard_data(can_control)
    rows_by_device = {}
    for row in data["rules"]:
        rows_by_device.setdefault(row["device_id"], []).append(row)
    # Retained, unresolved incident states: an unmonitored device keeps its open incident.
    open_states = dict(DetectionState.objects.filter(
        confirmed_status__in=("Warning", "Under Attack"), event__isnull=False, event__ended_at__isnull=True
    ).values_list("public_ip_id", "confirmed_status"))
    sensor_fleet = fleet_snapshot()
    global_thresholds = DDoSDetectionSettings.objects.filter(pk=1).first()
    cpu_thresholds = {device_id: (cpu_warning, cpu_attack)
                      for device_id, cpu_warning, cpu_attack
                      in DeviceDDoSThreshold.objects.values_list("device_id", "cpu_warning", "cpu_attack")}
    devices = []
    for device in Device.objects.filter(device_type="mikrotik").values(
            "id", "name", "management_ip", "enabled"):
        metrics = _device_metrics(sensor_fleet.get(device["id"], []), now)
        ips = []
        for row in rows_by_device.get(device["id"], []):
            monitored = row["monitoring_health"] != "Not Monitored"
            if monitored:
                # Only a live, fresh sample may drive the current status shown on this page.
                status = row["ddos_status"] if row["monitoring_health"] == "Active" else "Unknown"
            else:
                # Retained incident on an unmonitored assignment keeps its last confirmed severity.
                status = open_states.get(row["id"], "Unknown")
            ips.append({"id": row["id"], "address": row["address"], "monitored": monitored,
                        "status": status, "attacked": status == "Under Attack", "warning": status == "Warning",
                        "health": row["monitoring_health"]})
        monitored = any(ip["monitored"] for ip in ips)
        # CPU limits come from the device's own override, else the global default.
        cpu_warning, cpu_attack = cpu_thresholds.get(device["id"], (
            global_thresholds.cpu_warning if global_thresholds else None,
            global_thresholds.cpu_attack if global_thresholds else None))
        devices.append({
            "id": device["id"], "name": device["name"], "management_ip": device["management_ip"],
            "enabled": device["enabled"], "monitored": monitored,
            "attacked": any(ip["attacked"] for ip in ips),
            "warning": (not any(ip["attacked"] for ip in ips)) and any(ip["warning"] for ip in ips),
            "cpu_warning": float(cpu_warning) if cpu_warning is not None else None,
            "cpu_attack": float(cpu_attack) if cpu_attack is not None else None,
            "metrics": metrics, "sensors_url": reverse("devices") + f"#inspect-{device['id']}", "ips": ips})
    return {
        "can_control": can_control, "generated_at": now,
        "bandwidth_scale_mbps": float(global_thresholds.bandwidth_mbps_attack) if global_thresholds else None,
        "high_cpu": HIGH_CPU, "warn_cpu": WARN_CPU, "devices": devices}


def control(action, device_id=None):
    """Start/stop monitoring through the existing runtime. Stopping keeps all data and incidents."""
    from public_ips.services.monitoring_runtime import start_device, stop
    scope = PublicIP.objects.filter(device__device_type="mikrotik")
    if device_id is not None:
        get_object_or_404(Device, pk=device_id, device_type="mikrotik")
        scope = scope.filter(device_id=device_id)
    if action == "stop":
        stop(list(scope.values_list("pk", flat=True)))
        return "Monitoring stopped. Saved samples and incidents are retained."
    eligible = list(scope.filter(provisioning_status="verified", device__enabled=True).values_list("pk", "device_id"))
    if not eligible:
        raise ValidationError("No enabled device with a verified public IP is available to monitor.")
    device_ids = sorted({device for _, device in eligible})
    if len(device_ids) > 1:
        raise ValidationError(
            "Only one device can be monitored at a time. Start monitoring from the device you want.")
    start_device(device_ids[0])
    return (f"Monitoring is starting for {len(eligible)} public IP{'s' if len(eligible) != 1 else ''}. "
            "Live data appears after two valid samples.")
