"""App-owned worker lifecycle; only a deliberate administrator POST starts it."""
import os
from pathlib import Path
import subprocess
import sys
import uuid

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from devices.services.router_lock import router_lock
from public_ips.models import MonitoringRun, PublicIP
from monitor.services.raw_settings import polling_interval


def live_run():
    run = MonitoringRun.objects.filter(pk=1, active=True).first()
    if run and (timezone.now() - (run.heartbeat_at or run.started_at)).total_seconds() <= max(20, polling_interval() + 15):
        return run
    return None


def covers(run, assignment_id):
    """True when this run monitors the assignment (older single-IP runs have no assignment_ids)."""
    return bool(run) and (assignment_id == run.assignment_id_snapshot or assignment_id in (run.assignment_ids or []))


def run_message(assignment_id, run, sample_message=""):
    if covers(run, assignment_id):
        if run.error:
            return run.error + " " + sample_message
        if run.active and run.heartbeat_at is None:
            return "Starting monitoring. Waiting for two valid counter samples. " + sample_message
    return sample_message


def requested(token):
    return MonitoringRun.objects.filter(pk=1, active=True, token=token).exists()


def heartbeat(token):
    MonitoringRun.objects.filter(pk=1, active=True, token=token).update(heartbeat_at=timezone.now())


def finish(token, error=""):
    MonitoringRun.objects.filter(pk=1, token=token).update(active=False, stopped_at=timezone.now(), error=error[:500])


def launch(run):
    root = Path(settings.BASE_DIR)
    log_path = root / "runtime" / "app-monitoring.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as log:
        subprocess.Popen([sys.executable, "-u", str(root / "manage.py"), "poll_raw_firewall",
                          "--device-id", str(run.device_id_snapshot),
                          "--all-device-ips", "--managed-token", str(run.token)], cwd=root, stdin=subprocess.DEVNULL,
                         stdout=log, stderr=subprocess.STDOUT,
                         creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                         start_new_session=os.name != "nt")


def start(assignment_id):
    """Start monitoring the device that owns this assignment (all of its verified IPs)."""
    ip = PublicIP.objects.filter(pk=assignment_id).only("device_id").first()
    if ip is None:
        raise ValidationError("This public IP assignment no longer exists.")
    if not ip.device_id:
        raise ValidationError("Select an enabled MikroTik with verified RAW monitoring rules.")
    return start_device(ip.device_id)


def start_device(device_id):
    """Monitor every verified public IP assigned to one device in a single worker."""
    with router_lock(-1):
        existing = live_run()
        if existing:
            if existing.device_id_snapshot == device_id:
                return existing
            raise ValidationError("Another device is being monitored. Stop it before starting this one.")
        # Also reject an unmanaged CLI worker or a worker still finishing a read.
        with router_lock(0):
            pass
        with transaction.atomic():
            ips = list(PublicIP.objects.select_related("device").filter(
                device_id=device_id, provisioning_status="verified",
                device__enabled=True, device__device_type="mikrotik").order_by("pk"))
            if not ips:
                raise ValidationError("Select an enabled MikroTik with verified RAW monitoring rules.")
            ids = [ip.pk for ip in ips]
            # Preference changes must not invalidate the retained traffic profile.
            PublicIP.objects.filter(pk__in=ids).update(monitoring_enabled=True)
            run, _ = MonitoringRun.objects.update_or_create(pk=1, defaults={
                "token": uuid.uuid4(), "active": True, "device_id_snapshot": device_id,
                "assignment_id_snapshot": ids[0], "assignment_ids": ids, "address": ips[0].address,
                "started_at": timezone.now(), "heartbeat_at": None, "stopped_at": None, "error": ""})
        try:
            launch(run)
        except (OSError, ValueError):
            finish(run.token, "The monitoring worker could not be started. Check the server configuration.")
            raise ValidationError("The monitoring worker could not be started. Check the server configuration.") from None
        return run


def stop(assignment_ids):
    with router_lock(-1):
        device_ids = list(PublicIP.objects.filter(pk__in=assignment_ids, device_id__isnull=False)
                          .values_list("device_id", flat=True).distinct())
        MonitoringRun.objects.filter(pk=1, device_id_snapshot__in=device_ids).update(
            active=False, stopped_at=timezone.now())
        PublicIP.objects.filter(pk__in=assignment_ids).update(monitoring_enabled=False)
        # No further polling for these devices: release the cached RouterOS connection.
        from devices.services.router_session import close_connection
        for device_id in device_ids:
            close_connection(device_id)
        # Stop sampling means detection can no longer be confirmed: clear the confirmed status
        # and close open incidents. Otherwise a stale "Under Attack" would be shown forever
        # on the DDoS Detection page while the Public IP table already reports Unknown.
        from monitor.models import DetectionState, DetectionEvent
        now = timezone.now()
        stale = DetectionState.objects.filter(public_ip_id__in=assignment_ids)
        DetectionEvent.objects.filter(
            id__in=stale.exclude(event=None).values_list("event_id", flat=True), ended_at__isnull=True
        ).update(ended_at=now)
        stale.update(confirmed_status="Unknown", warning_count=0, attack_count=0,
                     warning_recovery_count=0, attack_recovery_count=0,
                     last_valid_at=None, pending_since=None, pending_peaks={},
                     triggering_metrics=[], event=None)
