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


def run_message(assignment_id, run, sample_message=""):
    if run and run.assignment_id_snapshot == assignment_id:
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
                          "--assignment-id", str(run.assignment_id_snapshot), "--public-ip", run.address,
                          "--managed-token", str(run.token)], cwd=root, stdin=subprocess.DEVNULL,
                         stdout=log, stderr=subprocess.STDOUT,
                         creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                         start_new_session=os.name != "nt")


def start(assignment_id):
    with router_lock(-1):
        existing = live_run()
        if existing:
            if existing.assignment_id_snapshot == assignment_id:
                return existing
            raise ValidationError("Another public IP is being monitored. Stop it before starting this one.")
        # Also reject an unmanaged CLI worker or a worker still finishing a read.
        with router_lock(0):
            pass
        with transaction.atomic():
            ip = PublicIP.objects.select_related("device").filter(pk=assignment_id).first()
            if ip is None:
                raise ValidationError("This public IP assignment no longer exists.")
            if not ip.device_id or not ip.device.enabled or ip.device.device_type != "mikrotik" or ip.provisioning_status != "verified":
                raise ValidationError("Select an enabled MikroTik with verified RAW monitoring rules.")
            # Preference changes must not invalidate the retained traffic profile.
            PublicIP.objects.filter(pk=ip.pk).update(monitoring_enabled=True)
            run, _ = MonitoringRun.objects.update_or_create(pk=1, defaults={
                "token": uuid.uuid4(), "active": True, "device_id_snapshot": ip.device_id,
                "assignment_id_snapshot": ip.pk, "address": ip.address,
                "started_at": timezone.now(), "heartbeat_at": None, "stopped_at": None, "error": ""})
        try:
            launch(run)
        except (OSError, ValueError):
            finish(run.token, "The monitoring worker could not be started. Check the server configuration.")
            raise ValidationError("The monitoring worker could not be started. Check the server configuration.") from None
        return run


def stop(assignment_ids):
    with router_lock(-1):
        MonitoringRun.objects.filter(pk=1, assignment_id_snapshot__in=assignment_ids).update(
            active=False, stopped_at=timezone.now())
        PublicIP.objects.filter(pk__in=assignment_ids).update(monitoring_enabled=False)
