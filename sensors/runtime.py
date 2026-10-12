"""Launch one SNMP worker after an explicit administrator Add/Start action."""
import os
import subprocess
import sys
import time
from django.conf import settings
from django.db import transaction
from django.db.models import F
from .locking import worker_lock, worker_running, WorkerBusy
from .models import Sensor, SensorRuntime


class StartupError(Exception):
    pass


def ensure_worker():
    try:
        with worker_lock('startup'):
            if worker_running():
                return
            path = settings.BASE_DIR / 'runtime' / 'snmp' / 'worker.log'
            with path.open('a', encoding='utf-8') as log:
                process = subprocess.Popen([sys.executable, '-u', str(settings.BASE_DIR / 'manage.py'), 'poll_sensors'],
                    cwd=settings.BASE_DIR, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), start_new_session=os.name != 'nt')
            for _ in range(30):
                if worker_running():
                    return
                if process.poll() is not None:
                    break
                time.sleep(.1)
            raise StartupError('The SNMP worker did not become ready. Check runtime/snmp/worker.log and press Start to retry.')
    except WorkerBusy:
        # Another Add/Start request owns startup. Its worker must become ready.
        for _ in range(40):
            if worker_running():
                return
            time.sleep(.1)
        raise StartupError('SNMP worker startup is busy. Press Start to retry.') from None
    except OSError:
        raise StartupError('The SNMP worker could not be launched. Check server permissions and press Start to retry.') from None


def start_sensors(ids):
    if not ids:
        return
    with transaction.atomic():
        SensorRuntime.objects.update_or_create(pk=1, defaults={'polling_authorized': True})
        Sensor.objects.filter(pk__in=ids).update(enabled=True, error='', revision=F('revision') + 1)
    try:
        ensure_worker()
    except StartupError as error:
        Sensor.objects.filter(pk__in=ids).update(enabled=False, error=str(error), revision=F('revision') + 1)
        raise
