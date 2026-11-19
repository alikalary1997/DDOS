"""Launch one SNMP worker after an explicit administrator Add/Start action."""
import hashlib
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from django.conf import settings
from django.db import transaction
from django.db.models import F
from .locking import worker_lock, worker_running, WorkerBusy
from .models import Sensor, SensorRuntime


class StartupError(Exception):
    pass


def _runtime_directory():
    return settings.BASE_DIR / 'runtime' / 'snmp'


def _stamp_path():
    return _runtime_directory() / 'worker.version'


def code_version():
    """Fingerprint of this process's sensor code.

    A worker keeps its module objects in memory for its whole life, so code edited after it
    started is never picked up. Comparing this fingerprint is how an outdated worker is
    detected instead of silently polling with old logic.
    """
    digest = hashlib.sha256()
    for name in sorted(Path(__file__).parent.glob('*.py')):
        digest.update(name.name.encode())
        try:
            digest.update(name.read_bytes())
        except OSError:
            continue
    return digest.hexdigest()


def write_version_stamp():
    """Record the code this worker is running. Called by the worker process at startup."""
    path = _stamp_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(code_version(), encoding='utf-8')


def worker_is_outdated():
    """True when a worker is running, but from code older than what is on disk now."""
    try:
        stamped = _stamp_path().read_text(encoding='utf-8').strip()
    except OSError:
        return False
    return bool(stamped) and stamped != code_version()


def stop_worker():
    """Ask a running worker to exit, then wait for its lock to be released.

    The worker holds runtime/snmp/worker.lock for its whole life, so a lock that can be taken
    means the process is gone. The PID is read from the same runtime directory the worker
    writes, so this never signals an unrelated process.
    """
    pid_path = _runtime_directory() / 'worker.pid'
    try:
        raw = pid_path.read_text(encoding='utf-8').strip()
        pid = int(raw) if raw.isdigit() and int(raw) > 1 else None
    except OSError:
        pid = None
    if pid:
        if os.name == 'nt':
            # An invisible child has no console to send a signal to; taskkill is deterministic.
            try:
                subprocess.run(['taskkill', '/F', '/PID', str(pid)], capture_output=True, check=False, timeout=10)
            except (OSError, subprocess.SubprocessError):
                pass
        else:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
    for _ in range(100):
        if not worker_running():
            return True
        time.sleep(.1)
    return not worker_running()


def ensure_worker(restart_outdated=True):
    """Start the worker, replacing a running one that predates the code now on disk.

    Returns nothing on success. Raises StartupError when an outdated worker could not be
    replaced: it must never be silently left running on stale code, because a worker keeps its
    modules in memory and would keep reading with logic that no longer matches the server.
    """
    try:
        with worker_lock('startup'):
            if worker_running():
                if not (restart_outdated and worker_is_outdated()):
                    return
                # A worker from older code is running; replace it rather than leave sensors
                # reading with logic that no longer matches the server.
                if not stop_worker():
                    raise StartupError(
                        'An SNMP worker running older code could not be stopped. '
                        'Restart NetShield, then press Start again.')
            _spawn()
    except WorkerBusy:
        # Another Add/Start request owns startup. Its worker must become ready.
        for _ in range(40):
            if worker_running():
                return
            time.sleep(.1)
        raise StartupError('SNMP worker startup is busy. Press Start to retry.') from None
    except OSError:
        raise StartupError('The SNMP worker could not be launched. Check server permissions and press Start to retry.') from None


def _spawn():
    _runtime_directory().mkdir(parents=True, exist_ok=True)
    path = _runtime_directory() / 'worker.log'
    with path.open('a', encoding='utf-8') as log:
        process = subprocess.Popen([sys.executable, '-u', str(settings.BASE_DIR / 'manage.py'), 'poll_sensors'],
            cwd=settings.BASE_DIR, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), start_new_session=os.name != 'nt')
    try:
        # Never write a non-integer pid: a mocked or failed spawn must not leave a file that a
        # later stop_worker() would mistake for a real process id.
        (_runtime_directory() / 'worker.pid').write_text(str(int(process.pid)), encoding='utf-8')
    except (OSError, TypeError, ValueError):
        pass
    for _ in range(30):
        if worker_running():
            return
        if process.poll() is not None:
            break
        time.sleep(.1)
    raise StartupError('The SNMP worker did not become ready. Check runtime/snmp/worker.log and press Start to retry.')


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
