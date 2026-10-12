"""Independent OS lock; never contends with RouterOS/RAW monitoring locks."""
import os
from contextlib import contextmanager
from django.conf import settings


class WorkerBusy(Exception):
    pass


@contextmanager
def worker_lock(name='worker'):
    directory = settings.BASE_DIR / 'runtime' / 'snmp'
    directory.mkdir(parents=True, exist_ok=True)
    if name not in ('worker', 'startup'):
        raise ValueError('Invalid SNMP lock name')
    with (directory / f'{name}.lock').open('a+b') as handle:
        if handle.tell() == 0:
            handle.write(b'0')
            handle.flush()
        handle.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise WorkerBusy('An SNMP sensor worker is already running.') from None
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == 'nt':
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def worker_running():
    try:
        with worker_lock():
            return False
    except WorkerBusy:
        return True
