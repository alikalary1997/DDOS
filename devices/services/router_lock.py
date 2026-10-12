"""Per-device OS locks shared by provisioning, interface discovery and polling."""
import os
from contextlib import contextmanager
from pathlib import Path

from django.conf import settings


class RouterBusy(Exception):
    pass


@contextmanager
def router_lock(device_id):
    directory = Path(settings.NETSHIELD_ROUTER_LOCK_DIRECTORY)
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / f"device-{int(device_id)}.lock").open("a+b") as handle:
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise RouterBusy("Another operation is using this device. Please retry.") from None
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
