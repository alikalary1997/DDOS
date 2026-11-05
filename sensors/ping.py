"""Bounded read-only ICMP echo adapter. Sends echo requests only; never configures anything."""
import ipaddress
import os
import re
import subprocess
import time
from types import SimpleNamespace
from devices.services.targets import validate_target, TargetPolicyError

PROBES = 3
TIMEOUT_MS = 1000
# Wall-clock cap for all parallel probes; stragglers are killed.
DEADLINE = 3.0


class PingError(Exception):
    pass


def check_target(device):
    """Apply the management-address allowlist; returns the canonical IP string."""
    if not device.enabled or device.device_type != 'mikrotik':
        raise PingError("Enable a saved MikroTik device before using Ping sensors.")
    try:
        return validate_target(SimpleNamespace(pk=device.pk, management_ip=device.management_ip, api_port=device.api_port))
    except TargetPolicyError as error:
        raise PingError(str(error)) from None


def command(address):
    version = ipaddress.ip_address(address).version
    flag = '-6' if version == 6 else '-4'
    if os.name == 'nt':
        executable = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'PING.EXE')
        return [executable, '-n', '1', '-w', str(TIMEOUT_MS), flag, address]
    return ['ping', '-c', '1', '-W', str(max(1, TIMEOUT_MS // 1000)), flag, address]


def reply_ms(output, address):
    """Latency from one echo's output, or None when it was not a reply from the target.

    A reply line must name the target and carry a time=<n>ms or time<1ms token. Gateway
    "Destination host unreachable" lines (exit code 0 on Windows) and replies from other
    addresses therefore count as lost.
    """
    escaped = re.escape(address)
    for line in output.splitlines():
        if not re.search(r'(?<![0-9a-fA-F:.])' + escaped + r'(?![0-9a-fA-F]|[.:][0-9a-fA-F])', line, re.IGNORECASE):
            continue
        match = re.search(r'time\s*([=<])\s*([0-9]+(?:\.[0-9]+)?)\s*ms', line, re.IGNORECASE)
        if match:
            # Windows prints time<1ms below its 1 ms resolution; use the midpoint, not zero.
            return 0.5 if match.group(1) == '<' else float(match.group(2))
    return None


def summarize(results):
    replies = [value for value in results if value is not None]
    return {'ping_ms': sum(replies) / len(replies) if replies else None,
            'packet_loss': (len(results) - len(replies)) / len(results) * 100}


def probe(device, count=PROBES):
    address = check_target(device)
    argv = command(address)
    flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    processes = []
    try:
        for _ in range(count):
            processes.append(subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                              stderr=subprocess.DEVNULL, creationflags=flags, text=True,
                                              encoding='utf-8', errors='replace'))
        end = time.monotonic() + DEADLINE
        results = []
        for process in processes:
            try:
                output, _ = process.communicate(timeout=max(0.1, end - time.monotonic()))
                results.append(reply_ms(output or '', address))
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                results.append(None)
        return summarize(results)
    except OSError:
        raise PingError("The ping utility could not be run on the NetShield server.") from None
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.communicate()
