"""Reusable, fail-closed identity checks for a single monitoring target."""
from dataclasses import dataclass, field
from ipaddress import IPv4Address

from public_ips.models import PublicIP


class MonitoringScopeError(Exception):
    pass


@dataclass
class MonitoringScope:
    device_id: int
    assignment_id: int
    address: str
    _version: tuple | None = field(default=None, init=False, repr=False)

    def __post_init__(self):
        try:
            address = IPv4Address(self.address)
            if self.device_id <= 0 or self.assignment_id <= 0 or not address.is_global or address.is_multicast:
                raise ValueError
            self.address = str(address)
        except (ValueError, TypeError):
            raise MonitoringScopeError("Provide positive device/assignment IDs and a public IPv4 address.") from None

    def validate(self):
        ip = PublicIP.objects.select_related("device").filter(
            pk=self.assignment_id, device_id=self.device_id, address=self.address,
            monitoring_enabled=True, provisioning_status="verified",
            device__enabled=True, device__device_type="mikrotik",
        ).first()
        if ip is None:
            raise MonitoringScopeError("The scoped assignment is missing, changed, disabled or no longer verified. Worker stopped.")
        device = ip.device
        version = (ip.updated_at, ip.incoming_monitoring_interface, ip.provisioning_verified_at,
                   device.management_ip, device.api_port, device.use_ssl, device.username,
                   device.encrypted_password, device.incoming_monitoring_interface)
        if self._version is not None and self._version != version:
            raise MonitoringScopeError("The scoped assignment or saved device profile changed. Worker stopped.")
        self._version = version
        return ip

    def targets(self):
        return [self.validate()]

    def matches(self, run):
        return (self.device_id, self.assignment_id, self.address) == (
            run.device_id_snapshot, run.assignment_id_snapshot, run.address)


@dataclass
class DeviceMonitoringScope:
    """Every verified, monitoring-enabled public IP on one device, polled in a single router session."""
    device_id: int
    _version: tuple | None = field(default=None, init=False, repr=False)

    def __post_init__(self):
        if not isinstance(self.device_id, int) or self.device_id <= 0:
            raise MonitoringScopeError("Provide a positive device ID.")

    def targets(self):
        ips = list(PublicIP.objects.select_related("device").filter(
            device_id=self.device_id, monitoring_enabled=True, provisioning_status="verified",
            device__enabled=True, device__device_type="mikrotik").order_by("pk"))
        if not ips:
            raise MonitoringScopeError("The device has no verified public IP to monitor, or it changed. Worker stopped.")
        device = ips[0].device
        version = (device.management_ip, device.api_port, device.use_ssl, device.username,
                   device.encrypted_password, device.incoming_monitoring_interface,
                   tuple((ip.pk, ip.address, ip.updated_at, ip.incoming_monitoring_interface,
                          ip.provisioning_verified_at) for ip in ips))
        if self._version is not None and self._version != version:
            raise MonitoringScopeError("A monitored public IP or the saved device profile changed. Worker stopped.")
        self._version = version
        return ips

    validate = targets

    def matches(self, run):
        return run.device_id_snapshot == self.device_id
