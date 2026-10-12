"""Database authorization bound to the saved management/credential profile."""
import hashlib
import hmac
import json
from django.conf import settings


def device_fingerprint(device):
    values = [device.management_ip, device.api_port, device.use_ssl, device.username,
              device.encrypted_password, device.incoming_monitoring_interface,
              device.enabled, device.device_type]
    return hmac.new(settings.SECRET_KEY.encode(), json.dumps(values).encode(), hashlib.sha256).hexdigest()


def device_provisioning_requested(device):
    return bool(device.raw_provisioning_enabled and device.enabled and device.device_type == "mikrotik")


def device_writes_enabled(device):
    return bool(device_provisioning_requested(device) and device.raw_provisioning_authorized_at
                and device.raw_provisioning_authorized_by_id and device.raw_provisioning_fingerprint
                and hmac.compare_digest(device.raw_provisioning_fingerprint, device_fingerprint(device)))
