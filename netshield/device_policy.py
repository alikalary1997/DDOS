"""Explicit deployment policy; an environment override never falls back."""
import json
import os
from django.core.exceptions import ImproperlyConfigured


def load_device_policy(base_dir, *, local=False):
    if "NETSHIELD_DEVICE_ALLOWED_NETWORKS" in os.environ:
        return (tuple(value.strip() for value in os.environ["NETSHIELD_DEVICE_ALLOWED_NETWORKS"].split(",")
                      if value.strip()), "environment:NETSHIELD_DEVICE_ALLOWED_NETWORKS")
    path = base_dir / "device_management_allowlist.json"
    source = str(path) + (" (local profile)" if local else " (normal profile)")
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return (), source + " (missing; deny all)"
    except (OSError, ValueError):
        raise ImproperlyConfigured("The device management allowlist configuration file cannot be read or parsed.") from None
    if not isinstance(config, dict):
        raise ImproperlyConfigured("The device management allowlist configuration must be an object.")
    values = config.get("allowed_networks", [])
    local_values = config.get("local_additional_networks", []) if local else []
    if any(not isinstance(items, list) or any(not isinstance(item, str) for item in items)
           for items in (values, local_values)):
        raise ImproperlyConfigured("Device management allowlist entries must be lists of IP/CIDR strings.")
    return tuple(dict.fromkeys(value.strip() for value in values + local_values if value.strip())), source
