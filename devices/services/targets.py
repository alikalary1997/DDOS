"""Strict server-owned connection policy; no DNS or browser targets."""
import ipaddress
import math
import logging

from django.conf import settings
logger = logging.getLogger("netshield.target_policy")


class TargetPolicyError(Exception):
    def __init__(self, message, code="invalid_allowlist"):
        self.code = code
        super().__init__(message)


def _deny(device, reason, message, *, address=None, networks=()):
    # Only canonical IPs/CIDRs and the fixed configuration source enter logs.
    # Never log the raw device object, malformed values or credential fields.
    logger.warning("device_id=%s management_ip=%s policy_source=%s allowed_networks=%s reason=%s",
                   getattr(device, "pk", None), address or "invalid",
                   getattr(settings, "DEVICE_CONNECTION_ALLOWLIST_SOURCE", "Django:DEVICE_CONNECTION_ALLOWED_NETWORKS"),
                   ",".join(str(network) for network in networks) or "none/invalid", reason)
    raise TargetPolicyError(message, reason) from None


def configured_networks():
    values = getattr(settings, "DEVICE_CONNECTION_ALLOWED_NETWORKS", ())
    if not isinstance(values, (list, tuple)):
        raise TargetPolicyError("The device management allowlist is not configured correctly.")
    try:
        if any(not isinstance(value, str) for value in values):
            raise ValueError
        return tuple(ipaddress.ip_network(value.strip(), strict=True) for value in values)
    except (ValueError, TypeError):
        raise TargetPolicyError("The device management allowlist is not configured correctly.") from None


def connection_timeout():
    try:
        value = float(getattr(settings, "DEVICE_CONNECTION_TIMEOUT", 3.0))
    except (TypeError, ValueError):
        raise TargetPolicyError("The device connection timeout is not configured correctly.") from None
    if not math.isfinite(value) or not 0.5 <= value <= 10:
        raise TargetPolicyError("The device connection timeout must be between 0.5 and 10 seconds.")
    return value


def validate_target(device):
    try:
        if "%" in str(device.management_ip):
            raise ValueError
        address = ipaddress.ip_address(device.management_ip)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        port = device.api_port
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError
    except (ValueError, TypeError):
        _deny(device, "invalid_target", "The saved management IP or API port is invalid.")
    if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified or str(address) == "255.255.255.255":
        _deny(device, "forbidden_address", "This management address is not permitted for device connections.", address=address)
    try:
        networks = configured_networks()
    except TargetPolicyError as error:
        _deny(device, "invalid_allowlist", str(error), address=address)
    if not networks:
        _deny(device, "empty_allowlist", "The device management allowlist is empty or missing. Configure an explicit allowed IP or subnet; no connection was attempted.", address=address)
    for network in networks:
        if address.version != network.version or address not in network:
            continue
        if address.version == 4 and network.prefixlen < 31 and address in (network.network_address, network.broadcast_address):
            continue
        return str(address)
    _deny(device, "outside_allowlist", "The saved management IP is outside the configured device allowlist. Ask an administrator to check the configured IP/CIDR entries; no connection was attempted.", address=address, networks=networks)
