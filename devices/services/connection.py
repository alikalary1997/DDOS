"""Read-only, per-device RouterOS connection probes. Never log raw exceptions."""
import os
import socket
import ssl
from dataclasses import dataclass, field

import routeros_api
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.views.decorators.debug import sensitive_variables
from routeros_api import exceptions

from .credentials import CredentialError
from .targets import TargetPolicyError, connection_timeout, validate_target


@dataclass(frozen=True)
class ProbeResult:
    success: bool
    information: dict = field(default_factory=dict)
    error: str = ""
    code: str = ""


class InvalidRouterResponse(Exception):
    pass


def _integer(value, maximum):
    if isinstance(value, bool):
        return None
    try:
        text = str(value)
        if not text.isascii() or not text.isdecimal():
            return None
        number = int(text)
        return number if 0 <= number <= maximum else None
    except (ValueError, TypeError):
        return None


@sensitive_variables()
def _text(value, secret_values, limit):
    if not isinstance(value, str):
        return ""
    for secret in sorted((value for value in secret_values if value), key=len, reverse=True):
        value = value.replace(secret, "[redacted]")
    return "".join(character for character in value if character.isprintable())[:limit]


@sensitive_variables()
def _information(identity_rows, resource_rows, secret_values):
    if not identity_rows or not resource_rows or not isinstance(identity_rows[0], dict) or not isinstance(resource_rows[0], dict):
        raise InvalidRouterResponse
    identity, resource = identity_rows[0], resource_rows[0]
    total = _integer(resource.get("total-memory"), 2**63 - 1)
    free = _integer(resource.get("free-memory"), 2**63 - 1)
    if total is not None and free is not None and free > total:
        total = free = None
    return {
        "router_identity": _text(identity.get("name"), secret_values, 255),
        "routeros_version": _text(resource.get("version"), secret_values, 120),
        "model": _text(resource.get("board-name") or resource.get("model"), secret_values, 120),
        "uptime": _text(resource.get("uptime"), secret_values, 120),
        "cpu_usage": _integer(resource.get("cpu-load"), 100),
        "total_memory": total, "free_memory": free,
    }


def _nested_exception(error):
    # routeros_api wraps socket exceptions in RouterOsApiConnectionError.args.
    seen = set()
    while id(error) not in seen:
        seen.add(id(error))
        nested = next((arg for arg in getattr(error, "args", ()) if isinstance(arg, BaseException)), None)
        if nested is None:
            return error
        error = nested
    return error


@sensitive_variables()
def probe_device(device):
    connection = None
    try:
        if not device.enabled:
            return ProbeResult(False, error="The device is disabled. Enable it before testing.", code="disabled")
        if device.device_type != "mikrotik":
            return ProbeResult(False, error="Connection testing is supported only for MikroTik devices.", code="unsupported_device")
        host = validate_target(device)
        timeout = connection_timeout()
        password = device.get_password()
        context = None
        if device.use_ssl:
            try:
                context = ssl.create_default_context(cafile=getattr(settings, "DEVICE_CONNECTION_CA_FILE", None))
            except (OSError, ValueError, ssl.SSLError):
                return ProbeResult(False, error="The trusted TLS CA configuration could not be loaded.", code="tls_configuration")
            # These settings are mandatory, including IP address certificate matching.
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
        connection = routeros_api.RouterOsApiPool(
            host, username=device.username, password=password, port=device.api_port,
            plaintext_login=True, use_ssl=device.use_ssl,
            ssl_verify=True, ssl_verify_hostname=True, ssl_context=context,
        )
        # Applied before get_api(): bounds both TCP connect and socket reads/writes.
        connection.set_timeout(timeout)
        api = connection.get_api()
        identity = api.get_resource("/system/identity").get()
        resource = api.get_resource("/system/resource").get()
        secrets = (device.username, password, device.encrypted_password, os.environ.get("NETSHIELD_DEVICE_ENCRYPTION_KEY", ""))
        return ProbeResult(True, _information(identity, resource, secrets))
    except TargetPolicyError as error:
        return ProbeResult(False, error=str(error), code="target_policy")
    except (CredentialError, ImproperlyConfigured):
        return ProbeResult(False, error="Stored device credentials could not be decrypted. Check the server encryption configuration.", code="credentials_unavailable")
    except InvalidRouterResponse:
        return ProbeResult(False, error="The RouterOS API returned invalid system information.", code="invalid_response")
    except Exception as error:
        cause = _nested_exception(error)
        if isinstance(cause, ssl.SSLCertVerificationError):
            return ProbeResult(False, error="TLS certificate verification failed. Check the trusted CA and certificate management IP.", code="tls_verification")
        if isinstance(cause, ssl.SSLError):
            return ProbeResult(False, error="TLS connection failed. No plaintext fallback was attempted.", code="tls_failed")
        if isinstance(cause, (socket.timeout, TimeoutError)):
            return ProbeResult(False, error="The device API connection timed out.", code="timeout")
        if isinstance(cause, ConnectionRefusedError):
            return ProbeResult(False, error="The device refused the API connection. Check the configured API service and port.", code="connection_refused")
        if isinstance(error, (exceptions.RouterOsApiCommunicationError, exceptions.RouterOsApiFatalCommunicationError, exceptions.FatalRouterOsApiError)):
            return ProbeResult(False, error="The router rejected API login or read access. Check credentials and API permissions.", code="api_rejected")
        if isinstance(error, exceptions.RouterOsApiParsingError):
            return ProbeResult(False, error="The RouterOS API response could not be read.", code="invalid_response")
        return ProbeResult(False, error="The connection test failed. Check the device and API configuration.", code="connection_failed")
    finally:
        if connection is not None:
            try:
                connection.disconnect()
            except Exception:
                # Cleanup errors must never override the sanitized result or leak credentials.
                pass
