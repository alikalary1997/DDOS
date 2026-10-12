"""Saved-device RouterOS transport; no raw errors or credential output."""
import socket
import ssl
from contextlib import contextmanager

import routeros_api
from routeros_api.exceptions import RouterOsApiError
from routeros_api.exceptions import RouterOsApiConnectionClosedError
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.views.decorators.debug import sensitive_variables

from .connection import _nested_exception, _text
from .credentials import CredentialError
from .targets import TargetPolicyError, connection_timeout, validate_target
from public_ips.services.diagnostics import event, encryption_key_status


class RouterAccessError(Exception):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


@contextmanager
@sensitive_variables()
def router_session(device):
    pool = None
    connected = False
    try:
        available, valid = encryption_key_status()
        event("encryption_key", device_id=device.pk, key_available=available, key_valid=valid)
        if not device.enabled or device.device_type != "mikrotik":
            raise RouterAccessError("device_unavailable", "An enabled MikroTik device is required.")
        host = validate_target(device)
        event("target_validation", device_id=device.pk, result="success")
        timeout = connection_timeout()
        event("password_decryption", device_id=device.pk, result="attempt")
        password = device.get_password()
        event("password_decryption", device_id=device.pk, result="success")
        context = None
        if device.use_ssl:
            context = ssl.create_default_context(cafile=getattr(settings, "DEVICE_CONNECTION_CA_FILE", None))
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
        event("api_connection", device_id=device.pk, api_port=device.api_port, use_ssl=device.use_ssl, result="attempt")
        pool = routeros_api.RouterOsApiPool(
            host, username=device.username, password=password, port=device.api_port,
            plaintext_login=True, use_ssl=device.use_ssl, ssl_verify=True,
            ssl_verify_hostname=True, ssl_context=context,
        )
        pool.set_timeout(timeout)
        api = pool.get_api()
        connected = True
        event("api_connection", device_id=device.pk, result="success")
        yield api
    except RouterAccessError as error:
        event("router_session", device_id=device.pk, result=error.code)
        raise
    except TargetPolicyError as error:
        event("target_validation", device_id=device.pk, result="target_policy")
        raise RouterAccessError("target_policy", str(error)) from None
    except (CredentialError, ImproperlyConfigured):
        event("password_decryption", device_id=device.pk, result="credentials_unavailable")
        raise RouterAccessError("credentials_unavailable", "Stored credentials could not be decrypted.") from None
    except Exception as error:
        if not isinstance(error, (RouterOsApiError, OSError, ValueError, TypeError)):
            raise
        cause = _nested_exception(error)
        if isinstance(cause, (socket.timeout, TimeoutError)):
            code, message = "timeout", "The RouterOS API operation timed out. Retry will check for existing rules first."
        elif isinstance(cause, ssl.SSLError):
            code, message = "tls_failed", "Verified TLS failed. No plaintext fallback was attempted."
            if isinstance(cause, ssl.SSLCertVerificationError):
                message = "TLS certificate verification failed: " + str(cause.verify_message)
            elif getattr(cause, "reason", None):
                message = "TLS handshake failed: " + str(cause.reason)
        else:
            code, message = "api_failed", "The RouterOS API operation failed. Check connectivity and API permissions."
        reason = code
        if isinstance(cause, ConnectionRefusedError):
            reason, message = "connection_refused", "The saved management IP/API port refused the connection."
        elif isinstance(cause, ConnectionResetError):
            reason, message = "connection_reset", "The API connection was reset by the remote endpoint."
        elif isinstance(cause, RouterOsApiConnectionClosedError):
            reason, message = "connection_closed", "The remote endpoint closed the API connection."
        elif isinstance(cause, OSError) and getattr(cause, "errno", None) in (51, 65, 101, 113, 10051, 10065):
            reason, message = "network_unreachable", "The saved management address is unreachable from this server."
        original = getattr(cause, "original_message", None)
        if isinstance(original, dict):
            detail = original.get("message", original.get(b"message", ""))
            if isinstance(detail, bytes):
                detail = detail.decode("utf-8", errors="replace")
            import os
            detail = _text(detail, (locals().get("password", ""), device.username,
                                   device.encrypted_password,
                                   os.environ.get("NETSHIELD_DEVICE_ENCRYPTION_KEY", "")), 500)
            if detail:
                message = "RouterOS API: " + detail
        event("api_operation" if connected else "api_connection", device_id=device.pk, result=code, reason=reason, errno=getattr(cause, "errno", None), winerror=getattr(cause, "winerror", None))
        raise RouterAccessError(code, message) from None
    finally:
        if pool is not None:
            try:
                pool.disconnect()
            except Exception:
                pass
