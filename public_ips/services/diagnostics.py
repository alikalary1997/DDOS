"""Bounded provisioning diagnostics: IDs, booleans, counts and fixed codes only."""
import logging
import os
from contextlib import contextmanager
from contextvars import ContextVar
from cryptography.fernet import Fernet
from django.views.decorators.debug import sensitive_variables

logger = logging.getLogger("netshield.provisioning")
_context = ContextVar("netshield_provisioning_diagnostics", default=(None, None))
_codes = {"pending", "failed", "provisioned", "attempt", "success", "blocked", "skipped",
          "approval_required", "permission_denied", "unassigned", "review_required",
          "verified", "rule_conflict", "device_busy", "database_failed", "provisioning_failed",
          "credentials_unavailable", "target_policy", "device_unavailable", "timeout", "tls_failed", "api_failed",
          "connection_refused", "connection_reset", "network_unreachable", "connection_closed"}
_numeric = {"count", "attempt_id", "api_port", "public_ip_id", "device_id", "errno", "winerror"}
_boolean = {"triggered", "live_enabled", "scope_enabled", "key_available", "key_valid", "use_ssl"}


@sensitive_variables()
def encryption_key_status():
    key = os.environ.get("NETSHIELD_DEVICE_ENCRYPTION_KEY")
    if not key:
        return False, False
    try:
        Fernet(key.encode("ascii"))
        return True, True
    except (ValueError, TypeError, UnicodeError):
        return True, False


def event(stage, **values):
    # Never accept credentials, API arguments/responses, user text, or raw errors.
    public_ip_id, device_id = _context.get()
    safe = {"public_ip_id": public_ip_id, "device_id": device_id}
    for name, value in values.items():
        if name in _numeric and (value is None or type(value) is int):
            safe[name] = value
        elif name in _boolean and type(value) is bool:
            safe[name] = value
        elif name in {"result", "reason"} and value in _codes:
            safe[name] = value
    logger.info("stage=%s %s", stage, " ".join(f"{name}={value}" for name, value in safe.items()))


@contextmanager
def diagnostic_scope(public_ip_id=None, device_id=None):
    token = _context.set((public_ip_id, device_id))
    try:
        yield
    finally:
        _context.reset(token)


def read_raw(raw):
    event("raw_read", result="attempt")
    try:
        rows = raw.get()
    except Exception:
        event("raw_read", result="failed")
        raise
    event("raw_read", result="success", count=len(rows) if isinstance(rows, list) else None)
    return rows
