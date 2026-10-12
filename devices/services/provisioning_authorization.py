"""Read-only validation followed by separate explicit per-device authorization."""
from datetime import timedelta

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.utils import timezone

from devices.models import Device
from devices.services.connection import probe_device
from devices.services.management import audit_change
from devices.services.router_lock import router_lock
from devices.services.router_session import router_session
from public_ips.services.device_approval import device_fingerprint
from public_ips.services.preflight import inspect_rules

PREFLIGHT_VALID_FOR = timedelta(minutes=15)


def require_administrator(actor):
    if not actor or not actor.is_authenticated or not actor.is_active or not (actor.is_staff or actor.is_superuser):
        raise PermissionDenied("Administrator authorization is required.")


def validation_is_current(device):
    age = timezone.now() - device.raw_preflight_at if device.raw_preflight_at else None
    return bool(age is not None and timedelta(0) <= age <= PREFLIGHT_VALID_FOR
                and device.last_connection_test_succeeded is True
                and device.raw_preflight_fingerprint == device_fingerprint(device))


def validate_provisioning(device_id, address, actor):
    """Reads system information, interface and RAW rules; never writes router rules."""
    require_administrator(actor)
    with router_lock(device_id):
        device = Device.objects.get(pk=device_id)
        fingerprint = device_fingerprint(device)
        # Clear previous preflight first so a failed validation cannot be authorized.
        Device.objects.filter(pk=device_id).update(
            raw_preflight_at=None, raw_preflight_fingerprint="", raw_preflight_address=None,
            raw_preflight_message="Read-only validation in progress.")
        result = probe_device(device)
        tested_at = timezone.now()
        Device.objects.filter(pk=device_id, updated_at=device.updated_at).update(
            last_connection_test=tested_at, last_connection_test_succeeded=result.success,
            last_connection_error=result.error)
        try:
            if not result.success:
                raise ValidationError(result.error)
            with router_session(device) as api:
                _, specifications, found = inspect_rules(api, device, address)
            current = Device.objects.get(pk=device_id)
            if device_fingerprint(current) != fingerprint:
                raise ValidationError("Device configuration changed during validation. Validate again.")
            Device.objects.filter(pk=device_id).update(
                raw_preflight_at=timezone.now(), raw_preflight_fingerprint=fingerprint,
                raw_preflight_address=address,
                raw_preflight_message=f"Passed: connection, saved interface and RAW rules. {len(found)} existing, {3 - len(found)} missing. No rules changed.")
            return specifications, found
        except Exception as error:
            from devices.services.router_session import RouterAccessError
            from public_ips.services.rules import RuleConflict
            if isinstance(error, ValidationError):
                message = "; ".join(error.messages)
            elif isinstance(error, (RouterAccessError, RuleConflict)):
                message = str(error)
            else:
                message = "Read-only validation failed. No router writes were attempted."
            Device.objects.filter(pk=device_id).update(raw_preflight_message=message[:500])
            raise ValidationError(message) from None


def authorize_provisioning(device_id, actor, *, confirmed, fingerprint, renew_existing=False):
    require_administrator(actor)
    if confirmed is not True:
        raise ValidationError("Explicit authorization is required before enabling live writes.")
    with router_lock(device_id), transaction.atomic():
        device = Device.objects.select_for_update().get(pk=device_id)
        if renew_existing:
            from public_ips.services.device_approval import device_provisioning_requested
            if not device_provisioning_requested(device):
                raise ValidationError("Automatic provisioning was disabled during validation. No live writes are authorized.")
        if not device.enabled or device.device_type != "mikrotik":
            raise ValidationError("An enabled MikroTik device is required.")
        if not validation_is_current(device) or fingerprint != device.raw_preflight_fingerprint:
            raise ValidationError("Run successful connection and read-only RAW validation for this saved configuration before authorizing provisioning.")
        audit_change(device, actor, "provision_enable", ("raw_provisioning_enabled",))
        Device.objects.filter(pk=device_id).update(
            raw_provisioning_enabled=True, raw_provisioning_authorized_at=timezone.now(),
            raw_provisioning_authorized_by=actor,
            raw_provisioning_fingerprint=device.raw_preflight_fingerprint)


def disable_provisioning(device_id, actor):
    require_administrator(actor)
    with router_lock(device_id), transaction.atomic():
        device = Device.objects.select_for_update().get(pk=device_id)
        audit_change(device, actor, "provision_disable", ("raw_provisioning_enabled",))
        Device.objects.filter(pk=device_id).update(
            raw_provisioning_enabled=False, raw_provisioning_authorized_at=None,
            raw_provisioning_authorized_by=None, raw_provisioning_fingerprint="")
