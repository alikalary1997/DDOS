"""Audited, idempotent addition of exact passthrough rules. Release gate is OFF."""
from dataclasses import dataclass, field
import time

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import DatabaseError, transaction
from django.utils import timezone
from django.views.decorators.debug import sensitive_variables

from devices.models import Device
from devices.services.router_lock import RouterBusy, router_lock
from devices.services.router_session import RouterAccessError, router_session
from public_ips.models import AssignmentReview, ProvisioningAttempt, PublicIP
from .rules import RuleConflict, placement, rule_id, validate_rules
from .preflight import inspect_rules
from .controlled_test import scoped_writes_enabled
from .diagnostics import diagnostic_scope, encryption_key_status, event, read_raw
from .device_approval import device_writes_enabled, device_provisioning_requested

# Tests patch this only while using a mocked transport. Requires approved code release.
ROUTER_WRITES_RELEASED = False


@dataclass
class ProvisionResult:
    success: bool = False
    code: str = ""
    message: str = ""
    created: list = field(default_factory=list)
    verified: list = field(default_factory=list)


def writes_enabled():
    return ROUTER_WRITES_RELEASED is True and settings.NETSHIELD_RAW_PROVISIONING_ENABLED is True


def verify_added_rule(raw, specifications, comment, before):
    """Allow bounded RouterOS readback convergence; never repeat an add."""
    for delay in (0, 0.15, 0.35, 0.7):
        if delay:
            time.sleep(delay)
        try:
            found = validate_rules(read_raw(raw), specifications)
            identifier = found.get(comment)
            if identifier is None or identifier in before:
                raise RuleConflict("The newly requested rule could not be uniquely verified.")
            return identifier
        except RuleConflict:
            if delay == 0.7:
                raise
            event("rule_readback_retry", result="attempt")


def _finish(public_ip, attempt, result):
    now = timezone.now()
    status = "verified" if result.success else "awaiting_approval" if result.code == "approval_required" else "failed"
    with transaction.atomic():
        ProvisioningAttempt.objects.filter(pk=attempt.pk).update(
            finished_at=now, status=status,
            code=result.code, message=result.message,
            created_rule_ids=result.created, verified_rule_ids=result.verified,
        )
        updates = {
            "provisioning_status": status,
            "provisioning_code": result.code, "provisioning_message": result.message,
            "provisioning_attempted_at": now,
            "provisioning_verified_at": now if result.success else None,
            "monitoring_enabled": result.success,
        }
        PublicIP.objects.filter(pk=public_ip.pk).update(**updates)
    return result


@sensitive_variables()
def provision_public_ip(public_ip_id, actor):
    device_id = PublicIP.objects.filter(pk=public_ip_id).values_list("device_id", flat=True).first()
    with diagnostic_scope(public_ip_id, device_id):
        available, valid = encryption_key_status()
        event("provisioning_triggered", triggered=True, live_enabled=writes_enabled(), key_available=available, key_valid=valid)
        try:
            result = _provision_public_ip(public_ip_id, actor)
        except DatabaseError:
            event("provisioning_final", result="database_failed")
            raise
        event("provisioning_final", result=result.code)
        return result


@sensitive_variables()
def _provision_public_ip(public_ip_id, actor):
    if not actor or not actor.is_authenticated or not actor.is_active or not (actor.is_staff or actor.is_superuser):
        return ProvisionResult(code="permission_denied", message="Administrator access is required.")
    public_ip = PublicIP.objects.get(pk=public_ip_id)
    if public_ip.device_id is None:
        return ProvisionResult(code="unassigned", message="Assign this public IP to a MikroTik device before provisioning.")
    device = Device.objects.get(pk=public_ip.device_id)
    approved_device = device_writes_enabled(device)
    revalidate = not writes_enabled() and device_provisioning_requested(device) and not approved_device
    scoped = scoped_writes_enabled(public_ip, actor) or approved_device
    event("write_gate", live_enabled=writes_enabled(), scope_enabled=scoped, result="success" if writes_enabled() or scoped else "approval_required")
    if (scoped or revalidate) and AssignmentReview.objects.filter(public_ip_id=public_ip.pk, cleanup_required=True, status="pending").exists():
        return ProvisionResult(code="review_required", message="Add-only provisioning cannot reconcile historical cleanup. Review the assignment first.")
    if writes_enabled():
        from .cleanup import cleanup_review
        for review in AssignmentReview.objects.filter(public_ip_id=public_ip.pk, cleanup_required=True, status="pending"):
            if (review.previous_address, review.previous_device_id_snapshot, review.previous_interface) == (
                public_ip.address, public_ip.device_id, public_ip.incoming_monitoring_interface):
                continue  # Description-only edits can reuse the existing exact set.
            cleanup = cleanup_review(review.pk, actor)
            if not cleanup.success:
                return cleanup  # Do not add a replacement until old ownership is resolved.
    # Audit persistence must succeed before any network action or write.
    with transaction.atomic():
        attempt = ProvisioningAttempt.objects.create(
            public_ip=public_ip, actor=actor, device_id=public_ip.device_id, address_snapshot=public_ip.address,
            interface_snapshot=public_ip.incoming_monitoring_interface,
        )
        PublicIP.objects.filter(pk=public_ip.pk).update(
            provisioning_status="pending", provisioning_code="", provisioning_message="Provisioning in progress.", monitoring_enabled=False, provisioning_verified_at=None,
        )
    event("provisioning_pending", attempt_id=attempt.pk, result="pending")
    result = ProvisionResult()
    if revalidate:
        from devices.services.provisioning_authorization import validate_provisioning, authorize_provisioning
        try:
            validate_provisioning(device.pk, public_ip.address, actor)
            device.refresh_from_db()
            authorize_provisioning(device.pk, actor, confirmed=True,
                                   fingerprint=device.raw_preflight_fingerprint, renew_existing=True)
            device.refresh_from_db()
            approved_device = device_writes_enabled(device)
            scoped = scoped_writes_enabled(public_ip, actor) or approved_device
        except ValidationError as error:
            result.code, result.message = "preflight_failed", "; ".join(error.messages)
            return _finish(public_ip, attempt, result)
        except RouterBusy:
            result.code, result.message = "device_busy", "Another operation is using this device. Please retry."
            return _finish(public_ip, attempt, result)
    if not (writes_enabled() or scoped):
        result.code = "approval_required"
        result.message = "Pending approval: automatic RAW provisioning is disabled or its saved configuration authorization is invalid. Validate and authorize this device in Devices > RAW provisioning. No MikroTik API connection was attempted."
        return _finish(public_ip, attempt, result)
    try:
        with router_lock(public_ip.device_id):
            original_device_id = public_ip.device_id
            public_ip.refresh_from_db()
            if public_ip.device_id != original_device_id:
                raise RuleConflict("The assignment changed during provisioning. Please retry.")
            if not (writes_enabled() or scoped_writes_enabled(public_ip, actor) or device_writes_enabled(Device.objects.get(pk=public_ip.device_id))):
                raise RouterAccessError("approval_required", "The approved device or public IP configuration changed. No further writes are permitted.")
            device = Device.objects.get(pk=public_ip.device_id)
            if approved_device and public_ip.incoming_monitoring_interface != device.incoming_monitoring_interface:
                raise RuleConflict("The assignment interface differs from the approved device's saved interface.")
            with transaction.atomic():
                PublicIP.objects.filter(pk=public_ip.pk).update(
                    provisioning_status="connecting", provisioning_message="Connecting to the saved MikroTik API.")
                ProvisioningAttempt.objects.filter(pk=attempt.pk).update(status="connecting")
            with router_session(device) as api:
                raw, specifications, _ = inspect_rules(api, device, public_ip.address, public_ip.incoming_monitoring_interface)
                for specification in specifications:
                    # Re-read before each add, including retries after uncertain API outcomes.
                    rows = read_raw(raw)
                    found = validate_rules(rows, specifications)
                    if specification["comment"] in found:
                        event("rule_reused", result="success")
                        continue
                    current = PublicIP.objects.get(pk=public_ip.pk)
                    if not (writes_enabled() or scoped_writes_enabled(current, actor) or device_writes_enabled(Device.objects.get(pk=current.device_id))):
                        raise RouterAccessError("approval_required", "Provisioning is disabled pending approval.")
                    requested = list(attempt.requested_rule_comments) + [specification["comment"]]
                    ProvisioningAttempt.objects.filter(pk=attempt.pk).update(requested_rule_comments=requested)
                    attempt.requested_rule_comments = requested
                    before = set(rule_id(row) for row in rows)
                    arguments = dict(specification)
                    anchor = placement(rows)
                    if anchor is not None:
                        arguments["place-before"] = anchor
                    # Only add exists in this write service: no set/remove/move/enable/reset.
                    event("rule_creation", result="attempt")
                    try:
                        raw.add(**arguments)
                    except Exception:
                        event("rule_creation", result="failed")
                        raise
                    event("rule_creation", result="success")
                    identifier = verify_added_rule(raw, specifications, specification["comment"], before)
                    result.created.append(identifier)
                    event("rule_verification", result="success", count=len(result.created))
                    ProvisioningAttempt.objects.filter(pk=attempt.pk).update(created_rule_ids=result.created)
                event("final_verification", result="attempt")
                found = validate_rules(read_raw(raw), specifications)
                if len(found) != 3:
                    raise RuleConflict("All three monitoring rules could not be verified.")
                result.success = True
                result.code = "verified"
                result.message = "All three RAW monitoring rules are verified. Polling must provide valid samples before monitoring is active."
                result.verified = list(found.values())
                event("final_verification", result="success", count=len(found))
    except RuleConflict as error:
        result.code, result.message = "rule_conflict", str(error)
    except RouterBusy:
        result.code, result.message = "device_busy", "Another operation is using this device. Please retry."
    except RouterAccessError as error:
        result.code, result.message = error.code, str(error)
    except DatabaseError:
        # Audit/result persistence problems must not cause further writes.
        result.code, result.message = "database_failed", "Provisioning stopped because its audit state could not be saved."
    except Exception:
        result.code, result.message = "provisioning_failed", "Provisioning failed. Retry will verify existing rules before adding anything."
    return _finish(public_ip, attempt, result)
