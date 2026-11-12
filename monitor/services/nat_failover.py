"""Automatic NAT failover to a device's single SOS Public address.

Runs inside the existing detection pipeline (after a sample is evaluated) - no new poller.
Only a CONFIRMED "Under Attack" state triggers a switch, and only while the device-level
Protection toggle is on. SOS Public and Protection are ONE setting for the whole device;
every NAT entry in the device's list is checked. Only the NAT rule whose comment equals an
entry name is touched, and a switched rule is never reverted automatically.
"""
import logging

from django.utils import timezone

from devices.services.router_lock import RouterBusy, router_lock
from devices.services.router_session import RouterAccessError, router_session
from monitor.models import DeviceDDoSProtection, DeviceDDoSProtectionRule, DetectionState, NatFailoverLog

logger = logging.getLogger(__name__)


def _norm(address):
    return (address or "").strip().split("/")[0]


def _log(device, rule, trigger, result, message="", old="", new=""):
    return NatFailoverLog.objects.create(
        device=device, device_name=getattr(device, "name", "") or "",
        nat_comment=rule.name if rule else "", old_address=_norm(old), new_address=_norm(new),
        trigger_address=_norm(getattr(trigger, "address", "")),
        triggered_by=trigger, status_at_trigger="Under Attack",
        result=result, message=message[:400])


def evaluate_device_failover(device_id, lock_held=False):
    """Switch every matching NAT entry to the device's SOS Public while Protection is on.

    Returns the list of NatFailoverLog rows created. Never raises: this is an active change
    to live customer traffic, so a failure must be logged, not crash the detection pipeline.

    `lock_held=True` means the caller already holds this device's router lock. This is the
    normal case: the signal fires from inside the polling cycle, which holds
    router_lock(device_id) for the whole sample write. Re-acquiring it there would always
    raise RouterBusy and silently skip the switch.
    """
    try:
        return _evaluate(device_id, lock_held=lock_held)
    except Exception:
        logger.exception("NAT failover evaluation failed for device_id=%s", device_id)
        return []


def _evaluate(device_id, lock_held=False):
    from devices.models import Device
    protection = DeviceDDoSProtection.objects.filter(device_id=device_id).first()
    if protection is None or not protection.enabled:
        return []                       # Protection OFF: never touch any NAT rule
    sos = _norm(protection.sos_public)
    if not sos:
        return []                       # nothing to fail over to
    rules = list(protection.rules.exclude(name=""))
    if not rules:
        return []
    device = Device.objects.filter(pk=device_id, enabled=True, device_type="mikrotik").first()
    if device is None:
        return []

    def attacked_now():
        return [(state.public_ip, state) for state in DetectionState.objects.select_related("public_ip").filter(
            confirmed_status="Under Attack", public_ip__device_id=device_id).exclude(public_ip=None)]

    if not attacked_now():
        return []                       # confirmed attack only; never a single raw sample

    created = []
    try:
        if lock_held:
            created = _switch(device, device_id, rules, sos, attacked_now)
        else:
            with router_lock(device_id):
                created = _switch(device, device_id, rules, sos, attacked_now)
    except RouterBusy:
        # Lock contention is expected while the poller owns the device; try again next cycle.
        logger.info("NAT failover skipped: device_id=%s busy", device_id)
    except RouterAccessError as error:
        pending = attacked_now()
        created.append(_log(device, rules[0], pending[0][0] if pending else None, "failed", str(error)[:400]))
    except Exception:
        logger.exception("NAT failover failed for device_id=%s", device_id)
    return created


def _switch(device, device_id, rules, sos, attacked_now):
    created = []
    attacked = attacked_now()
    if not attacked:
        return created
    with router_session(device) as api:
        nat = api.get_resource("/ip/firewall/nat")
        rows = nat.get()
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            return [_log(device, rules[0], attacked[0][0], "failed",
                         "The NAT rule listing could not be validated.")]
        for rule in rules:
            trigger = attacked[0][0]
            # Cooldown: one switch per entry; no automatic revert, ever.
            if rule.switched_at is not None:
                continue
            selected = [row for row in rows if row.get("comment") == rule.name]
            if not selected:
                created.append(_log(device, rule, trigger, "skipped",
                                    "No NAT rule with this comment exists on the device."))
                continue
            if len(selected) > 1:
                created.append(_log(device, rule, trigger, "failed",
                                    "Duplicate NAT comments require manual review."))
                continue
            row = selected[0]
            current = _norm(row.get("to-addresses", ""))
            if current == sos:
                continue                # already on SOS Public: nothing to do, no log spam
            try:
                nat.set(id=row.get("id", row.get(".id")), **{"to-addresses": sos})
            except Exception as error:
                logger.warning("NAT failover set failed for comment=%s device=%s", rule.name, device_id)
                created.append(_log(device, rule, trigger, "failed",
                                    f"The NAT rule could not be updated: {type(error).__name__}",
                                    old=current, new=sos))
                continue
            after = [item for item in nat.get() if item.get("id") == row.get("id")]
            if not after or _norm(after[0].get("to-addresses", "")) != sos:
                created.append(_log(device, rule, trigger, "failed",
                                    "The NAT change could not be verified.", old=current, new=sos))
                continue
            rule.switched_at = timezone.now()
            rule.switched_from = current
            rule.save(update_fields=["switched_at", "switched_from"])
            created.append(_log(device, rule, trigger, "switched",
                                f"Switched to SOS Public after a confirmed attack on {trigger.address}.",
                                old=current, new=sos))
    return created
