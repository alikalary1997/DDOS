"""Delete exactly one public IP's three monitoring RAW rules, matched by comment.

Scope guarantees: only the comments MONITOR-<ip>, MONITOR-SYN-<ip> and MONITOR-UDP-<ip>
are ever removed, and only when the rule's chain/action/dst-address also match the
expected schema. Every other firewall rule on the device is untouched.
"""
from dataclasses import dataclass, field

from devices.models import Device
from devices.services.router_lock import RouterBusy, router_lock
from devices.services.router_session import RouterAccessError, router_session
from .diagnostics import event
from .device_approval import device_writes_enabled
from .provisioning import writes_enabled
from .rules import RuleConflict, expected_rules, rule_id


@dataclass
class RuleDeleteResult:
    success: bool = False
    code: str = ""
    message: str = ""
    removed: list = field(default_factory=list)   # comments actually deleted
    missing: list = field(default_factory=list)   # comments already absent (fine)


def delete_monitor_rules(device, address, interface, actor=None, already_locked=False):
    """Remove the three MONITOR rules for `address`, skipping any that are already gone.

    Safe to call repeatedly: a second call finds nothing and reports success.
    Pass already_locked=True when the caller already holds this device's router lock.
    """
    try:
        specifications = expected_rules(address, interface)
    except RuleConflict as error:
        return RuleDeleteResult(code="invalid_target", message=str(error))
    comments = [spec["comment"] for spec in specifications]
    by_comment = {spec["comment"]: spec for spec in specifications}

    if not (writes_enabled() or device_writes_enabled(device)):
        return RuleDeleteResult(
            code="approval_required",
            message="Rule cleanup is disabled until RAW provisioning is approved for this device. "
                    "No MikroTik API connection was attempted.")
    try:
        if already_locked:
            return _delete_locked(device, specifications, address, by_comment)
        with router_lock(device.pk):
            return _delete_locked(device, specifications, address, by_comment)
    except RouterBusy:
        return RuleDeleteResult(code="device_busy", message="Another operation is using this device. Please retry.")
    except RouterAccessError as error:
        return RuleDeleteResult(code=error.code, message=str(error))
    except RuleConflict as error:
        return RuleDeleteResult(code="rule_conflict", message=str(error))
    except Device.DoesNotExist:
        return RuleDeleteResult(code="device_missing", message="The device no longer exists.")
    except Exception:
        return RuleDeleteResult(code="cleanup_failed",
                                message="The router could not be reached, so monitoring rules were not removed.")


def _delete_locked(device, specifications, address, by_comment):
    with router_session(device) as api:
        raw = api.get_resource("/ip/firewall/raw")

        def listing():
            rows = raw.get()
            if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                raise RuleConflict("The RAW rule listing could not be validated.")
            return rows

        rows = listing()
        removed, missing = [], []
        for spec in specifications:
            selected = [row for row in rows if row.get("comment") == spec["comment"]]
            if not selected:
                missing.append(spec["comment"])       # never created or already deleted
                continue
            if len(selected) > 1:
                raise RuleConflict("Duplicate monitoring comments require manual review.")
            row = selected[0]
            # Only delete rules that still look like ours; anything else is left alone.
            if (row.get("chain") != spec["chain"] or row.get("action") != spec["action"]
                    or str(row.get("dst-address", "")).split("/")[0] != address):
                raise RuleConflict("A monitoring comment no longer matches the expected rule; cleanup was blocked.")
            event("rule_deletion", result="attempt")
            raw.remove(id=rule_id(row))
            event("rule_deletion", result="success")
            removed.append(spec["comment"])
        # Verify: none of this IP's comments may remain.
        leftovers = [row for row in listing() if row.get("comment") in by_comment]
        if leftovers:
            raise RuleConflict("Monitoring rules remain after removal; cleanup could not be verified.")
        return RuleDeleteResult(
            success=True, code="verified", removed=removed, missing=missing,
            message=("Removed " + ", ".join(removed) + ".") if removed
            else "No monitoring rules existed for this address.")


def cleanup_before_removal(public_ip, actor=None):
    """Remove this public IP's three rules before the record is removed.

    Returns ``(blocker, removed)``: ``blocker`` is None when removal may proceed, otherwise a
    message explaining why it was blocked; ``removed`` lists the comments actually deleted.

    Chosen failure policy (safer option): if the router cannot be reached the public IP is
    NOT removed, so NetShield and the router never disagree silently. When cleanup is not
    permitted at all (RAW provisioning is disabled for the device, or the IP was never
    verified so no rules were ever created), removal proceeds and no connection is made.
    """
    from public_ips.models import PublicIP

    if public_ip.device_id is None:
        return None, []  # nothing was ever provisioned without a device
    current = PublicIP.objects.filter(pk=public_ip.pk).values(
        "address", "device_id", "incoming_monitoring_interface", "provisioning_status").first()
    if not current:
        return None, []
    device = Device.objects.filter(pk=current["device_id"]).first()
    if device is None:
        return None, []  # device gone: nothing to connect to
    if current["provisioning_status"] != "verified" and not device_writes_enabled(device):
        # Rules are only ever created by a verified provisioning run, and writes are off.
        return None, []
    if not (writes_enabled() or device_writes_enabled(device)):
        # Rules may exist on the router but this deployment may not touch it.
        return None, []
    result = delete_monitor_rules(device, current["address"], current["incoming_monitoring_interface"], actor,
                                  already_locked=True)
    if result.success:
        return None, result.removed
    return (f"Could not remove the RAW monitoring rules for {current['address']} on {device.name}: "
            f"{result.message} The public IP was not removed — retry once the device is reachable, "
            f"or handle the router rules manually."), []
