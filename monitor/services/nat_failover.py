"""DDoS Protection: scoped NAT failover plus an always-on Null-IP route.

Runs inside the existing detection pipeline (after a sample is evaluated) - no new poller.
Only CONFIRMED "Under Attack" states trigger anything, and only while the device-level
Protection toggle is on. SOS Public, Null IP and Protection are ONE setting per device.

Two independent actions fire from the same confirmed attack:

* NAT switch - only the NAT rules whose comment is one of this device's listed entries AND
  whose current ``to-addresses`` equals the attacked public IP are switched to SOS Public.
  When nothing matches, no NAT rule is touched at all.
* Null-IP route - the attacked IP is routed to the device's Null IP as a /32; this runs
  regardless of whether any NAT rule matched, and is skipped (with a log) when unset.

Neither action is ever reverted automatically.
"""
import logging

from devices.services.router_lock import RouterBusy, router_lock
from devices.services.router_session import RouterAccessError, router_session
from monitor.models import DeviceDDoSProtection, NatFailoverLog, DetectionState

logger = logging.getLogger(__name__)


def _norm(address):
    return (address or "").strip().split("/")[0]


def _log(device, comment, trigger, result, message="", old="", new=""):
    return NatFailoverLog.objects.create(
        device=device, device_name=getattr(device, "name", "") or "",
        nat_comment=comment or "", old_address=_norm(old), new_address=_norm(new),
        trigger_address=_norm(getattr(trigger, "address", "")),
        triggered_by=trigger, status_at_trigger="Under Attack",
        result=result, message=message[:400])


def evaluate_device_failover(device_id, lock_held=False):
    """Apply the device's DDoS Protection actions for its currently confirmed attacks.

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
        logger.exception("DDoS Protection evaluation failed for device_id=%s", device_id)
        return []


def attacked_public_ips(device_id):
    """Public IP rows on this device whose state is CONFIRMED Under Attack (never raw samples)."""
    return list(
        DetectionState.objects.select_related("public_ip")
        .filter(confirmed_status="Under Attack", public_ip__device_id=device_id)
        .exclude(public_ip=None)
        .order_by("public_ip_id"))


def _evaluate(device_id, lock_held=False):
    from devices.models import Device
    protection = DeviceDDoSProtection.objects.filter(device_id=device_id).first()
    if protection is None or not protection.enabled:
        return []                       # Protection OFF: never touch the router
    sos = _norm(protection.sos_public)
    null_ip = _norm(protection.null_ip)
    if not sos and not null_ip:
        return []                       # neither action can do anything
    entries = [rule.name for rule in protection.rules.exclude(name="") if rule.name]
    device = Device.objects.filter(pk=device_id, enabled=True, device_type="mikrotik").first()
    if device is None:
        return []

    def pending():
        return [(state.public_ip, state) for state in attacked_public_ips(device_id)]

    if not pending():
        return []                       # confirmed attack only; never a single raw sample

    created = []
    try:
        if lock_held:
            created = _run(device, device_id, sos, null_ip, entries, pending)
        else:
            with router_lock(device_id):
                created = _run(device, device_id, sos, null_ip, entries, pending)
    except RouterBusy:
        # Lock contention is expected while the poller owns the device; try again next cycle.
        logger.info("DDoS Protection skipped: device_id=%s busy", device_id)
    except RouterAccessError as error:
        detail = str(error)[:360]
        for trigger, _state in pending():
            if sos:
                created.append(_log(device, "", trigger, "failed", f"NAT switch skipped - device unreachable: {detail}"))
            if null_ip:
                created.append(_log(device, "", trigger, "failed", f"Null IP route skipped - device unreachable: {detail}"))
    except Exception:
        logger.exception("DDoS Protection failed for device_id=%s", device_id)
    return created


def _run(device, device_id, sos, null_ip, entries, pending):
    """One RouterOS session for both actions; each attacked IP is handled independently."""
    created = []
    with router_session(device) as api:
        nat = api.get_resource("/ip/firewall/nat") if sos else None
        routes = api.get_resource("/ip/route") if null_ip else None
        attacked = list(pending())
        if nat is not None and attacked:
            created.extend(_switch_matching(device, device_id, nat, attacked, sos, entries))
        for trigger, _state in attacked:
            if routes is not None:
                created.extend(_add_null_route(device, device_id, routes, trigger, null_ip))
    return created


def _switch_matching(device, device_id, nat, attacked, sos, entries):
    """Switch ONLY the listed NAT rules whose to-addresses equals an attacked public IP."""
    created = []
    rows = nat.get()
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        return [_log(device, "", attacked[0][0], "failed",
                     "The NAT rule listing could not be validated.")]

    for trigger, _state in attacked:
        address = _norm(trigger.address)
        matches = [row for row in rows
                   if (row.get("comment") or "") in entries
                   and _norm(row.get("to-addresses", "")) == address]
        # An entry already carrying SOS Public no longer matches this IP: that is the
        # "already switched" case, not a missing rule - stay quiet about it.
        if not matches:
            if any((row.get("comment") or "") in entries
                   and _norm(row.get("to-addresses", "")) == sos for row in rows):
                continue
            created.append(_log(device, "", trigger, "skipped",
                                f"No NAT rule matching this device's entries has to-addresses {address}; "
                                "no NAT rule was changed."))
            continue
        comments = [row.get("comment") for row in matches]
        if len(set(comments)) != len(comments):
            created.append(_log(device, comments[0], trigger, "failed",
                                "Duplicate NAT comments require manual review."))
            continue
        if all(_norm(row.get("to-addresses", "")) == sos for row in matches):
            continue                  # already on SOS Public: nothing to do, no log spam
        for row in matches:
            comment = row.get("comment") or ""
            current = _norm(row.get("to-addresses", ""))
            if current == sos:
                continue              # this rule is already switched
            try:
                nat.set(id=row.get("id", row.get(".id")), **{"to-addresses": sos})
            except Exception as error:
                logger.warning("DDoS Protection NAT set failed for comment=%s device=%s", comment, device_id)
                created.append(_log(device, comment, trigger, "failed",
                                    f"The NAT rule could not be updated: {type(error).__name__}",
                                    old=current, new=sos))
                continue
            after = [item for item in nat.get()
                     if isinstance(item, dict) and item.get("id") == row.get("id")]
            if not after or _norm(after[0].get("to-addresses", "")) != sos:
                created.append(_log(device, comment, trigger, "failed",
                                    "The NAT change could not be verified.", old=current, new=sos))
                continue
            created.append(_log(device, comment, trigger, "switched",
                                f"Switched to SOS Public after a confirmed attack on {trigger.address}.",
                                old=current, new=sos))
    return created


def _add_null_route(device, device_id, routes, trigger, null_ip):
    """Route this attacked IP to the Null IP. Unconditional; skips cleanly if unset."""
    attacked = _norm(trigger.address)
    if not null_ip:
        return [_log(device, "", trigger, "skipped",
                     "Null IP is not configured for this device; no route was added.")]
    destination = f"{attacked}/32"
    try:
        existing = routes.get()
        for row in existing if isinstance(existing, list) else []:
            if not isinstance(row, dict):
                continue
            if (_norm(row.get("dst-address", "")) == attacked
                    and _norm(row.get("gateway", "")) == null_ip):
                return []                 # already routed: never add twice, never revert
        routes.add(disabled="no", **{"dst-address": destination, "gateway": null_ip,
                                     "routing-table": "main"})
    except Exception as error:
        logger.warning("DDoS Protection route add failed device=%s dst=%s", device_id, destination)
        return [_log(device, "", trigger, "failed",
                     f"The Null IP route could not be added: {type(error).__name__}",
                     old="", new=f"{destination} via {null_ip}")]
    return [_log(device, "", trigger, "switched",
                 f"Routed {destination} to Null IP {null_ip} after a confirmed attack.",
                 old="", new=f"{destination} via {null_ip}")]
