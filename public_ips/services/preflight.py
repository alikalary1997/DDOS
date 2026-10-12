"""Read-only checks shared by preflight and the gated write workflow."""
from .rules import RuleConflict, expected_rules, placement, validate_rules
from .diagnostics import event, read_raw


def inspect_rules(api, device, address, interface=None):
    interface = device.incoming_monitoring_interface if interface is None else interface
    if not interface or not interface.isprintable():
        raise RuleConflict("Select an incoming monitoring interface before provisioning.")
    specifications = expected_rules(address, interface)
    event("interface_read", device_id=device.pk, result="attempt")
    interfaces = api.get_resource("/interface").get()
    event("interface_read", device_id=device.pk, result="success", count=len(interfaces) if isinstance(interfaces, list) else None)
    if not isinstance(interfaces, list) or any(not isinstance(row, dict) for row in interfaces):
        raise RuleConflict("The interface listing could not be validated.")
    selected = [row for row in interfaces if row.get("name") == interface]
    if len(selected) != 1:
        raise RuleConflict("The selected incoming interface does not exist or is ambiguous.")
    # A disabled interface is a valid rule target; never change its state.
    raw = api.get_resource("/ip/firewall/raw")
    rows = read_raw(raw)
    found = validate_rules(rows, specifications)
    placement(rows)
    return raw, specifications, found
