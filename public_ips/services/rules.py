"""Exact NetShield monitor schema and conservative placement validation."""
import ipaddress
import re


class RuleConflict(Exception):
    pass


def rule_id(row):
    value = row.get("id", row.get(".id", ""))
    if not isinstance(value, str) or not re.fullmatch(r"\*[0-9a-fA-F]{1,16}", value):
        raise RuleConflict("The RAW rule identifier is invalid.")
    return value


def expected_rules(address, interface):
    try:
        parsed = ipaddress.IPv4Address(address)
    except (ValueError, TypeError):
        raise RuleConflict("Enter a valid public IPv4 address.") from None
    if not parsed.is_global or parsed.is_multicast:
        raise RuleConflict("Enter a publicly routable IPv4 address.")
    if not isinstance(interface, str) or not interface or len(interface) > 255 or not interface.isprintable() or interface != interface.strip():
        raise RuleConflict("Enter a valid Ethernet interface for this public IP.")
    address = str(parsed)
    common = {"chain": "prerouting", "action": "passthrough", "dst-address": address}
    return [
        {**common, "comment": f"MONITOR-{address}", "in-interface": interface},
        {**common, "comment": f"MONITOR-SYN-{address}", "protocol": "tcp", "tcp-flags": "syn"},
        {**common, "comment": f"MONITOR-UDP-{address}", "protocol": "udp"},
    ]


def flag(value):
    return str(value).lower() in ("true", "yes", "1")


def _destination(value):
    try:
        network = ipaddress.ip_network(value, strict=False)
        return str(network.network_address) if network.version == 4 and network.prefixlen == 32 else ""
    except (ValueError, TypeError):
        return ""


def matches(row, expected):
    if any(flag(row.get(field, "false")) for field in ("disabled", "invalid", "dynamic", "log")):
        return False
    for key in ("chain", "action", "comment"):
        if row.get(key) != expected[key]:
            return False
    if row.get("in-interface", "") != expected.get("in-interface", ""):
        return False
    if _destination(row.get("dst-address", "")) != expected["dst-address"]:
        return False
    protocol = {"6": "tcp", "17": "udp", "all": ""}.get(str(row.get("protocol", "")), str(row.get("protocol", "")))
    if protocol != expected.get("protocol", "") or row.get("tcp-flags", "") != expected.get("tcp-flags", ""):
        return False
    # Unknown matchers can restrict counters or have side effects. Fail closed.
    metadata = {"id", ".id", "packets", "bytes", "disabled", "invalid", "dynamic", "log", "log-prefix"}
    fields = set(expected) | {"protocol", "tcp-flags", "in-interface"}
    for key, value in row.items():
        if key not in metadata | fields and value not in ("", None, "false", False):
            return False
    return not row.get("log-prefix", "")


def validate_rules(rows, specifications):
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise RuleConflict("The RAW rule listing could not be validated.")
    ids = [rule_id(row) for row in rows]
    if len(ids) != len(set(ids)):
        raise RuleConflict("The RAW rule listing contains duplicate identifiers.")
    found = {}
    for expected in specifications:
        candidates = [row for row in rows if row.get("comment") == expected["comment"]]
        if len(candidates) > 1:
            raise RuleConflict("Duplicate monitoring comments require manual review.")
        if candidates:
            row = candidates[0]
            if not matches(row, expected):
                raise RuleConflict("An existing monitoring comment has conflicting rule properties.")
            index = rows.index(row)
            earlier = [item for item in rows[:index] if item.get("chain") == "prerouting" and not flag(item.get("disabled", "false"))]
            if any(item.get("action") not in ("passthrough", "log") for item in earlier):
                raise RuleConflict("An existing monitoring rule follows a potentially terminating prerouting rule.")
            found[expected["comment"]] = rule_id(row)
    return found


def placement(rows):
    # Add ahead of the first prerouting rule, preserving every existing rule's order.
    for row in rows:
        if row.get("chain") == "prerouting":
            return rule_id(row)
    return None
