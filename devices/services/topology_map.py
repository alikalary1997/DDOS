"""4-column visual map of the device topology chain (read-only).

The chain is whatever the network actually has: a Core at the top, "Limit" devices under it,
PPPoE servers under those, and towers either under a PPPoE server or straight under a Limit.
Nothing here assumes fixed counts or a fixed number of levels - every card and every connector
comes from the real `Device.topology_parent` chain.

A device's column comes from how deep it sits in its own branch (0 = Core, 1 = Limit,
2 = PPPoE, 3+ = Tower), so a Tower hung straight off a Limit still lands in the TOWERS
column and its connector simply spans the empty PPPoE column for that branch.

All statistics are read from stored sensor data and are `None` when no fresh reading exists -
the template renders "No data" rather than inventing a number.
"""
from datetime import timedelta

from django.utils import timezone

from devices.models import Device

LEVELS = (
    ("core", "Core"),
    ("limit", "Limit Servers"),
    ("pppoe", "PPPoE Servers"),
    ("tower", "Towers"),
)
LEVELS_INDEX = {key: index for index, (key, _label) in enumerate(LEVELS)}
LEVELS_LABELS = dict(LEVELS)


def _level_key(depth, device=None):
    """Column for a device: depth decides Core and Limit; deeper nodes are PPPoE or Tower.

    Depth alone cannot separate the two deeper columns, because a tower hung straight off a
    Limit also sits at depth 2. The device's own PPPoE evidence decides: anything that has a
    PPPoE sensor (or a stored session count) is a PPPoE server, otherwise it is a tower.

    A Cisco switch is never a PPPoE server: it is the core when nothing is above it, and a
    tower (a switch at a site) anywhere else in the chain.
    """
    if device is not None and device.device_type == "cisco":
        return "core" if depth <= 0 else "tower"
    if depth <= 0:
        return "core"
    if depth == 1:
        return "limit"
    if device is None:
        return "pppoe"
    if any(sensor.kind == "pppoe" for sensor in device.sensors.all()):
        return "pppoe"
    return "tower"


def _fresh_cutoff(sensor):
    # Same staleness rule the sensor list and detail pages use.
    from sensors.polling import staleness_window
    return timedelta(seconds=staleness_window(sensor.interval))


def _latest(device, kind):
    """Newest valid sample for one sensor kind, or None when absent/stale/invalid."""
    for sensor in device.sensors.all():
        if sensor.kind != kind or not sensor.enabled:
            continue
        sample = sensor.samples.order_by("-timestamp").first()
        if sample is None or not sample.valid:
            return None
        if sample.timestamp < timezone.now() - _fresh_cutoff(sensor):
            return None
        return sample
    return None


def _traffic_mbps(device):
    sample = _latest(device, "traffic")
    if sample is None:
        return None
    incoming, outgoing = sample.in_mbps or 0, sample.out_mbps or 0
    return incoming + outgoing


def _pppoe_users(device):
    sample = _latest(device, "pppoe")
    return None if sample is None else sample.pppoe_users


def _readings(device):
    """This device's own sensor readings, for the detail panel.

    Every figure is None when that sensor has no fresh valid sample, so the panel can show a
    dash rather than a stale or invented number.
    """
    from sensors.polling import format_uptime

    cpu = _latest(device, "cpu")
    traffic = _latest(device, "traffic")
    uptime = _latest(device, "uptime")
    ping = _latest(device, "ping")
    pppoe = _latest(device, "pppoe")
    neighbours = _latest(device, "neighbors")
    return {
        "cpu": cpu.cpu if cpu else None,
        "bandwidth_in": traffic.in_mbps if traffic else None,
        "bandwidth_out": traffic.out_mbps if traffic else None,
        "bandwidth_interface": (traffic.interface_status or "") if traffic else "",
        "uptime": format_uptime(uptime.uptime_seconds) if uptime else None,
        "uptime_seconds": uptime.uptime_seconds if uptime else None,
        "users": pppoe.pppoe_users if pppoe else None,
        "neighbors": neighbours.neighbor_count if neighbours else None,
        "ping_ms": ping.ping_ms if ping else None,
        "packet_loss": ping.packet_loss if ping else None,
    }


class _Node:
    """One device in the chain, plus its real depth and computed column."""

    def __init__(self, device, depth):
        self.device = device
        self.depth = depth
        self.level = _level_key(depth, device)
        self.children = []


def _build_chain():
    """Every device keyed by pk, wired into a cycle-safe forest."""
    devices = list(Device.objects.all().order_by("name"))
    nodes = {device.pk: _Node(device, 0) for device in devices}
    roots = []
    for device in devices:
        parent = nodes.get(device.topology_parent_id)
        if parent is None or parent is nodes[device.pk]:
            roots.append(nodes[device.pk])
        else:
            parent.children.append(nodes[device.pk])
    # Depth-first from each root, cut off if a cycle ever slipped past validation.
    ordered = []

    def walk(node, depth, seen):
        node.depth = depth
        node.level = _level_key(depth, node.device)
        ordered.append(node)
        for child in node.children:
            if child.device.pk not in seen:
                walk(child, depth + 1, seen | {child.device.pk})

    for root in roots:
        walk(root, 0, frozenset({root.device.pk}))
    return ordered


def _stats(node, subtree):
    """Headline stat for a card: (label, value, unit, note).

    `unit` is always a non-empty noun so a card can never render a bare number - a value of
    0 still reads as "0 PPPoE servers". `value=None` means there is no fresh reading.
    """
    if node.level == "core":
        values = [v for v in (_traffic_mbps(n.device) for n in subtree) if v is not None]
        return ("Network throughput", round(sum(values), 2) if values else None, "Mbps",
                f"{sum(1 for n in subtree if n.level == 'limit')} limits below")
    if node.level == "limit":
        servers = sum(1 for n in subtree if n.level == "pppoe")
        mbps = _traffic_mbps(node.device)
        detail = f"{servers} PPPoE server{'s' if servers != 1 else ''}"
        traffic = f"{mbps:.2f} Mbps" if mbps is not None else "traffic no data"
        return ("PPPoE servers", servers, f"PPPoE server{'s' if servers != 1 else ''}", f"{detail} · {traffic}")
    if node.level == "pppoe":
        towers = sum(1 for n in subtree if n.level == "tower")
        # Include this server's own sessions, not just those of the towers below it.
        users = [u for u in (_pppoe_users(n.device) for n in [node] + subtree) if u is not None]
        tower_word = f"tower{'s' if towers != 1 else ''}"
        users_note = f"{sum(users)} users" if users else "users no data"
        return ("Towers", towers, tower_word, f"{towers} {tower_word} · {users_note}")
    # Tower: its own sensors only - never a descendant roll-up it does not have.
    users = _pppoe_users(node.device)
    mbps = _traffic_mbps(node.device)
    parts = []
    if users is not None:
        parts.append(f"{users} PPPoE users")
    if mbps is not None:
        parts.append(f"{mbps:.2f} Mbps")
    if users is not None:
        return ("Site", users, f"PPPoE user{'s' if users != 1 else ''}", " · ".join(parts))
    if mbps is not None:
        # Round here, not only in the note: the summary line uses `value` directly, and a raw
        # sensor float renders as 479.97997768423136 Mbps on the card.
        return ("Site", round(mbps, 2), "Mbps", f"{mbps:.2f} Mbps")
    return ("Site", None, "", "No data")


# Canvas geometry. The chain runs TOP to BOTTOM: the core sits at the top and each level is a
# band underneath it, with cards spread left to right inside their band. Connectors are bold
# vertical curves from a parent's bottom edge down into its child's top edge.
NODE_WIDTH = 168
NODE_HEIGHT = 40
# Horizontal pitch between sibling cards, and the gap between level bands.
COLUMN_GAP = 16
ROW_GAP = 62
HEADER_HEIGHT = 30           # room for the per-level band labels
SIDE_PADDING = 8
# A wide-enough minimum keeps a small tree from stretching across the panel, which is what makes
# the 12px card text look oversized. The canvas still grows with the widest band.
MIN_CANVAS_WIDTH = 760


def _row_layout(ordered, children_of):
    """Horizontal position per device, with each parent centred over its children.

    The map flows top to bottom, so a device's ROW is its depth in the chain and its COLUMN is
    where it sits across that band. Leaves are numbered left to right, then every parent takes
    the midpoint of its children - keeping each fan-out symmetrical however lopsided a branch is.
    """
    columns = {}
    cursor = [0]

    def resolve(node, seen):
        if node.device.pk in columns:
            return columns[node.device.pk]
        kids = [child for child in children_of.get(node.device.pk, [])
                if child.device.pk not in seen and child.device.pk != node.device.pk]
        if not kids:
            columns[node.device.pk] = cursor[0]
            cursor[0] += 1
            return columns[node.device.pk]
        placed = [resolve(child, seen | {child.device.pk}) for child in kids]
        columns[node.device.pk] = (min(placed) + max(placed)) / 2
        return columns[node.device.pk]

    for node in ordered:
        resolve(node, frozenset({node.device.pk}))
    return columns


def _column_layout(ordered):
    """How many cards each of the four stage columns holds."""
    return {key: sum(1 for node in ordered if node.level == key) for key, _label in LEVELS}


def _device_state(device):
    tested = device.last_connection_test_succeeded
    if device.last_connection_test is None or tested is None:
        return "not-tested"
    if not device.enabled:
        return "offline"
    return "online" if tested else "offline"


def build_map():
    """Nodes laid out in depth bands (top to bottom) plus the connectors between them."""
    ordered = _build_chain()
    descendants = {node.device.pk: [] for node in ordered}

    def collect(node, seen):
        found = []
        for child in node.children:
            if child.device.pk in seen:
                continue
            found.append(child)
            found.extend(collect(child, seen | {child.device.pk}))
        descendants[node.device.pk] = found
        return found

    # Collect from the roots only: walking `ordered` would overwrite subtrees with partial ones.
    for node in ordered:
        if node.depth == 0:
            collect(node, frozenset({node.device.pk}))

    children_of = {node.device.pk: list(node.children) for node in ordered}
    columns = _row_layout(ordered, children_of)

    # One band per depth in the chain. The chain is not a balanced tree (a tower can hang
    # straight off a limit), so the bands come from each device's own depth rather than from
    # a fixed four-level list.
    depths = {node.device.pk: _depth_of(node, ordered) for node in ordered}
    band_count = max(depths.values(), default=0) + 1

    # Width: enough for the widest band. Cards are centred inside it so a narrow band does not
    # sit against the left edge.
    widest = max((max(columns.values()) if columns else 0) + 1, 1)
    content_width = widest * NODE_WIDTH + max(0, widest - 1) * COLUMN_GAP
    canvas_width = max(MIN_CANVAS_WIDTH, int(content_width) + SIDE_PADDING * 2)
    left = (canvas_width - content_width) / 2
    canvas_height = HEADER_HEIGHT + band_count * (NODE_HEIGHT + ROW_GAP) + 8

    nodes = []
    for node in ordered:
        subtree = descendants[node.device.pk]
        label, value, unit, note = _stats(node, subtree)
        site_group = 1 + sum(1 for n in subtree if n.level == "tower")
        nodes.append({
            "key": node.device.pk, "name": node.device.name,
            "ip": str(node.device.management_ip), "state": _device_state(node.device),
            "device_type": node.device.device_type,
            "level": node.level, "label": label, "value": value, "unit": unit, "note": note,
            # Depth picks the band (row), the centred layout picks the place across it.
            "x": round(left + columns[node.device.pk] * (NODE_WIDTH + COLUMN_GAP)),
            "y": round(HEADER_HEIGHT + depths[node.device.pk] * (NODE_HEIGHT + ROW_GAP)),
            "w": NODE_WIDTH, "h": NODE_HEIGHT,
            "summary": _summary(node, value, unit),
            "site_count": site_group if node.level == "tower" and site_group > 1 else 0,
            # Per-device readings for the detail panel.
            "readings": _readings(node.device),
            "children_count": len(node.children),
        })

    by_key = {node["key"]: node for node in nodes}
    links = []
    for node in ordered:
        for child in node.children:
            parent_node, child_node = by_key.get(node.device.pk), by_key.get(child.device.pk)
            if not parent_node or not child_node:
                continue
            # Vertical flow: out of the parent's bottom edge, into the child's top edge. `mid`
            # is the control-point y both bezier handles share, which is what makes the curve.
            links.append({
                "id": f"{node.device.pk}-{child.device.pk}",
                "from": node.device.pk, "to": child.device.pk,
                "x1": parent_node["x"] + NODE_WIDTH / 2, "y1": parent_node["y"] + NODE_HEIGHT,
                "x2": child_node["x"] + NODE_WIDTH / 2, "y2": child_node["y"],
                "mid": round((parent_node["y"] + NODE_HEIGHT + child_node["y"]) / 2),
            })

    # A band label above each depth, showing how many devices are in it. Every level gets a
    # label even when it holds nothing, so the map always reads Core / Limit / PPPoE / Towers
    # in that order and a skipped level is visibly empty rather than silently absent.
    band_labels = []
    for depth in range(band_count):
        members = [node for node in ordered if depths[node.device.pk] == depth]
        # A band's label follows the first level present in it; an empty band keeps the level
        # of the stage it stands in for, taken from the fixed chain order.
        level = members[0].level if members else LEVELS[min(depth, len(LEVELS) - 1)][0]
        band_labels.append({"depth": depth, "key": level, "label": LEVELS_LABELS.get(level, level.title()),
                            "count": len(members), "x": SIDE_PADDING,
                            "y": round(HEADER_HEIGHT + depth * (NODE_HEIGHT + ROW_GAP) - 8)})

    return {
        "nodes": nodes, "links": links, "height": canvas_height,
        "width": canvas_width, "node_width": NODE_WIDTH, "node_height": NODE_HEIGHT,
        "columns": band_labels,
        "total": len(ordered), "core_count": sum(1 for node in nodes if node["level"] == "core"),
    }


def _depth_of(node, ordered):
    """How many links sit between this device and a root - its band on the map."""
    parent_of = {}
    for parent in ordered:
        for child in parent.children:
            parent_of.setdefault(child.device.pk, parent.device.pk)
    depth, seen = 0, set()
    current = parent_of.get(node.device.pk)
    while current is not None and current not in seen:
        seen.add(current)
        depth += 1
        current = parent_of.get(current)
    return depth


def _summary(node, value, unit):
    """One short line under the node name, as in the reference cards."""
    if value is None:
        return "No data"
    return f"{value} {unit}".strip()


def switch_ports(device):
    """Live SNMP port states for one switch, plus its sensor readings and per-port neighbours.

    Reads the device's saved SNMP credentials and returns a plain payload. Nothing is invented:
    when SNMP is unavailable the caller gets an `error` and no port list, so the panel can say
    so instead of drawing a made-up green/red grid. Neighbours are attached to the port they
    were learned on; a failure there removes only the neighbours, never the port grid.
    """
    from sensors import snmp
    from sensors.models import SNMPProfile
    from devices.services.credentials import CredentialError, decrypt_password

    profile = SNMPProfile.objects.filter(device=device).first()
    if not profile or profile.validated_ip != device.management_ip:
        return {"ok": False, "error": "Test and save SNMP credentials for this device first."}
    try:
        community = decrypt_password(profile.community)
        ports = snmp.read(device, community, profile.port, "ports")
    except snmp.SNMPError as error:
        return {"ok": False, "error": str(error)}
    except CredentialError:
        return {"ok": False, "error": "Stored SNMP credentials could not be decrypted."}
    try:
        by_port = snmp.read(device, community, profile.port, "neighbors")
    except snmp.SNMPError:
        # A switch that answers the port table but not LLDP still shows its ports.
        by_port = {}
    # Only physical-looking ports are drawn in the grid: VLAN and loopback pseudo-interfaces
    # are not ports a cable plugs into, and would read as permanently "up".
    physical = [p for p in ports if not p["name"].lower().startswith(("vlan", "loopback", "null", "tunnel"))]
    # LLDP reports its local ports with abbreviated names (Gi0/1) while ifDescr says
    # GigabitEthernet0/1, so neighbours are matched on the trailing "<slot>/<port>" instead.
    def port_suffix(name):
        digits = "".join(ch for ch in name if ch.isdigit() or ch == "/")
        return digits.strip("/") or name.lower()

    neighbours_by_suffix = {}
    for interface, entries in by_port.items():
        neighbours_by_suffix.setdefault(port_suffix(interface), []).extend(entries)
    for port in physical:
        port["neighbors"] = neighbours_by_suffix.get(port_suffix(port["name"]), [])
    # Optical readings come from ports() itself, so a copper port simply has none: that absence
    # is what marks a port as fiber, and it is reported explicitly rather than left implicit.
    for port in physical:
        optical = port.get("optical")
        port["fiber"] = bool(port.get("fiber"))
        port["optical"] = optical if isinstance(optical, dict) else None
        # A port can have a transceiver yet publish no DOM values (older Catalyst platforms do
        # not serve CISCO-ENTITY-SENSOR-MIB at all). Saying so is better than an empty panel.
        port["optical_unavailable"] = port["fiber"] and port["optical"] is None
    # VLAN membership is reported per port: an access port names the VLAN it is in, a trunk the
    # native VLAN it carries untagged. A port with no membership (uplink, routed port) sends
    # nothing, which the panel shows as no VLAN row rather than inventing one.
    for port in physical:
        port.setdefault("vlan", None)
        port.setdefault("vlan_name", None)
        port.setdefault("vlan_mode", None)
        port.setdefault("vlan_native", None)
    return {"ok": True, "ports": physical, "total": len(physical),
            "connected": sum(1 for p in physical if p["oper"] == "up"),
            "disabled": sum(1 for p in physical if p["admin"] == "down"),
            "fiber_count": sum(1 for p in physical if p["fiber"]),
            "trunk_count": sum(1 for p in physical if p["vlan_mode"] == "trunk"),
            "neighbor_count": sum(len(p["neighbors"]) for p in physical),
            "readings": _readings(device)}
