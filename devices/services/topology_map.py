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
    return {
        "cpu": cpu.cpu if cpu else None,
        "bandwidth_in": traffic.in_mbps if traffic else None,
        "bandwidth_out": traffic.out_mbps if traffic else None,
        "bandwidth_interface": (traffic.interface_status or "") if traffic else "",
        "uptime": format_uptime(uptime.uptime_seconds) if uptime else None,
        "uptime_seconds": uptime.uptime_seconds if uptime else None,
        "users": pppoe.pppoe_users if pppoe else None,
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
        return ("Site", mbps, "Mbps", " · ".join(parts))
    return ("Site", None, "", "No data")


# Canvas geometry: four fixed stages stacked vertically. Each stage is a full-width band of
# cards flowing left to right, and connectors drop from the bottom edge of a parent card to the
# top edge of its children's cards. Cards are wide-but-short so a name and its stat share a row.
NODE_WIDTH = 260
NODE_HEIGHT = 62
NODE_GAP = 18              # horizontal distance between cards in the same row
ROW_HEIGHT = 78            # vertical pitch inside a stage
STAGE_HEADER = 26          # stage title band above its first row
STAGE_GAP = 40             # breathing room between two stages, also where connectors run
CANVAS_WIDTH = 900
CANVAS_PADDING = 12


def _assign_columns(ordered, children_of):
    """Column index per device inside its stage, with each parent centred on its children.

    Leaves are numbered first, left to right, so a stage stays compact. Parents are then
    placed at the midpoint of their children's columns, which keeps every fan-out symmetrical
    regardless of how many devices a stage holds. Same rule as the horizontal version's rows,
    just applied along the other axis.
    """
    columns = {}
    cursor = 0

    # Pass 1: leaves take successive columns in document order.
    for node in ordered:
        kids = [child for child in children_of.get(node.device.pk, []) if child.device.pk != node.device.pk]
        if not kids:
            columns[node.device.pk] = cursor
            cursor += 1

    # Pass 2: resolve parents deepest-first so a child's column is always known.
    def resolve(node, seen):
        if node.device.pk in columns:
            return columns[node.device.pk]
        kids = [child for child in children_of.get(node.device.pk, [])
                if child.device.pk not in seen and child.device.pk != node.device.pk]
        if not kids:
            columns[node.device.pk] = cursor
            return columns[node.device.pk]
        placed = [resolve(child, seen | {child.device.pk}) for child in kids]
        columns[node.device.pk] = (min(placed) + max(placed)) / 2
        return columns[node.device.pk]

    for node in ordered:
        resolve(node, frozenset({node.device.pk}))
    return columns


def _stage_layout(ordered, columns, children_of):
    """Vertical band per stage: top y, its row count, and each card's rank inside the band.

    Cards fill a stage left to right and wrap onto a new row only when they no longer fit across
    the canvas, so a branch with a dozen towers grows the TOWERS band instead of shrinking every
    card. An empty stage keeps its header and a little breathing room.
    """
    layout = {}
    y = CANVAS_PADDING
    for key, _label in LEVELS:
        members = [node for node in ordered if node.level == key]
        per_row = max(1, (CANVAS_WIDTH - CANVAS_PADDING * 2 + NODE_GAP) // (NODE_WIDTH + NODE_GAP))
        rows_needed = max(1, -(-len(members) // per_row)) if members else 0
        layout[key] = {
            "top": y, "per_row": per_row,
            "height": STAGE_HEADER + rows_needed * ROW_HEIGHT,
            "rows": rows_needed,
            "count": len(members),
            # Rank each card left to right inside its stage; that rank is what decides its
            # column, so two cards can never be rounded onto the same slot.
            "rank": {
                node.device.pk: rank
                for rank, node in enumerate(sorted(members, key=lambda n: columns[n.device.pk]))
            },
        }
        y += STAGE_HEADER + rows_needed * ROW_HEIGHT + STAGE_GAP
    return layout, y - STAGE_GAP + CANVAS_PADDING


def _device_state(device):
    tested = device.last_connection_test_succeeded
    if device.last_connection_test is None or tested is None:
        return "not-tested"
    if not device.enabled:
        return "offline"
    return "online" if tested else "offline"


def build_map():
    """Nodes laid out in four columns plus the connector curves between them."""
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
    columns = _assign_columns(ordered, children_of)
    stage, canvas_height = _stage_layout(ordered, columns, children_of)

    nodes = []
    for node in ordered:
        subtree = descendants[node.device.pk]
        label, value, unit, note = _stats(node, subtree)
        site_group = 1 + sum(1 for n in subtree if n.level == "tower")
        band = stage[node.level]
        rank = band["rank"][node.device.pk]
        # Centre the whole stage when it fits on a single row.
        padding = 0
        if band["rows"] == 1:
            room = CANVAS_WIDTH - CANVAS_PADDING * 2
            used_width = band["count"] * NODE_WIDTH + (band["count"] - 1) * NODE_GAP
            padding = max(0, (room - used_width) // 2)
        col = rank % band["per_row"]
        row = rank // band["per_row"]
        nodes.append({
            "key": node.device.pk, "name": node.device.name,
            "ip": str(node.device.management_ip), "state": _device_state(node.device),
            "level": node.level, "label": label, "value": value, "unit": unit, "note": note,
            "x": CANVAS_PADDING + padding + col * (NODE_WIDTH + NODE_GAP),
            "y": round(band["top"] + STAGE_HEADER + row * ROW_HEIGHT),
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
            # Downward flow: out of the parent's bottom edge, into the child's top edge.
            links.append({
                "id": f"{node.device.pk}-{child.device.pk}",
                "from": node.device.pk, "to": child.device.pk,
                "x1": parent_node["x"] + NODE_WIDTH / 2, "y1": parent_node["y"] + NODE_HEIGHT,
                "x2": child_node["x"] + NODE_WIDTH / 2, "y2": child_node["y"],
            })

    return {
        "nodes": nodes, "links": links, "height": canvas_height,
        "width": CANVAS_WIDTH, "node_width": NODE_WIDTH, "node_height": NODE_HEIGHT,
        "columns": [
            {"key": key, "label": label,
             "x": CANVAS_PADDING, "y": stage[key]["top"] + 15,
             "count": stage[key]["count"]}
            for key, label in LEVELS
        ],
        "total": len(ordered), "core_count": sum(1 for node in nodes if node["level"] == "core"),
    }


def _summary(node, value, unit):
    """One short line under the node name, as in the reference cards."""
    if value is None:
        return "No data"
    return f"{value} {unit}".strip()
