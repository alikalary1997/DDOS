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


def _level_key(depth, device=None):
    """Column for a device: depth decides Core and Limit; deeper nodes are PPPoE or Tower.

    Depth alone cannot separate the two deeper columns, because a tower hung straight off a
    Limit also sits at depth 2. The device's own PPPoE evidence decides: anything that has a
    PPPoE sensor (or a stored session count) is a PPPoE server, otherwise it is a tower.
    """
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
    return timedelta(seconds=max(30, sensor.interval * 3))


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


# Card geometry, mirrored in CSS (.topo-card) so SVG lines meet the real boxes.
CARD_HEIGHT = 84
GAP = 26
TOP = 34


def build_map():
    """Columns of cards plus the connector paths between parent and child cards."""
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

    columns = {key: [] for key, _label in LEVELS}
    for node in ordered:
        columns[node.level].append(node)

    # Rows are assigned per column; the tallest column sets the canvas height.
    positions = {}
    for key, items in columns.items():
        for index, node in enumerate(items):
            positions[node.device.pk] = (key, index)

    tallest = max((len(items) for items in columns.values()), default=0)
    height = TOP + tallest * (CARD_HEIGHT + GAP) + GAP

    rendered = {}
    for key, items in columns.items():
        rendered[key] = []
        for index, node in enumerate(items):
            subtree = descendants[node.device.pk]
            label, value, unit, note = _stats(node, subtree)
            tested = node.device.last_connection_test_succeeded
            if node.device.last_connection_test is None or tested is None:
                state = "not-tested"
            elif not node.device.enabled:
                state = "offline"
            else:
                state = "online" if tested else "offline"
            site_group = 1 + sum(1 for n in subtree if n.level == "tower")
            rendered[key].append({
                "key": node.device.pk, "name": node.device.name,
                "ip": str(node.device.management_ip), "state": state,
                "label": label, "value": value, "unit": unit, "note": note,
                "column": list(columns).index(key), "row": index,
                "site_count": site_group if node.level == "tower" and site_group > 1 else 0,
            })

    # Connector: parent's right edge -> child's left edge, drawn as a cubic curve.
    links = []
    for node in ordered:
        for child in node.children:
            if child.device.pk not in positions or node.device.pk not in positions:
                continue
            parent_column, parent_row = positions[node.device.pk]
            child_column, child_row = positions[child.device.pk]
            # Trace the straight row each card sits on across its column slot.
            links.append({
                "id": f"{node.device.pk}-{child.device.pk}",
                "from_column": list(columns).index(parent_column),
                "to_column": list(columns).index(child_column),
                "from_index": round(TOP + parent_row * (CARD_HEIGHT + GAP) + CARD_HEIGHT / 2),
                "to_index": round(TOP + child_row * (CARD_HEIGHT + GAP) + CARD_HEIGHT / 2),
            })

    return {
        "columns": [{"key": key, "label": label, "cards": rendered[key]} for key, label in LEVELS],
        "links": links, "height": height, "card_height": CARD_HEIGHT,
        "total": len(ordered), "core_count": len(columns["core"]),
    }
