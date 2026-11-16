"""Read-only projection of the device topology chain (device -> device only).

The chain is whatever depth the network actually has: a Cisco core at the top, MikroTik
"Limit" devices under it, PPPoE servers under those, and towers either under a PPPoE
server or straight under a Limit. Nothing here assumes a fixed number of levels.

This is independent of Groups: a device's Group tag has no effect on this tree.
"""
from devices.models import Device


def _children_map():
    children = {}
    for device in Device.objects.all():
        if device.topology_parent_id is not None:
            children.setdefault(device.topology_parent_id, []).append(device)
    for items in children.values():
        items.sort(key=lambda device: (device.name.lower(), device.pk))
    return children


def build_topology():
    """Top-level chain rows, each with nested `children` (recursive to any depth)."""
    children = _children_map()
    roots = [device for device in Device.objects.all() if device.topology_parent_id is None]
    roots.sort(key=lambda device: (device.name.lower(), device.pk))
    return [_row(device, 0, children, frozenset()) for device in roots]


def _row(device, depth, children, seen):
    seen = seen | {device.pk}
    nested = [_row(child, depth + 1, children, seen)
              for child in children.get(device.pk, []) if child.pk not in seen]
    return {
        "device": device, "key": f"d:{device.pk}", "pk": device.pk, "depth": depth,
        "name": device.name, "ip": str(device.management_ip),
        "group_name": device.group.name if device.group_id else "",
        "children": nested, "has_children": bool(children.get(device.pk)),
    }


def topology_summary():
    """Devices in the chain and the deepest level actually in use."""
    rows = list(Device.objects.values("id", "topology_parent_id"))
    levels = {row["id"]: row["topology_parent_id"] for row in rows}
    deepest = 0
    for device_id in levels:
        depth, seen, current = 1, {device_id}, levels.get(device_id)
        while current is not None and current not in seen:
            seen.add(current)
            depth += 1
            current = levels.get(current)
        deepest = max(deepest, depth)
    return {"devices": len(rows), "depth": deepest}


def topology_path(device_id):
    """Ancestors of a device, outermost first (used for readable labels)."""
    path, seen, current = [], set(), device_id
    while current is not None and current not in seen:
        seen.add(current)
        device = Device.objects.filter(pk=current).only("id", "name", "topology_parent_id").first()
        if device is None:
            break
        path.append(device)
        current = device.topology_parent_id
    return list(reversed(path))
