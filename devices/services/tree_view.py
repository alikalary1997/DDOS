"""Read-only projection of the Groups tree (groups nested under groups only).

A device's Group is a pure label/filter tag and never has topology meaning. Device
topology lives in devices/services/topology.py and is entirely separate.
"""
from devices.models import Device, Group


def _children_map():
    children = {}
    for group in Group.objects.all():
        if group.parent_id is not None:
            children.setdefault(group.parent_id, []).append(group)
    for items in children.values():
        items.sort(key=lambda group: (group.name.lower(), group.pk))
    return children


def _direct_device_counts():
    """Devices tagged directly into each group id."""
    counts = {}
    for group_id in Device.objects.exclude(group=None).values_list("group_id", flat=True):
        counts[group_id] = counts.get(group_id, 0) + 1
    return counts


def _subtree_ids(group, children):
    """This group plus every nested sub-group, at any depth (cycle-safe)."""
    ids, seen, stack = [group.pk], {group.pk}, list(children.get(group.pk, []))
    while stack:
        child = stack.pop()
        if child.pk in seen:
            continue
        seen.add(child.pk)
        ids.append(child.pk)
        stack.extend(children.get(child.pk, []))
    return ids


def build_tree():
    """Top-level group rows, each with nested `children` (recursive to any depth)."""
    children = _children_map()
    direct = _direct_device_counts()
    roots = [group for group in Group.objects.all() if group.parent_id is None]
    roots.sort(key=lambda group: (group.name.lower(), group.pk))
    return [_row(group, 0, children, direct) for group in roots]


def _row(group, depth, children, direct):
    subtree = _subtree_ids(group, children)
    return {
        "group": group, "key": f"g:{group.pk}", "pk": group.pk, "depth": depth,
        "name": group.name,
        "children": [_row(child, depth + 1, children, direct) for child in children.get(group.pk, [])],
        "has_children": bool(children.get(group.pk)),
        # Recursive: everything in this branch, including nested sub-groups.
        "group_count": len(subtree) - 1,
        "device_count": sum(direct.get(group_id, 0) for group_id in subtree),
    }
