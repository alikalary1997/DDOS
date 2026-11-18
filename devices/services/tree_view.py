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
    device_count = sum(direct.get(group_id, 0) for group_id in subtree)
    return {
        "group": group, "key": f"g:{group.pk}", "pk": group.pk, "depth": depth,
        "name": group.name,
        "children": [_row(child, depth + 1, children, direct) for child in children.get(group.pk, [])],
        "has_children": bool(children.get(group.pk)),
        # Recursive: everything in this branch, including nested sub-groups.
        "group_count": len(subtree) - 1,
        "device_count": device_count,
        "status": _rollup_status(subtree),
        # Plain-language delete confirmation, so the impact is visible before it is undone.
        "delete_warning": _delete_warning(device_count, len(subtree) - 1),
    }


def device_status(device):
    """One status vocabulary for group rollups, matching the fleet's online/offline rules."""
    tested = device.last_connection_test_succeeded
    if device.last_connection_test is None or tested is None:
        return "unknown"
    if not device.enabled:
        return "offline"
    return "online" if tested else "offline"


def _rollup_status(group_ids):
    """Worst status across a branch, plus a count per status (reference-style badges)."""
    counts = {"online": 0, "offline": 0, "unknown": 0}
    for status in Device.objects.filter(group_id__in=group_ids).values_list(
            "last_connection_test", "last_connection_test_succeeded", "enabled"):
        tested_at, succeeded, enabled = status
        if tested_at is None or succeeded is None:
            counts["unknown"] += 1
        elif not enabled or not succeeded:
            counts["offline"] += 1
        else:
            counts["online"] += 1
    if counts["offline"]:
        tone = "critical"
    elif counts["unknown"]:
        tone = "warning"
    elif counts["online"]:
        tone = "healthy"
    else:
        tone = "empty"
    return {"counts": counts, "tone": tone, "total": sum(counts.values())}


def tree_summary_with_status():
    """KPI figures for the Devices page (reference's four cards)."""
    rows = _device_rows()
    groups = Group.objects.count()
    devices = len(rows)
    return {
        "groups": groups,
        "devices": devices,
        "tagged": sum(1 for row in rows if row["group_key"]),
        "untagged": sum(1 for row in rows if not row["group_key"]),
        "online": sum(1 for row in rows if row["status"] == "online"),
        "high_cpu": sum(1 for row in rows if row["cpu"] is not None and row["cpu"] > 80),
        "unconnected": sum(1 for row in rows if not row["topology_key"]),
    }


def _device_rows():
    """Every device plus the readings from its own SNMP sensors.

    Only sensors that are actually reporting contribute a value: a stopped, stale or failed
    sensor yields None and the table shows an em dash rather than a stale number.
    """
    from sensors.presentation import fleet_snapshot
    from monitor.models import DeviceDDoSProtection

    snapshots = fleet_snapshot()
    protection = dict(DeviceDDoSProtection.objects.values_list("device_id", "enabled"))
    rows = []
    for device in Device.objects.all().order_by("name"):
        sensors = snapshots.get(device.pk, [])

        def sensor_of(kind):
            return next((s for s in sensors if s["kind"] == kind), None)

        def reading(kind, pick):
            """A value only when that sensor is live and its latest sample was valid."""
            sensor = sensor_of(kind)
            if not sensor or not sensor.get("has_reading"):
                return None
            value = pick(sensor)
            return None if value is None else value

        traffic_in = reading("traffic", lambda s: s["in_mbps"])
        traffic_out = reading("traffic", lambda s: s["out_mbps"])
        traffic = (traffic_in + traffic_out) if traffic_in is not None and traffic_out is not None else None
        pppoe_sensor = sensor_of("pppoe")
        status = device_status(device)
        rows.append({
            "id": device.pk,
            "name": device.name,
            "ip": str(device.management_ip),
            "model": device.model or dict(Device.DeviceType.choices).get(device.device_type, ""),
            "group_key": f"g:{device.group_id}" if device.group_id else "",
            "topology_key": f"d:{device.topology_parent_id}" if device.topology_parent_id else "",
            # Readings are None when no fresh sample exists; the table shows an em dash.
            "cpu": reading("cpu", lambda s: s["cpu"]),
            "traffic_mbps": round(traffic, 2) if traffic is not None else None,
            "traffic_in": round(traffic_in, 2) if traffic_in is not None else None,
            "traffic_out": round(traffic_out, 2) if traffic_out is not None else None,
            "traffic_interface": (sensor_of("traffic") or {}).get("interface_name") or "",
            "uptime": reading("uptime", lambda s: s["uptime"]),
            "uptime_seconds": reading("uptime", lambda s: s["uptime_seconds"]),
            "users": reading("pppoe", lambda s: s["pppoe_users"]),
            # A PPPoE sensor that is not reporting is called out rather than hidden, because a
            # missing user count on a PPPoE server usually means the device is busy.
            "users_state": (pppoe_sensor or {}).get("status", "") if pppoe_sensor else "",
            "ping_ms": reading("ping", lambda s: s["ping_ms"]),
            "packet_loss": reading("ping", lambda s: s["packet_loss"]),
            "sensor_count": sum(1 for s in sensors if s["enabled"]),
            "sensor_active": sum(1 for s in sensors if s["status"] == "Active"),
            "status": status,
            "status_label": {"online": "ONLINE", "offline": "OFFLINE", "unknown": "NOT TESTED"}[status],
            # Per-device DDoS Protection flag, toggled from the table.
            "protection": bool(protection.get(device.pk, False)),
        })
    return rows


def _group_options(groups):
    """"Ungrouped" plus every group, for the inline group select on each row."""
    return [{"key": "", "label": "Ungrouped"}] + [
        {"key": f"g:{group.pk}", "label": group.name} for group in groups]


def _topology_options(devices, names):
    """"Not connected" plus every device except this one, matching the reference picker."""
    return [{"key": f"d:{device.pk}", "label": names.get(device.pk, device.name)} for device in devices]


def build_group_page():
    """Data for the reference-style Groups page: sidebar groups, summary and device rows."""
    groups = list(Group.objects.all().order_by("name"))
    devices = _device_rows()
    names = {device.pk: device.name for device in Device.objects.all()}

    # Sidebar entries mirror the reference: All devices, each group, then Ungrouped.
    sidebar = [{"key": "all", "label": "All devices", "counts": _status_counts(devices)}]
    for group in groups:
        tagged = [row for row in devices if row["group_key"] == f"g:{group.pk}"]
        sidebar.append({"key": f"g:{group.pk}", "label": group.name, "counts": _status_counts(tagged)})
    untagged = [row for row in devices if not row["group_key"]]
    sidebar.append({"key": "none", "label": "Ungrouped", "counts": _status_counts(untagged)})

    return {
        "groups": [{"key": f"g:{g.pk}", "name": g.name, "pk": g.pk} for g in groups],
        "devices_json": devices,
        "sidebar_json": sidebar,
        "group_options": _group_options(groups),
        "topology_options": _topology_options(Device.objects.all().order_by("name"), names),
        "tree_summary": tree_summary_with_status(),
    }


def _status_counts(rows):
    """Group health comes from each device's own sensors, not from a connection test."""
    counts = {"ok": 0, "wn": 0, "bad": 0, "idle": 0}
    for row in rows:
        total = row.get("sensor_count") or 0
        active = row.get("sensor_active") or 0
        if not total:
            counts["idle"] += 1
        elif active == total:
            counts["ok"] += 1
        elif active == 0:
            counts["bad"] += 1
        else:
            counts["wn"] += 1
    return counts


def _delete_warning(devices, subgroups):
    parts = []
    if devices:
        parts.append(f"{devices} device{'s' if devices != 1 else ''} will be untagged and kept in inventory")
    if subgroups:
        parts.append(f"{subgroups} nested sub-group{'s' if subgroups != 1 else ''} will be removed")
    if not parts:
        return "This group is empty. It will be removed."
    return "Delete this group? " + "; ".join(parts) + ". No device is deleted. This cannot be undone."


def delete_impact(group):
    """What removing this group would touch, so the UI can warn before it happens.

    Devices are never deleted - they are only untagged, so they stay in inventory as
    "Untagged". Nested sub-groups go with the parent.
    """
    children = _children_map()
    subtree = _subtree_ids(group, children)
    return {
        "devices": Device.objects.filter(group_id__in=subtree).count(),
        "subgroups": len(subtree) - 1,
    }


def delete_group(group):
    """Delete a group and its nested sub-groups, leaving every device in place but untagged.

    `Device.group` is SET_NULL, but the untag is done explicitly first so the behaviour does
    not depend on the FK's on_delete and is guaranteed even for nested sub-groups.
    """
    children = _children_map()
    subtree = _subtree_ids(group, children)
    from django.db import transaction

    with transaction.atomic():
        untagged = Device.objects.filter(group_id__in=subtree).update(group=None)
        deleted, _detail = Group.objects.filter(pk__in=subtree).delete()
    return {"devices": untagged, "groups": len(subtree), "rows": deleted}
