"""Explicit credential-free inventory and connection-result presentation."""
INVENTORY_FIELDS = (
    "id", "name", "management_ip", "device_type", "model", "enabled", "api_port", "use_ssl", "description",
    "incoming_monitoring_interface", "router_identity", "routeros_version", "uptime", "cpu_usage", "total_memory", "free_memory",
    "last_connection_test", "last_connection_test_succeeded", "last_successful_connection", "last_connection_error",
    "raw_provisioning_enabled", "raw_provisioning_authorized_at", "raw_preflight_message", "raw_preflight_at",
)


def present_device(row):
    row = dict(row)
    succeeded = row["last_connection_test_succeeded"]
    if row["last_connection_test"] is None or succeeded is None:
        status, code = "Not Tested", "not_tested"
    else:
        status, code = ("Online", "online") if succeeded else ("Offline", "offline")
    row["status"] = status
    row["test_label"] = {"online": "Last Test Successful", "offline": "Last Test Failed", "not_tested": "Not Tested"}[code]
    row["raw_status"] = ("Enabled" if row["enabled"] and "changed" not in row.get("raw_preflight_message", "").lower() else "Needs Revalidation") if row["raw_provisioning_enabled"] else (
        "Needs Revalidation" if "changed" in row.get("raw_preflight_message", "").lower() else "Disabled")
    row["connection_status"] = code
    row["status_filter"] = code if row["enabled"] else "disabled"
    row["tested_at"] = row["last_connection_test"].isoformat() if row["last_connection_test"] else ""
    row["cpu_display"] = str(row["cpu_usage"]) + "%" if row["cpu_usage"] is not None and succeeded else "Not available"
    total, free = row["total_memory"], row["free_memory"]
    used = total - free if succeeded and total is not None and free is not None and 0 <= free <= total else None
    row["used_memory"] = used
    row["ram_display"] = f"{used / 1048576:.1f} / {total / 1048576:.1f} MiB" if used is not None else "Not available"
    row["ram_usage_percent"] = round(used / total * 100, 1) if used is not None and total else None
    row["status_note"] = "Result of the last test; current reachability is not monitored."
    return row
