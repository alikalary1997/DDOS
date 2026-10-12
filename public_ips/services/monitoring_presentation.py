"""Present validated cache samples without contacting a router."""
import math


def traffic_fields(sample, address):
    def number(value):
        return value if (isinstance(value, (int, float)) and not isinstance(value, bool)
                         and math.isfinite(value) and value >= 0) else None

    active = sample.get("status") == "Monitoring" or sample.get("retained") is True
    fields = {key: number(sample.get(key)) if active else None
              for key in ("packets", "bytes", "pps", "mbps")}
    fields["last_update"] = sample.get("last_update") if active else None
    fields["retained"] = sample.get("retained") is True
    protocols = sample.get("protocol_rules", [])
    if not isinstance(protocols, list):
        protocols = []
    for key, prefix in (("syn_pps", "MONITOR-SYN-"), ("udp_pps", "MONITOR-UDP-")):
        matches = [row for row in protocols if isinstance(row, dict) and row.get("name") == prefix + address]
        fields[key] = number(matches[0].get("pps")) if active and len(matches) == 1 else None
        fields[key.replace("pps", "packets")] = number(matches[0].get("packets")) if active and len(matches) == 1 else None
    history = sample.get("last_traffic")
    fields["last_traffic"] = traffic_fields(history, address) if isinstance(history, dict) else None
    return fields
