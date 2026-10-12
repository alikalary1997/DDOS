"""Retain real snapshots without representing historic rates as current traffic."""
from copy import deepcopy
from public_ips.models import FirewallSample


def snapshot(row):
    return deepcopy({key: value for key, value in row.items()
                     if key not in ("last_successful", "last_traffic", "retained")})


def same_profile(left, right):
    return all(left.get(key) == right.get(key) for key in ("id", "device_id", "address", "profile_version"))


def retain(device_id, rows):
    previous = FirewallSample.objects.filter(device_id=device_id).first()
    old = {row.get("id"): row for row in previous.rows if isinstance(row, dict)} if previous else {}
    for row in rows:
        prior = old.get(row["id"], {})
        if same_profile(prior, row):
            for key in ("last_successful", "last_traffic"):
                if prior.get(key):
                    row[key] = prior[key]
            if "last_successful" not in row and prior.get("status") == "Monitoring":
                row["last_successful"] = snapshot(prior)
        if row.get("status") == "Monitoring":
            row["last_successful"] = snapshot(row)
            rates = [row.get("pps"), row.get("bps")] + [p.get("pps") for p in row.get("protocol_rules", [])]
            if any(isinstance(value, (int, float)) and value > 0 for value in rates):
                row["last_traffic"] = snapshot(row)
    # A different selected IP on the same device must not erase its siblings' history.
    selected = {row["id"] for row in rows}
    return rows + [row for identifier, row in old.items() if identifier not in selected]
