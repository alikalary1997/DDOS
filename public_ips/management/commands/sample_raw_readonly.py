"""Bounded single-assignment diagnostic; no router or database mutations."""
import json
import time

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from devices.services.router_lock import RouterBusy, router_lock
from devices.services.router_session import RouterAccessError, router_session
from monitor.services.raw_settings import polling_interval
from public_ips.models import PublicIP
from public_ips.services.monitoring import RateCalculator
from public_ips.services.rules import RuleConflict, expected_rules, rule_id, validate_rules


class Command(BaseCommand):
    help = "Read a bounded number of real RAW counter samples for one saved public IP."

    def add_arguments(self, parser):
        parser.add_argument("address")
        parser.add_argument("--samples", type=int, default=3)

    def emit(self, value):
        self.stdout.write(json.dumps(value))
        self.stdout.flush()

    def handle(self, *args, **options):
        count = options["samples"]
        if not 1 <= count <= 24:
            raise CommandError("Use between 1 and 24 samples.")
        ip = PublicIP.objects.select_related("device").filter(address=options["address"]).first()
        if ip is None or ip.device is None:
            raise CommandError("This public IP is not assigned to a saved device.")
        device = ip.device
        specifications = expected_rules(ip.address, ip.incoming_monitoring_interface)
        calculator = RateCalculator()
        previous_at = None
        try:
            with router_lock(device.pk), router_session(device) as api:
                raw = api.get_resource("/ip/firewall/raw")
                self.emit({"event": "connected", "device": device.name, "device_id": device.pk,
                           "management_ip": device.management_ip, "api_port": device.api_port,
                           "ssl": device.use_ssl, "public_ip": ip.address,
                           "interface": ip.incoming_monitoring_interface,
                           "device_interface": device.incoming_monitoring_interface,
                           "polling_interval": polling_interval(), "samples": count})
                for index in range(count):
                    rows = raw.get()
                    found = validate_rules(rows, specifications)
                    if len(found) != 3:
                        raise RuleConflict("Missing monitoring rules: " + ", ".join(
                            spec["comment"] for spec in specifications if spec["comment"] not in found))
                    if any("packets" not in row or "bytes" not in row for row in rows):
                        stats = raw.call("print", {"stats": ""})
                        ids = [rule_id(row) for row in stats]
                        if len(ids) != len(set(ids)):
                            raise RuleConflict("Duplicate RAW counter identifiers.")
                        by_id = {rule_id(row): row for row in stats}
                        rows = [dict(row, **{key: by_id.get(rule_id(row), {}).get(key)
                                           for key in ("packets", "bytes")}) for row in rows]
                    at = time.monotonic()
                    timestamp = timezone.now().isoformat()
                    counters = []
                    for spec in specifications:
                        identifier = found[spec["comment"]]
                        row = next(row for row in rows if rule_id(row) == identifier)
                        packets, byte_count, pps, bps = calculator.rates(
                            device.pk, identifier, row, at, tuple(sorted(spec.items())))
                        counters.append({"comment": spec["comment"], "rule_id": identifier,
                                         "packets": packets, "bytes": byte_count, "pps": pps,
                                         "mbps": bps / 1000000 if bps is not None else None,
                                         "status": "valid" if pps is not None else
                                         "baseline" if index == 0 and packets is not None and byte_count is not None
                                         else "invalid_or_rebaseline"})
                    self.emit({"event": "sample", "sample": index + 1, "timestamp": timestamp,
                               "elapsed_seconds": at - previous_at if previous_at is not None else None,
                               "polling_interval": polling_interval(), "rules": counters,
                               "rule_order": [row.get("comment", "") for row in rows
                                              if row.get("comment") in found]})
                    previous_at = at
                    if index + 1 < count:
                        while True:
                            remaining = polling_interval() - (time.monotonic() - at)
                            if remaining <= 0:
                                break
                            time.sleep(min(1, remaining))
        except (RouterAccessError, RouterBusy, RuleConflict) as error:
            self.emit({"event": "error", "timestamp": timezone.now().isoformat(),
                       "code": getattr(error, "code", type(error).__name__), "message": str(error)})
            raise CommandError("Read-only sampling stopped; no rules or counters were changed.") from None
        self.emit({"event": "complete", "samples": count})
