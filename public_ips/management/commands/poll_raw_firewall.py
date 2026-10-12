"""Single process poller; release gate remains disabled pending approval."""
import time
from django.core.management.base import BaseCommand, CommandError
from django.db import close_old_connections
from django.utils import timezone

from devices.services.router_lock import RouterBusy, router_lock
from public_ips.services.monitoring_scope import MonitoringScope, MonitoringScopeError
from public_ips.services.monitoring import RateCalculator, poll_device, polling_enabled
from monitor.services.raw_settings import polling_interval


def wait_for_next_cycle(started, deadline=None, managed_token=None):
    """Re-read DB while idle; never cancel an API read or launch a parallel cycle."""
    while polling_enabled():
        if managed_token:
            from public_ips.services.monitoring_runtime import requested
            if not requested(managed_token):
                return
        if deadline is not None and time.monotonic() >= deadline:
            return
        remaining = polling_interval() - (time.monotonic() - started)
        if remaining <= 0:
            return
        time.sleep(min(1.0, remaining))


class Command(BaseCommand):
    help = "Poll one explicitly scoped assignment; never creates or changes RAW rules."

    def add_arguments(self, parser):
        parser.add_argument("--device-id", type=int, required=True)
        parser.add_argument("--assignment-id", type=int, required=True)
        parser.add_argument("--public-ip", required=True)
        parser.add_argument("--duration-seconds", type=int, default=None,
                            help="Stop automatically after this many seconds; omit only for approved continuous operation.")
        parser.add_argument("--managed-token", default=None, help="Internal app worker generation.")

    def handle(self, *args, **options):
        from public_ips.services.monitoring_runtime import requested, heartbeat, finish
        from public_ips.models import MonitoringRun
        token = options.get("managed_token")
        if token:
            from uuid import UUID
            try:
                token = UUID(token)
            except ValueError:
                raise CommandError("Invalid worker generation.") from None
            if not MonitoringRun.objects.filter(pk=1, token=token, active=True,
                device_id_snapshot=options["device_id"], assignment_id_snapshot=options["assignment_id"],
                address=options["public_ip"]).exists():
                raise CommandError("Worker scope does not match the requested app target.")
        elif MonitoringRun.objects.filter(pk=1, active=True).exists():
            raise CommandError("Monitoring is controlled by the application. Stop it there first.")
        if not polling_enabled():
            raise CommandError("RAW polling is disabled pending approval.")
        calculator = RateCalculator()
        duration = options.get("duration_seconds")
        if duration is not None and duration <= 0:
            raise CommandError("Duration must be a positive number of seconds.")
        try:
            scope = MonitoringScope(options["device_id"], options["assignment_id"], options["public_ip"])
            # Singleton across all worker processes on the same NetShield host.
            with router_lock(0):
                scope.validate()
                deadline = time.monotonic() + duration if duration is not None else None
                self.stdout.write(f"Scoped RAW monitoring: device {scope.device_id}, assignment {scope.assignment_id}, IP {scope.address}.")
                while polling_enabled():
                    if token:
                        if not requested(token):
                            break
                        heartbeat(token)
                    if deadline is not None and time.monotonic() >= deadline:
                        self.stdout.write("RAW polling stopped: duration limit reached.")
                        break
                    started = time.monotonic()
                    close_old_connections()
                    scope.validate()
                    poll_device(scope.device_id, calculator, scope=scope)
                    if token:
                        heartbeat(token)
                        wait_for_next_cycle(started, deadline=deadline, managed_token=token)
                    elif deadline is None:
                        wait_for_next_cycle(started)
                    else:
                        wait_for_next_cycle(started, deadline=deadline)
        except MonitoringScopeError as error:
            if token and not requested(token):
                self.stdout.write("RAW polling stopped from the application.")
                return
            if token:
                finish(token, str(error))
            raise CommandError(str(error)) from None
        except RouterBusy:
            if token:
                finish(token, "Another worker is already running.")
            raise CommandError("A RAW polling worker is already running.") from None
        except KeyboardInterrupt:
            self.stdout.write("RAW polling stopped.")

        except Exception:
            if token:
                finish(token, "Monitoring stopped because a safe sample could not be completed.")
            raise CommandError("RAW polling stopped because a safe sample could not be completed.") from None
        finally:
            if token:
                MonitoringRun.objects.filter(pk=1, token=token, active=True).update(
                    active=False, stopped_at=timezone.now())
