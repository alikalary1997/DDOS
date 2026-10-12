"""Explicit read-only preflight. This command cannot enable or write RAW rules."""
import ipaddress

from django.core.exceptions import ImproperlyConfigured
from django.core.management.base import BaseCommand, CommandError

from devices.models import Device
from devices.services.credentials import CredentialError
from devices.services.router_lock import RouterBusy, router_lock
from devices.services.router_session import RouterAccessError, router_session
from public_ips.services.preflight import inspect_rules
from public_ips.services.rules import RuleConflict
from public_ips.models import PublicIP
from public_ips.services.diagnostics import diagnostic_scope, event, encryption_key_status


class Command(BaseCommand):
    help = "Read-only: check saved credentials, API connection, incoming interface and RAW rules."

    def add_arguments(self, parser):
        parser.add_argument("device_id", type=int)
        parser.add_argument("public_ip", help="Public IPv4 address planned for provisioning")

    def handle(self, *args, **options):
        record_id = PublicIP.objects.filter(device_id=options["device_id"], address=options["public_ip"]).values_list("pk", flat=True).first()
        with diagnostic_scope(record_id, options["device_id"]):
            return self.run_preflight(*args, **options)

    def run_preflight(self, *args, **options):
        try:
            address = str(ipaddress.IPv4Address(options["public_ip"]))
            device = Device.objects.get(pk=options["device_id"])
            record = PublicIP.objects.filter(device=device, address=address).first()
            interface = record.incoming_monitoring_interface if record else device.incoming_monitoring_interface
            # Authenticate the encrypted token before contacting the router.
            available, valid = encryption_key_status()
            event("read_only_preflight", public_ip_id=record.pk if record else None, result="attempt", key_available=available, key_valid=valid)
            event("password_decryption", result="attempt")
            device.get_password()
            event("password_decryption", result="success")
            with diagnostic_scope(record.pk if record else None, device.pk):
                with router_lock(device.pk), router_session(device) as api:
                    _, specifications, found = inspect_rules(api, device, address, interface)
        except (ValueError, Device.DoesNotExist):
            raise CommandError("Select an existing device and a valid IPv4 address.") from None
        except (CredentialError, ImproperlyConfigured):
            event("read_only_preflight", result="credentials_unavailable")
            raise CommandError("Encryption key unavailable or saved credentials cannot be decrypted.") from None
        except (RouterAccessError, RuleConflict, RouterBusy) as error:
            event("read_only_preflight", result=error.code if isinstance(error, RouterAccessError) else "rule_conflict")
            raise CommandError(str(error)) from None
        except Exception:
            event("read_only_preflight", result="failed")
            raise CommandError("Read-only preflight failed; no RAW writes were attempted.") from None
        self.stdout.write("PASS: encryption key and saved credentials, API connection, incoming interface, and RAW conflict/placement checks.")
        event("read_only_preflight", result="success", count=len(found))
        self.stdout.write(f"Correct existing rules: {len(found)}; missing rules: {len(specifications) - len(found)}.")
        self.stdout.write("No rules changed. Real-router writes remain gated pending explicit authorization.")
