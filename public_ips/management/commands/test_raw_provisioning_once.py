"""Preview by default; add-only, record-scoped test after explicit code approval."""
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.core.management.base import BaseCommand, CommandError
from devices.models import Device
from public_ips.models import PublicIP
from public_ips.services.controlled_test import controlled_test_scope
from public_ips.services.provisioning import provision_public_ip, writes_enabled
from public_ips.services.rules import RuleConflict, expected_rules


class Command(BaseCommand):
    help = "Preview one saved RAW assignment. --apply is blocked until the first live test is explicitly released."

    def add_arguments(self, parser):
        parser.add_argument("public_ip_id", type=int)
        parser.add_argument("--apply", action="store_true")
        parser.add_argument("--actor-id", type=int)
        parser.add_argument("--confirm-device-id", type=int)
        parser.add_argument("--confirm-address")
        parser.add_argument("--confirm-interface")

    def handle(self, *args, **options):
        try:
            public_ip = PublicIP.objects.get(pk=options["public_ip_id"])
            device = Device.objects.get(pk=public_ip.device_id)
            specifications = expected_rules(public_ip.address, public_ip.incoming_monitoring_interface)
        except (PublicIP.DoesNotExist, Device.DoesNotExist):
            raise CommandError("Select a saved Public IP assigned to a saved MikroTik device.") from None
        except RuleConflict as error:
            raise CommandError(str(error)) from None
        self.stdout.write(f"Public IP record {public_ip.pk}: {public_ip.address}; device {device.pk}: {device.name}; interface: {public_ip.incoming_monitoring_interface}.")
        for specification in specifications:
            self.stdout.write(str(specification))
        if not options["apply"]:
            self.stdout.write("Preview only: no router connection, database change or rule write.")
            return
        if writes_enabled():
            raise CommandError("Disable global provisioning before a controlled first live test.")
        if (options["confirm_device_id"], options["confirm_address"], options["confirm_interface"]) != (
            device.pk, public_ip.address, public_ip.incoming_monitoring_interface):
            raise CommandError("Confirm the exact device ID, saved public IP and saved interface.")
        try:
            actor = get_user_model().objects.get(pk=options["actor_id"])
        except get_user_model().DoesNotExist:
            raise CommandError("Select an existing administrator actor ID.") from None
        try:
            with controlled_test_scope(public_ip, actor):
                result = provision_public_ip(public_ip.pk, actor)
        except PermissionDenied as error:
            raise CommandError(str(error)) from None
        if not result.success:
            raise CommandError(result.message)
        self.stdout.write(result.message)
        self.stdout.write(f"Created {len(result.created)} rules; verified {len(result.verified)} rules. One-operation scope closed; global writes remain disabled.")
