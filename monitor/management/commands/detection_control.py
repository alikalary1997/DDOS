"""Server-wide passive detection switch. This command never starts polling."""
from django.core.management.base import BaseCommand
from django.db import transaction
from monitor.models import DetectionPolicy, DetectionState


class Command(BaseCommand):
    help = "Enable or disable passive detection globally. No router access."

    def add_arguments(self, parser):
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("--enable", action="store_true")
        group.add_argument("--disable", action="store_true")
    @transaction.atomic
    def handle(self, *args, **options):
        policy, _ = DetectionPolicy.objects.select_for_update().get_or_create(pk=1)
        policy.enabled = bool(options["enable"])
        policy.save()
        DetectionState.objects.update(warning_count=0, attack_count=0, warning_recovery_count=0,
                                      attack_recovery_count=0, last_valid_at=None, pending_since=None, pending_peaks={})
        self.stdout.write("Passive detection enabled globally; per-IP opt-outs are preserved. Polling was not started." if policy.enabled else
                          "Detection disabled. Incident history retained; polling was not changed.")
