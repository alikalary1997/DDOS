from django.core.management.base import BaseCommand
from django.db.models import F
from sensors.models import Sensor, SensorRuntime


class Command(BaseCommand):
    help = 'Explicitly authorize or disable SNMP polling; does not launch any worker.'

    def add_arguments(self, parser):
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument('--approve', action='store_true')
        group.add_argument('--disable', action='store_true')

    def handle(self, *args, **options):
        approved = options['approve']
        SensorRuntime.objects.update_or_create(pk=1, defaults={'polling_authorized': approved})
        if not approved:
            Sensor.objects.update(enabled=False, revision=F('revision') + 1)
        self.stdout.write('SNMP polling authorized; sensors still require Start.' if approved else 'SNMP polling disabled; all sensors stopped.')
