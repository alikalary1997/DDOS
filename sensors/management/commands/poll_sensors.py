import time
from django.core.management.base import BaseCommand, CommandError
from sensors.locking import worker_lock, WorkerBusy
from sensors.models import SensorRuntime
from sensors.polling import Poller, authorized


class Command(BaseCommand):
    help = 'Read-only SNMP sensor worker. Requires the separate sensor polling authorization gate.'

    def handle(self, *args, **options):
        if not authorized():
            raise CommandError('SNMP polling is not authorized. No connections attempted.')
        try:
            with worker_lock():
                try:
                    self.stdout.write('SNMP sensor worker running. Ctrl+C stops it safely.')
                    poller = Poller()
                    while poller.cycle():
                        time.sleep(0.5)
                except KeyboardInterrupt:
                    self.stdout.write('Stopping SNMP sensor worker.')
                finally:
                    SensorRuntime.objects.filter(pk=1).update(heartbeat=None)
        except WorkerBusy as error:
            raise CommandError(str(error)) from None
        self.stdout.write('SNMP sensor worker stopped.')
