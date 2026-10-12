from django.core.validators import MinValueValidator, MaxValueValidator
from django.db import models
from devices.fields import EncryptedPasswordField


INTERVALS = [(n, f"{n} seconds") for n in (2, 5, 10, 15, 30, 60, 120, 300)]


class SNMPProfile(models.Model):
    device = models.OneToOneField("devices.Device", on_delete=models.CASCADE, related_name="snmp_profile")
    community = EncryptedPasswordField()
    port = models.PositiveIntegerField(default=161, validators=[MinValueValidator(1), MaxValueValidator(65535)])
    validated_ip = models.GenericIPAddressField()
    tested_at = models.DateTimeField()
    revision = models.PositiveIntegerField(default=1)


class SensorRuntime(models.Model):
    # A separate release gate. Creating sensors or starting Django never enables it.
    id = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)
    polling_authorized = models.BooleanField(default=False)
    heartbeat = models.DateTimeField(null=True)


class Sensor(models.Model):
    KINDS = [("traffic", "Traffic Sensor"), ("uptime", "Uptime Sensor"), ("cpu", "CPU Sensor")]
    device = models.ForeignKey("devices.Device", on_delete=models.CASCADE, related_name="sensors")
    kind = models.CharField(max_length=10, choices=KINDS)
    name = models.CharField(max_length=120)
    interface_index = models.PositiveIntegerField(default=0)
    interface_name = models.CharField(max_length=255, blank=True)
    interval = models.PositiveIntegerField(default=10, choices=INTERVALS)
    enabled = models.BooleanField(default=False)
    revision = models.PositiveIntegerField(default=1)
    last_attempt = models.DateTimeField(null=True)
    last_success = models.DateTimeField(null=True)
    error = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["pk"]
        constraints = [models.UniqueConstraint(fields=["device", "kind", "interface_index"], name="unique_device_sensor"),
                       models.CheckConstraint(condition=models.Q(interval__in=[n for n, _ in INTERVALS]), name="sensor_interval_supported")]


class SensorSample(models.Model):
    sensor = models.ForeignKey(Sensor, on_delete=models.CASCADE, related_name="samples")
    timestamp = models.DateTimeField(db_index=True)
    valid = models.BooleanField(default=True)
    error = models.CharField(max_length=255, blank=True)
    cpu = models.FloatField(null=True)
    uptime_seconds = models.FloatField(null=True)
    restart_detected = models.BooleanField(default=False)
    interface_status = models.CharField(max_length=16, blank=True)
    # Store exact decimal strings: SQLite NUMERIC affinity rounds large uint64s.
    # Arithmetic uses validated Python integers in the polling baseline.
    in_octets = models.CharField(max_length=20, null=True)
    out_octets = models.CharField(max_length=20, null=True)
    in_mbps = models.FloatField(null=True)
    out_mbps = models.FloatField(null=True)
    counter_reset = models.BooleanField(default=False)

    class Meta:
        ordering = ["timestamp", "pk"]
        indexes = [models.Index(fields=["sensor", "-timestamp"])]
