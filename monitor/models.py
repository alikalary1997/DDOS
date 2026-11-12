from django.db import models
from django.core.exceptions import ValidationError
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone

POLLING_INTERVALS = (2, 5, 10, 15, 30, 60)
DEFAULT_POLLING_INTERVAL = 5

DETECTION_METRICS = (("total_pps", "Total PPS"), ("bandwidth_mbps", "Bandwidth (Mbps)"),
                     ("syn_pps", "TCP SYN PPS"), ("udp_pps", "UDP PPS"))

# RAW-sample metrics. CPU is evaluated separately: it comes from the device's CPU sensor.
CPU_METRIC = ("cpu", "CPU (%)")
# Every threshold row, in display order, used by both settings forms and the engine.
THRESHOLD_METRICS = DETECTION_METRICS + (CPU_METRIC,)


class DDoSDetectionSettings(models.Model):
    """Persistent thresholds; evaluated only when detection is explicitly enabled."""
    id = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)
    total_pps_warning = models.DecimalField(max_digits=15, decimal_places=3, default=10000, validators=[MinValueValidator(0)])
    total_pps_attack = models.DecimalField(max_digits=15, decimal_places=3, default=50000, validators=[MinValueValidator(0)])
    bandwidth_mbps_warning = models.DecimalField(max_digits=15, decimal_places=3, default=100, validators=[MinValueValidator(0)])
    bandwidth_mbps_attack = models.DecimalField(max_digits=15, decimal_places=3, default=500, validators=[MinValueValidator(0)])
    syn_pps_warning = models.DecimalField(max_digits=15, decimal_places=3, default=2000, validators=[MinValueValidator(0)])
    syn_pps_attack = models.DecimalField(max_digits=15, decimal_places=3, default=10000, validators=[MinValueValidator(0)])
    udp_pps_warning = models.DecimalField(max_digits=15, decimal_places=3, default=5000, validators=[MinValueValidator(0)])
    udp_pps_attack = models.DecimalField(max_digits=15, decimal_places=3, default=20000, validators=[MinValueValidator(0)])
    cpu_warning = models.DecimalField(max_digits=6, decimal_places=3, default=70, validators=[MinValueValidator(0), MaxValueValidator(100)])
    cpu_attack = models.DecimalField(max_digits=6, decimal_places=3, default=90, validators=[MinValueValidator(0), MaxValueValidator(100)])
    updated_at = models.DateTimeField(auto_now=True)

    def clean(self):
        super().clean()
        errors = {}
        for metric, label in THRESHOLD_METRICS:
            warning, attack = getattr(self, metric + "_warning"), getattr(self, metric + "_attack")
            # Field validation reports malformed and nonfinite values separately.
            try:
                if warning is not None and attack is not None and attack <= warning:
                    errors[metric + "_attack"] = f"{label}: Attack must be greater than Warning."
            except (TypeError, ValueError, ArithmeticError):
                continue
        if errors:
            raise ValidationError(errors)

    class Meta:
        constraints = [models.CheckConstraint(condition=models.Q(id=1), name="ddos_settings_singleton")] + [
            constraint for metric, _ in THRESHOLD_METRICS for constraint in (
                models.CheckConstraint(condition=models.Q(**{metric + "_warning__gte": 0}), name=f"ddos_{metric}_warning_nonnegative"),
                models.CheckConstraint(condition=models.Q(**{metric + "_attack__gt": models.F(metric + "_warning")}), name=f"ddos_{metric}_attack_above_warning"),
            )] + [
            models.CheckConstraint(condition=models.Q(cpu_warning__lte=100), name="ddos_cpu_warning_max"),
            models.CheckConstraint(condition=models.Q(cpu_attack__lte=100), name="ddos_cpu_attack_max"),
        ]


class DeviceDDoSThreshold(models.Model):
    """Per-device threshold override. The absence of a row means the device follows
    the global DDoSDetectionSettings defaults (no copied values)."""
    device = models.OneToOneField("devices.Device", on_delete=models.CASCADE, related_name="ddos_threshold")
    total_pps_warning = models.DecimalField(max_digits=15, decimal_places=3, default=10000, validators=[MinValueValidator(0)])
    total_pps_attack = models.DecimalField(max_digits=15, decimal_places=3, default=50000, validators=[MinValueValidator(0)])
    bandwidth_mbps_warning = models.DecimalField(max_digits=15, decimal_places=3, default=100, validators=[MinValueValidator(0)])
    bandwidth_mbps_attack = models.DecimalField(max_digits=15, decimal_places=3, default=500, validators=[MinValueValidator(0)])
    syn_pps_warning = models.DecimalField(max_digits=15, decimal_places=3, default=2000, validators=[MinValueValidator(0)])
    syn_pps_attack = models.DecimalField(max_digits=15, decimal_places=3, default=10000, validators=[MinValueValidator(0)])
    udp_pps_warning = models.DecimalField(max_digits=15, decimal_places=3, default=5000, validators=[MinValueValidator(0)])
    udp_pps_attack = models.DecimalField(max_digits=15, decimal_places=3, default=20000, validators=[MinValueValidator(0)])
    cpu_warning = models.DecimalField(max_digits=6, decimal_places=3, default=70, validators=[MinValueValidator(0), MaxValueValidator(100)])
    cpu_attack = models.DecimalField(max_digits=6, decimal_places=3, default=90, validators=[MinValueValidator(0), MaxValueValidator(100)])
    updated_at = models.DateTimeField(auto_now=True)

    def clean(self):
        super().clean()
        errors = {}
        for metric, label in THRESHOLD_METRICS:
            warning, attack = getattr(self, metric + "_warning"), getattr(self, metric + "_attack")
            try:
                if warning is not None and attack is not None and attack <= warning:
                    errors[metric + "_attack"] = f"{label}: Attack must be greater than Warning."
            except (TypeError, ValueError, ArithmeticError):
                continue
        if errors:
            raise ValidationError(errors)

    class Meta:
        constraints = [
            constraint for metric, _ in THRESHOLD_METRICS for constraint in (
                models.CheckConstraint(condition=models.Q(**{metric + "_warning__gte": 0}), name=f"ddos_device_{metric}_warning_nonnegative"),
                models.CheckConstraint(condition=models.Q(**{metric + "_attack__gt": models.F(metric + "_warning")}), name=f"ddos_device_{metric}_attack_above_warning"),
            )] + [
            models.CheckConstraint(condition=models.Q(cpu_warning__lte=100), name="ddos_device_cpu_warning_max"),
            models.CheckConstraint(condition=models.Q(cpu_attack__lte=100), name="ddos_device_cpu_attack_max"),
        ]


class DeviceDDoSProtection(models.Model):
    """Legacy container for a device's DDoS Protection NAT list.

    SOS Public and the Protection toggle are now PER ENTRY (see DeviceDDoSProtectionRule).
    The device-level fields are kept only so existing rows migrate cleanly and the older
    per-device settings screen keeps rendering."""
    device = models.OneToOneField("devices.Device", on_delete=models.CASCADE, related_name="ddos_protection")
    # Deprecated: superseded by DeviceDDoSProtectionRule.sos_public.
    sos_public = models.CharField(max_length=255, blank=True, default="")
    # Deprecated: superseded by DeviceDDoSProtectionRule.protection_enabled.
    enabled = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)


class DeviceDDoSProtectionRule(models.Model):
    """One NAT entry of a device's DDoS Protection list.

    `name` matches the RouterOS NAT rule's comment exactly (e.g. "iQ-25-01").
    `sos_public` is the failover target for this entry; `protection_enabled` turns the
    automatic failover on for this entry only."""
    protection = models.ForeignKey(DeviceDDoSProtection, on_delete=models.CASCADE, related_name="rules")
    position = models.PositiveIntegerField(default=0)
    name = models.CharField(max_length=120, blank=True, default="")
    value = models.DecimalField(max_digits=15, decimal_places=3, null=True, blank=True)
    sos_public = models.CharField(max_length=255, blank=True, default="")
    protection_enabled = models.BooleanField(default=False)
    # Set when an automatic failover actually switches this entry; stays set after the
    # attack recovers so the entry is not switched back automatically (no flapping).
    switched_at = models.DateTimeField(null=True, blank=True)
    switched_from = models.CharField(max_length=255, blank=True, default="")

    class Meta:
        ordering = ["position", "pk"]


class NatFailoverLog(models.Model):
    """Visible audit trail of every automatic NAT to-addresses change."""
    RESULT_CHOICES = [("switched", "Switched"), ("failed", "Failed"), ("skipped", "Skipped"),
                      ("unchanged", "Unchanged")]
    device = models.ForeignKey("devices.Device", null=True, on_delete=models.SET_NULL, related_name="nat_failover_logs")
    device_name = models.CharField(max_length=120, blank=True, default="")
    nat_comment = models.CharField(max_length=120, blank=True, default="")
    old_address = models.CharField(max_length=255, blank=True, default="")
    new_address = models.CharField(max_length=255, blank=True, default="")
    trigger_address = models.CharField(max_length=255, blank=True, default="")
    triggered_by = models.ForeignKey("public_ips.PublicIP", null=True, on_delete=models.SET_NULL)
    status_at_trigger = models.CharField(max_length=20, default="")
    result = models.CharField(max_length=20, choices=RESULT_CHOICES, default="switched")
    message = models.CharField(max_length=400, blank=True, default="")
    created_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        ordering = ["-created_at", "-pk"]


class RAWMonitoringSettings(models.Model):
    """One server-wide configuration; separate from browser refresh preferences."""
    id = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)
    polling_interval = models.PositiveSmallIntegerField(
        default=DEFAULT_POLLING_INTERVAL,
        choices=[(seconds, f"{seconds} seconds") for seconds in POLLING_INTERVALS])
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.CheckConstraint(condition=models.Q(id=1), name="raw_monitoring_singleton"),
            models.CheckConstraint(condition=models.Q(polling_interval__in=POLLING_INTERVALS),
                                   name="raw_monitoring_supported_interval"),
        ]


class DetectionPolicy(models.Model):
    id = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)
    enabled = models.BooleanField(default=True, editable=False)
    confirmation_samples = models.PositiveSmallIntegerField(default=3, validators=[MinValueValidator(1), MaxValueValidator(100)])
    recovery_samples = models.PositiveSmallIntegerField(default=3, validators=[MinValueValidator(1), MaxValueValidator(100)])
    hysteresis_percent = models.PositiveSmallIntegerField(default=20, validators=[MinValueValidator(0), MaxValueValidator(99)])
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.CheckConstraint(condition=models.Q(id=1), name="detection_policy_singleton"),
            models.CheckConstraint(condition=models.Q(confirmation_samples__range=(1, 100)), name="detection_confirmation_range"),
            models.CheckConstraint(condition=models.Q(recovery_samples__range=(1, 100)), name="detection_recovery_range"),
            models.CheckConstraint(condition=models.Q(hysteresis_percent__range=(0, 99)), name="detection_hysteresis_range"),
        ]


class DetectionEvent(models.Model):
    public_ip = models.ForeignKey("public_ips.PublicIP", null=True, on_delete=models.SET_NULL)
    device = models.ForeignKey("devices.Device", null=True, on_delete=models.SET_NULL)
    assignment_id_snapshot = models.PositiveBigIntegerField()
    device_id_snapshot = models.PositiveBigIntegerField()
    address = models.GenericIPAddressField(protocol="IPv4")
    device_name = models.CharField(max_length=255)
    management_ip = models.GenericIPAddressField()
    profile_key = models.CharField(max_length=64)
    started_at = models.DateTimeField()
    ended_at = models.DateTimeField(null=True, blank=True)
    last_observed_at = models.DateTimeField()
    triggering_metrics = models.JSONField(default=list)
    peak_total_pps = models.FloatField(default=0)
    peak_bandwidth_mbps = models.FloatField(default=0)
    peak_syn_pps = models.FloatField(default=0)
    peak_udp_pps = models.FloatField(default=0)
    peak_cpu = models.FloatField(default=0)
    highest_severity = models.CharField(max_length=20)

    @property
    def duration_seconds(self):
        from django.utils import timezone
        return max(0, int(((self.ended_at or timezone.now()) - self.started_at).total_seconds()))

    class Meta:
        ordering = ["-started_at", "-pk"]
        constraints = [models.UniqueConstraint(
            fields=["assignment_id_snapshot", "profile_key"], condition=models.Q(ended_at__isnull=True),
            name="one_open_detection_incident")]


class DetectionState(models.Model):
    public_ip = models.OneToOneField("public_ips.PublicIP", on_delete=models.CASCADE)
    profile_key = models.CharField(max_length=64)
    configuration_key = models.CharField(max_length=64, blank=True)
    confirmed_status = models.CharField(max_length=20, default="Unknown")
    last_sample_at = models.DateTimeField(null=True)
    last_valid_at = models.DateTimeField(null=True)
    warning_count = models.PositiveIntegerField(default=0)
    attack_count = models.PositiveIntegerField(default=0)
    warning_recovery_count = models.PositiveIntegerField(default=0)
    attack_recovery_count = models.PositiveIntegerField(default=0)
    pending_since = models.DateTimeField(null=True)
    pending_peaks = models.JSONField(default=dict)
    triggering_metrics = models.JSONField(default=list)
    event = models.ForeignKey(DetectionEvent, null=True, on_delete=models.SET_NULL)
