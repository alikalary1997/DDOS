from django.db import models
from django.core.exceptions import ValidationError
from django.core.validators import MinValueValidator, MaxValueValidator

POLLING_INTERVALS = (2, 5, 10, 15, 30, 60)
DEFAULT_POLLING_INTERVAL = 5

DETECTION_METRICS = (("total_pps", "Total PPS"), ("bandwidth_mbps", "Bandwidth (Mbps)"),
                     ("syn_pps", "TCP SYN PPS"), ("udp_pps", "UDP PPS"))


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
    updated_at = models.DateTimeField(auto_now=True)

    def clean(self):
        super().clean()
        errors = {}
        for metric, label in DETECTION_METRICS:
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
            constraint for metric, _ in DETECTION_METRICS for constraint in (
                models.CheckConstraint(condition=models.Q(**{metric + "_warning__gte": 0}), name=f"ddos_{metric}_warning_nonnegative"),
                models.CheckConstraint(condition=models.Q(**{metric + "_attack__gt": models.F(metric + "_warning")}), name=f"ddos_{metric}_attack_above_warning"),
            )]


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
