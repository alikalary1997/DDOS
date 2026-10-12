import ipaddress

from django.core.exceptions import ValidationError
from django.db import models
from django.conf import settings


def validate_public_ipv4(value):
    try:
        address = ipaddress.IPv4Address(value)
    except (ValueError, TypeError):
        raise ValidationError("Enter a valid public IPv4 address.") from None
    if not address.is_global or address.is_multicast:
        raise ValidationError("Enter a publicly routable IPv4 address.")


class PublicIP(models.Model):
    address = models.GenericIPAddressField(protocol="IPv4", unique=True, validators=[validate_public_ipv4])
    device = models.ForeignKey(
        "devices.Device", on_delete=models.PROTECT, related_name="public_ips", null=True, blank=True,
        limit_choices_to={"device_type": "mikrotik"},
    )
    description = models.TextField(max_length=1000, blank=True)
    incoming_monitoring_interface = models.CharField(max_length=255, blank=True)
    provisioning_status = models.CharField(max_length=20, default="not_attempted", editable=False)
    provisioning_code = models.CharField(max_length=40, blank=True, editable=False)
    provisioning_message = models.CharField(max_length=255, blank=True, editable=False)
    provisioning_attempted_at = models.DateTimeField(null=True, blank=True, editable=False)
    provisioning_verified_at = models.DateTimeField(null=True, blank=True, editable=False)
    monitoring_enabled = models.BooleanField(default=False, editable=False)
    detection_enabled = models.BooleanField(default=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["address", "pk"]

    def __str__(self):
        return self.address

    def clean(self):
        super().clean()
        if self.incoming_monitoring_interface and (not self.incoming_monitoring_interface.isprintable() or self.incoming_monitoring_interface != self.incoming_monitoring_interface.strip()):
            raise ValidationError({"incoming_monitoring_interface": "Enter a valid Ethernet interface name without surrounding whitespace."})
        if self.device_id and not self._meta.get_field("device").remote_field.model.objects.filter(
            pk=self.device_id, device_type="mikrotik"
        ).exists():
            raise ValidationError({"device": "Select a saved MikroTik device."})

    def save(self, *args, **kwargs):
        if self._state.adding and self.device_id and not self.incoming_monitoring_interface:
            self.incoming_monitoring_interface = self._meta.get_field("device").remote_field.model.objects.values_list(
                "incoming_monitoring_interface", flat=True).get(pk=self.device_id)
        self.full_clean()
        return super().save(*args, **kwargs)


class ProvisioningAttempt(models.Model):
    public_ip = models.ForeignKey(PublicIP, on_delete=models.SET_NULL, null=True, related_name="provisioning_attempts")
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    device = models.ForeignKey("devices.Device", on_delete=models.SET_NULL, null=True)
    address_snapshot = models.GenericIPAddressField(protocol="IPv4")
    interface_snapshot = models.CharField(max_length=255, blank=True)
    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, default="started")
    code = models.CharField(max_length=40, blank=True)
    message = models.CharField(max_length=255, blank=True)
    requested_rule_comments = models.JSONField(default=list)
    created_rule_ids = models.JSONField(default=list)
    verified_rule_ids = models.JSONField(default=list)

    class Meta:
        ordering = ["-started_at", "-pk"]


class FirewallSample(models.Model):
    device = models.OneToOneField("devices.Device", on_delete=models.CASCADE, related_name="firewall_sample")
    sampled_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=30, default="not_monitored")
    rows = models.JSONField(default=list)


class MonitoringRun(models.Model):
    """Administrator-controlled single worker, pinned to one assignment."""
    id = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)
    token = models.UUIDField()
    active = models.BooleanField(default=False)
    device_id_snapshot = models.PositiveBigIntegerField()
    assignment_id_snapshot = models.PositiveBigIntegerField()
    address = models.GenericIPAddressField(protocol="IPv4")
    started_at = models.DateTimeField()
    heartbeat_at = models.DateTimeField(null=True)
    stopped_at = models.DateTimeField(null=True)
    error = models.CharField(max_length=500, blank=True)

    class Meta:
        constraints = [models.CheckConstraint(condition=models.Q(id=1), name="monitoring_run_singleton")]


class AssignmentReview(models.Model):
    """Durable database-change history; cleanup is never implied or executed."""
    public_ip = models.ForeignKey(PublicIP, null=True, on_delete=models.SET_NULL, related_name="assignment_reviews")
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL)
    action = models.CharField(max_length=20)
    previous_address = models.GenericIPAddressField(protocol="IPv4")
    new_address = models.GenericIPAddressField(protocol="IPv4", null=True)
    previous_device_id_snapshot = models.PositiveBigIntegerField(null=True)
    new_device_id_snapshot = models.PositiveBigIntegerField(null=True)
    previous_device_name = models.CharField(max_length=255, blank=True)
    previous_management_ip = models.GenericIPAddressField(null=True)
    previous_interface = models.CharField(max_length=255, blank=True)
    previous_provisioning_status = models.CharField(max_length=20)
    rule_references = models.JSONField(default=list)
    cleanup_required = models.BooleanField(default=False)
    status = models.CharField(max_length=20, default="pending")
    cleanup_code = models.CharField(max_length=40, blank=True)
    cleanup_message = models.CharField(max_length=255, blank=True)
    requested_removal_ids = models.JSONField(default=list)
    removed_rule_ids = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-pk"]
