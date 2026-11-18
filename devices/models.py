import ipaddress

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.views.decorators.debug import sensitive_variables

from .fields import EncryptedPasswordField
from .services.credentials import decrypt_password, encrypt_password


class Group(models.Model):
    """A named label a device can be tagged with, optionally nested under another Group.

    Groups nest under Groups only - never under a device. This is a pure label/filter
    structure and has no relationship to a device's topology parent.
    """
    name = models.CharField(max_length=120, unique=True)
    parent = models.ForeignKey(
        "self", null=True, blank=True, on_delete=models.CASCADE, related_name="child_groups")

    class Meta:
        ordering = ["name", "pk"]

    def __str__(self):
        return self.name

    def set_parent(self, node):
        """Assign a parent Group, or None for top level. Devices can never be a parent."""
        if node is not None and not isinstance(node, Group):
            raise ValidationError("A group's parent must be another group, or top level.")
        if node is not None and self.pk and node.pk == self.pk:
            raise ValidationError("A group cannot be its own parent.")
        if node is not None and self.pk and node.pk in self.descendant_ids():
            raise ValidationError("That group is nested under this one, so it cannot also be its parent.")
        self.parent = node

    def descendant_ids(self, seen=None):
        """Ids of every group nested under this one, at any depth (cycle-safe)."""
        seen = set() if seen is None else seen
        found, stack = set(), list(Group.objects.filter(parent=self))
        while stack:
            group = stack.pop()
            if group.pk in seen:
                continue
            seen.add(group.pk)
            found.add(group.pk)
            stack.extend(Group.objects.filter(parent=group))
        return found


def group_key(group):
    """Picker identifier for a Group."""
    return f"g:{group.pk}"


def group_from_key(key):
    """Resolve a `g:<id>` key (or blank for top level) to a Group."""
    key = (key or "").strip()
    if not key:
        return None
    kind, _, raw = key.partition(":")
    if kind != "g" or not raw.isdigit():
        raise ValidationError("Select a group, or Top level.")
    group = Group.objects.filter(pk=int(raw)).first()
    if group is None:
        raise ValidationError("The selected group no longer exists.")
    return group


def child_groups(group):
    """Direct sub-groups of a group, by name."""
    return list(Group.objects.filter(parent=group))


def tree_nodes():
    """Every Group as a flat row with its parent id (one query)."""
    return list(Group.objects.values("id", "name", "parent"))


def tree_summary():
    """Groups summary: total groups and the deepest nesting level in use."""
    rows = tree_nodes()
    parents = {row["id"]: row["parent"] for row in rows}
    depth_of = {}

    def depth(pk, trail=()):
        if pk in depth_of:
            return depth_of[pk]
        parent = parents.get(pk)
        value = 0 if parent is None or parent in trail else depth(parent, trail + (pk,)) + 1
        depth_of[pk] = value
        return value

    levels = [depth(pk) for pk in parents]
    return {"groups": len(rows), "depth": max(levels) + 1 if levels else 0}


class Device(models.Model):

    class DeviceType(models.TextChoices):
        MIKROTIK = "mikrotik", "MikroTik"
        CISCO = "cisco", "Cisco"
        OTHER = "other", "Other"

    name = models.CharField(max_length=120)
    management_ip = models.GenericIPAddressField(protocol="both", unpack_ipv4=True)
    device_type = models.CharField(max_length=20, choices=DeviceType.choices, default=DeviceType.MIKROTIK)
    model = models.CharField(max_length=120, blank=True)
    api_port = models.PositiveIntegerField(
        default=8729, validators=[MinValueValidator(1), MaxValueValidator(65535)]
    )
    use_ssl = models.BooleanField(default=True, help_text="Use API-SSL with certificate verification; never fall back to API.")
    username = models.CharField(max_length=150, blank=True)
    encrypted_password = EncryptedPasswordField(blank=True)
    incoming_monitoring_interface = models.CharField(max_length=255, blank=True)
    description = models.TextField(max_length=1000, blank=True)
    enabled = models.BooleanField(default=True)
    # Two independent labels on a device:
    #   group         - optional tag for filtering/labelling (nested groups, no topology meaning)
    #   topology_parent - the real network chain: what this device connects to (device -> device)
    group = models.ForeignKey(
        Group, null=True, blank=True, on_delete=models.SET_NULL, related_name="devices")
    topology_parent = models.ForeignKey(
        "self", null=True, blank=True, on_delete=models.SET_NULL, related_name="topology_children")
    raw_provisioning_enabled = models.BooleanField(default=True, editable=False)
    raw_provisioning_authorized_at = models.DateTimeField(null=True, blank=True, editable=False)
    raw_provisioning_authorized_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL,
        related_name="raw_provisioning_authorizations", editable=False)
    raw_provisioning_fingerprint = models.CharField(max_length=64, blank=True, editable=False)
    raw_preflight_at = models.DateTimeField(null=True, blank=True, editable=False)
    raw_preflight_fingerprint = models.CharField(max_length=64, blank=True, editable=False)
    raw_preflight_address = models.GenericIPAddressField(protocol="IPv4", null=True, blank=True, editable=False)
    raw_preflight_message = models.CharField(max_length=500, blank=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_successful_connection = models.DateTimeField(null=True, blank=True)
    last_connection_error = models.TextField(blank=True, editable=False)

    last_connection_test = models.DateTimeField(null=True, blank=True, editable=False)
    last_connection_test_succeeded = models.BooleanField(null=True, blank=True, editable=False)
    router_identity = models.CharField(max_length=255, blank=True, editable=False)
    routeros_version = models.CharField(max_length=120, blank=True, editable=False)
    uptime = models.CharField(max_length=120, blank=True, editable=False)
    cpu_usage = models.PositiveSmallIntegerField(
        null=True, blank=True, editable=False, validators=[MinValueValidator(0), MaxValueValidator(100)]
    )
    total_memory = models.PositiveBigIntegerField(null=True, blank=True, editable=False)
    free_memory = models.PositiveBigIntegerField(null=True, blank=True, editable=False)

    @property
    def used_memory(self):
        if self.total_memory is None or self.free_memory is None:
            return None
        return self.total_memory - self.free_memory

    class Meta:
        ordering = ["name", "pk"]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(cpu_usage__isnull=True) | models.Q(cpu_usage__gte=0, cpu_usage__lte=100),
                name="devices_cpu_usage_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(total_memory__isnull=True) | models.Q(free_memory__isnull=True) | models.Q(free_memory__lte=models.F("total_memory")),
                name="devices_memory_values_valid",
            ),
            models.UniqueConstraint(
                fields=["management_ip", "api_port"], name="devices_unique_management_endpoint"
            ),
            models.CheckConstraint(
                condition=models.Q(api_port__gte=1, api_port__lte=65535),
                name="devices_api_port_valid",
            ),
        ]

    def __str__(self):
        return self.name

    def clean_fields(self, exclude=None):
        # Reject a scope ID before Django normalizes the IPv6 literal.
        if "management_ip" not in (exclude or ()) and "%" in str(self.management_ip):
            raise ValidationError({"management_ip": "Enter an unscoped IPv4 or IPv6 address."})
        super().clean_fields(exclude=exclude)

    def clean(self):
        super().clean()
        errors = {}
        # A Cisco switch is inventory-only: no RouterOS API, so no username/password.
        needs_credentials = self.device_type == self.DeviceType.MIKROTIK
        required = ("name", "username") if needs_credentials else ("name",)
        for field in required:
            value = getattr(self, field)
            if isinstance(value, str):
                setattr(self, field, value.strip())
            if not getattr(self, field):
                errors[field] = "This field is required."
        if not needs_credentials:
            self.username = (self.username or "").strip()
        try:
            # Scoped IPv6 literals are not stable management endpoints.
            if "%" in str(self.management_ip):
                raise ValueError
            self.management_ip = str(ipaddress.ip_address(self.management_ip))
        except (ValueError, TypeError):
            errors["management_ip"] = "Enter a valid IPv4 or IPv6 address."
        if errors:
            raise ValidationError(errors)

    def set_topology_parent(self, node):
        """Set the device this one connects to (None = top level), rejecting cycles.

        Only the topology chain is touched: the device's Group tag is left exactly as is.
        """
        if node is not None and not isinstance(node, Device):
            raise ValidationError("A topology parent must be a device, or top level.")
        if node is not None and self.pk and node.pk == self.pk:
            raise ValidationError("A device cannot connect to itself.")
        if node is not None and self.pk and node.pk in self.topology_descendant_ids():
            raise ValidationError("That device already sits below this one, so it cannot also be a parent.")
        self.topology_parent = node

    def topology_descendant_ids(self):
        """Ids of every device below this one in the topology chain (cycle-safe)."""
        found, seen, stack = set(), set(), list(Device.objects.filter(topology_parent=self))
        while stack:
            device = stack.pop()
            if device.pk in seen:
                continue
            seen.add(device.pk)
            found.add(device.pk)
            stack.extend(Device.objects.filter(topology_parent=device))
        return found

    def topology_ancestor_ids(self):
        """Ids of every device above this one (used for display paths)."""
        found, seen, current = [], set(), self.topology_parent
        while current is not None and current.pk not in seen:
            seen.add(current.pk)
            found.append(current.pk)
            current = current.topology_parent
        return found
    @sensitive_variables()
    def set_password(self, password):
        self.encrypted_password = encrypt_password(password)

    @sensitive_variables()
    def get_password(self):
        return decrypt_password(self.encrypted_password)

    def save(self, *args, **kwargs):
        if self.pk:
            fields = ("management_ip", "api_port", "use_ssl", "username", "encrypted_password",
                      "incoming_monitoring_interface", "enabled", "device_type")
            previous = Device.objects.filter(pk=self.pk).values(*fields).first()
            if previous and any(previous[field] != getattr(self, field) for field in fields):
                # Keep explicit per-device enablement. The old fingerprint cannot
                # authorize the new profile until Save/Retry revalidates it.
                self.raw_preflight_at = None
                self.raw_preflight_fingerprint = ""
                self.raw_preflight_address = None
                self.raw_preflight_message = "Device configuration changed. Automatic provisioning will revalidate the saved profile on the next Public IP Save or Retry."
                if kwargs.get("update_fields") is not None:
                    kwargs["update_fields"] = set(kwargs["update_fields"]) | {
                        "raw_preflight_at", "raw_preflight_fingerprint", "raw_preflight_address",
                        "raw_preflight_message"}
        # Django save() does not normally run validators or uniqueness checks.
        self.full_clean()
        return super().save(*args, **kwargs)


class DeviceChange(models.Model):
    """Credential-free history retained after device deletion."""
    device = models.ForeignKey(Device, null=True, on_delete=models.SET_NULL, related_name="management_changes")
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL)
    device_id_snapshot = models.PositiveBigIntegerField()
    action = models.CharField(max_length=20)
    name_snapshot = models.CharField(max_length=120)
    management_ip_snapshot = models.GenericIPAddressField()
    api_port_snapshot = models.PositiveIntegerField()
    use_ssl_snapshot = models.BooleanField()
    incoming_interface_snapshot = models.CharField(max_length=255, blank=True)
    changed_fields = models.JSONField(default=list)
    assigned_ip_count = models.PositiveIntegerField(default=0)
    router_cleanup_performed = models.BooleanField(default=False, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-pk"]
