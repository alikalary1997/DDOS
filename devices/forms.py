"""Allowlisted device creation fields; passwords are never redisplayed."""
from django import forms
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.views.decorators.debug import sensitive_variables

from .models import Device, Group, group_from_key, group_key, tree_nodes
from .services.credentials import CredentialError


def group_choices():
    """(key, label) for every Group plus Top level. Devices are never offered here."""
    rows = {row["id"]: row for row in tree_nodes()}

    def path(pk, trail=()):
        row = rows.get(pk)
        if row is None or pk in trail or len(trail) > 12:
            return ""
        parent = row["parent"]
        label = row["name"]
        prefix = path(parent, trail + (pk,)) if parent is not None else ""
        return f"{prefix} / {label}" if prefix else label

    return [("", "Top level")] + [(f"g:{pk}", path(pk)) for pk in rows]


def device_choices(exclude=None):
    """(key, label) for every Device plus Top level, for the topology chain picker."""
    devices = list(Device.objects.values("id", "name", "management_ip", "topology_parent_id"))
    by_id = {row["id"]: row for row in devices}
    return [("", "Top level")] + [
        (f"d:{row['id']}", f"{row['name']} ({row['management_ip']})")
        for row in devices if row["id"] != exclude]


class GroupField(forms.ChoiceField):
    """Tag picker: Top level (no group) or any nested Group. Never a device.

    Choices are rebuilt for every form instance, so a group created moments ago is
    immediately selectable.
    """

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("label", "Group")
        kwargs.setdefault("required", False)
        kwargs["choices"] = group_choices()
        super().__init__(*args, **kwargs)

    def clean(self, value):
        value = super().clean(value)
        try:
            return group_from_key(value)
        except ValidationError as error:
            raise forms.ValidationError(error.messages[0]) from None


class TopologyField(forms.ChoiceField):
    """'Connects to' picker: Top level or any other Device. Never a group."""

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("label", "Connects to")
        kwargs.setdefault("required", False)
        self._exclude = None
        kwargs["choices"] = device_choices()
        super().__init__(*args, **kwargs)

    def set_exclude(self, device_id):
        """Never offer the device itself or anything already beneath it (a loop)."""
        self._exclude = device_id
        selected = device_choices()
        blocked = {device_id} | (Device.objects.get(pk=device_id).topology_descendant_ids() if device_id else set())
        self.choices = [(key, label) for key, label in selected
                        if not key or int(key.split(":")[1]) not in blocked]

    def clean(self, value):
        value = super().clean(value)
        if not value:
            return None
        kind, _, raw = value.partition(":")
        if kind != "d" or not raw.isdigit():
            raise forms.ValidationError("Select a device, or Top level.")
        device = Device.objects.filter(pk=int(raw)).first()
        if device is None:
            raise forms.ValidationError("The selected device no longer exists.")
        return device


class AddDeviceForm(forms.Form):
    name = forms.CharField(label="Device Name", max_length=120, widget=forms.TextInput(attrs={"id": "deviceName", "placeholder": "Device name", "autofocus": True}))
    management_ip = forms.GenericIPAddressField(label="Management IP Address", protocol="both", unpack_ipv4=True, widget=forms.TextInput(attrs={"placeholder": "IPv4 or IPv6 address", "spellcheck": "false"}))
    device_type = forms.ChoiceField(label="Device Type", choices=Device.DeviceType.choices, initial=Device.DeviceType.MIKROTIK)
    api_port = forms.IntegerField(label="API Port", min_value=1, max_value=65535, initial=8729, required=False)
    # API-SSL is only meaningful for MikroTik. It stays a required-choice field so a bad value is
    # still rejected; an absent value (a Cisco switch posts no API fields) defaults to enabled.
    use_ssl = forms.TypedChoiceField(label="API-SSL", choices=(("true", "Enabled"), ("false", "Disabled")), coerce=lambda value: value == "true", initial="true")
    username = forms.CharField(label="Username", max_length=150, required=False, widget=forms.TextInput(attrs={"autocomplete": "off", "placeholder": "API username", "spellcheck": "false"}))
    password = forms.CharField(label="Password", strip=False, max_length=4096, required=False, widget=forms.PasswordInput(render_value=False, attrs={"autocomplete": "new-password", "placeholder": "API password"}))
    incoming_monitoring_interface = forms.CharField(label="Incoming monitoring interface", max_length=255, required=False, widget=forms.TextInput(attrs={"placeholder": "Exact RouterOS interface name"}))
    description = forms.CharField(label="Description", required=False, max_length=1000, widget=forms.Textarea(attrs={"rows": 3, "placeholder": "Location, role or notes"}))
    group = GroupField()
    topology_parent = TopologyField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Rebuilt per form: a group or device created a moment ago is immediately selectable.
        self.fields["group"].choices = group_choices()
        self.fields["topology_parent"].set_exclude(None)
        # A Cisco switch submits no API fields at all; treat a missing choice as the default.
        data = self.data
        if data and "device_type" in data and data.get("device_type") != Device.DeviceType.MIKROTIK:
            if not data.get("use_ssl"):
                data = data.copy()
                data["use_ssl"] = "true"
                self.data = data

    def clean_management_ip(self):
        if "%" in str(self.data.get("management_ip", "")):
            raise forms.ValidationError("Enter an unscoped IPv4 or IPv6 address.")
        return self.cleaned_data["management_ip"]

    def clean_use_ssl(self):
        # A Cisco switch submits no API fields, so an absent value falls back to the default.
        value = self.cleaned_data.get("use_ssl")
        return True if value is None else value

    def clean_incoming_monitoring_interface(self):
        value = self.cleaned_data["incoming_monitoring_interface"]
        if value and not value.isprintable():
            raise forms.ValidationError("Enter a valid interface name.")
        return value

    @sensitive_variables()
    def clean(self):
        cleaned = super().clean()
        device_type = cleaned.get("device_type")
        is_mikrotik = device_type == Device.DeviceType.MIKROTIK
        # MikroTik talks the RouterOS API; a Cisco switch is managed over SSH. Both need a
        # login, but the API-only fields (port, SSL, interface) belong to MikroTik alone.
        self.credentials_required = True
        for field in ("username", "password"):
            if not cleaned.get(field):
                self.add_error(field, "This field is required.")
        if is_mikrotik:
            if not cleaned.get("api_port"):
                self.add_error("api_port", "This field is required.")
        else:
            # A Cisco switch has no RouterOS API: no port or SSL, and no monitoring interface.
            cleaned["incoming_monitoring_interface"] = ""
            cleaned["api_port"] = cleaned.get("api_port") or 8729
        if cleaned.get("use_ssl") is None and not self.has_error("use_ssl"):
            cleaned["use_ssl"] = True
        if self.errors:
            return cleaned
        if Device.objects.filter(management_ip=cleaned["management_ip"], api_port=cleaned["api_port"]).exists():
            raise forms.ValidationError("A device with this management IP and API port already exists.")
        self.instance = Device(**{field: cleaned[field] for field in (
            "name", "management_ip", "device_type", "api_port", "use_ssl", "description", "incoming_monitoring_interface",
        )})
        self.instance.username = cleaned.get("username") or ""
        # Two independent labels: the group tag and the topology chain parent.
        self.instance.group = cleaned.get("group")
        self.instance.topology_parent = cleaned.get("topology_parent")
        try:
            if cleaned.get("password"):
                self.instance.set_password(cleaned["password"])
            else:
                self.instance.encrypted_password = ""
            self.instance.full_clean()
        except (ImproperlyConfigured, CredentialError):
            self.add_error(None, "Device credential encryption is unavailable. Contact the server administrator.")
        except ValidationError as error:
            self.add_error(None, error)
        finally:
            # Keep the password out of later processing and response context.
            cleaned.pop("password", None)
        return cleaned

    def save(self):
        if not self.is_valid():
            raise ValueError("Cannot save an invalid device form.")
        self.instance.save()
        return self.instance


class MonitoringInterfaceForm(forms.Form):
    incoming_monitoring_interface = forms.CharField(max_length=255, label="Incoming monitoring interface")

    def clean_incoming_monitoring_interface(self):
        value = self.cleaned_data["incoming_monitoring_interface"]
        if not value.isprintable():
            raise forms.ValidationError("Enter a valid interface name.")
        return value


class ProvisioningValidationForm(forms.Form):
    public_ip = forms.GenericIPAddressField(label="Public IP for read-only validation", protocol="IPv4")

    def clean_public_ip(self):
        from public_ips.models import validate_public_ipv4
        address = self.cleaned_data["public_ip"]
        validate_public_ipv4(address)
        return address


class EditDeviceForm(AddDeviceForm):
    """An optional replacement password; stored ciphertext is never rendered."""
    EDIT_FIELDS = ("name", "management_ip", "device_type", "api_port", "use_ssl", "username",
                   "incoming_monitoring_interface", "description")

    @sensitive_variables()
    def __init__(self, *args, instance, **kwargs):
        self.instance = instance
        self.original = {field: getattr(instance, field) for field in self.EDIT_FIELDS}
        self.original["group"] = group_key(instance.group) if instance.group else ""
        self.original["topology_parent"] = f"d:{instance.topology_parent_id}" if instance.topology_parent_id else ""
        initial = dict(self.original, use_ssl=instance.use_ssl, password="")
        kwargs["initial"] = initial
        super().__init__(*args, **kwargs)
        self.fields["name"].widget.attrs["id"] = "editDeviceName"
        # A device may not connect to itself or to anything already beneath it (that is a loop).
        self.fields["topology_parent"].set_exclude(instance.pk)
        self.fields["password"].required = False
        self.fields["password"].help_text = "Leave blank to keep the stored password."
        self.fields["password"].widget.attrs["placeholder"] = "Leave blank to keep current password"
        self.changed_fields = []

    def clean_management_ip(self):
        if "%" in str(self.data.get(self.add_prefix("management_ip"), "")):
            raise forms.ValidationError("Enter an unscoped IPv4 or IPv6 address.")
        return self.cleaned_data["management_ip"]

    def clean_incoming_monitoring_interface(self):
        value = self.cleaned_data["incoming_monitoring_interface"]
        if value and not value.isprintable():
            raise forms.ValidationError("Enter a valid interface name.")
        return value

    @sensitive_variables()
    def clean(self):
        # Do not call AddDeviceForm.clean(), which creates a new device.
        cleaned = forms.Form.clean(self)
        replacement = cleaned.pop("password", "")
        # Both device types store a login. Only MikroTik has the RouterOS API fields on top.
        is_mikrotik = cleaned.get("device_type") == Device.DeviceType.MIKROTIK
        if not is_mikrotik:
            cleaned["api_port"] = cleaned.get("api_port") or 8729
            cleaned["incoming_monitoring_interface"] = ""
        if not cleaned.get("username"):
            self.add_error("username", "This field is required.")
        if self.errors:
            return cleaned
        if Device.objects.filter(management_ip=cleaned["management_ip"], api_port=cleaned["api_port"]).exclude(pk=self.instance.pk).exists():
            self.add_error(None, "A device with this management IP and API port already exists.")
            return cleaned
        # A new device needs a password; an existing one may keep the stored one.
        if not (replacement or self.instance.encrypted_password):
            self.add_error("password", "This device needs a password.")
            return cleaned
        for field in self.EDIT_FIELDS:
            setattr(self.instance, field, cleaned[field])
            if cleaned[field] != self.original[field]:
                self.changed_fields.append(field)
        try:
            # Both assignments are independent and idempotent, so a repeated pass is harmless.
            parent = cleaned.get("group")
            if (group_key(parent) if parent else "") != self.original["group"] and "group" not in self.changed_fields:
                self.changed_fields.append("group")
            self.instance.group = parent
            topology_parent = cleaned.get("topology_parent")
            new_topology = f"d:{topology_parent.pk}" if topology_parent else ""
            if new_topology != self.original["topology_parent"] and "topology_parent" not in self.changed_fields:
                self.changed_fields.append("topology_parent")
            self.instance.set_topology_parent(topology_parent)
            if replacement:
                self.instance.set_password(replacement)
                self.changed_fields.append("password")
            self.instance.full_clean()
        except (ImproperlyConfigured, CredentialError):
            self.add_error(None, "Device credential encryption is unavailable. Contact the server administrator.")
        except ValidationError as error:
            # Cycle/self-parent refusals belong on the parent picker; anything else is general.
            text = " ".join(getattr(error, "messages", None) or ["Check the device fields and management IP/API port uniqueness."])
            if "parent" in text.lower() or "nested under" in text.lower():
                self.add_error("group", text)
            else:
                self.add_error(None, "Check the device fields and management IP/API port uniqueness.")
        return cleaned
