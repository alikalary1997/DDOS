"""Allowlisted device creation fields; passwords are never redisplayed."""
from django import forms
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.views.decorators.debug import sensitive_variables

from .models import Device
from .services.credentials import CredentialError


class AddDeviceForm(forms.Form):
    name = forms.CharField(label="Device Name", max_length=120, widget=forms.TextInput(attrs={"id": "deviceName", "placeholder": "Device name", "autofocus": True}))
    management_ip = forms.GenericIPAddressField(label="Management IP Address", protocol="both", unpack_ipv4=True, widget=forms.TextInput(attrs={"placeholder": "IPv4 or IPv6 address", "spellcheck": "false"}))
    device_type = forms.ChoiceField(label="Device Type", choices=Device.DeviceType.choices, initial=Device.DeviceType.MIKROTIK)
    api_port = forms.IntegerField(label="API Port", min_value=1, max_value=65535, initial=8729)
    use_ssl = forms.TypedChoiceField(label="API-SSL", choices=(("true", "Enabled"), ("false", "Disabled")), coerce=lambda value: value == "true", initial="true")
    username = forms.CharField(label="Username", max_length=150, widget=forms.TextInput(attrs={"autocomplete": "off", "placeholder": "API username", "spellcheck": "false"}))
    password = forms.CharField(label="Password", strip=False, max_length=4096, widget=forms.PasswordInput(render_value=False, attrs={"autocomplete": "new-password", "placeholder": "API password"}))
    incoming_monitoring_interface = forms.CharField(label="Incoming monitoring interface", max_length=255, required=False, widget=forms.TextInput(attrs={"placeholder": "Exact RouterOS interface name"}))
    description = forms.CharField(label="Description", required=False, max_length=1000, widget=forms.Textarea(attrs={"rows": 3, "placeholder": "Location, role or notes"}))

    def clean_management_ip(self):
        if "%" in str(self.data.get("management_ip", "")):
            raise forms.ValidationError("Enter an unscoped IPv4 or IPv6 address.")
        return self.cleaned_data["management_ip"]

    def clean_incoming_monitoring_interface(self):
        value = self.cleaned_data["incoming_monitoring_interface"]
        if value and not value.isprintable():
            raise forms.ValidationError("Enter a valid interface name.")
        return value

    @sensitive_variables()
    def clean(self):
        cleaned = super().clean()
        if self.errors:
            return cleaned
        if Device.objects.filter(management_ip=cleaned["management_ip"], api_port=cleaned["api_port"]).exists():
            raise forms.ValidationError("A device with this management IP and API port already exists.")
        self.instance = Device(**{field: cleaned[field] for field in (
            "name", "management_ip", "device_type", "api_port", "use_ssl", "username", "description", "incoming_monitoring_interface",
        )})
        try:
            self.instance.set_password(cleaned["password"])
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
    EDIT_FIELDS = ("name", "management_ip", "api_port", "use_ssl", "username", "incoming_monitoring_interface", "description")

    @sensitive_variables()
    def __init__(self, *args, instance, **kwargs):
        self.instance = instance
        self.original = {field: getattr(instance, field) for field in self.EDIT_FIELDS}
        initial = dict(self.original, use_ssl="true" if instance.use_ssl else "false", password="")
        kwargs["initial"] = initial
        super().__init__(*args, **kwargs)
        self.fields.pop("device_type")
        self.fields["name"].widget.attrs["id"] = "editDeviceName"
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
        if self.errors:
            return cleaned
        if Device.objects.filter(management_ip=cleaned["management_ip"], api_port=cleaned["api_port"]).exclude(pk=self.instance.pk).exists():
            self.add_error(None, "A device with this management IP and API port already exists.")
            return cleaned
        for field in self.EDIT_FIELDS:
            setattr(self.instance, field, cleaned[field])
            if cleaned[field] != self.original[field]:
                self.changed_fields.append(field)
        try:
            if replacement:
                self.instance.set_password(replacement)
                self.changed_fields.append("password")
            self.instance.full_clean()
        except (ImproperlyConfigured, CredentialError):
            self.add_error(None, "Device credential encryption is unavailable. Contact the server administrator.")
        except ValidationError:
            self.add_error(None, "Check the device fields and management IP/API port uniqueness.")
        return cleaned
