from django import forms

from devices.models import Device
from .models import PublicIP


class DeviceChoiceField(forms.ModelChoiceField):
    def label_from_instance(self, device):
        return f"{device.name} ({device.management_ip})"


class AddPublicIPForm(forms.ModelForm):
    use_device_interface = True
    authorize_provisioning = forms.BooleanField(
        required=False,
        label="Re-enable automatic RAW provisioning if disabled",
        help_text="Automatic provisioning is on by default. Use this option only for a device that was explicitly disabled. Save validates the saved API profile before creating missing rules.",
    )
    device = DeviceChoiceField(
        queryset=Device.objects.none(), label="Assigned MikroTik Device",
        empty_label="Select a saved MikroTik device",
    )

    class Meta:
        model = PublicIP
        fields = ("address", "device", "incoming_monitoring_interface", "description")
        labels = {"address": "Public IP Address", "incoming_monitoring_interface": "Ethernet Interface"}
        widgets = {
            "address": forms.TextInput(attrs={"placeholder": "Enter public IPv4 address", "spellcheck": "false", "maxlength": 15}),
            "incoming_monitoring_interface": forms.TextInput(attrs={"placeholder": "Exact MikroTik interface name", "maxlength": 255, "spellcheck": "false"}),
            "description": forms.Textarea(attrs={"rows": 3, "placeholder": "Purpose, customer or location", "maxlength": 1000}),
        }
        error_messages = {"address": {"unique": "This public IP address is already assigned."}}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # The dropdown must never fetch credentials, including ciphertext.
        self.fields["device"].queryset = Device.objects.filter(
            device_type="mikrotik"
        ).only("id", "name", "management_ip", "incoming_monitoring_interface").order_by("name", "pk")
        self.fields["incoming_monitoring_interface"].help_text = "Enter this IP's exact interface. If blank, its saved interface or the device default is copied into the record."
        if self.use_device_interface:
            self.fields.pop("incoming_monitoring_interface")

    def clean(self):
        cleaned = super().clean()
        device = cleaned.get("device")
        interface = cleaned.get("incoming_monitoring_interface", "")
        if self.use_device_interface and device:
            interface = device.incoming_monitoring_interface
        if not interface and device:
            interface = self.instance.incoming_monitoring_interface or device.incoming_monitoring_interface
        if device and not interface:
            self.add_error(None if self.use_device_interface else "incoming_monitoring_interface", "Configure the assigned MikroTik device's incoming monitoring interface before adding this public IP.")
        elif interface and not interface.isprintable():
            self.add_error(None if self.use_device_interface else "incoming_monitoring_interface", "Enter a valid Ethernet interface name.")
        cleaned["incoming_monitoring_interface"] = interface
        return cleaned


class EditPublicIPForm(AddPublicIPForm):
    use_device_interface = False
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields.pop("authorize_provisioning")
        self.fields["device"].required = False
        self.fields["device"].empty_label = "Unassigned — keep the IP without a device"
