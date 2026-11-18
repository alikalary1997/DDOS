from django import forms
from .models import Sensor, INTERVALS

# Kinds whose reading is an SNMP table walk need a floor above their own duration.
MINIMUM_INTERVAL = {'pppoe': 30}


class ProfileForm(forms.Form):
    community = forms.CharField(max_length=255, strip=False, widget=forms.PasswordInput(render_value=False))
    port = forms.IntegerField(initial=161, min_value=1, max_value=65535)


class AddSensorForm(forms.Form):
    kind = forms.ChoiceField(choices=Sensor.KINDS, widget=forms.RadioSelect)
    interval = forms.TypedChoiceField(choices=INTERVALS, coerce=int, initial=10)
    discovery = forms.CharField(required=False, widget=forms.HiddenInput)
    interfaces = forms.MultipleChoiceField(required=False, widget=forms.CheckboxSelectMultiple)

    def __init__(self, *args, interfaces=(), **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['interfaces'].choices = [(str(i['index']), f"{i['name']} — {i['status']}") for i in interfaces]

    def clean(self):
        cleaned = super().clean()
        kind, interval = cleaned.get('kind'), cleaned.get('interval')
        # A PPPoE reading walks a session table and takes seconds on a busy server. Polling it
        # faster than that leaves the sensor permanently overdue, which shows as stale data.
        minimum = MINIMUM_INTERVAL.get(kind)
        if minimum and interval and interval < minimum:
            raise forms.ValidationError(
                f"{dict(Sensor.KINDS)[kind]} needs an interval of at least {minimum} seconds, "
                f"because each reading walks the PPP session table.")
        return cleaned


class EditSensorForm(forms.ModelForm):
    class Meta:
        model = Sensor
        fields = ['name', 'interval']
