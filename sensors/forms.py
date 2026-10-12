from django import forms
from .models import Sensor, INTERVALS


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


class EditSensorForm(forms.ModelForm):
    class Meta:
        model = Sensor
        fields = ['name', 'interval']
