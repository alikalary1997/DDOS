from django import forms
from .models import DEFAULT_POLLING_INTERVAL, POLLING_INTERVALS, DETECTION_METRICS, DDoSDetectionSettings, DetectionPolicy


class DetectionPolicyForm(forms.ModelForm):
    class Meta:
        model = DetectionPolicy
        fields = ["confirmation_samples", "recovery_samples", "hysteresis_percent"]
        labels = {"confirmation_samples": "Consecutive samples to enter Warning / Under Attack",
                  "recovery_samples": "Consecutive samples to recover", "hysteresis_percent": "Recovery hysteresis (%)"}


class DDoSDetectionSettingsForm(forms.ModelForm):
    class Meta:
        model = DDoSDetectionSettings
        fields = [metric + "_" + level for metric, _ in DETECTION_METRICS for level in ("warning", "attack")]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for metric, label in DETECTION_METRICS:
            for level in ("warning", "attack"):
                field = self.fields[metric + "_" + level]
                field.label = f"{label} {level.title()}"
                field.widget.attrs.update({"min": "0", "step": "0.001", "inputmode": "decimal",
                                           "aria-label": field.label})

    @property
    def threshold_rows(self):
        return [{"label": label, "warning": self[metric + "_warning"], "attack": self[metric + "_attack"]}
                for metric, label in DETECTION_METRICS]


class RAWMonitoringSettingsForm(forms.Form):
    polling_interval = forms.TypedChoiceField(
        label="Polling Interval", coerce=int, initial=DEFAULT_POLLING_INTERVAL,
        choices=[(seconds, f"{seconds} seconds") for seconds in POLLING_INTERVALS])
