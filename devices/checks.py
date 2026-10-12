from django.core.checks import Error, register

from .services.targets import TargetPolicyError, configured_networks, connection_timeout


@register()
def connection_configuration(app_configs, **kwargs):
    errors = []
    try:
        configured_networks()
    except TargetPolicyError:
        errors.append(Error("Device connection allowlist must contain valid IP network CIDRs.", id="devices.E001"))
    try:
        connection_timeout()
    except TargetPolicyError:
        errors.append(Error("Device connection timeout must be between 0.5 and 10 seconds.", id="devices.E002"))
    return errors
