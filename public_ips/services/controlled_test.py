"""One-operation provisioning approval; does not release global writes or cleanup."""
from contextlib import contextmanager
from contextlib import nullcontext
from contextvars import ContextVar
from django.core.exceptions import PermissionDenied
from django.views.decorators.debug import sensitive_variables
from devices.models import Device

# Change only after the user explicitly approves the first selected live test.
CONTROLLED_LIVE_TEST_RELEASED = False
# (Public IP record ID, administrator ID, device ID, address, saved interface).
# Set only to the exact target authorized by the user; never supplied by a browser.
APPROVED_LIVE_TEST_TARGET = None
_approval = ContextVar("netshield_controlled_provisioning", default=None)


def web_provisioning_scope(public_ip, actor):
    """Enter only a server-approved target; browser fields cannot grant approval."""
    target = (public_ip.pk, actor.pk, public_ip.device_id, public_ip.address,
              public_ip.incoming_monitoring_interface)
    if CONTROLLED_LIVE_TEST_RELEASED is True and target == APPROVED_LIVE_TEST_TARGET:
        return controlled_test_scope(public_ip, actor)
    return nullcontext()


@sensitive_variables()
def _snapshot(public_ip, actor):
    device = Device.objects.get(pk=public_ip.device_id)
    return (public_ip.pk, actor.pk, public_ip.device_id, public_ip.address,
            public_ip.incoming_monitoring_interface, device.management_ip,
            device.api_port, device.use_ssl, device.username, device.encrypted_password,
            device.enabled, device.device_type)


@sensitive_variables()
def scoped_writes_enabled(public_ip, actor):
    approved = _approval.get()
    return (CONTROLLED_LIVE_TEST_RELEASED is True and approved is not None
            and approved[:5] == APPROVED_LIVE_TEST_TARGET
            and actor.is_authenticated and actor.is_active and (actor.is_staff or actor.is_superuser)
            and approved == _snapshot(public_ip, actor))


@contextmanager
@sensitive_variables()
def controlled_test_scope(public_ip, actor):
    if CONTROLLED_LIVE_TEST_RELEASED is not True:
        raise PermissionDenied("The first live test has not been explicitly authorized. No router connection was attempted.")
    if not actor.is_authenticated or not actor.is_active or not (actor.is_staff or actor.is_superuser):
        raise PermissionDenied("Administrator authorization is required.")
    snapshot = _snapshot(public_ip, actor)
    if snapshot[:5] != APPROVED_LIVE_TEST_TARGET:
        raise PermissionDenied("This device, public IP, interface and administrator are outside the approved first live test.")
    token = _approval.set(snapshot)
    try:
        yield
    finally:
        _approval.reset(token)
