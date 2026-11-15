"""Device database changes only. Never connects to or writes to routers."""
from contextlib import contextmanager
from django.db import transaction
from django.shortcuts import get_object_or_404
from devices.models import Device, DeviceChange
from devices.services.router_lock import RouterBusy, router_lock
from public_ips.models import FirewallSample, PublicIP
from public_ips.services.assignments import clear_assignment_samples, delete_assignment, invalidate_assignment, record_review

CONNECTION_FIELDS = {"management_ip", "api_port", "use_ssl", "username", "password", "incoming_monitoring_interface"}
# The one field whose change re-targets live polling automatically (see sensors.polling).
MANAGEMENT_IP_FIELD = "management_ip"


@contextmanager
def locked_device(device_id):
    with router_lock(device_id), transaction.atomic():
        device = get_object_or_404(Device.objects.select_for_update(), pk=device_id)
        if PublicIP.objects.filter(device_id=device_id, provisioning_status__in=("pending", "connecting")).exists():
            raise RouterBusy("Provisioning is pending. Please retry shortly.")
        yield device


def audit_change(device, actor, action, changed_fields=()):
    return DeviceChange.objects.create(
        device=device, actor=actor, device_id_snapshot=device.pk, action=action,
        name_snapshot=device.name, management_ip_snapshot=device.management_ip,
        api_port_snapshot=device.api_port, use_ssl_snapshot=device.use_ssl,
        incoming_interface_snapshot=device.incoming_monitoring_interface,
        changed_fields=list(changed_fields), assigned_ip_count=PublicIP.objects.filter(device=device).count())


def save_device(form, actor):
    from devices.services.router_session import close_connection

    device = form.instance
    if not form.changed_fields:
        return device
    # Audit before mutation so a persistence failure rolls back the whole change.
    original = Device.objects.get(pk=device.pk)
    audit_change(original, actor, "edit", form.changed_fields)
    # Drop the cached RouterOS session before the profile changes: the next poll must dial
    # the new address (or credentials) rather than reusing a socket opened to the old one.
    close_connection(device.pk)
    if CONNECTION_FIELDS.intersection(form.changed_fields):
        # An IP-only edit re-targets live polling: keep each assignment's verified state and
        # monitoring preference so the sensor/RAW cycles simply resume on the new address.
        # The device is the same router and the RAW rules are matched by comment, not by
        # address, so nothing about the rules changes. Any other profile change still
        # requires the operator's review, exactly as before.
        ip_only = set(form.changed_fields) == {MANAGEMENT_IP_FIELD}
        for ip in PublicIP.objects.select_for_update().filter(device_id=device.pk):
            record_review(ip, "device_edit", ip.address, device.pk, actor)
            clear_assignment_samples(ip.pk, {device.pk})
            if ip_only:
                # Nothing on the assignment itself changed: keep its verification and its
                # updated_at intact so the running worker's scope stays valid.
                continue
            invalidate_assignment(ip)
            ip.save()
        # A saved connection profile has changed; old results cannot describe it.
        device.last_connection_test = None
        device.last_connection_test_succeeded = None
        device.last_successful_connection = None
        device.last_connection_error = ""
        device.router_identity = device.routeros_version = device.model = device.uptime = ""
        device.cpu_usage = device.total_memory = device.free_memory = None
    return form.save()


@transaction.atomic
def remove_device(device, actor):
    # Called under the device lock; outer transaction covers every IP and audit.
    assignments = list(PublicIP.objects.select_for_update().filter(device_id=device.pk))
    audit_change(device, actor, "delete")  # Records count before assignments disappear.
    deleted_ip_ids = [ip.pk for ip in assignments]
    for ip in assignments:
        public_ip_id = ip.pk
        # Reuses database-only stop/cache cleanup and durable rule-review snapshots.
        delete_assignment(ip, actor, database_only=True)
        # Remove stale references from earlier assignments as well, without
        # touching other IP rows or deleting another device's cache container.
        clear_assignment_samples(public_ip_id, set(FirewallSample.objects.values_list("device_id", flat=True)))
    device.delete()  # Sample cache cascades; historical audit FKs become NULL.
    # The device is gone: drop any cached RouterOS session held by this process.
    from devices.services.router_session import close_connection
    close_connection(device.pk)
    return deleted_ip_ids
