"""Device database changes only. Never connects to or writes to routers."""
from contextlib import contextmanager
from django.db import transaction
from django.shortcuts import get_object_or_404
from devices.models import Device, DeviceChange
from devices.services.router_lock import RouterBusy, router_lock
from public_ips.models import FirewallSample, PublicIP
from public_ips.services.assignments import clear_assignment_samples, delete_assignment, invalidate_assignment, record_review

CONNECTION_FIELDS = {"management_ip", "api_port", "use_ssl", "username", "password", "incoming_monitoring_interface"}


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
    device = form.instance
    if not form.changed_fields:
        return device
    # Audit before mutation so a persistence failure rolls back the whole change.
    original = Device.objects.get(pk=device.pk)
    audit_change(original, actor, "edit", form.changed_fields)
    if CONNECTION_FIELDS.intersection(form.changed_fields):
        for ip in PublicIP.objects.select_for_update().filter(device_id=device.pk):
            record_review(ip, "device_edit", ip.address, device.pk, actor)
            invalidate_assignment(ip)
            clear_assignment_samples(ip.pk, {device.pk})
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
    return deleted_ip_ids
