"""Transactional database changes only; no RouterOS calls or rule cleanup."""
from contextlib import ExitStack, contextmanager
from django.db import transaction
from django.shortcuts import get_object_or_404
from devices.models import Device
from devices.services.router_lock import RouterBusy, router_lock
from public_ips.models import AssignmentReview, FirewallSample, ProvisioningAttempt, PublicIP


@contextmanager
def locked_assignment(public_ip_id, new_device_id=None):
    original = get_object_or_404(PublicIP, pk=public_ip_id)
    with ExitStack() as stack:
        for device_id in sorted({original.device_id, new_device_id} - {None}):
            stack.enter_context(router_lock(device_id))
        with transaction.atomic():
            current = get_object_or_404(PublicIP.objects.select_for_update(), pk=public_ip_id)
            if current.device_id != original.device_id or current.provisioning_status in ("pending", "connecting"):
                raise RouterBusy("The assignment is busy. Please retry shortly.")
            yield current


def clear_assignment_samples(public_ip_id, device_ids):
    for sample in FirewallSample.objects.select_for_update().filter(device_id__in=device_ids - {None}):
        rows = [row for row in sample.rows if not isinstance(row, dict) or row.get("id") != public_ip_id]
        if rows != sample.rows:
            sample.rows = rows
            sample.save(update_fields=["rows"])


def record_review(ip, action, previous_address, previous_device_id, actor=None, previous_interface=None):
    interface = ip.incoming_monitoring_interface if previous_interface is None else previous_interface
    device = Device.objects.filter(pk=previous_device_id).values(
        "name", "management_ip", "incoming_monitoring_interface").first() or {}
    references = []
    for attempt in ProvisioningAttempt.objects.filter(public_ip_id=ip.pk).values(
        "id", "device_id", "address_snapshot", "interface_snapshot", "status",
        "requested_rule_comments", "created_rule_ids", "verified_rule_ids"):
        if attempt["requested_rule_comments"] or attempt["created_rule_ids"] or attempt["verified_rule_ids"] or attempt["status"] == "verified":
            references.append(attempt)
    cleanup_required = bool(references) or ip.provisioning_status == "verified"
    if ip.provisioning_status == "verified" and not references:
        references.append({"device_id": previous_device_id, "address_snapshot": previous_address,
                           "interface_snapshot": interface,
                           "expected_comments": [prefix + previous_address for prefix in ("MONITOR-", "MONITOR-SYN-", "MONITOR-UDP-")],
                           "verified_rule_ids": [], "note": "Previously verified; rule IDs require review."})
    return AssignmentReview.objects.create(
        public_ip=ip, actor=actor, action=action, previous_address=previous_address,
        new_address=None if action in ("delete", "device_delete") else ip.address,
        previous_device_id_snapshot=previous_device_id,
        new_device_id_snapshot=None if action in ("delete", "device_delete") else ip.device_id,
        previous_device_name=device.get("name", ""), previous_management_ip=device.get("management_ip"),
        previous_interface=interface,
        previous_provisioning_status=ip.provisioning_status, rule_references=references,
        cleanup_required=cleanup_required,
    )


def invalidate_assignment(ip):
    ip.monitoring_enabled = False
    ip.provisioning_status = "review_required"
    ip.provisioning_code = "assignment_review"
    ip.provisioning_message = "Provisioning review required. Existing router rules were retained; router cleanup has not been performed."
    ip.provisioning_verified_at = None
    ip.provisioning_attempted_at = None


def save_assignment(form, original_address, original_device_id, actor=None, original_interface=None):
    ip = form.instance
    action = "unassign" if original_device_id is not None and ip.device_id is None else "reassign" if ip.device_id != original_device_id else "edit"
    record_review(ip, action, original_address, original_device_id, actor, original_interface)
    invalidate_assignment(ip)
    clear_assignment_samples(ip.pk, {original_device_id, ip.device_id})
    form.save()
    return True  # Every edit requires fresh review, including description-only edits.


def unassign_assignment(ip, actor=None):
    original_device_id = ip.device_id
    if original_device_id is None:
        return False
    ip.device_id = None
    record_review(ip, "unassign", ip.address, original_device_id, actor)
    invalidate_assignment(ip)
    clear_assignment_samples(ip.pk, {original_device_id})
    ip.save()
    return True


def delete_assignment(ip, actor=None, database_only=False):
    review = record_review(ip, "device_delete" if database_only else "delete", ip.address, ip.device_id, actor)
    invalidate_assignment(ip)
    ip.save(update_fields=["monitoring_enabled", "provisioning_status", "provisioning_code", "provisioning_message",
                           "provisioning_verified_at", "provisioning_attempted_at", "updated_at"])
    clear_assignment_samples(ip.pk, {ip.device_id})
    ip.delete()  # Both provisioning audits and assignment reviews retain snapshots.
    return review
