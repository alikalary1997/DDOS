from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import DatabaseError, IntegrityError, transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.http import JsonResponse
from django.conf import settings
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_POST, require_http_methods

from devices.models import Device
from devices.views import may_add_devices
from devices.services.router_lock import RouterBusy
from .forms import AddPublicIPForm, EditPublicIPForm
from .models import AssignmentReview, PublicIP
from .services.diagnostics import event
from .services.monitoring_presentation import traffic_fields


@never_cache
@login_required(login_url="device_login")
@require_POST
def detection_control(request, public_ip_id, action):
    if not may_add_devices(request.user):
        raise PermissionDenied("Administrator access is required.")
    if action not in ("enable", "disable"):
        return JsonResponse({"error": "Invalid detection action."}, status=400)
    from monitor.models import DetectionState
    with transaction.atomic():
        ip = get_object_or_404(PublicIP.objects.select_for_update(), pk=public_ip_id)
        # Do not change updated_at: a detection preference does not alter the RAW profile.
        PublicIP.objects.filter(pk=ip.pk).update(detection_enabled=action == "enable")
        DetectionState.objects.filter(public_ip=ip).update(warning_count=0, attack_count=0,
            warning_recovery_count=0, attack_recovery_count=0, pending_since=None, pending_peaks={}, last_valid_at=None)
    messages.success(request, f"Passive detection {action}d for {ip.address}. Monitoring was not changed.")
    return redirect("public_ips")


def inventory_context(request, form=None, unavailable=False, edit_form=None, edit_ip=None, delete_ip=None):
    rows = [] if unavailable else list(PublicIP.objects.values(
        "id", "address", "device_id", "device__name", "device__management_ip", "description", "incoming_monitoring_interface",
        "provisioning_status", "provisioning_message", "provisioning_code", "provisioning_verified_at", "monitoring_enabled"
    ))
    from .services.monitoring import cached_rows, polling_enabled
    snapshots = {} if unavailable else cached_rows()
    from .services.monitoring_runtime import live_run, run_message
    from .models import MonitoringRun
    run = None if unavailable else live_run()
    last_run = None if unavailable else MonitoringRun.objects.filter(pk=1).first()
    from monitor.services.detection_presentation import DetectionPresentation
    detection = None if unavailable else DetectionPresentation()
    for row in rows:
        sample = snapshots.get(row["id"], {}) if row["provisioning_status"] == "verified" else {}
        row["monitoring_running"] = bool(run and run.assignment_id_snapshot == row["id"])
        row["monitoring_status"] = sample.get("status", "Not monitored")
        row.update(traffic_fields(sample, row["address"]))
        row.update(detection.fields(row["id"], sample))
        row["monitoring_message"] = run_message(row["id"], last_run, sample.get("message", ""))
    devices = [] if unavailable else [
        {"id": device.pk, "name": device.name, "management_ip": device.management_ip,
         "provisioning_enabled": device.raw_provisioning_enabled and device.enabled}
        for device in Device.objects.filter(device_type="mikrotik").only(
            "id", "name", "management_ip", "api_port", "use_ssl",
            "incoming_monitoring_interface", "enabled", "device_type", "raw_provisioning_enabled")]
    display_form = form if form is not None else AddPublicIPForm()
    if unavailable:
        display_form.fields["device"].queryset = Device.objects.none()
    from .services.provisioning import writes_enabled
    from monitor.services.raw_settings import polling_interval
    return {
        "active_page": "public_ips", "public_ip_inventory_ready": True,
        "public_ip_rows": rows, "available_devices": devices,
        "total_public_ips": None if unavailable else len(rows),
        "inventory_unavailable": unavailable, "can_add_public_ips": may_add_devices(request.user),
        "add_ip_form": display_form,
        "open_add_ip": form is not None,
        "pending_cleanup_reviews": 0 if unavailable else AssignmentReview.objects.filter(cleanup_required=True, status="pending").count(),
        "cleanup_reviews": [] if unavailable else list(AssignmentReview.objects.filter(cleanup_required=True, status="pending").exclude(action="device_delete")),
        "edit_ip_form": edit_form, "edit_ip": edit_ip, "delete_ip": delete_ip,
        "raw_polling_enabled": polling_enabled(),
        "raw_polling_interval": polling_interval(),
        "raw_provisioning_enabled": writes_enabled(),
        "raw_device_provisioning_enabled": any(device["provisioning_enabled"] for device in devices),
        "monitored_public_ips": None if unavailable else sum(row["monitoring_status"] == "Monitoring" for row in rows),
        "unmonitored_public_ips": None if unavailable else sum(row["monitoring_status"] != "Monitoring" for row in rows),
    }


def render_inventory(request, form=None, status=200):
    try:
        context = inventory_context(request, form)
    except DatabaseError:
        context = inventory_context(request, form, unavailable=True)
        status = 503
    return render(request, "monitor/public_ips.html", context, status=status)


@never_cache
@login_required(login_url="device_login")
@require_GET
def inventory(request):
    return render_inventory(request)


@never_cache
@login_required(login_url="device_login")
@require_POST
def add_public_ip(request):
    if not may_add_devices(request.user):
        raise PermissionDenied("Administrator access is required.")
    list(messages.get_messages(request))
    event("add_public_ip_post", result="attempt")
    form = AddPublicIPForm(request.POST)
    try:
        if form.is_valid():
            event("form_validation", device_id=form.cleaned_data["device"].pk, result="success")
            with transaction.atomic():
                public_ip = form.save()
            event("assignment_saved", public_ip_id=public_ip.pk, device_id=public_ip.device_id, result="success")
            messages.success(request, "Public IP saved successfully.")
            if form.cleaned_data["authorize_provisioning"]:
                if not _authorize_selected_device(request, public_ip):
                    return redirect("public_ips")
            _provision_assignment(request, public_ip.pk)
            return redirect("public_ips")
    except IntegrityError:
        event("assignment_saved", result="database_failed")
        form.add_error(None, "The public IP could not be saved. Check whether it is already assigned.")
    except ValidationError:
        event("assignment_saved", result="failed")
        form.add_error(None, "The public IP could not be saved. Check the address and selected MikroTik device.")
    except DatabaseError:
        event("assignment_saved", result="database_failed")
        form.add_error(None, "The public IP could not be saved. Please try again.")
        return render(request, "monitor/public_ips.html", inventory_context(request, form, unavailable=True), status=503)
    event("form_validation", result="failed")
    return render_inventory(request, form, status=400)


def _authorize_selected_device(request, public_ip):
    from devices.services.provisioning_authorization import validate_provisioning, authorize_provisioning
    from .services.device_approval import device_writes_enabled
    device = Device.objects.get(pk=public_ip.device_id)
    if device_writes_enabled(device):
        return True
    try:
        validate_provisioning(device.pk, public_ip.address, request.user)
        device.refresh_from_db()
        authorize_provisioning(device.pk, request.user, confirmed=True,
                               fingerprint=device.raw_preflight_fingerprint)
        return True
    except ValidationError as error:
        message = "; ".join(error.messages)
        PublicIP.objects.filter(pk=public_ip.pk).update(
            provisioning_status="failed", provisioning_code="preflight_failed",
            provisioning_message=message, provisioning_verified_at=None,
            monitoring_enabled=False)
        messages.warning(request, "Public IP assignment retained. Provisioning failed: " + message)
        return False


def _provision_assignment(request, public_ip_id):
    from .services.provisioning import provision_public_ip
    from .services.controlled_test import web_provisioning_scope
    try:
        public_ip = PublicIP.objects.get(pk=public_ip_id)
        with web_provisioning_scope(public_ip, request.user):
            result = provision_public_ip(public_ip_id, request.user)
        if result.success:
            messages.success(request, result.message)
        elif result.code == "approval_required":
            messages.warning(request, "Provisioning pending. " + result.message)
        else:
            messages.warning(request, "Provisioning failed. " + result.message)
    except DatabaseError:
        event("provisioning_dispatch", public_ip_id=public_ip_id, result="database_failed")
        # The assignment has already committed; never imply that it was lost.
        messages.warning(request, "Public IP assignment retained. Provisioning audit could not be saved; no further writes were attempted.")


@never_cache
@login_required(login_url="device_login")
@require_POST
def retry_provisioning(request, public_ip_id):
    if not may_add_devices(request.user):
        raise PermissionDenied("Administrator access is required.")
    if not PublicIP.objects.filter(pk=public_ip_id).exists():
        from django.http import Http404
        raise Http404("Public IP not found.")
    if not PublicIP.objects.filter(pk=public_ip_id, device_id__isnull=False).exists():
        messages.warning(request, "Assign this public IP to a MikroTik device before provisioning.")
        return redirect("public_ips")
    _provision_assignment(request, public_ip_id)
    return redirect("public_ips")


@never_cache
@login_required(login_url="device_login")
@require_GET
def raw_monitoring_data(request):
    from .services.monitoring import cached_rows
    try:
        snapshots = cached_rows()
        from .services.monitoring_runtime import live_run, run_message
        from .models import MonitoringRun
        run = live_run()
        last_run = MonitoringRun.objects.filter(pk=1).first()
        items = []
        from monitor.services.detection_presentation import DetectionPresentation
        detection = DetectionPresentation()
        for ip in PublicIP.objects.values("id", "address", "monitoring_enabled", "provisioning_status", "provisioning_code", "provisioning_message"):
            row = snapshots.get(ip["id"], {}) if ip["provisioning_status"] == "verified" else {}
            items.append({
                "id": ip["id"], "status": row.get("status", "Not monitored"),
                "monitoring_enabled": ip["monitoring_enabled"],
                "monitoring_running": bool(run and run.assignment_id_snapshot == ip["id"]),
                "provisioning_status": ip["provisioning_status"], "provisioning_code": ip["provisioning_code"], "provisioning_message": ip["provisioning_message"],
                "monitoring_message": run_message(ip["id"], last_run, row.get("message", "")),
                **traffic_fields(row, ip["address"]),
                **detection.fields(ip["id"], row),
            })
        from monitor.services.raw_settings import polling_interval
        return JsonResponse({"rows": items, "polling_interval": polling_interval()})
    except DatabaseError:
        return JsonResponse({"error": "Monitoring data is unavailable."}, status=503)


@never_cache
@login_required(login_url="device_login")
@require_POST
def monitoring_control(request, scope, object_id, action):
    if not may_add_devices(request.user):
        raise PermissionDenied("Administrator access is required.")
    if scope not in ("ip", "device") or action not in ("start", "stop"):
        return JsonResponse({"error": "Invalid monitoring action."}, status=400)
    query = PublicIP.objects.filter(pk=object_id) if scope == "ip" else PublicIP.objects.filter(device_id=object_id)
    if action == "start":
        query = query.filter(provisioning_status="verified", device_id__isnull=False)
    try:
        from .services.monitoring_runtime import start, stop
        identifiers = list(query.values_list("pk", flat=True))
        if action == "start" and len(identifiers) > 1:
            messages.warning(request, "Select one Public IP card to start monitoring. Other addresses will remain stopped.")
        elif identifiers:
            if action == "start":
                start(identifiers[0])
                messages.success(request, "Monitoring is starting. Live rates appear after two valid samples.")
            else:
                stop(identifiers)
                messages.success(request, "Monitoring stopped. The last traffic samples are retained.")
        else:
            messages.warning(request, "No eligible saved public IP assignments were found.")
    except ValidationError as error:
        messages.error(request, " ".join(error.messages))
    except RouterBusy:
        messages.warning(request, "A monitoring worker is still running or stopping. Please retry shortly.")
    except DatabaseError:
        messages.error(request, "The monitoring preference could not be saved.")
    return redirect("public_ips")


@never_cache
@login_required(login_url="device_login")
@require_http_methods(["GET", "POST"])
def edit_public_ip(request, public_ip_id):
    if not may_add_devices(request.user):
        raise PermissionDenied("Administrator access is required.")
    ip = get_object_or_404(PublicIP, pk=public_ip_id)
    form = EditPublicIPForm(instance=ip, prefix="edit")
    if request.method == "POST":
        from devices.services.router_lock import RouterBusy
        from .services.assignments import locked_assignment, save_assignment
        form = EditPublicIPForm(request.POST, instance=ip, prefix="edit")
        try:
            candidate = request.POST.get("edit-device", "")
            target = int(candidate) if len(candidate) <= 20 and candidate.isascii() and candidate.isdecimal() else None
            with locked_assignment(public_ip_id, target) as current:
                old_address, old_device, old_interface = current.address, current.device_id, current.incoming_monitoring_interface
                form = EditPublicIPForm(request.POST, instance=current, prefix="edit")
                if form.is_valid():
                    changed = save_assignment(form, old_address, old_device, request.user, old_interface)
                    messages.success(request, "Public IP updated successfully. " + (
                        "Polling stopped. Provisioning review required; existing router rules were retained and router cleanup has not been performed. Use Retry provisioning for approval-gated reconciliation."
                        if changed else "No router configuration was changed."))
                    return redirect("public_ips")
        except RouterBusy:
            form.add_error(None, "This device or assignment is busy. Please retry shortly.")
        except (IntegrityError, ValidationError):
            form.add_error(None, "Public IP could not be saved. Check for duplicates and valid inputs.")
        except DatabaseError:
            messages.error(request, "Public IP could not be saved. Please try again.")
            return redirect("public_ips")
    context = inventory_context(request, edit_form=form, edit_ip=ip)
    return render(request, "monitor/public_ips.html", context, status=400 if request.method == "POST" else 200)


@never_cache
@login_required(login_url="device_login")
@require_http_methods(["GET", "POST"])
def delete_public_ip(request, public_ip_id):
    if not may_add_devices(request.user):
        raise PermissionDenied("Administrator access is required.")
    ip = get_object_or_404(PublicIP, pk=public_ip_id)
    if request.method == "GET":
        return render(request, "monitor/public_ips.html", inventory_context(request, delete_ip=ip))
    if request.POST.get("confirm") != "yes":
        messages.error(request, "Confirm deletion before removing this public IP.")
        return redirect("public_ips")
    from devices.services.router_lock import RouterBusy
    from .services.assignments import locked_assignment, delete_assignment
    try:
        with locked_assignment(public_ip_id) as current:
            review = delete_assignment(current, request.user)
        from .services.provisioning import writes_enabled
        messages.success(request, "Public IP deleted successfully. NetShield polling stopped; " + (
            "audit history retained; associated router rule cleanup will be verified separately."
            if writes_enabled() and review.cleanup_required else "router rules and audit history were retained."))
        if writes_enabled() and review.cleanup_required:
            from .services.cleanup import cleanup_review
            try:
                result = cleanup_review(review.pk, request.user)
                (messages.success if result.success else messages.warning)(request, result.message)
            except DatabaseError:
                messages.warning(request, "Public IP deletion was saved. Router cleanup audit could not be saved; the review is retained for retry.")
    except RouterBusy:
        messages.error(request, "This device or assignment is busy. Please retry shortly.")
    except DatabaseError:
        messages.error(request, "Public IP could not be deleted. Please try again.")
    return redirect("public_ips")


@never_cache
@login_required(login_url="device_login")
@require_POST
def retry_cleanup(request, review_id):
    if not may_add_devices(request.user):
        raise PermissionDenied("Administrator access is required.")
    get_object_or_404(AssignmentReview, pk=review_id)
    from .services.cleanup import cleanup_review
    try:
        result = cleanup_review(review_id, request.user)
        (messages.success if result.success else messages.warning)(request, result.message)
    except DatabaseError:
        messages.error(request, "Cleanup audit could not be saved; review retained for retry.")
    return redirect("public_ips")


@never_cache
@login_required(login_url="device_login")
@require_POST
def unassign_public_ip(request, public_ip_id):
    if not may_add_devices(request.user):
        raise PermissionDenied("Administrator access is required.")
    from devices.services.router_lock import RouterBusy
    from .services.assignments import locked_assignment, unassign_assignment
    try:
        with locked_assignment(public_ip_id) as current:
            changed = unassign_assignment(current, request.user)
        messages.success(request, "Public IP unassigned. Record retained; polling stopped. Provisioning review required; router cleanup has not been performed." if changed else "Public IP is already unassigned.")
    except RouterBusy:
        messages.error(request, "This device or assignment is busy. Please retry shortly.")
    except DatabaseError:
        messages.error(request, "Public IP could not be unassigned. Please try again.")
    return redirect("public_ips")
