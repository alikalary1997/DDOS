from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.contrib import messages
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_POST, require_http_methods

from devices.views import may_add_devices
from public_ips.models import PublicIP
from public_ips.services.monitoring import polling_enabled
from .services.dashboard_data import dashboard_data


@login_required(login_url="device_login")
@require_GET
@never_cache
def monitoring_data(request):
    return JsonResponse(dashboard_data(may_add_devices(request.user)))


@login_required(login_url="device_login")
@require_POST
@never_cache
def start_monitoring(request):
    if not may_add_devices(request.user):
        raise PermissionDenied
    from public_ips.services.monitoring_runtime import live_run
    if live_run():
        return JsonResponse(dashboard_data(True))
    if not polling_enabled():
        return JsonResponse({"monitoring": False, "error": "Open Public IP Monitoring and click Start Monitoring on the address you want to monitor."}, status=409)
    PublicIP.objects.filter(provisioning_status="verified", device__enabled=True, device__device_type="mikrotik").update(
        monitoring_enabled=True, updated_at=timezone.now())
    return JsonResponse(dashboard_data(True))


@login_required(login_url="device_login")
@require_POST
@never_cache
def stop_monitoring(request):
    if not may_add_devices(request.user):
        raise PermissionDenied
    from public_ips.services.monitoring_runtime import stop
    from devices.services.router_lock import RouterBusy
    try:
        stop(list(PublicIP.objects.filter(monitoring_enabled=True).values_list("pk", flat=True)))
    except RouterBusy:
        return JsonResponse({"error": "A monitoring operation is busy. Retry shortly."}, status=409)
    return JsonResponse(dashboard_data(True))


@login_required(login_url="device_login")
@require_GET
@never_cache
def dashboard(request):
    return render(request, "monitor/dashboard.html", {"dashboard_data": dashboard_data(may_add_devices(request.user))})


def devices(request):
    """Render the device UI without storing credentials or contacting routers."""
    return render(request, "monitor/devices.html")


def public_ips(request):
    """Render public IP management previews without persistence or router calls."""
    return render(request, "monitor/public_ips.html", {"active_page": "public_ips"})


def traffic_monitor(request):
    """Render the traffic frontend without telemetry calls or monitoring controls."""
    return render(request, "monitor/traffic_monitor.html", {"active_page": "traffic_monitor"})


@login_required(login_url="device_login")
@require_GET
@never_cache
def ddos_detection(request):
    from django.core.paginator import Paginator
    from .models import DetectionEvent, DetectionPolicy
    return render(request, "monitor/ddos_detection.html", {
        "active_page": "ddos_detection", "detection_policy": DetectionPolicy.objects.filter(pk=1).first(),
        "events": Paginator(DetectionEvent.objects.all(), 25).get_page(request.GET.get("page"))})


def alerts(request):
    """Render alert UI previews without alert detection, persistence or notifications."""
    return render(request, "monitor/alerts.html", {"active_page": "alerts"})


def reports(request):
    """Render report layouts without generation, persistence or scheduled delivery."""
    return render(request, "monitor/reports.html", {"active_page": "reports"})


@login_required(login_url="device_login")
@require_http_methods(["GET", "POST"])
@never_cache
def settings_page(request):
    from .forms import RAWMonitoringSettingsForm, DDoSDetectionSettingsForm, DetectionPolicyForm
    from .models import RAWMonitoringSettings, DDoSDetectionSettings, DetectionPolicy
    from django.db import DatabaseError
    from django.urls import reverse
    from .services.raw_settings import polling_interval
    can_manage = may_add_devices(request.user)
    if request.method == "POST" and not can_manage:
        raise PermissionDenied("Administrator access is required.")
    section = request.POST.get("settings_section", "raw") if request.method == "POST" else None
    form = RAWMonitoringSettingsForm(request.POST if section == "raw" else None,
                                     initial={"polling_interval": polling_interval()})
    stored = DDoSDetectionSettings.objects.filter(pk=1).first() or DDoSDetectionSettings(pk=1)
    detection_form = DDoSDetectionSettingsForm(request.POST if section == "ddos" else None, instance=stored)
    policy = DetectionPolicy.objects.filter(pk=1).first() or DetectionPolicy(pk=1)
    policy_form = DetectionPolicyForm(request.POST if section == "ddos_policy" else None, instance=policy)
    if section == "ddos":
        if detection_form.is_valid():
            try:
                detection_form.save()
            except DatabaseError:
                detection_form.add_error(None, "Thresholds could not be saved. Please try again.")
            else:
                messages.success(request, "DDoS detection thresholds saved. Detection activation was not changed.")
                return redirect(reverse("settings") + "#detectionSettings")
        messages.error(request, "Thresholds were not saved. Correct the errors below.")
    elif section == "ddos_policy":
        if policy_form.is_valid():
            try:
                policy_form.save()
            except DatabaseError:
                policy_form.add_error(None, "Detection policy could not be saved. Please try again.")
            else:
                messages.success(request, "Detection confirmation and recovery settings saved. Activation was not changed.")
                return redirect(reverse("settings") + "#detectionSettings")
        messages.error(request, "Detection policy was not saved. Correct the errors below.")
    elif section == "raw" and form.is_valid():
        RAWMonitoringSettings.objects.update_or_create(pk=1, defaults={
            "polling_interval": form.cleaned_data["polling_interval"]})
        messages.success(request, "RAW monitoring polling interval saved. The running worker applies it without a restart.")
        return redirect("settings")
    elif section not in (None, "raw"):
        messages.error(request, "Unknown settings section. No changes were saved.")
    if not can_manage:
        form.fields["polling_interval"].disabled = True
        for field in detection_form.fields.values():
            field.disabled = True
        for field in policy_form.fields.values():
            field.disabled = True
    return render(request, "monitor/settings.html", {"active_page": "settings",
        "raw_monitoring_form": form, "can_manage_raw_settings": can_manage,
        "ddos_settings_form": detection_form,
        "detection_policy_form": policy_form, "detection_policy": policy,
        "raw_polling_interval": polling_interval()}, status=400 if request.method == "POST" else 200)
