import logging

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ImproperlyConfigured, PermissionDenied, ValidationError
from django.db import DatabaseError, IntegrityError, transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.http import JsonResponse
from django.utils import timezone
from django.db.models import Q
from .presentation import INVENTORY_FIELDS, present_device
from .services.connection import probe_device
from django.views.decorators.cache import never_cache
from django.views.decorators.debug import sensitive_post_parameters, sensitive_variables
from django.views.decorators.http import require_GET, require_POST, require_http_methods

from .forms import AddDeviceForm, EditDeviceForm, MonitoringInterfaceForm
from .models import Device
from .services.credentials import CredentialError


logger = logging.getLogger(__name__)


@never_cache
@login_required(login_url="device_login")
@require_http_methods(["GET", "POST"])
def raw_provisioning_settings(request, device_id):
    if not may_add_devices(request.user):
        raise PermissionDenied("Administrator access is required.")
    from .forms import ProvisioningValidationForm
    from .services.provisioning_authorization import (
        authorize_provisioning, disable_provisioning, validate_provisioning, validation_is_current)
    from .services.router_lock import RouterBusy
    from public_ips.models import PublicIP
    from public_ips.services.device_approval import device_writes_enabled
    from public_ips.services.rules import expected_rules
    device = get_object_or_404(Device, pk=device_id, device_type="mikrotik")
    initial_address = device.raw_preflight_address or PublicIP.objects.filter(device=device).values_list("address", flat=True).first()
    form = ProvisioningValidationForm(initial={"public_ip": initial_address})
    status = 200
    if request.method == "POST":
        action = request.POST.get("action")
        form = ProvisioningValidationForm({"public_ip": initial_address or ""})
        form.is_valid()
        try:
            if action == "validate":
                form = ProvisioningValidationForm(request.POST)
                if form.is_valid():
                    validate_provisioning(device_id, form.cleaned_data["public_ip"], request.user)
                    messages.success(request, "Connection and read-only RAW preflight passed. Review the target and explicitly authorize provisioning below.")
                    return redirect("device_raw_provisioning", device_id=device_id)
                status = 400
            elif action == "enable":
                authorize_provisioning(device_id, request.user,
                    confirmed=request.POST.get("authorize") == "yes",
                    fingerprint=request.POST.get("fingerprint", ""))
                messages.success(request, "Automatic RAW provisioning enabled for this device. New Public IP Save and existing Retry actions will add and verify only missing monitoring rules.")
                return redirect("device_raw_provisioning", device_id=device_id)
            elif action == "disable":
                disable_provisioning(device_id, request.user)
                messages.success(request, "Automatic RAW provisioning disabled. Router rules were retained.")
                return redirect("device_raw_provisioning", device_id=device_id)
            else:
                form.add_error(None, "Select a valid provisioning action.")
                status = 400
        except ValidationError as error:
            form.add_error(None, error)
            status = 400
        except RouterBusy:
            form.add_error(None, "This device is busy. Please retry shortly.")
            status = 409
        except DatabaseError:
            form.add_error(None, "Provisioning settings could not be saved. Please retry.")
            status = 503
        device.refresh_from_db()
    ready = validation_is_current(device)
    rules = expected_rules(device.raw_preflight_address, device.incoming_monitoring_interface) if ready else []
    # The device object contains credentials; only allowlisted values reach the template.
    profile = {field: getattr(device, field) for field in (
        "id", "name", "management_ip", "api_port", "use_ssl", "incoming_monitoring_interface",
        "raw_preflight_at", "raw_preflight_address", "raw_preflight_message",
        "raw_preflight_fingerprint", "raw_provisioning_authorized_at")}
    return render(request, "monitor/device_raw_provisioning.html", {
        "active_page": "devices", "device": profile, "validation_form": form,
        "provisioning_enabled": device_writes_enabled(device), "preflight_ready": ready,
        "expected_rules": ["add " + " ".join(
            f'{key}="{value}"' if key in ("comment", "in-interface") else f"{key}={value}"
            for key, value in rule.items()) for rule in rules]}, status=status)


def may_add_devices(user):
    return user.is_authenticated and user.is_active and (user.is_staff or user.is_superuser)


def inventory_context(request, form=None, unavailable=False):
    # Do not fetch usernames, ciphertext or other credential fields for inventory.
    rows = [] if unavailable else [present_device(row) for row in Device.objects.values(*INVENTORY_FIELDS)]
    if not unavailable:
        from public_ips.models import PublicIP
        assigned = {}
        assigned_rows = {}
        for item in PublicIP.objects.filter(device_id__in=[row["id"] for row in rows]).values("id", "device_id", "address"):
            assigned.setdefault(item["device_id"], []).append(item["address"])
            assigned_rows.setdefault(item["device_id"], []).append(item)
        for row in rows:
            row["assigned_public_ips"] = assigned.get(row["id"], [])
            row["assigned_public_ip_rows"] = assigned_rows.get(row["id"], [])
        # Bounded history, fetched together; this read-only presentation never contacts routers.
        from .models import DeviceChange
        from public_ips.models import ProvisioningAttempt
        audits, attempts = {}, {}
        ids = [row["id"] for row in rows]
        for item in DeviceChange.objects.filter(device_id_snapshot__in=ids).order_by("device_id_snapshot", "-id").values(
                "device_id_snapshot", "action", "created_at", "changed_fields"):
            history = audits.setdefault(item["device_id_snapshot"], [])
            if len(history) < 10:
                history.append(item)
        for item in ProvisioningAttempt.objects.filter(device_id__in=ids).order_by("device_id", "-id").values(
                "device_id", "address_snapshot", "status", "message", "started_at"):
            history = attempts.setdefault(item["device_id"], [])
            if len(history) < 10:
                history.append(item)
        for row in rows:
            row["audit_history"] = audits.get(row["id"], [])
            row["provisioning_history"] = attempts.get(row["id"], [])
        from sensors.presentation import fleet_snapshot, summarize_sensors
        sensor_groups = fleet_snapshot()
        for row in rows:
            row['snmp_sensors'] = sensor_groups.get(row['id'], [])
            row['snmp_cpu'] = next((s for s in row['snmp_sensors'] if s['kind'] == 'cpu'), None)
            row['snmp_uptime'] = next((s for s in row['snmp_sensors'] if s['kind'] == 'uptime'), None)
            row['snmp_traffic'] = [s for s in row['snmp_sensors'] if s['kind'] == 'traffic']
            summary = summarize_sensors(row['snmp_sensors'])
            row['sensor_health'] = ('No sensors' if not summary['total'] else 'Needs attention' if summary['attention']
                else f"{summary['active']} active" if summary['active'] else 'Waiting for data' if summary['enabled'] else 'Stopped')
            row['sensor_health_tone'] = 'attention' if summary['attention'] else 'active' if summary['active'] else 'idle'
        sensor_summary = summarize_sensors([sensor for row in rows for sensor in row['snmp_sensors']])
        from sensors.polling import authorized
        sensor_authorized = authorized()
    return {
        "active_page": "devices", "inventory_ready": True, "device_rows": rows, "total_devices": None if unavailable else len(rows),
        "snmp_polling_authorized": False if unavailable else sensor_authorized,
        "sensor_summary": {'total': None, 'active': None, 'attention': None} if unavailable else sensor_summary,
        "inventory_unavailable": unavailable,
        "online_devices": None if unavailable else sum(row["connection_status"] == "online" for row in rows),
        "offline_devices": None if unavailable else sum(row["connection_status"] == "offline" for row in rows),
        "raw_enabled_devices": None if unavailable else sum(row["raw_status"] == "Enabled" for row in rows),
        "can_add_devices": may_add_devices(request.user),
        "add_device_form": form if form is not None else AddDeviceForm(),
        "open_add_device": form is not None,
    }


@never_cache
@login_required(login_url="device_login")
@require_GET
def inventory(request):
    try:
        context = inventory_context(request)
    except DatabaseError:
        return render(request, "monitor/devices.html", inventory_context(request, unavailable=True), status=503)
    return render(request, "monitor/devices.html", context)


@never_cache
@login_required(login_url="device_login")
@require_POST
@sensitive_post_parameters("password")
@sensitive_variables()
def add_device(request):
    if not may_add_devices(request.user):
        raise PermissionDenied("Administrator access is required.")
    # A previous unconsumed success must not appear on a failed submission.
    list(messages.get_messages(request))
    form = AddDeviceForm(request.POST)
    try:
        if form.is_valid():
            # Commit before issuing the success message or redirect.
            with transaction.atomic():
                form.save()
            messages.success(request, "Device saved successfully.")
            return redirect("devices")
    except (IntegrityError, ValidationError):
        # A competing request can insert this endpoint after form validation.
        form.add_error(None, "The device could not be saved. Check for an existing device with this management IP and API port.")
    except (ImproperlyConfigured, CredentialError):
        form.add_error(None, "Device credential encryption is unavailable. Contact the server administrator.")
    except DatabaseError:
        form.add_error(None, "The device could not be saved. Please try again.")
        return render(request, "monitor/devices.html", inventory_context(request, form, unavailable=True), status=503)
    return render(request, "monitor/devices.html", inventory_context(request, form), status=400)


@never_cache
@require_POST
@sensitive_post_parameters()
@sensitive_variables()
def test_connection(request, device_id):
    if not request.user.is_authenticated:
        return JsonResponse({"ok": False, "error": "Please sign in again."}, status=401)
    if not may_add_devices(request.user):
        return JsonResponse({"ok": False, "error": "Administrator access is required."}, status=403)
    if set(request.POST) - {"csrfmiddlewaretoken"} or request.content_type not in ("", "application/x-www-form-urlencoded", "multipart/form-data"):
        return JsonResponse({"ok": False, "error": "Only a saved device may be tested."}, status=400)
    try:
        device = Device.objects.get(pk=device_id)
        if not device.enabled or device.device_type != "mikrotik":
            return JsonResponse({"ok": False, "error": "Testing requires an enabled MikroTik device."}, status=400)
        result = probe_device(device)
        completed = timezone.now()
        updates = {
            "last_connection_test": completed,
            "last_connection_test_succeeded": result.success,
            "last_connection_error": result.error,
        }
        if result.success:
            updates.update(result.information)
            updates["last_successful_connection"] = completed
        else:
            updates.update(router_identity="", routeros_version="", uptime="", cpu_usage=None, total_memory=None, free_memory=None)
        # No transaction spans the network call; do not overwrite a newer completed test.
        saved = Device.objects.filter(pk=device_id, updated_at=device.updated_at).filter(
            Q(last_connection_test__isnull=True) | Q(last_connection_test__lte=completed)
        ).update(**updates)
        row = Device.objects.values(*INVENTORY_FIELDS).get(pk=device_id)
        if not saved:
            return JsonResponse({"ok": False, "error": "The device profile changed or a newer test completed. Please test the saved profile again.", "device": present_device(row)}, status=409)
    except Device.DoesNotExist:
        return JsonResponse({"ok": False, "error": "The saved device was not found."}, status=404)
    except DatabaseError:
        return JsonResponse({"ok": False, "error": "The connection result could not be saved. Please try again."}, status=503)
    return JsonResponse({
        "ok": result.success, "error": result.error, "code": result.code,
        "message": "Connection test succeeded." if result.success else "Connection test failed.",
        "device": present_device(row),
    })


@never_cache
@login_required(login_url="device_login")
@require_POST
def save_monitoring_interface(request, device_id):
    if not may_add_devices(request.user):
        raise PermissionDenied("Administrator access is required.")
    form = MonitoringInterfaceForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Enter a valid incoming monitoring interface.")
        return redirect("devices")
    from .services.router_lock import RouterBusy, router_lock
    try:
        with router_lock(device_id):
            with transaction.atomic():
                eligible = Device.objects.filter(pk=device_id, device_type="mikrotik")
                if not eligible.exists():
                    return JsonResponse({"ok": False, "error": "The saved MikroTik device was not found."}, status=404)
                changed = eligible.exclude(incoming_monitoring_interface=form.cleaned_data["incoming_monitoring_interface"]).update(
                    incoming_monitoring_interface=form.cleaned_data["incoming_monitoring_interface"],
                    updated_at=timezone.now(),
                    raw_preflight_at=None, raw_preflight_fingerprint="", raw_preflight_address=None,
                    raw_preflight_message="Interface changed. Automatic provisioning will revalidate the saved profile on the next Public IP Save or Retry.",
                )
                # Existing verification is tied to the previous interface, so invalidate it.
                from public_ips.models import PublicIP
                PublicIP.objects.filter(device_id=device_id if changed else -1).update(
                    provisioning_status="not_attempted", provisioning_code="interface_changed",
                    provisioning_message="Interface saved. Retry provisioning to verify the rules.",
                    provisioning_verified_at=None, monitoring_enabled=False,
                )
        messages.success(request, "Incoming monitoring interface saved. No router configuration was changed.")
    except RouterBusy:
        messages.error(request, "Another operation is using this device. Please retry.")
    except (DatabaseError, OSError):
        messages.error(request, "The incoming monitoring interface could not be saved.")
    return redirect("devices")


@never_cache
@require_POST
@sensitive_post_parameters()
@sensitive_variables()
def monitoring_interfaces(request, device_id):
    if not may_add_devices(request.user):
        return JsonResponse({"ok": False, "error": "Administrator access is required."}, status=403)
    from .services.router_lock import RouterBusy, router_lock
    from .services.router_session import RouterAccessError, router_session
    from .services.connection import _text
    import os
    try:
        device = Device.objects.get(pk=device_id)
        with router_lock(device.pk), router_session(device) as api:
            rows = api.get_resource("/interface").get()
            secrets = (device.username, device.get_password(), device.encrypted_password,
                       os.environ.get("NETSHIELD_DEVICE_ENCRYPTION_KEY", ""))
            names = []
            for row in rows:
                name = row.get("name")
                if not isinstance(name, str) or not name or len(name) > 255:
                    continue
                # Skip reflected secrets; never expose or save a rewritten interface name.
                if _text(name, secrets, 255) != name:
                    continue
                if str(row.get("disabled", "false")).lower() not in ("true", "yes", "1"):
                    names.append(name)
        return JsonResponse({"ok": True, "interfaces": sorted(set(names))})
    except Device.DoesNotExist:
        return JsonResponse({"ok": False, "error": "The saved device was not found."}, status=404)
    except RouterAccessError as error:
        return JsonResponse({"ok": False, "error": str(error)}, status=400)
    except (RouterBusy, DatabaseError, OSError):
        return JsonResponse({"ok": False, "error": "Interfaces could not be retrieved. Please retry."}, status=503)

    except Exception:
        return JsonResponse({"ok": False, "error": "The RouterOS interface response could not be safely read."}, status=503)


@never_cache
@login_required(login_url="device_login")
@require_http_methods(["GET", "POST"])
@sensitive_post_parameters("password", "edit-password")
@sensitive_variables()
def edit_device(request, device_id):
    if not may_add_devices(request.user):
        raise PermissionDenied("Administrator access is required.")
    device = get_object_or_404(Device, pk=device_id)
    form = EditDeviceForm(instance=device, prefix="edit")
    ajax = request.headers.get("Accept") == "application/json"
    status = 200
    if request.method == "POST":
        list(messages.get_messages(request))
        from .services.management import locked_device, save_device
        from .services.router_lock import RouterBusy
        form = EditDeviceForm(request.POST, instance=device, prefix="edit")
        status = 400
        try:
            with locked_device(device_id) as current:
                form = EditDeviceForm(request.POST, instance=current, prefix="edit")
                if form.is_valid():
                    save_device(form, request.user)
                    message = "Device updated successfully. No router configuration was changed."
                    if ajax:
                        row = Device.objects.values(*INVENTORY_FIELDS).get(pk=device_id)
                        return JsonResponse({"ok": True, "message": message, "device": present_device(row)})
                    messages.success(request, message)
                    return redirect("devices")
        except RouterBusy:
            form.add_error(None, "This device is busy. Please retry shortly.")
            status = 409
        except (IntegrityError, ValidationError):
            form.add_error(None, "The device could not be saved. Check for a duplicate management IP/API port.")
        except (ImproperlyConfigured, CredentialError):
            form.add_error(None, "Device credential encryption is unavailable. Contact the server administrator.")
        except (DatabaseError, OSError):
            form.add_error(None, "The device could not be saved. Please try again.")
            status = 503
        if ajax:
            return JsonResponse({"ok": False, "error": "Device was not saved. Correct the errors below.", "errors": form.errors.get_json_data()}, status=status)
    context = inventory_context(request)
    context.update(edit_device_form=form, edit_device={"id": device.pk, "name": device.name})
    return render(request, "monitor/devices.html", context, status=status)


@never_cache
@login_required(login_url="device_login")
@require_http_methods(["GET", "POST"])
def delete_device(request, device_id):
    if not may_add_devices(request.user):
        raise PermissionDenied("Administrator access is required.")
    # Confirmation display never fetches credentials.
    device = get_object_or_404(Device.objects.only("id", "name"), pk=device_id)
    from public_ips.models import PublicIP
    count = PublicIP.objects.filter(device_id=device_id).count()
    error = ""
    status = 200
    ajax = request.headers.get("Accept") == "application/json"
    if request.method == "POST":
        list(messages.get_messages(request))
        if request.POST.get("confirm") != "yes":
            error, status = "Confirm deletion before removing this device.", 400
        else:
            from .services.management import locked_device, remove_device
            from .services.router_lock import RouterBusy
            try:
                with locked_device(device_id) as current:
                    deleted_ip_ids = remove_device(current, request.user)
                message = f"Device deleted successfully, together with {len(deleted_ip_ids)} assigned public IP record(s). Audit history was retained. Router rules may remain; router cleanup was not performed."
                if ajax:
                    return JsonResponse({"ok": True, "message": message, "deleted_id": device_id, "deleted_public_ip_ids": deleted_ip_ids, "router_cleanup_performed": False})
                messages.success(request, message)
                return redirect("devices")
            except RouterBusy:
                error, status = "This device is busy. Please retry shortly.", 409
            except (DatabaseError, OSError) as exc:
                # Do not log database exception text: it can contain credential values.
                logger.error("Device deletion failed: device_id=%s exception_type=%s", device_id, type(exc).__name__)
                error, status = "The device and its public IPs could not be deleted. No changes were saved. Refresh and try again.", 503
        if ajax:
            return JsonResponse({"ok": False, "error": error, "assigned_ip_count": count}, status=status)
    context = inventory_context(request)
    context.update(delete_device={"id": device.pk, "name": device.name}, assigned_ip_count=count, delete_device_error=error)
    return render(request, "monitor/devices.html", context, status=status)
