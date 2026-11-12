from functools import wraps
from types import SimpleNamespace
from datetime import timedelta
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core import signing
from django.core.exceptions import ImproperlyConfigured
from django.db import transaction
from django.db.models import F
from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.debug import sensitive_post_parameters, sensitive_variables
from django.views.decorators.http import require_POST, require_GET
from devices.models import Device
from devices.services.credentials import encrypt_password, decrypt_password, CredentialError
from . import ping, snmp
from .forms import ProfileForm, AddSensorForm, EditSensorForm
from .models import SNMPProfile, Sensor, SensorRuntime
from .polling import authorized, format_uptime
from .locking import worker_running
from .runtime import start_sensors, StartupError


def administrator(fn):
    @login_required
    @wraps(fn)
    def wrapped(request, *args, **kwargs):
        if not request.user.is_active or not (request.user.is_staff or request.user.is_superuser):
            return HttpResponseForbidden('Administrator access is required.')
        return fn(request, *args, **kwargs)
    return wrapped


def device_for(pk):
    return get_object_or_404(Device.objects.defer('username', 'encrypted_password'), pk=pk, device_type='mikrotik')


@login_required
@require_GET
def fleet_data(request):
    from .presentation import fleet_snapshot
    response = JsonResponse({'devices': fleet_snapshot()})
    response['Cache-Control'] = 'no-store'
    return response


def context(device, user_can_edit=False):
    profile = SNMPProfile.objects.filter(device=device).first()
    from monitor.models import DDoSDetectionSettings, DeviceDDoSThreshold, DeviceDDoSProtection
    from monitor.forms import DeviceDDoSThresholdForm
    override = DeviceDDoSThreshold.objects.filter(device=device).first()
    if override:
        ddos_form = DeviceDDoSThresholdForm(instance=override)
    else:
        initial = {}
        global_settings = DDoSDetectionSettings.objects.filter(pk=1).first()
        if global_settings:
            initial = {field: getattr(global_settings, field) for field in DeviceDDoSThresholdForm.Meta.fields}
        ddos_form = DeviceDDoSThresholdForm(initial=initial)
    protection = DeviceDDoSProtection.objects.filter(device=device).prefetch_related("rules").first()
    return {'device': device, 'profile_ready': bool(profile and profile.validated_ip == device.management_ip),
            'profile_form': ProfileForm(initial={'port': profile.port if profile else 161}),
            'sensor_form': AddSensorForm(), 'sensors': Sensor.objects.filter(device=device),
            'polling_authorized': authorized(), 'active_page': 'devices',
            'ddos_form': ddos_form, 'has_ddos_override': bool(override),
            'protection': protection, 'protection_rules': list(protection.rules.all()) if protection else [],
            'protection_enabled_count': sum(1 for rule in protection.rules.all() if rule.protection_enabled) if protection else 0,
            'switched_count': sum(1 for rule in protection.rules.all() if rule.switched_at) if protection else 0,
            'can_edit_protection': user_can_edit,
            'protection_enabled': bool(protection and protection.enabled),
            'sos_public': protection.sos_public if protection else ''}


@login_required
@require_GET
def inventory(request, device_id):
    return render(request, 'sensors/inventory.html', context(
        device_for(device_id), request.user.is_staff or request.user.is_superuser))


@administrator
@require_POST
def ddos_protection_toggle(request, device_id):
    """Flip the DDoS Protection enabled flag for this device (storage only, no behaviour)."""
    device = device_for(device_id)
    from monitor.models import DeviceDDoSProtection
    with transaction.atomic():
        protection, _ = DeviceDDoSProtection.objects.select_for_update().get_or_create(device=device)
        requested = request.POST.get('enabled')
        # Explicit target value keeps repeated clicks idempotent.
        protection.enabled = (not protection.enabled) if requested is None else requested == '1'
        protection.save(update_fields=['enabled', 'updated_at'])
    messages.success(request, f"DDoS Protection {'enabled' if protection.enabled else 'disabled'} for {device.name}.")
    return redirect('devices')


@administrator
@require_POST
def ddos_protection(request, device_id):
    """Persist the device's NAT list plus its single SOS Public and Protection switch."""
    device = device_for(device_id)
    from monitor.models import DeviceDDoSProtection, DeviceDDoSProtectionRule
    from decimal import Decimal, InvalidOperation
    # Name + Value per row; blank names are dropped.
    names = request.POST.getlist('rule_name')
    values = request.POST.getlist('rule_value')
    rows = []
    for index, name in enumerate(names):
        name = name.strip()
        if not name:
            continue
        raw_value = (values[index] if index < len(values) else '').strip()
        try:
            value = Decimal(raw_value) if raw_value else None
        except (InvalidOperation, ValueError):
            value = None
        rows.append({'name': name, 'value': value})
    # One SOS Public and one Protection switch for the whole section (whole device).
    sos_public = request.POST.get('sos_public', '').strip()
    protection_enabled = request.POST.get('protection_enabled') == '1'
    with transaction.atomic():
        protection, _ = DeviceDDoSProtection.objects.select_for_update().get_or_create(device=device)
        previous_sos = (protection.sos_public or '').strip()
        protection.sos_public = sos_public
        protection.enabled = protection_enabled
        protection.save(update_fields=['sos_public', 'enabled', 'updated_at'])
        # Keep the switch latch only while the Sos Public target is unchanged AND the entry is
        # still switched to it. A changed SOS Public means every entry must be re-evaluated:
        # otherwise an entry latched under the old address could never fail over to the new one.
        changed_target = (previous_sos or '') != sos_public
        keep = {}
        if not changed_target:
            for rule in protection.rules.all():
                if rule.switched_at and (rule.switched_from or '') != sos_public:
                    keep[rule.name] = (rule.switched_at, rule.switched_from)
        protection.rules.all().delete()
        DeviceDDoSProtectionRule.objects.bulk_create([
            DeviceDDoSProtectionRule(
                protection=protection, position=position, name=row['name'], value=row['value'],
                sos_public=sos_public,
                protection_enabled=protection_enabled,
                switched_at=None if not protection_enabled else keep.get(row['name'], (None, ''))[0],
                switched_from='' if not protection_enabled else keep.get(row['name'], (None, ''))[1])
            for position, row in enumerate(rows)])
    messages.success(request, 'DDoS Protection settings saved for this device.' + (
        ' The SOS Public address changed, so all entries are re-armed for failover.' if changed_target else ''))
    return redirect('device_sensors', device_id=device.pk)
    messages.success(request, 'DDoS Protection settings saved for this device.')
    return redirect('device_sensors', device_id=device.pk)


@administrator
@require_POST
def ddos_protection_reset(request, device_id):
    """Clear an entry's switched latch so a later attack may trigger the switch again."""
    device = device_for(device_id)
    from monitor.models import DeviceDDoSProtectionRule
    rule = get_object_or_404(DeviceDDoSProtectionRule, pk=request.POST.get('rule_id'), protection__device=device)
    rule.switched_at = None
    rule.switched_from = ''
    rule.save(update_fields=['switched_at', 'switched_from'])
    messages.success(request, f"Automatic failover re-armed for {rule.name or 'this entry'}. "
                              "The NAT rule is not changed until the next confirmed attack.")
    return redirect('device_sensors', device_id=device.pk)


@administrator
@require_POST
def ddos_settings(request, device_id):
    device = device_for(device_id)
    from monitor.models import DeviceDDoSThreshold
    from monitor.forms import DeviceDDoSThresholdForm
    if request.POST.get('action') == 'reset':
        DeviceDDoSThreshold.objects.filter(device=device).delete()
        messages.success(request, 'DDoS thresholds reset to the global defaults.')
        return redirect('device_sensors', device_id=device.pk)
    override = DeviceDDoSThreshold.objects.filter(device=device).first()
    form = DeviceDDoSThresholdForm(request.POST, instance=override)
    if form.is_valid():
        instance = form.save(commit=False)
        instance.device = device
        instance.save()
        messages.success(request, 'DDoS thresholds saved for this device. Detection activation was not changed.')
        return redirect('device_sensors', device_id=device.pk)
    ctx = context(device)
    ctx['ddos_form'] = form
    ctx['has_ddos_override'] = bool(override)
    messages.error(request, 'Thresholds were not saved. Correct the errors below.')
    return render(request, 'sensors/inventory.html', ctx, status=400)


@administrator
@require_POST
@sensitive_post_parameters('community')
@sensitive_variables()
def profile(request, device_id):
    device = device_for(device_id)
    ctx = context(device)
    form = ProfileForm(request.POST)
    ctx['profile_form'] = form
    if form.is_valid():
        try:
            community, port = form.cleaned_data['community'], form.cleaned_data['port']
            ciphertext = encrypt_password(community)
            snmp.read(device, community, port, 'test')
            with transaction.atomic():
                current_device = Device.objects.select_for_update().get(pk=device.pk)
                if current_device.management_ip != device.management_ip or not current_device.enabled:
                    raise snmp.SNMPError('The device changed during the connection test. Try again.')
                existing = SNMPProfile.objects.filter(device=device).first()
                SNMPProfile.objects.update_or_create(device=device, defaults={
                    'community': ciphertext, 'port': port, 'validated_ip': device.management_ip,
                    'tested_at': timezone.now(), 'revision': existing.revision + 1 if existing else 1})
                Sensor.objects.filter(device=device).exclude(kind='ping').update(enabled=False, revision=F('revision') + 1)
            messages.success(request, 'SNMP connection verified. Credentials saved encrypted; SNMP sensors remain stopped. Ping sensors are unaffected by SNMP credentials.')
            return redirect('device_sensors', device_id=device.pk)
        except snmp.SNMPError as error:
            form.add_error(None, str(error))
        except (CredentialError, ImproperlyConfigured):
            form.add_error(None, 'SNMP credential encryption is unavailable. Check the server encryption key.')
    return render(request, 'sensors/inventory.html', ctx, status=400)


def saved_profile(device):
    profile = SNMPProfile.objects.filter(device=device).first()
    if not device.enabled or not profile or profile.validated_ip != device.management_ip:
        raise snmp.SNMPError('Test and save SNMP credentials for this device first.')
    return profile


@administrator
@require_POST
def discover(request, device_id):
    device = device_for(device_id)
    ctx = context(device)
    try:
        profile = saved_profile(device)
        interfaces = snmp.read(device, decrypt_password(profile.community), profile.port, 'interfaces')
        token = signing.dumps({'device': device.pk, 'ip': device.management_ip, 'revision': profile.revision,
                               'user': request.user.pk, 'interfaces': interfaces}, salt='snmp-discovery', compress=True)
        ctx['sensor_form'] = AddSensorForm(interfaces=interfaces,
            initial={'kind': 'traffic', 'discovery': token, 'interval': 10})
        ctx['discovered'] = True
        if not interfaces:
            ctx['sensor_error'] = 'No interfaces were returned by the device.'
    except snmp.SNMPError as error:
        ctx['sensor_error'] = str(error)
    except (CredentialError, ImproperlyConfigured):
        ctx['sensor_error'] = 'Stored SNMP credentials could not be decrypted.'
    return render(request, 'sensors/inventory.html', ctx, status=400 if ctx.get('sensor_error') else 200)


@administrator
@require_POST
def detect(request, device_id):
    device = device_for(device_id)
    ctx = context(device)
    kind = request.POST.get('kind')
    if kind not in ('cpu', 'uptime', 'ping'):
        return JsonResponse({'error': 'Choose CPU, Uptime or Ping.'}, status=400)
    ctx['sensor_form'] = AddSensorForm(initial={'kind': kind, 'interval': 10})
    if kind == 'ping':
        # A one-off ICMP probe: needs no SNMP credentials and creates no sensor.
        try:
            reading = ping.probe(device)
            if reading['ping_ms'] is None:
                raise ping.PingError('Ping detected no reply (100% packet loss).')
            ctx['sensor_success'] = (f"Ping Sensor detected: {reading['ping_ms']:.1f} ms, "
                                     f"{reading['packet_loss']:g}% loss. You can now add this sensor.")
        except ping.PingError as error:
            ctx['sensor_error'] = str(error)
        return render(request, 'sensors/inventory.html', ctx, status=400 if ctx.get('sensor_error') else 200)
    try:
        profile = saved_profile(device)
        reading = snmp.read(device, decrypt_password(profile.community), profile.port, 'sample', SimpleNamespace(kind=kind))
        value = f"{reading['cpu']:.1f}%" if kind == 'cpu' else format_uptime(reading['uptime_seconds'])
        ctx['sensor_success'] = f"{dict(Sensor.KINDS)[kind]} detected: {value}. You can now add this sensor."
    except snmp.SNMPError as error:
        ctx['sensor_error'] = str(error)
    except (CredentialError, ImproperlyConfigured):
        ctx['sensor_error'] = 'Stored SNMP credentials could not be decrypted.'
    return render(request, 'sensors/inventory.html', ctx, status=400 if ctx.get('sensor_error') else 200)


@administrator
@require_POST
def add(request, device_id):
    device = device_for(device_id)
    ctx = context(device)
    interfaces = []
    kind = request.POST.get('kind')
    try:
        # Ping sensors use ICMP only: they are validated by the device allowlist at
        # probe time and never require saved SNMP credentials.
        profile = None if kind == 'ping' else saved_profile(device)
        if kind == 'ping':
            # Validate the management address against the allowlist before anything is saved.
            ping.check_target(device)
        if request.POST.get('kind') == 'traffic':
            payload = signing.loads(request.POST.get('discovery', ''), salt='snmp-discovery', max_age=600)
            if (payload['device'], payload['ip'], payload['revision'], payload['user']) != (device.pk, device.management_ip, profile.revision, request.user.pk):
                raise signing.BadSignature()
            interfaces = payload['interfaces']
        form = AddSensorForm(request.POST, interfaces=interfaces)
        ctx['sensor_form'], ctx['discovered'] = form, bool(interfaces)
        if form.is_valid():
            data = form.cleaned_data
            targets = [i for i in interfaces if str(i['index']) in data['interfaces']] if data['kind'] == 'traffic' else [{'index': 0, 'name': ''}]
            if not targets:
                form.add_error('interfaces', 'Select at least one discovered interface.')
            else:
                created_ids = []
                with transaction.atomic():
                    for target in targets:
                        sensor, created = Sensor.objects.get_or_create(device=device, kind=data['kind'], interface_index=target['index'], defaults={
                            'interface_name': target['name'], 'name': target['name'] or dict(Sensor.KINDS)[data['kind']], 'interval': data['interval']})
                        if created:
                            created_ids.append(sensor.pk)
                try:
                    start_sensors(created_ids)
                    messages.success(request, 'New sensors are monitoring. CPU and uptime need one reading; bandwidth needs two counter readings.' if created_ids else 'These sensors already exist. Use Start to resume a stopped sensor.')
                except StartupError as error:
                    messages.error(request, f'Sensors saved, but monitoring could not start. {error}')
                return redirect('device_sensors', device_id=device.pk)
    except ping.PingError as error:
        ctx['sensor_error'] = str(error)
    except (signing.BadSignature, KeyError, TypeError):
        ctx['sensor_error'] = 'Interface selection expired or changed. Discover interfaces again.'
    except snmp.SNMPError as error:
        ctx['sensor_error'] = str(error)
    return render(request, 'sensors/inventory.html', ctx, status=400)


@administrator
def edit(request, device_id, sensor_id):
    sensor = get_object_or_404(Sensor, pk=sensor_id, device_id=device_id)
    form = EditSensorForm(request.POST if request.method == 'POST' else None, instance=sensor)
    if request.method == 'POST' and form.is_valid():
        # Update only editable fields; preserve concurrent Start/Stop state.
        Sensor.objects.filter(pk=sensor.pk).update(name=form.cleaned_data['name'], interval=form.cleaned_data['interval'], revision=F('revision') + 1)
        messages.success(request, 'Sensor settings saved. The worker applies the new interval automatically.')
        return redirect('device_sensors', device_id=device_id)
    return render(request, 'sensors/edit.html', {'form': form, 'sensor': sensor})


@administrator
@require_POST
def control(request, device_id, sensor_id, action):
    sensor = get_object_or_404(Sensor, pk=sensor_id, device_id=device_id)
    if action == 'delete':
        sensor.delete()
        messages.success(request, 'Sensor and its historical samples deleted from NetShield.')
    elif action in ('start', 'stop'):
        if action == 'start' and sensor.kind != 'ping':
            try:
                saved_profile(device_for(device_id))
            except snmp.SNMPError as error:
                messages.error(request, str(error))
                return redirect('devices') if request.POST.get('next') == 'devices' else redirect('device_sensors', device_id=device_id)
        if action == 'start':
            try:
                start_sensors([sensor.pk])
                messages.success(request, 'Sensor started. Waiting for a valid ping reply.' if sensor.kind == 'ping' else 'Sensor started. Waiting for a valid SNMP reading.')
            except StartupError as error:
                messages.error(request, str(error))
        else:
            Sensor.objects.filter(pk=sensor.pk).update(enabled=False, revision=F('revision') + 1)
            messages.success(request, 'Sensor stopped; historical samples retained.')
    else:
        return JsonResponse({'error': 'Unknown action'}, status=400)
    return redirect('devices') if request.POST.get('next') == 'devices' else redirect('device_sensors', device_id=device_id)


@login_required
@require_GET
def data(request, device_id):
    device = device_for(device_id)
    gate, running = authorized(), worker_running()
    rows = []
    for sensor in Sensor.objects.filter(device=device):
        samples = list(sensor.samples.order_by('-timestamp', '-pk')[:120])[::-1]
        last = samples[-1] if samples else None
        fresh = last and last.timestamp >= timezone.now() - timedelta(seconds=max(30, sensor.interval * 3))
        if not sensor.enabled:
            status = 'Stopped'
        elif not gate or not running or not device.enabled:
            status = 'Paused'
        elif not last:
            status = 'Waiting for data'
        elif not fresh:
            status = 'Stale'
        elif not last.valid:
            status = 'Connection Failed'
        else:
            status = 'Active'
        row = {'id': sensor.pk, 'status': status, 'last_success': sensor.last_success,
               'error': sensor.error, 'kind': sensor.kind, 'interval': sensor.interval,
               'cpu': None, 'uptime': None, 'in_mbps': None, 'out_mbps': None,
               'ping_ms': None, 'packet_loss': None,
               'interface_status': None, 'restart_detected': False, 'counter_reset': False,
               'history': [{'timestamp': s.timestamp, 'cpu': s.cpu, 'in_mbps': s.in_mbps, 'out_mbps': s.out_mbps,
                            'uptime': format_uptime(s.uptime_seconds), 'restart_detected': s.restart_detected,
                            'ping_ms': s.ping_ms if s.valid else None,
                            'packet_loss': s.packet_loss if s.valid else None,
                            'valid': s.valid} for s in samples]}
        if last and last.valid:
            row.update(cpu=last.cpu, uptime=format_uptime(last.uptime_seconds), in_mbps=last.in_mbps,
                       out_mbps=last.out_mbps, interface_status=last.interface_status,
                       ping_ms=last.ping_ms, packet_loss=last.packet_loss,
                       restart_detected=last.restart_detected, counter_reset=last.counter_reset)
        row['restart_count'] = sensor.samples.filter(restart_detected=True).count()
        rows.append(row)
    response = JsonResponse({'sensors': rows, 'worker_running': running, 'polling_authorized': gate})
    response['Cache-Control'] = 'no-store'
    return response
