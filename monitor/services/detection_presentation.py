"""Read-only status projection. Unavailable traffic never becomes Normal."""
from django.utils import timezone
from monitor.models import DDoSDetectionSettings, DetectionPolicy, DetectionState
from public_ips.models import PublicIP
from public_ips.services.monitoring import polling_enabled
from public_ips.services.monitoring_runtime import live_run
from .detection import authorized, configuration_key, profile_key, timestamp
from .raw_settings import sample_freshness_seconds


class DetectionPresentation:
    def __init__(self):
        self.policy = DetectionPolicy.objects.filter(pk=1).first()
        self.thresholds = DDoSDetectionSettings.objects.filter(pk=1).first()
        self.states = {state.public_ip_id: state for state in DetectionState.objects.all()}
        self.ips = {ip.pk: ip for ip in PublicIP.objects.select_related("device").defer("device__username", "device__encrypted_password")}
        self.polling = polling_enabled()
        self.run = live_run()

    def fields(self, assignment_id, row):
        ip = self.ips.get(assignment_id)
        at = timestamp(row.get("attempted_at"))
        fresh = at and 0 <= (timezone.now() - at).total_seconds() <= sample_freshness_seconds(row.get("polling_interval"))
        monitored = (ip and ip.device_id and ip.device.enabled and self.polling and ip.monitoring_enabled and ip.provisioning_status == "verified"
                     and (not self.run or self.run.assignment_id_snapshot == assignment_id))
        health = "Not Monitored"
        if monitored:
            health = "Stale"
            if fresh and row.get("status") == "Connection error":
                health = "Connection Failed"
            elif fresh and row.get("status") == "Monitoring" and not row.get("retained"):
                health = "Active"
        result = {"monitoring_health": health, "ddos_status": "Unknown", "ddos_metrics": [],
                  "detection_enabled": bool(ip and ip.detection_enabled),
                  "ddos_message": "Detection is disabled for this assignment."}
        if not ip or not authorized(self.policy, ip) or not self.thresholds:
            return result
        state = self.states.get(assignment_id)
        result["ddos_message"] = "Waiting for fresh, valid detection samples."
        if (health == "Active" and state and state.last_valid_at == at and state.profile_key == profile_key(ip)
                and state.configuration_key == configuration_key(self.thresholds, self.policy)):
            result.update(ddos_status=state.confirmed_status, ddos_metrics=state.triggering_metrics,
                          ddos_message="" if state.confirmed_status != "Unknown" else "Confirming consecutive samples.")
        return result
