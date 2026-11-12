"""Consume persisted cache updates without changing polling or router operations."""
import logging
from django.db import transaction
from django.db.models.signals import post_save
from django.dispatch import receiver
from public_ips.models import FirewallSample


@receiver(post_save, sender=FirewallSample, dispatch_uid="netshield_detect_firewall_sample")
def detect_sample(sender, instance, raw=False, **kwargs):
    if raw:
        return
    from .services.detection import process_sample
    try:
        # A detection failure must not roll back a successfully collected sample.
        with transaction.atomic():
            process_sample(instance)
    except Exception:
        logging.getLogger(__name__).exception("Detection evaluation failed for device_id=%s", instance.device_id)
    # Automatic NAT failover rides on the same cycle, after confirmed states are saved.
    try:
        from .services.nat_failover import evaluate_device_failover
        evaluate_device_failover(instance.device_id)
    except Exception:
        logging.getLogger(__name__).exception("NAT failover check failed for device_id=%s", instance.device_id)
