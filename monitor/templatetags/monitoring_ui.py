"""Presentation labels only; no router operations."""
from django import template

register = template.Library()


@register.filter
def provisioning_label(row):
    if row.get("provisioning_code") == "rule_conflict":
        return "Conflict"
    if row.get("provisioning_status") == "verified":
        return "Provisioned"
    if row.get("provisioning_status") == "failed":
        return "Failed"
    return "Pending"


@register.filter
def monitoring_label(row):
    if row.get("monitoring_health"):
        return row["monitoring_health"]
    if row.get("retained"):
        return "Saved Sample"
    if row.get("provisioning_status") != "verified" or not row.get("monitoring_enabled"):
        return "Not Monitored"
    return "Active" if row.get("monitoring_status") == "Monitoring" else "No Data"
