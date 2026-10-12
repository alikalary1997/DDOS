"""Approval-gated cleanup of audited, exact NetShield rules only.

Never called by device deletion or the shared database-only assignment service.
"""
from devices.models import Device
from devices.services.router_lock import RouterBusy, router_lock
from devices.services.router_session import RouterAccessError, router_session
from public_ips.models import AssignmentReview, PublicIP
from .provisioning import ProvisionResult, writes_enabled
from .rules import RuleConflict, expected_rules, matches, rule_id


def cleanup_review(review_id, actor):
    if not actor or not actor.is_authenticated or not actor.is_active or not (actor.is_staff or actor.is_superuser):
        return ProvisionResult(code="permission_denied", message="Administrator access is required.")
    review = AssignmentReview.objects.get(pk=review_id)
    if review.action == "device_delete":
        return ProvisionResult(code="database_only", message="Device deletion is database-only; router cleanup is not permitted.")
    if not writes_enabled():
        return ProvisionResult(code="approval_required", message="Router cleanup awaits approval. No router connection or change was performed.")
    if not review.cleanup_required:
        return ProvisionResult(success=True, code="not_required", message="No router cleanup is required.")
    removed = list(review.removed_rule_ids)
    try:
        with router_lock(review.previous_device_id_snapshot):
            review.refresh_from_db()
            device = Device.objects.get(pk=review.previous_device_id_snapshot)
            if device.management_ip != review.previous_management_ip:
                raise RuleConflict("The original router connection profile changed; manual review is required.")
            if PublicIP.objects.filter(address=review.previous_address, device_id=device.pk).exclude(pk=review.public_ip_id).exists():
                raise RuleConflict("Another current public IP record uses this rule set; cleanup was blocked.")
            specifications = expected_rules(review.previous_address, review.previous_interface)
            by_comment = {spec["comment"]: spec for spec in specifications}
            known = set()
            for reference in review.rule_references:
                if reference.get("device_id") == device.pk and reference.get("address_snapshot") == review.previous_address:
                    known.update(reference.get("verified_rule_ids", []))
                    known.update(reference.get("created_rule_ids", []))
            with router_session(device) as api:
                raw = api.get_resource("/ip/firewall/raw")
                def candidates():
                    rows = raw.get()
                    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                        raise RuleConflict("The RAW rule listing could not be validated.")
                    ids = [rule_id(row) for row in rows]
                    if len(ids) != len(set(ids)):
                        raise RuleConflict("Duplicate RAW rule identifiers require manual review.")
                    result = []
                    for comment, specification in by_comment.items():
                        selected = [row for row in rows if row.get("comment") == comment]
                        if len(selected) > 1:
                            raise RuleConflict("Duplicate monitoring comments require manual review.")
                        if selected:
                            row = selected[0]
                            if rule_id(row) not in known or not matches(row, specification):
                                raise RuleConflict("Rule ownership or properties could not be verified; cleanup was blocked.")
                            result.append(rule_id(row))
                    return result
                targets = candidates()  # Validate the entire set before removing anything.
                for identifier in targets:
                    if identifier not in candidates():
                        continue
                    if not writes_enabled():
                        raise RouterAccessError("approval_required", "Router cleanup awaits approval.")
                    requested = list(review.requested_removal_ids)
                    if identifier not in requested:
                        requested.append(identifier)
                    AssignmentReview.objects.filter(pk=review.pk).update(requested_removal_ids=requested, cleanup_code="removing", cleanup_message="Removal requested; verification pending.")
                    review.requested_removal_ids = requested
                    raw.remove(id=identifier)
                    if identifier in candidates():
                        raise RuleConflict("Rule removal could not be verified.")
                    if identifier not in removed:
                        removed.append(identifier)
                    AssignmentReview.objects.filter(pk=review.pk).update(removed_rule_ids=removed)
                if candidates():
                    raise RuleConflict("Monitoring rules remain; cleanup could not be verified.")
            AssignmentReview.objects.filter(pk=review.pk).update(status="completed", cleanup_required=False, cleanup_code="verified", cleanup_message="Associated monitoring rule cleanup verified.", removed_rule_ids=removed)
            return ProvisionResult(success=True, code="verified", message="Associated monitoring rule cleanup verified.")
    except Device.DoesNotExist:
        code, message = "device_missing", "The original device no longer exists. Router cleanup was not performed."
    except (RuleConflict, RouterBusy) as error:
        code, message = "cleanup_conflict", str(error)
    except RouterAccessError as error:
        code, message = error.code, str(error)
    except Exception:
        code, message = "cleanup_failed", "Cleanup could not be verified. Retry will check audited rules before further changes."
    AssignmentReview.objects.filter(pk=review.pk).update(cleanup_code=code, cleanup_message=message, removed_rule_ids=removed)
    return ProvisionResult(code=code, message=message)
