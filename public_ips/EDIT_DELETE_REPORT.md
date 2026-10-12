# Public IP Inventory: layout, edit and delete

## Changes
- Consistent explicit column widths, numeric alignment, wrapping descriptions/status messages, a dedicated 250px Actions column, and horizontal scrolling on small screens. Uses existing theme variables and page design.
- Every administrator row has Edit and Delete actions, alongside unchanged Retry provisioning, Start Monitoring and Stop Monitoring actions.
- Edit opens the existing inventory with a pre-filled modal for address, saved MikroTik device and description. Validation errors reopen the form without committing invalid data. Successful saving redirects to refreshed inventory.
- Delete opens a confirmation modal. Removal requires an authenticated administrator, CSRF-protected POST and explicit confirmation. Failures show sanitized messages.
- Edits/deletes are database-only and never call RouterOS or provisioning. Changing the address or assigned device stops its polling, clears verification and removes its cached samples. Retry provisioning remains separate and gated. Description-only editing preserves verification and polling preference; cache versioning safely rebaselines rates.
- Delete stops the assignment's NetShield polling, removes only that assignment's cached rows, retains other assignments/devices, and retains provisioning audit snapshots.
- Shared per-device locks serialize changes with polling/provisioning. Busy devices or pending provisioning are refused with a retry message. Transactions roll back cleanup if saving/deleting fails.
- Add, Search, Device Filter, Monitoring Status Filter, device controls and two-second counter refresh are retained.

## Files
Updated:
- public_ips/models.py
- public_ips/views.py
- public_ips/urls.py
- monitor/templates/monitor/public_ips.html
- monitor/static/monitor/css/public_ips.css
- monitor/static/monitor/js/public_ips.js
Created:
- public_ips/services/assignments.py
- public_ips/migrations/0003_alter_provisioningattempt_public_ip.py
- public_ips/tests/test_edit_delete.py

The migration changes only ProvisioningAttempt.public_ip to nullable SET_NULL, allowing an assignment to be deleted while preserving its audit history. Applied successfully; no pending migrations or model changes remain.

## Validation
- Project Python environment verified (Django 6.1.2).
- 11 focused edit/delete tests passed.
- Full automated suite: 182 tests passed, including existing Dashboard, encrypted credential, device, Public IP, RAW provisioning and counter tests.
- Django system checks passed.
- makemigrations --check --dry-run and migrate --check passed.
- JavaScript syntax check passed after final UI changes.
- Existing device, public IP, audit and sample rows compared to backup after migration: unchanged; SQLite foreign key check passed.
- Live provisioning and polling remain disabled; no real router connections or configuration changes were made.
- Browser visual verification could not be performed: no browser was available.

Backup before modification and migration: D:/DDOS/backups/public-ip-edit-delete-2026-10-10T134300800Z.

## Use
Reload /public-ips/ (restart the local development server if it has not reloaded). As an administrator, choose Edit for a pre-filled form or Delete for confirmation. Address/device changes require a separate approved Retry provisioning; existing MikroTik rules remain untouched. No new credentials are needed.
