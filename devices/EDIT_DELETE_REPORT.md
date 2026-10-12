# Devices: working Edit and Delete actions

## Behavior
The existing Actions menu exposes Test Connection, Edit Device and Delete Device for administrators. Existing Load/Save incoming interface controls remain available. The existing page, themes, search/filter controls, Dashboard and Public IP workflows are preserved.

Edit opens an existing-style pre-filled modal for device name, management IP, API port, API-SSL, API username, optional replacement password, incoming monitoring interface and description. The existing password/ciphertext is never rendered. Blank password keeps the exact ciphertext; a replacement uses the existing Fernet service and server-side environment key. Field validation, canonical management addresses and duplicate endpoint checks remain enforced. Encryption configuration errors fail closed. The API username is shown only in the authenticated administrator's edit form because editing it is explicitly requested; inventory and JSON results exclude credentials.

Edit/Delete saves use authenticated, CSRF-protected POST. JavaScript submits asynchronously and updates the inventory row, counters and details without a full-page reload; native server forms remain available as fallback. Validation/failure messages are sanitized and passwords are cleared in the modal after submission/close.

Delete confirmation shows the saved device name and current assigned public IP count. Assigned public IPs block deletion both in the UI and on the server, including direct POST; users must unassign/reassign them first. No public IP record is automatically removed. Confirmation is required. Transactions and per-device locks guard mutations and audit persistence. Pending provisioning/busy devices refuse edits/deletion safely.

## Monitoring and audit integrity
Changing endpoint, TLS setting, API username/password or incoming interface clears old connection snapshots and invalidates assigned public IP verification/cached counters. Assigned IPs remain linked and enter provisioning review, preserving old rule references through the existing AssignmentReview mechanism. Name/description-only changes preserve existing monitoring preference/verification.

A late Test Connection result cannot overwrite a newer edited profile or newer test. The MikroTik API/connection service itself is unchanged.

New credential-free DeviceChange audit records retain device ID/name/management endpoint/interface snapshots, actor, action, changed field names and assigned IP count. They contain no password, ciphertext, API username or encryption key and survive device deletion. Existing provisioning audits and assignment-review snapshots remain retained. Only an unassigned device's obsolete sample cache is removed with that device. No router configuration or firewall rules are changed.

## Files
Updated:
- devices/models.py
- devices/forms.py
- devices/views.py
- devices/urls.py
- monitor/templates/monitor/devices.html
- monitor/templates/monitor/components/device_actions.html
- monitor/static/monitor/js/devices.js
- devices/tests/test_add_inventory.py (replace old disabled-menu expectation)
Created:
- devices/services/management.py
- devices/migrations/0004_devicechange.py
- devices/tests/test_management.py

## Validation
- Verified project virtual environment (Django 6.1.2).
- 17 focused management tests passed.
- Full suite: 211 automated tests passed, including existing Devices, Test Connection, encrypted credentials, Public IP lifecycle, Dashboard, RAW provisioning and monitoring tests.
- Django system checks passed.
- makemigrations --check --dry-run: no changes detected.
- migrate --check passed after applying devices.0004_devicechange successfully.
- JavaScript syntax check passed after final UI changes.
- Existing device, public IP, sample, provisioning audit and assignment review records compared to backup by named columns: unchanged; SQLite foreign key check passed; no audit/example records seeded.
- All live provisioning/polling gates and settings remain disabled. No real router calls, configuration changes or firewall changes were made.
- No browser visual verification was performed.

Backup before modifications and migration: D:/DDOS/backups/device-edit-delete-2026-10-10T141737567Z.

Reload /devices/ (restart .\start-netshield-local.ps1 if Python changes have not reloaded). As an administrator, select Actions â†’ Edit Device or Delete Device. Leave password empty to preserve it. Device deletion atomically deletes all assigned public IP records and their cached monitoring state. Provisioning history is retained; MikroTik RAW rules are not removed.
