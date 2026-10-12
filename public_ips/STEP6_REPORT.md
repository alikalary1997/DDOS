# Step 6: database-side Public IP management

## Implemented
- Edit existing public IPv4 address, assigned saved MikroTik device and description using the existing pre-filled inventory modal. Validation and global duplicate rejection are preserved.
- Reassign an IP to another saved MikroTik through Edit. Select Unassigned to retain the IP without a device, or use the dedicated administrator-only POST Unassign action.
- Confirmed Delete permanently removes the selected NetShield IP record while preserving provisioning audits and review records. No other IP/device records are removed.
- The Devices expanded Assigned Public IPs section exposes Edit, Unassign and Delete to administrators, reusing the Public IP endpoints.
- Public IP inventory explicitly displays Unassigned and offers an Unassigned device filter. Existing Add, search, filters, polling controls and Retry Provisioning are retained.
- Dashboard uses the existing database-driven endpoint and two-second refresh: only assigned IPs are included; deleted/unassigned IPs disappear and reassigned IPs cannot reuse old samples.

## Provisioning and cache safety
Every successful edit (including description-only), reassign, unassign and delete stops this IP's polling, clears its cached rows and verification, and records review history transactionally. Retained records enter review_required. Per-device locks serialize changes against existing router work; busy/pending provisioning refuses the change with a retry message.

The new AssignmentReview model preserves previous address/device/interface and provisioning status, actor and timestamp, new assignment, and known requested comments/created or verified rule IDs copied from provisioning audit history. Review records survive deletion and include durable device snapshots. Existing rule IDs remain historical references only, never verification for a new assignment. Historical rule review counts appear in inventory when cleanup may be needed. No cleanup has been performed or claimed. Existing provisioning audits remain intact.

Unassigned IPs are refused by provisioning and monitoring-start controls, and excluded from the worker's device selection. No router connection, creation, deletion, or configuration modification was made in this step. Live provisioning and polling gates and settings remain OFF.

## Files
Updated:
- public_ips/models.py
- public_ips/forms.py
- public_ips/views.py
- public_ips/urls.py
- public_ips/services/assignments.py
- public_ips/services/provisioning.py (unassigned-target guard only; release gate unchanged)
- public_ips/management/commands/poll_raw_firewall.py (exclude unassigned IPs)
- devices/views.py
- monitor/templates/monitor/devices.html
- monitor/templates/monitor/public_ips.html
- public_ips/tests/test_edit_delete.py (description edits now require review)
Created:
- public_ips/migrations/0004_alter_publicip_device_assignmentreview.py
- public_ips/tests/test_assignment_lifecycle.py

The existing MikroTik monitoring/API service, firewall rule templates, theme styles, and Dashboard refresh implementation were not modified.

## Verification
- Python environment verified: project virtual environment, Django 6.1.2.
- 23 focused edit/delete/lifecycle tests passed.
- Full automated suite: 194 tests passed (including existing device, Dashboard, encrypted credential, RAW provisioning, monitoring, authentication and CSRF tests).
- Django system checks passed.
- makemigrations --check --dry-run: no changes detected.
- migrate --check: passed.
- Applied public_ips.0004_alter_publicip_device_assignmentreview successfully after automated tests passed.
- JavaScript syntax check passed.
- Existing device, Public IP, audit and sample rows compared to the backup after migration: unchanged. SQLite foreign key check passed. No example data or review records seeded.
- All live release gates and settings verified disabled. Real routers were not contacted.
- No browser visual verification was performed.

Backup of affected files and SQLite before changes: D:/DDOS/backups/step6-public-ip-2026-10-10T135629865Z.

## Local use
Refresh Devices or Public IPs; restart .\start-netshield-local.ps1 if needed to load Python changes. Edit chooses a new device or Unassigned. Unassign keeps the record; Delete asks for confirmation. The Dashboard updates through its existing two-second refresh. Changed assignments require provisioning review; live router cleanup or provisioning needs a separate approved step.
