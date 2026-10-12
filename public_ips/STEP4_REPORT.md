# NetShield Step 4 report

Implemented Add Public IP, assignment to a saved MikroTik device, and display of
real assignments in the existing Public IPs and Devices interfaces.

## Files created

- public_ips/__init__.py
- public_ips/apps.py
- public_ips/models.py
- public_ips/forms.py
- public_ips/views.py
- public_ips/urls.py
- public_ips/migrations/__init__.py
- public_ips/migrations/0001_initial.py
- public_ips/tests.py
- public_ips/README.md
- public_ips/STEP4_REPORT.md

## Existing files modified

- netshield/settings.py: register the dedicated app.
- monitor/urls.py: preserve named public_ips URL and route it to the app.
- devices/views.py: group credential-free public IP values by saved device.
- monitor/templates/monitor/public_ips.html: real inventory and native POST modal.
- monitor/templates/monitor/devices.html: expandable Assigned Public IPs per row.
- monitor/static/monitor/js/public_ips.js: allow Add POST, show validation errors,
  filter real rows; future monitoring previews remain local and cannot save.
- monitor/templates/monitor/components/header.html: Public IP inventory label.
- devices/tests/test_monitoring_regression.py: update anonymous Public IP page
  expectation to the required login redirect; monitoring tests preserved.

## Behavior and security

PublicIP stores unique IPv4 address, protected Device ForeignKey, optional
description, and created/updated dates. One MikroTik device can have many addresses.
The form accepts only saved MikroTik devices and publicly routable IPv4 literals;
it rejects invalid/private/reserved/IPv6/multicast addresses and global duplicates.
Success appears only after a committed save. Race/database failures are handled
with safe messages and no false success.

All Public IP inventory/management requires login. Active staff and superusers
may add; readers cannot add by direct POST. POST and Django CSRF are required.
Neither dropdown nor inventory queries fetch device username/ciphertext.
Public IP operations do not require credential decryption or connect to a router.

Inventory columns: Public IP, Assigned Device, Device Management IP, Description,
Status, Actions. Status is always Not monitored. Edit/remove and monitoring actions
remain unavailable. Devices show real assigned addresses below each device name.
No example IPs were inserted into the live database.

## Backup and migration

Backup directory: D:/DDOS/backups/public-ips-step4-20261010T095529Z

Affected pre-existing source files were copied before modification. The directory
also contains original source hashes, device-preservation digests and
db-pre-migration.sqlite3, produced with SQLite's online backup API and verified
using integrity_check before migration.

Applied: public_ips.0001_initial.
One existing device was retained. A comparison of every original device field,
including encrypted ciphertext, confirmed no changes after migration.
Live SQLite integrity verified; new Public IP table contained zero records.

## Test results

- Django system checks: normal and local settings, no issues.
- makemigrations --check --dry-run: no changes detected.
- migrate --check: no unapplied migrations.
- Public IP focused tests: 21 passed.
- Public IP plus monitoring regression tests after updating authentication
  expectation: 23 passed.
- Final complete regression suite: 125 passed in 32.128 seconds.
- JavaScript syntax check: passed.

Tests cover valid/invalid creation, optional description, multiple addresses per
device, duplicate validation and database uniqueness, missing/non-MikroTik devices,
protected device deletion, authentication/staff/superuser/inactive permissions,
POST/CSRF, safe database failure handling, escaping, no example seeding,
credential-free SQL/responses, unchanged ciphertext and absence of router calls.
The complete suite also covers device models/encryption, Add Device, real
connection code through mocks, local authentication and Dashboard start/stop/data
behavior with mocked router reads.

Source hash audit confirmed the existing MikroTik monitoring service, Dashboard
JavaScript/two-second refresh, theme script, device model, encrypted credential
service and Step 3 connection service were unchanged. Existing monitoring endpoint
paths/names and behavior are preserved.

No live router calls or interactive browser checks were performed during Step 4.
Server-rendered pages, forms and HTTP security were verified with Django clients;
browser modal behavior was reviewed and JavaScript syntax checked.

## Browser verification

1. Restart NetShield using .\start-netshield-local.ps1.
2. Open http://127.0.0.1:8000/public-ips/ and sign in as an administrator if needed.
3. Choose Add Public IP, enter an address you manage, select a saved MikroTik,
   optionally enter a description, then Save.
4. Confirm the success message and Not monitored inventory row.
5. Open Devices and expand Assigned Public IPs below the assigned device name.
6. A second different address may use the same device. Repeating an existing
   address shows validation errors and does not save.

No SNMP, automatic monitoring, firewall changes, traffic graphs or DDoS detection
implemented. Stopped after Step 4.
