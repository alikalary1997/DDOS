# NetShield Step 3 implementation report

Implemented saved-device-only MikroTik connection testing, real system snapshots,
and asynchronous updates in the existing Devices page.

## Files

Created:
- devices/services/targets.py: server-owned literal-IP/CIDR/port/timeout policy.
- devices/services/connection.py: read-only routeros_api probes, verified TLS,
  short timeouts, credential decryption, safe result parsing, disconnect cleanup.
- devices/presentation.py: explicit credential-free result/inventory projection.
- devices/checks.py: configuration system checks.
- devices/migrations/0002_connection_snapshots.py: nullable snapshots/test outcome,
  CPU and memory constraints.
- devices/tests/test_connection.py: 18 mocked connection/security/failure tests.
- devices/STEP3_REPORT.md: this report.

Modified:
- devices/models.py, apps.py, views.py, urls.py and README.md.
- devices/tests/test_add_inventory.py: existing status expectations updated.
- netshield/settings.py and netshield/settings_local.py: explicit CIDR allowlist,
  three-second operation timeout and optional trusted CA file configuration.
- monitor/templates/monitor/devices.html and components/device_actions.html.
- monitor/static/monitor/js/devices.js and css/devices.css.

## Backups and migration

Pre-change source copies and original source hashes:
backups/devices-step3-20261010T091139Z

SQLite online backup immediately before migrating:
backups/devices-step3-20261010T091139Z/db-pre-migration.sqlite3

Both backup integrity and live SQLite integrity verified. Migration
devices.0002_connection_snapshots applied successfully. A digest comparison of all
original device fields confirmed the existing one device and its encrypted
credentials were unchanged. The persistent Windows-user Fernet key was verified
against stored ciphertext without displaying any secret; no new key was generated.

## Verification

- Django checks: normal and explicit local settings, no issues.
- makemigrations --check --dry-run: no changes detected.
- migrate --check: no unapplied migrations.
- Complete regression suite: 102 passed.
- Final focused run: 45 passed (18 connection + 27 inventory), including two
  additional permission/database-error cases added after the full run.
- Total distinct passing test cases: 104.
- JavaScript node --check: passed.
- Existing Dashboard monitoring regression tests passed with mocked router calls.
- Original source hashes confirm the MikroTik monitoring service, Dashboard
  templates/JavaScript, shared theme assets and monitoring routes were unchanged.
- No live router was contacted during implementation; connection tests use mocks.
  Interactive browser/real-router verification remains for the local user.

Covered saved targets only; allowlist/port rejection before decryption/network;
TLS certificate enforcement/no downgrade; timeout/refusal/auth failures;
connection cleanup; missing/wrong keys; sanitized raw exceptions and reflected
router secrets; authentication/staff/superuser/inactive permissions; POST/CSRF;
credential-free HTML/JSON; encrypted ciphertext preservation; real RAM calculation;
CPU zero; missing/invalid telemetry; database failures; successful/failed snapshots
and retained historical last-success timestamp.

## Browser test

1. Restart NetShield using .\start-netshield-local.ps1.
2. Visit http://127.0.0.1:8000/devices/ and sign in as an administrator if needed.
3. For a saved, enabled MikroTik device within 172.26.241.0/24, choose
   Actions > Test Connection.
4. Confirm table/model/CPU/RAM/status and the existing details panel update.
   Last test time and sanitized errors appear in the row.

Only explicit local settings default to 172.26.241.0/24. Normal deployment
settings deny connections until NETSHIELD_DEVICE_ALLOWED_NETWORKS explicitly
defines permitted CIDRs. TLS requires a trusted certificate containing the saved
IP as an IP subject alternative name; NETSHIELD_DEVICE_TLS_CA_FILE optionally
points to an internal CA PEM. No TLS downgrade is attempted. Plain API remains
available only for profiles explicitly configured without API-SSL.

Online/Offline is the outcome of the last completed test, never a claim about
current connectivity. Dynamic CPU/RAM/uptime information is cleared after a failed
test; historical last successful time and last known hardware model may remain.
Traffic and PPS stay Not available. There is no continuous device monitoring.
The three-second timeout is per connection/socket operation, not a total-request
deadline. If the browser's 30-second wait expires, refresh to see any saved result.

No router configuration/firewall/user/restart operations, credential changes,
Edit/Delete, Public IP management, DDoS detection or subsequent steps implemented.
Stopped after Step 3.
