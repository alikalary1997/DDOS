# Database-driven Dashboard implementation

The Dashboard no longer imports or calls the legacy hardcoded MikroTik firewall service. Both / and /monitoring-data/ require login and read saved MikroTik devices, their saved Public IP assignments, and cached RAW samples. No browser refresh creates a RouterOS connection.

## Files
- Created monitor/services/dashboard_data.py: safe database projection, assignment filtering, separate total/SYN/UDP PPS and base-rule matched Mbps.
- Updated monitor/views.py: authenticated cache reads; administrator-only POST/CSRF start/stop controls change persisted polling preferences only. Start refuses while the existing polling release gate is disabled.
- Updated monitor/templates/monitor/dashboard.html and monitor/static/monitor/js/dashboard.js: existing panels/themes retained, saved inventory, separate provisioning/monitoring status, unavailable metrics, approved-workflow retry action, actual sample timestamps, and two-second refresh.
- Updated public_ips/services/monitoring.py: reject cached samples belonging to another device/address; clear stale protocol samples.
- Updated devices/tests/test_monitoring_regression.py, devices/tests/test_local_access.py, public_ips/tests/test_raw_monitoring.py: new database-driven contract and security/cache regressions.

The empty state is exactly: "No devices or public IPs configured yet."
Protocol subsets are never added to total PPS or traffic. Historical device connection tests are labeled as last tests, not current online status. Unrelated/unassigned rules are never rendered. Credentials and encryption keys are excluded from the Dashboard projection.

## Verification
- Python environment verified: project venv, Django 6.1.2.
- django check: passed.
- makemigrations --check --dry-run: no changes detected.
- migrate --check: passed; no migrations applied.
- Full automated suite: 171 tests passed, including existing device connection, encrypted credential, provisioning, firewall sampling and local session tests.
- node --check dashboard.js: passed.
- SQLite comparison against backup: saved device, Public IP, audit and sample records unchanged.
- Existing MikroTik monitoring service and rule templates were not modified.
- No real router API calls or configuration changes were made.
- No visual browser verification was performed.

## Safety and use
Provisioning and polling release gates and settings remain disabled. Existing automatic provisioning after assignment and Retry Provisioning remain gated and audited; this change does not authorize or enable writes. Counters will display only after explicit live authorization, successful verification and fresh valid samples from the existing worker. Missing rules, connection errors and unavailable/stale samples retain honest status.

Refresh the Dashboard; restart with .\start-netshield-local.ps1 if your server has not reloaded the Python changes. Sign in using your existing persistent local session. No additional migration is needed.

Backup of affected original files and SQLite: D:/DDOS/backups/dashboard-database-2026-10-10T123804417Z.
