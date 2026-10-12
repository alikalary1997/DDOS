# NetShield Step 5: offline-tested provisioning and RAW monitoring

Implemented and tested with mocks. Live provisioning and the new RAW poller remain
disabled. No real router configuration changes or implementation-time router reads
were made. Existing Dashboard monitoring remains untouched.

## Files and architecture

Modified:
- devices/models.py, forms.py, presentation.py, views.py, urls.py:
  explicit incoming interface; administrator-only saved-device interface discovery
  and local configuration; credentials unchanged.
- public_ips/models.py, views.py, urls.py:
  committed assignments invoke provisioning; audited retry; cached RAW data;
  administrator-only IP/device polling controls.
- netshield/settings.py: OFF gates and per-device OS lock directory.
- monitor/templates/monitor/devices.html, components/device_actions.html:
  incoming interface dropdown/discovery/save.
- monitor/templates/monitor/public_ips.html: provisioning result/retry,
  RAW packets/PPS/bytes/Mbps/time/status, polling controls and real cached counts.
- monitor/static/monitor/js/devices.js and public_ips.js:
  safe text-only updates; read-only cached refresh every two seconds when released.
- .gitignore: exclude runtime lock files.
- public_ips/README.md and devices/README.md: operation/security documentation.

Created:
- devices/services/router_session.py: saved credentials, allowlist, verified TLS,
  three-second socket/connect timeout, disconnect, sanitized failures.
- devices/services/router_lock.py: process-safe per-device OS locking.
- public_ips/services/rules.py: exact monitoring properties and safe placement.
- public_ips/services/provisioning.py: audit-before-network, gate-before-network,
  create missing rules only, re-read/verify, idempotent retries.
- public_ips/services/monitoring.py: separately gated read-only RAW sampler,
  monotonic counter deltas, cache and status freshness.
- public_ips/management/commands/poll_raw_firewall.py and package files:
  separately gated singleton worker, one read per active saved device per cycle.
- start-netshield-raw-polling.ps1: optional local worker launcher using the existing
  persistent encryption key; currently fails closed because polling is disabled.
- devices/migrations/0003_device_incoming_monitoring_interface.py.
- public_ips/migrations/0002_publicip_monitoring_enabled_and_more.py.
- public_ips/tests/test_provisioning.py and test_raw_monitoring.py.
- public_ips/services/__init__.py and tests/__init__.py.
- public_ips/STEP5_REPORT.md.

Moved public_ips/tests.py to public_ips/tests/test_inventory.py, with its model
import updated for the package structure; all prior tests retained.

## Database and backup

D:/DDOS/backups/step5-provisioning-20261010T104946Z contains pre-change source copies, source hashes,
db-pre-migration.sqlite3 and record-preservation.json.

Applied:
- devices.0003_device_incoming_monitoring_interface
- public_ips.0002_publicip_monitoring_enabled_and_more

The SQLite online backup and live database passed integrity_check.
All original fields of the existing one device and one Public IP were compared
before/after migration, including encrypted ciphertext, and are unchanged.
No live audit attempts or new sample records were inserted.

Public IP metadata now tracks provisioning outcome/verification and polling intent.
ProvisioningAttempt retains actor, original device/address/interface, timestamps,
result, requested comments, created IDs and verified IDs. Audit persistence failure
prevents network access or further writes. FirewallSample stores safe counter
snapshots independently of device credentials.

## Rule behavior

Required schema for each address:
- MONITOR-<IP>: prerouting, passthrough, selected incoming interface, host destination.
- MONITOR-SYN-<IP>: same restrictions, protocol=tcp, tcp-flags=syn.
- MONITOR-UDP-<IP>: same restrictions, protocol=udp.

The selected interface must exist exactly once and be enabled. Existing rules
must be static/enabled/valid, unlogged, and match the expected restrictions.
Additional nonempty matchers, conflicting properties, duplicate comments or IDs,
and monitoring rules following a potentially terminating prerouting rule fail
closed. Host destinations may be literal IPv4 or /32, never wider networks.

Missing rules are added ahead of the first prerouting rule. Existing rules retain
their properties and relative ordering. Each add is preceded by a fresh read and
an audit write, followed by validation; the complete set is verified at the end.
The service has no set/remove/move/enable/disable/reset operations.

Only NetShield attempts are serialized by its OS lock; external router changes
cannot be locked by NetShield. Unexpected changes cause verification conflicts.
An API timeout after add may mean that the rule was created. The audit records
the requested comment, and retry discovers the router state instead of blindly
repeating the write. Partial created rules are retained, never rolled back by
deletion. Failed provisioning retains the Public IP assignment.

The actual router's working rule properties have not been inspected during this
offline implementation. Live preflight may report conservative conflicts, including
different SYN flags/interface restrictions or existing rule placement. Such rules
will be reported, never silently modified.

RouterOS RAW reference:
https://manual.mikrotik.com/docs/cli-reference/ip/firewall/raw/

## Monitoring behavior

New provisioning requests polling only after all three rules verify; this does
not mean monitoring is active. The separate worker reads RAW only, with print
stats fallback if ordinary print omits counters. No new CPU/RAM/interface-bandwidth
polling or SNMP was added.

Total, SYN and UDP counters stay separate. The base MONITOR counter is the total;
protocol counters are never added into it. Rates require two valid samples and
actual monotonic elapsed time. First samples, missing/invalid counters, decreases,
rollovers, changed IDs/properties, errors, long gaps and stop/restart invalidate the
baseline. Rollover is conservatively treated as a reset; no assumed wrap width.

RAW-only sampling cannot identify a reboot/reset that happens between samples
if the new counters already exceed the previous values. Known discontinuities
are rebaselined without fabricated traffic.

Cached status requires the current assignment/preference version and a recent
sample (eight-second limit). Stopped/stale/invalidated samples cannot appear
Monitoring. Statuses: Monitoring, No matching RAW rule, Connection error,
Not monitored. Missing metrics show Not available. Volume is never classified
as an attack.

Browser reads use cached data and never open RouterOS connections. IP/device
Start/Stop only update NetShield preferences; they cannot change firewall rules.
The new worker is disabled and is not yet integrated with the legacy Dashboard.
It must not be enabled alongside that Dashboard path until shared-polling
integration is approved and regression-tested, to avoid duplicate polling.

## Tests and verification

- Full regression suite: 163 passed in 35.477 seconds.
- Final focused Public IP suite after UI notices/count/filter updates: 59 passed.
- Normal and local Django system checks: no issues.
- makemigrations --check --dry-run: no changes detected.
- migrate --check: no pending migrations.
- Devices/Public IP JavaScript syntax checks: passed.
- Existing Dashboard data/start/stop regression tests passed with router mocks.
- Live provisioning gate and new polling gate explicitly verified OFF.
- Source hashes verified unchanged Dashboard template/JavaScript/two-second refresh,
  monitor/views.py, monitoring routes, monitor/services/mikrotik_api.py, theme
  script, existing Test Connection service and credential encryption service.

Tests cover automatic invocation after assignment commit, all-new/partial/existing
rules, repeat retries, uncertain timeout outcomes, multiple IPs/devices, conflicts,
ordering, interface validation/discovery, per-device locking, audit failure,
authentication/permissions/POST/CSRF, no unrelated rule mutation, safe malformed
responses, secret-free responses, preserved ciphertext, RAW-only requests, actual
elapsed rates, overlap, resets/rollover, missing rules, stale caches and restart
invalidation. No real router writes were used to run these tests.
Interactive browser/actual-router verification remains pending.

## Current local workflow and next approval

Restart using .\start-netshield-local.ps1.
Devices > Actions > Load interfaces performs an administrator-triggered read-only
interface lookup. Select the real incoming interface and Save interface; this
updates NetShield only. Add Device also accepts an explicit interface name.

Adding a Public IP or Retry provisioning currently records a disabled attempt and
shows Provisioning failed with an approval-required message. The assignment stays
saved. No API connection or rule creation occurs through that provisioning path.

Both settings and code release gates are OFF, with no environment/browser enable
switch. A separately approved code change is required to release provisioning:
NETSHIELD_RAW_PROVISIONING_ENABLED and ROUTER_WRITES_RELEASED. Enabling alone will
not bulk-provision old assignments; Add Public IP or an explicit retry initiates
an attempt. Every attempt still enforces administrator access, saved target,
allowlist, verified TLS, interface checks and rule conflicts.

Stop here and request approval before enabling real-router provisioning.
The new poller and Dashboard integration remain separately gated/pending.
No SNMP, DDoS detection, alerts, routing changes, NAT or unrelated firewall edits.
