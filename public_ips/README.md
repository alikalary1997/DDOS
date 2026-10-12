# Public IP assignments, provisioning and RAW monitoring

## Monitoring from the application

Administrator-only Start Monitoring and Stop Monitoring buttons are visible on
each Public IP card. Start launches a single background worker pinned to that
assignment's device ID, assignment ID and IPv4 address. Other addresses never
join the scope automatically. Stop revokes the database run request; the worker
finishes an in-flight read, disconnects and releases its locks. A second Start on
the same live run is idempotent; starting another address requires stopping the
first. The saved Settings interval is used without a browser dependency.

Migration `public_ips.0006_monitoringrun` adds a singleton worker request with a
generation token and heartbeat. No worker is started by the migration, a GET,
or a Django restart. App Start is the explicit authorization for that scoped
read-only run; it does not edit source release flags or enable global polling.
The old gated CLI workflow remains available separately. Crash/startup failures
and stale heartbeats cannot report a live worker indefinitely. Logs are written
to `runtime/app-monitoring.log`; command arguments contain no device credentials.

Real sample snapshots persist in `FirewallSample`. Stopped, stale or disconnected
cards show the last successful values under **Saved Sample**, with their original
timestamp and an explicit historical-data notice. They do not count as active.
Current valid idle samples show zero PPS/Mbps and keep cumulative packet/byte
counters. Each metric updates in its existing place when a new sample arrives. There is
no separate Last traffic detected section; retained samples use the same fields. SYN and UDP packet counters
are shown independently. Past snapshots cannot be reconstructed for periods
before this retention feature existed. Assignment/profile changes invalidate
incompatible snapshots; normal Start/Stop preserves them.

The general dashboard continues to expose only current valid rates; retained
history is displayed explicitly on Public IP cards. Its Stop action also stops
the managed worker without discarding saved samples.

The monitoring page uses responsive address cards with independent provisioning
and telemetry badges, saved device/interface metadata, and Packets/PPS/Bytes/Mbps
metrics. Missing or stale samples show dashes. Details and secondary controls are
collapsed; search, device filtering and monitoring filtering work together.
Theme colors come from the shared NetShield tokens. The cache response includes
the saved `monitoring_enabled` preference so badges stay accurate after updates.
The page only reads database/cache data until an existing action is submitted.

The monitoring cards expose Total PPS, Total Mbps, TCP SYN PPS and UDP PPS,
plus packet/byte counters and the last successful sample timestamp. The
authenticated `raw_monitoring_data` response retains `pps`, `mbps`, `last_update`
and `status`, and adds `syn_pps`, `udp_pps` and `monitoring_message`. Both initial
HTML and subsequent JSON responses use the same cache presentation helper.
Protocol rates are selected by the exact comment for the assigned IP; they are
never summed into total traffic. Missing, invalid or duplicate protocol entries
produce null rates. Stale, stopped, disconnected or missing-rule samples produce
null metrics and a No Data/Not Monitored badge. Actual zero values remain zero.
Mbps uses up to six decimal places so low traffic remains visible. The existing
two-column card metrics layout uses shared light/dark theme tokens.

This UI integration does not enable the polling release gates or launch a worker.
Live values require separately approved worker activation and valid cache samples.

Continuous worker commands now require an explicit single-assignment scope:

```powershell
.\venv\Scripts\python.exe manage.py poll_raw_firewall --device-id 12 --assignment-id 32 --public-ip 185.166.25.75
```

This is the prepared Company test command, not an activation performed by this
change. Both polling release gates remain disabled pending approval. The worker
reads the saved Settings interval (currently 10 seconds for this installation).
The scope is reusable: provide a different matching device ID, assignment ID and
IPv4 address for a later authorized target. There is no implicit all-device mode.

Before every cycle, and again inside the device lock before API access, the
worker validates all three identifiers, device availability, assignment monitoring
enablement and verified provisioning. It pins the initial assignment version and
saved device connection/interface profile. Changes or deletion stop the worker;
an additional check discards a sample if a change occurred during the API read.
New assignments never expand the selected scope. Only the selected assignment's
rates and cache row are produced. The RAW rule listing is still read to validate
rule properties and placement; reading that listing does not monitor or publish
other assignments. MikroTik calls remain GET/print only.

The existing host-wide singleton lock prevents a second worker. Ctrl+C in the
worker terminal stops it, closes the RouterOS connection and releases the worker
and device locks. Cached dashboard values expire through the existing freshness
check. Do not run the command until continuous monitoring is explicitly approved
and its existing release gates are enabled.

UI validation: `manage.py test public_ips` (126 tests),
`node --test public_ips/tests/monitoring_ui.test.cjs` (3 tests), Django checks,
JavaScript syntax check, and migration dry-run passed. Browser visual QA could
not run because no Browser session was available. The redesign did not contact
RouterOS or alter live database records.

See [STEP5_REPORT.md](STEP5_REPORT.md) for the implementation, backups and tests.

Public IP assignments remain unique publicly routable IPv4 addresses associated
with saved MikroTik devices. Only active staff/superusers can add assignments,
retry provisioning, configure interfaces or change polling preferences.
All state changes use POST and CSRF protection.

Automatic add-only Save/Retry uses the device's database setting. Existing and
new MikroTik devices default to enabled after migration 0007. Save and Retry
validate the saved connection and run read-only RAW preflight before the first
write or after a device edit. No authorization checkbox is needed for enabled
devices. Enabling the default does not immediately provision old assignments.
Devices > Actions > RAW provisioning provides an explicit Disable override and
manual validation/authorization to re-enable a disabled device. Manual
validation expires after 15 minutes; successful authorization persists across
restarts and applies to every Public IP assigned to that device.
The database records the administrator, timestamp and a keyed fingerprint of
the saved endpoint, credentials, interface, enabled state and device type.
Configuration changes retain explicit per-device enablement but invalidate the
profile validation. Save/Retry automatically test the current saved connection
and run read-only RAW preflight before renewing the fingerprint and writing.
Runtime fingerprint checks still reject writes using a stale profile. Explicit
Disable stops renewal; device deletion retains router rules.
The Add form copies the selected device's saved interface. Disabled attempts
retain the assignment with `approval_required`; Retry uses the same service.
For an explicitly disabled device, the Add form offers re-enablement. With
that option checked, Save commits the assignment, tests the saved API profile,
runs a read-only preflight for the entered address, and enables per-device
provisioning only after successful validation. Failed validation retains the
assignment as Failed without enabling writes. Subsequent Save and Retry actions
use persisted device approval; configuration changes trigger automatic revalidation.
Global cleanup and RAW polling remain separately disabled.

RAW Traffic Monitoring has a database-backed polling interval in Settings:
2, 5 (default), 10, 15, 30 or 60 seconds. The administrator-only form uses CSRF
and supported-value validation; migration `monitor.0001_initial` seeds 5 seconds.
The existing `poll_raw_firewall` command reads configuration at each idle wait,
checking at most one second apart. Current API cycles complete without cancellation;
the singleton worker and per-device locks prevent overlapping operations.
Browser refresh reads cached results independently and displays the saved interval.
No interval change resets counters, clears rate baselines, or writes router rules.
Rates divide counter deltas by actual monotonic elapsed time, including 60-second
samples. Cache freshness accommodates the current and previous sample intervals.
Existing polling authorization/enablement gates still apply. Interval changes
need no Django or worker restart after the updated worker code is deployed.

Both settings profiles load the shared explicit deployment allowlist from
`netshield/device_management_allowlist.json`; local settings include its local
additional entries. `NETSHIELD_DEVICE_ALLOWED_NETWORKS`, when present, overrides
the complete file policy, including when explicitly empty (deny all). No device
IP is appended by application code. Restart Django after policy changes.
Test Connection and RAW sessions both enforce
`devices.services.targets.validate_target` before decrypting credentials or
opening a connection. Rejections log the applied policy on the server without
exposing credentials or policy contents in browser errors.

Latest read-only preflight for Noc (ID 8), `192.168.32.1:2525`, API SSL OFF,
public IP `5.5.5.55`, saved interface `ether3`: Test Connection passed;
credential decryption, API login, enabled interface, and RAW conflict/placement
checks passed. After explicit approval, assignment ID 15 (`5.5.5.55`) was
recreated and the three exact monitoring rules were added through RouterOS API:
total `*5`, SYN `*6`, UDP `*7`. The first attempt stopped on an immediate
verification conflict after creating two rules; fresh reads verified their exact
properties and an idempotent retry created only the remaining UDP rule.
All three rules were independently verified and the assignment is `verified`.
The unrelated existing rule configuration was preserved. This is historical
validation; that Noc record has since been removed. Current authorization is
stored in each saved device, with no hardcoded device IDs.

Home investigation: ID 10, `192.168.32.1:1122`, API SSL OFF, interface `ether5`,
assignment ID 19 (`1.1.1.1`). Save reached the provisioning service but the old
Noc-only settings gate returned `approval_required`. The new read-only
validation passed: zero matching rules, three missing, no conflicts. Home
remains disabled pending explicit authorization; no real-router writes were
performed during this fix.

On Devices > Actions, Load interfaces reads enabled interface names from the
saved router. Select and Save interface updates NetShield only, invalidates old
rule verification, and never edits router configuration. Device creation also
accepts an optional explicit interface name; no interface is assumed.

When provisioning is released, adding an assignment or Retry provisioning verifies
the interface and existing rules, adds only missing exact passthrough monitoring
rules, and re-reads to verify. Conflicts are reported, never overwritten. Failures
retain assignments and partial created rules. Retry is idempotent.

Monitoring is a separate read-only service and worker. Verified rules alone are
not active monitoring: fresh valid counter samples are required. Missing metrics
show Not available; protocol counters are not added to the base total. Start/Stop
only changes NetShield polling preferences. Existing Dashboard behavior remains
unchanged; shared integration and worker release are pending to avoid duplicate
connections with the legacy Dashboard.

No SNMP, CPU/RAM/interface bandwidth polling, DDoS detection, alerts, routing/NAT
changes, existing firewall edits or deletion are implemented in this step.
