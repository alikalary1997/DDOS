# Missing RouterOS requests — investigation

## Exact execution path

1. The Add modal uses a native POST with CSRF to `public_ip_add`; JavaScript does
   not cancel its submission. Its view requires an authenticated administrator.
2. `AddPublicIPForm` validates the address and saved device and copies the device's
   incoming interface into the assignment. No credentials come from the browser.
3. The view commits the assignment in a transaction before calling
   `_provision_assignment`, which invokes `provision_public_ip`.
4. Live database evidence: record 6, address 185.166.26.26, device 4, interface
   ether5 has provisioning audit 6 with code `approval_required` and zero requested,
   created or verified rules. Therefore Save **did trigger provisioning**.
5. Both `ROUTER_WRITES_RELEASED` and `NETSHIELD_RAW_PROVISIONING_ENABLED` are false;
   the controlled-test release is also false with no approved target. The normal
   Save path stops at this approval gate **before decrypting or connecting**.
6. Once approved, the existing RouterOS flow decrypts stored credentials, uses
   the saved management address/port/TLS settings, validates interfaces, reads
   RAW rules, adds only missing exact passthrough rules and verifies all three.
   It uses RouterOS API, not SSH/Telnet.

## Authorized read-only test

The only selected saved device is Home (ID 4), 192.168.32.1, API port 1122,
API-SSL enabled, incoming interface ether5. The current process initially had no
key, but the original Windows user key used by the server launcher exists, is
valid and successfully decrypts the saved password. It was loaded into the
diagnostic child process only; no new key was generated or stored.

The command environment's configured allowlist blocks this host. For the user's
explicit read-only test, the child process used an isolated /32 allowlist for
exactly 192.168.32.1. No persistent settings or router write gates were changed.

The real API connection attempt failed with `ConnectionRefusedError`, errno and
winerror **10061**, on 192.168.32.1:1122. This proves the attempted API connection
did not reach authenticated RouterOS/interface/RAW reads. It does not prove
whether the port lacks a listener or a network policy actively rejects it.
TLS and RouterOS login could not be verified. No plaintext fallback was attempted.
No interface reads, RAW reads, add requests or verification requests completed.

The operator must verify the saved port and that the intended RouterOS API-SSL
endpoint is reachable from this server, and review the explicit management
allowlist. This implementation does not change router services, TLS preference,
credentials, allowlist or global approval to force a connection.

## Diagnostics and visible status

`runtime/logs/provisioning.log` and the Django server console record assignment
IDs, device IDs, workflow stages, gate/key booleans, counts, numeric socket error
codes and fixed outcomes. Passwords, keys, ciphertext, API payloads, response rows
and exception text are never logged. Logs rotate at 1 MB with three backups.
Mock tests write `provisioning-tests.log`, separately from live diagnostics.
The initial mocked test log is archived as `provisioning-initial-mocked-tests.log`.

Pending approval is displayed as **Pending: approval required** rather than an
API failure; active provisioning shows Pending, real errors show Failed, and only
verified sets show Provisioned. The database-only refresh endpoint updates these
labels every two seconds using textContent. Failed assignments and Retry remain.
`awaiting_approval` is deliberately different from `pending`, so a blocked write
does not lock editing/deletion as if an API operation were running. Historical
approval-required failures are displayed as Pending without rewriting audits.
Device deletion remains database-only, including when approval is pending.

Restart the Django server to load the logging settings and reload Public IPs to
load the revised script. No firewall write release has been performed.

## Source files changed or added

- `netshield/settings.py`
- `devices/services/router_session.py`
- `public_ips/services/diagnostics.py` (new)
- `public_ips/services/preflight.py`
- `public_ips/services/provisioning.py`
- `public_ips/views.py`
- `public_ips/management/commands/check_raw_provisioning.py`
- `public_ips/tests/test_provisioning.py`
- `monitor/templates/monitor/public_ips.html`
- `monitor/static/monitor/js/public_ips.js`
- `public_ips/CONTROLLED_LIVE_TEST.md`
- `public_ips/PROVISIONING_DIAGNOSTICS_REPORT.md` (new)

Backup: `backups/provisioning-diagnostics-20261010-201535` contains source and
a consistent SQLite snapshot made before edits. Live testing used read-only
operations; automatic provisioning tests use isolated databases and mocked APIs.

Validation: full automated suite **253 tests passed**. Django system checks,
pending-migration checks, model/migration consistency and JavaScript syntax passed.
Live SQLite records match the pre-change backup and foreign keys are valid.
The live diagnostic log was checked against saved secrets without printing them;
no saved password, ciphertext or key was found. All live-write gates remain closed.
